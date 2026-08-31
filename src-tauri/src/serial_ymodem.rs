use std::{
    error::Error,
    fmt, io,
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

use netcatty_serial::{
    MAX_YMODEM_FILENAME_BYTES, SerialRawTransfer, SerialRawTransferEvent, SerialRuntimeError,
    SerialSessionId, SerialTransferId, SerialTransferKind, YMODEM_CANCEL_SEQUENCE, YmodemBytes,
    YmodemConfig, YmodemError, YmodemFileMetadata, YmodemProgress, YmodemProgressStage,
    YmodemReceiver, YmodemReceiverAction, YmodemSender, YmodemSenderAction,
    sanitize_ymodem_filename,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::DesktopState;

const SERIAL_SESSION_ID_BYTES: usize = 36;
const SERIAL_TRANSFER_ID_BYTES: usize = 36;
const MAX_NATIVE_PATH_BYTES: usize = 32 * 1024;
const MAX_UNIQUE_DESTINATION_ATTEMPTS: u32 = 10_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum SerialTransferDialogLocale {
    #[default]
    ZhCn,
    EnUs,
}

impl<'de> Deserialize<'de> for SerialTransferDialogLocale {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let locale = String::deserialize(deserializer)?;
        Ok(if locale == "en-US" {
            Self::EnUs
        } else {
            Self::ZhCn
        })
    }
}

fn serial_transfer_dialog_locale(
    locale: Option<SerialTransferDialogLocale>,
) -> SerialTransferDialogLocale {
    locale.unwrap_or_default()
}

struct YmodemDialogText {
    send_title: &'static str,
    receive_title: &'static str,
    all_files_filter: &'static str,
}

fn ymodem_dialog_text(locale: SerialTransferDialogLocale) -> YmodemDialogText {
    match locale {
        SerialTransferDialogLocale::ZhCn => YmodemDialogText {
            send_title: "选择要通过 YMODEM 发送的文件",
            receive_title: "选择保存 YMODEM 接收文件的文件夹",
            all_files_filter: "所有文件",
        },
        SerialTransferDialogLocale::EnUs => YmodemDialogText {
            send_title: "Select a file to send with YMODEM",
            receive_title: "Select a folder for received YMODEM files",
            all_files_filter: "All files",
        },
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SerialYmodemDirection {
    Send,
    Receive,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SerialYmodemProgressStage {
    Header,
    Data,
    Complete,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SerialYmodemProgressEvent {
    transfer_id: String,
    direction: SerialYmodemDirection,
    stage: SerialYmodemProgressStage,
    transferred_bytes: u64,
    total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    file_count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendSerialYmodemResponse {
    canceled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    total_bytes: u64,
    written_bytes: u64,
    packets_sent: u64,
}

impl SendSerialYmodemResponse {
    fn canceled() -> Self {
        Self {
            canceled: true,
            file_name: None,
            total_bytes: 0,
            written_bytes: 0,
            packets_sent: 0,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceivedSerialYmodemFile {
    file_name: String,
    total_bytes: u64,
    written_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiveSerialYmodemResponse {
    canceled: bool,
    files: Vec<ReceivedSerialYmodemFile>,
    file_count: u64,
    total_bytes: u64,
    written_bytes: u64,
}

impl ReceiveSerialYmodemResponse {
    fn canceled() -> Self {
        Self {
            canceled: true,
            files: Vec::new(),
            file_count: 0,
            total_bytes: 0,
            written_bytes: 0,
        }
    }
}

#[derive(Clone, Copy)]
enum NativeFileOperation {
    Select,
    Inspect,
    Open,
    Read,
    Write,
    Flush,
}

#[derive(Clone)]
enum SerialYmodemCommandError {
    InvalidSession,
    DialogFailed,
    SelectedPathInvalid,
    SelectedFileNotRegular,
    SelectedDestinationNotDirectory,
    DestinationExists,
    NativeFileFailed { operation: NativeFileOperation },
    Runtime(SerialRuntimeError),
    Protocol(YmodemError),
    ProgressChannelClosed,
    SerialClosed,
    InvalidState,
}

impl SerialYmodemCommandError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidSession => "YMODEM_INVALID_SESSION",
            Self::DialogFailed => "YMODEM_DIALOG_FAILED",
            Self::SelectedPathInvalid => "YMODEM_SELECTED_PATH_INVALID",
            Self::SelectedFileNotRegular => "YMODEM_NOT_FILE",
            Self::SelectedDestinationNotDirectory => "YMODEM_DESTINATION_NOT_DIRECTORY",
            Self::DestinationExists => "YMODEM_DESTINATION_EXISTS",
            Self::NativeFileFailed { .. } => "YMODEM_FILE_IO_FAILED",
            Self::Runtime(SerialRuntimeError::TransferActive { .. }) => "YMODEM_TRANSFER_BUSY",
            Self::Runtime(SerialRuntimeError::SessionNotFound) => "YMODEM_NO_SERIAL",
            Self::Runtime(SerialRuntimeError::InvalidTransferId) => "YMODEM_INVALID_TRANSFER",
            Self::Runtime(_) => "YMODEM_SERIAL_RUNTIME_FAILED",
            Self::Protocol(error) => error.code(),
            Self::ProgressChannelClosed => "YMODEM_PROGRESS_CHANNEL_CLOSED",
            Self::SerialClosed => "YMODEM_SERIAL_CLOSED",
            Self::InvalidState => "YMODEM_INVALID_STATE",
        }
    }
}

impl fmt::Debug for SerialYmodemCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SerialYmodemCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSession => formatter.write_str("Serial session ID is invalid"),
            Self::DialogFailed => formatter.write_str("Native YMODEM selection dialog failed"),
            Self::SelectedPathInvalid => formatter.write_str("Selected native path is invalid"),
            Self::SelectedFileNotRegular => formatter.write_str("Selected path is not a file"),
            Self::SelectedDestinationNotDirectory => {
                formatter.write_str("Selected destination is not a directory")
            }
            Self::DestinationExists => {
                formatter.write_str("Could not choose a destination file name")
            }
            Self::NativeFileFailed { operation } => {
                write!(formatter, "YMODEM native file {operation} failed")
            }
            Self::Runtime(error) => fmt::Display::fmt(error, formatter),
            Self::Protocol(error) => fmt::Display::fmt(error, formatter),
            Self::ProgressChannelClosed => {
                formatter.write_str("YMODEM progress receiver is unavailable")
            }
            Self::SerialClosed => formatter.write_str("Serial port closed during YMODEM transfer"),
            Self::InvalidState => formatter.write_str("YMODEM transfer state is invalid"),
        }
    }
}

impl fmt::Display for NativeFileOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Select => "selection",
            Self::Inspect => "inspection",
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
        })
    }
}

impl Error for SerialYmodemCommandError {}

impl From<SerialRuntimeError> for SerialYmodemCommandError {
    fn from(error: SerialRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<YmodemError> for SerialYmodemCommandError {
    fn from(error: YmodemError) -> Self {
        Self::Protocol(error)
    }
}

fn command_error(error: SerialYmodemCommandError) -> String {
    format!("{}: {error}", error.code())
}

#[tauri::command]
pub(crate) async fn send_serial_ymodem(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    session_id: String,
    locale: Option<SerialTransferDialogLocale>,
    on_progress: Channel<SerialYmodemProgressEvent>,
) -> Result<SendSerialYmodemResponse, String> {
    let locale = serial_transfer_dialog_locale(locale);
    let session_id = parse_session_id(&session_id).map_err(command_error)?;
    ensure_session_available(state.inner(), &session_id).map_err(command_error)?;
    let Some(selected_path) = choose_send_file(&window, locale)
        .await
        .map_err(command_error)?
    else {
        return Ok(SendSerialYmodemResponse::canceled());
    };
    let (mut source, metadata) = open_send_source(&selected_path)
        .await
        .map_err(command_error)?;
    let mut transfer = state
        .serial_sessions
        .begin_raw_transfer(&session_id, SerialTransferKind::YmodemSend)
        .map_err(SerialYmodemCommandError::from)
        .map_err(command_error)?;
    let result = drive_sender(&mut transfer, &mut source, metadata, &on_progress).await;
    if result.as_ref().is_err_and(should_send_protocol_abort) {
        let _ = transfer.write_protocol_abort(&YMODEM_CANCEL_SEQUENCE).await;
    }
    let finish = match &result {
        Ok((_, terminal_bytes)) => {
            transfer
                .finish_with_terminal_bytes(terminal_bytes.as_slice())
                .await
        }
        Err(_) => transfer.finish().await,
    };
    let (summary, _) = result.map_err(command_error)?;
    finish
        .map_err(SerialYmodemCommandError::from)
        .map_err(command_error)?;
    Ok(SendSerialYmodemResponse {
        canceled: false,
        file_name: Some(summary.file_name().to_owned()),
        total_bytes: summary.total_bytes,
        written_bytes: summary.written_bytes,
        packets_sent: summary.packets_sent,
    })
}

#[tauri::command]
pub(crate) async fn receive_serial_ymodem(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    session_id: String,
    locale: Option<SerialTransferDialogLocale>,
    on_progress: Channel<SerialYmodemProgressEvent>,
) -> Result<ReceiveSerialYmodemResponse, String> {
    let locale = serial_transfer_dialog_locale(locale);
    let session_id = parse_session_id(&session_id).map_err(command_error)?;
    ensure_session_available(state.inner(), &session_id).map_err(command_error)?;
    let Some(destination) = choose_receive_directory(&window, locale)
        .await
        .map_err(command_error)?
    else {
        return Ok(ReceiveSerialYmodemResponse::canceled());
    };
    validate_destination_directory(&destination)
        .await
        .map_err(command_error)?;
    let mut transfer = state
        .serial_sessions
        .begin_raw_transfer(&session_id, SerialTransferKind::YmodemReceive)
        .map_err(SerialYmodemCommandError::from)
        .map_err(command_error)?;
    let result = drive_receiver(&mut transfer, &destination, &on_progress).await;
    if result.as_ref().is_err_and(should_send_protocol_abort) {
        let _ = transfer.write_protocol_abort(&YMODEM_CANCEL_SEQUENCE).await;
    }
    let finish = match &result {
        Ok((_, terminal_bytes)) => {
            transfer
                .finish_with_terminal_bytes(terminal_bytes.as_slice())
                .await
        }
        Err(_) => transfer.finish().await,
    };
    let (response, _) = result.map_err(command_error)?;
    finish
        .map_err(SerialYmodemCommandError::from)
        .map_err(command_error)?;
    Ok(response)
}

#[tauri::command]
pub(crate) fn cancel_serial_ymodem(
    state: State<'_, DesktopState>,
    session_id: String,
    transfer_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id).map_err(command_error)?;
    let transfer_id = parse_transfer_id(&transfer_id).map_err(command_error)?;
    state
        .serial_sessions
        .request_transfer_cancel_exact(&session_id, &transfer_id)
        .map_err(SerialYmodemCommandError::from)
        .map_err(command_error)
}

async fn choose_send_file(
    window: &WebviewWindow,
    locale: SerialTransferDialogLocale,
) -> Result<Option<PathBuf>, SerialYmodemCommandError> {
    let text = ymodem_dialog_text(locale);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .app_handle()
        .dialog()
        .file()
        .set_title(text.send_title)
        .add_filter(text.all_files_filter, &["*"])
        .set_parent(window)
        .pick_file(move |selected| {
            let selected = selected
                .map(|path| path.into_path())
                .transpose()
                .map_err(|_| SerialYmodemCommandError::NativeFileFailed {
                    operation: NativeFileOperation::Select,
                });
            let _ = sender.send(selected);
        });
    receiver
        .await
        .map_err(|_| SerialYmodemCommandError::DialogFailed)?
}

async fn choose_receive_directory(
    window: &WebviewWindow,
    locale: SerialTransferDialogLocale,
) -> Result<Option<PathBuf>, SerialYmodemCommandError> {
    let text = ymodem_dialog_text(locale);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .app_handle()
        .dialog()
        .file()
        .set_title(text.receive_title)
        .set_parent(window)
        .pick_folder(move |selected| {
            let selected = selected
                .map(|path| path.into_path())
                .transpose()
                .map_err(|_| SerialYmodemCommandError::NativeFileFailed {
                    operation: NativeFileOperation::Select,
                });
            let _ = sender.send(selected);
        });
    receiver
        .await
        .map_err(|_| SerialYmodemCommandError::DialogFailed)?
}

fn parse_session_id(value: &str) -> Result<SerialSessionId, SerialYmodemCommandError> {
    if value.len() != SERIAL_SESSION_ID_BYTES {
        return Err(SerialYmodemCommandError::InvalidSession);
    }
    SerialSessionId::parse(value).map_err(|_| SerialYmodemCommandError::InvalidSession)
}

fn parse_transfer_id(value: &str) -> Result<SerialTransferId, SerialYmodemCommandError> {
    if value.len() != SERIAL_TRANSFER_ID_BYTES {
        return Err(SerialRuntimeError::InvalidTransferId.into());
    }
    SerialTransferId::parse(value).map_err(SerialYmodemCommandError::from)
}

fn ensure_session_available(
    state: &DesktopState,
    session_id: &SerialSessionId,
) -> Result<(), SerialYmodemCommandError> {
    match state.serial_sessions.active_transfer_kind(session_id)? {
        None => Ok(()),
        Some(kind) => Err(SerialYmodemCommandError::Runtime(
            SerialRuntimeError::TransferActive { kind },
        )),
    }
}

fn validate_native_path(path: &Path) -> Result<(), SerialYmodemCommandError> {
    let length = path.as_os_str().to_string_lossy().len();
    if length == 0 || length > MAX_NATIVE_PATH_BYTES {
        Err(SerialYmodemCommandError::SelectedPathInvalid)
    } else {
        Ok(())
    }
}

async fn open_send_source(
    path: &Path,
) -> Result<(tokio::fs::File, YmodemFileMetadata), SerialYmodemCommandError> {
    validate_native_path(path)?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or(SerialYmodemCommandError::SelectedPathInvalid)?;
    let file = tokio::fs::File::open(path).await.map_err(|_| {
        SerialYmodemCommandError::NativeFileFailed {
            operation: NativeFileOperation::Open,
        }
    })?;
    let file_metadata =
        file.metadata()
            .await
            .map_err(|_| SerialYmodemCommandError::NativeFileFailed {
                operation: NativeFileOperation::Inspect,
            })?;
    if !file_metadata.is_file() {
        return Err(SerialYmodemCommandError::SelectedFileNotRegular);
    }
    let modified_time = file_metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs());
    let metadata = YmodemFileMetadata::new(
        file_name,
        file_metadata.len(),
        modified_time,
        native_file_mode(&file_metadata),
    )?;
    Ok((file, metadata))
}

#[cfg(unix)]
fn native_file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn native_file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0o100644
}

async fn validate_destination_directory(path: &Path) -> Result<(), SerialYmodemCommandError> {
    validate_native_path(path)?;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| SerialYmodemCommandError::SelectedDestinationNotDirectory)?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(SerialYmodemCommandError::SelectedDestinationNotDirectory)
    }
}

async fn drive_sender(
    transfer: &mut SerialRawTransfer,
    source: &mut tokio::fs::File,
    metadata: YmodemFileMetadata,
    progress: &Channel<SerialYmodemProgressEvent>,
) -> Result<(netcatty_serial::YmodemSendSummary, YmodemBytes), SerialYmodemCommandError> {
    let transfer_id = transfer.transfer_id().clone();
    let file_name = metadata.file_name().to_owned();
    let total_bytes = metadata.total_bytes();
    emit_progress(
        progress,
        &transfer_id,
        SerialYmodemDirection::Send,
        YmodemProgress {
            transferred_bytes: 0,
            total_bytes,
            stage: YmodemProgressStage::Header,
        },
        Some(file_name.clone()),
        1,
    )?;
    let mut sender = YmodemSender::new(metadata, YmodemConfig::default())?;
    loop {
        while let Some(action) = sender.next_action() {
            match action {
                YmodemSenderAction::Write(bytes) => transfer.write(bytes.as_slice()).await?,
                YmodemSenderAction::ReadSource { exact_bytes } => {
                    let mut chunk = vec![0_u8; exact_bytes];
                    source.read_exact(&mut chunk).await.map_err(|_| {
                        SerialYmodemCommandError::NativeFileFailed {
                            operation: NativeFileOperation::Read,
                        }
                    })?;
                    sender.provide_source_chunk(&chunk)?;
                }
                YmodemSenderAction::Progress(value) => {
                    emit_progress(
                        progress,
                        &transfer_id,
                        SerialYmodemDirection::Send,
                        value,
                        Some(file_name.clone()),
                        1,
                    )?;
                }
                YmodemSenderAction::Completed {
                    summary,
                    terminal_bytes,
                } => return Ok((summary, terminal_bytes)),
                YmodemSenderAction::Failed(error) => return Err(error.into()),
            }
        }
        let timeout = sender
            .timeout()
            .ok_or(SerialYmodemCommandError::InvalidState)?;
        tokio::select! {
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::Data(bytes)) => sender.push_serial_bytes(bytes.as_slice())?,
                Some(SerialRawTransferEvent::CancelRequested) => sender.cancel(),
                None => return Err(SerialYmodemCommandError::SerialClosed),
            },
            _ = tokio::time::sleep(timeout) => sender.on_timeout()?,
        }
    }
}

async fn drive_receiver(
    transfer: &mut SerialRawTransfer,
    destination: &Path,
    progress: &Channel<SerialYmodemProgressEvent>,
) -> Result<(ReceiveSerialYmodemResponse, YmodemBytes), SerialYmodemCommandError> {
    let transfer_id = transfer.transfer_id().clone();
    emit_progress(
        progress,
        &transfer_id,
        SerialYmodemDirection::Receive,
        YmodemProgress {
            transferred_bytes: 0,
            total_bytes: 0,
            stage: YmodemProgressStage::Header,
        },
        None,
        0,
    )?;
    let mut receiver = YmodemReceiver::new(YmodemConfig::default());
    let mut pending_file: Option<PendingReceiveFile> = None;
    let mut files = Vec::new();
    let mut current_file_name = None;

    loop {
        while let Some(action) = receiver.next_action() {
            match action {
                YmodemReceiverAction::Write(bytes) => transfer.write(bytes.as_slice()).await?,
                YmodemReceiverAction::BeginFile(metadata) => {
                    if pending_file.is_some() {
                        return Err(SerialYmodemCommandError::InvalidState);
                    }
                    current_file_name = Some(metadata.file_name().to_owned());
                    pending_file = Some(
                        open_unique_destination(
                            destination,
                            metadata.file_name(),
                            metadata.total_bytes(),
                        )
                        .await?,
                    );
                    receiver.accept_file()?;
                }
                YmodemReceiverAction::WriteFile(bytes) => {
                    let pending = pending_file
                        .as_mut()
                        .ok_or(SerialYmodemCommandError::InvalidState)?;
                    pending
                        .file
                        .as_mut()
                        .ok_or(SerialYmodemCommandError::InvalidState)?
                        .write_all(bytes.as_slice())
                        .await
                        .map_err(|_| SerialYmodemCommandError::NativeFileFailed {
                            operation: NativeFileOperation::Write,
                        })?;
                    receiver.confirm_file_write()?;
                }
                YmodemReceiverAction::Progress(value) => {
                    emit_progress(
                        progress,
                        &transfer_id,
                        SerialYmodemDirection::Receive,
                        value,
                        current_file_name.clone(),
                        files.len() as u64,
                    )?;
                }
                YmodemReceiverAction::FileCompleted(summary) => {
                    let mut pending = pending_file
                        .take()
                        .ok_or(SerialYmodemCommandError::InvalidState)?;
                    pending
                        .file
                        .as_mut()
                        .ok_or(SerialYmodemCommandError::InvalidState)?
                        .flush()
                        .await
                        .map_err(|_| SerialYmodemCommandError::NativeFileFailed {
                            operation: NativeFileOperation::Flush,
                        })?;
                    pending.commit();
                    files.push(ReceivedSerialYmodemFile {
                        file_name: summary.file_name().to_owned(),
                        total_bytes: summary.total_bytes,
                        written_bytes: summary.written_bytes,
                    });
                    current_file_name = None;
                }
                YmodemReceiverAction::BatchCompleted {
                    file_count,
                    total_bytes,
                    terminal_bytes,
                } => {
                    if pending_file.is_some() {
                        return Err(SerialYmodemCommandError::InvalidState);
                    }
                    let written_bytes = files.iter().map(|file| file.written_bytes).sum();
                    emit_progress(
                        progress,
                        &transfer_id,
                        SerialYmodemDirection::Receive,
                        YmodemProgress {
                            transferred_bytes: written_bytes,
                            total_bytes,
                            stage: YmodemProgressStage::Complete,
                        },
                        None,
                        file_count,
                    )?;
                    return Ok((
                        ReceiveSerialYmodemResponse {
                            canceled: false,
                            files,
                            file_count,
                            total_bytes,
                            written_bytes,
                        },
                        terminal_bytes,
                    ));
                }
                YmodemReceiverAction::Failed(error) => return Err(error.into()),
            }
        }
        let timeout = receiver
            .timeout()
            .ok_or(SerialYmodemCommandError::InvalidState)?;
        tokio::select! {
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::Data(bytes)) => receiver.push_serial_bytes(bytes.as_slice())?,
                Some(SerialRawTransferEvent::CancelRequested) => receiver.cancel(),
                None => return Err(SerialYmodemCommandError::SerialClosed),
            },
            _ = tokio::time::sleep(timeout) => receiver.on_timeout()?,
        }
    }
}

fn emit_progress(
    channel: &Channel<SerialYmodemProgressEvent>,
    transfer_id: &SerialTransferId,
    direction: SerialYmodemDirection,
    progress: YmodemProgress,
    file_name: Option<String>,
    file_count: u64,
) -> Result<(), SerialYmodemCommandError> {
    channel
        .send(SerialYmodemProgressEvent {
            transfer_id: transfer_id.as_str().to_owned(),
            direction,
            stage: match progress.stage {
                YmodemProgressStage::Header => SerialYmodemProgressStage::Header,
                YmodemProgressStage::Data => SerialYmodemProgressStage::Data,
                YmodemProgressStage::Complete => SerialYmodemProgressStage::Complete,
            },
            transferred_bytes: progress.transferred_bytes,
            total_bytes: progress.total_bytes,
            file_name,
            file_count,
        })
        .map_err(|_| SerialYmodemCommandError::ProgressChannelClosed)
}

fn should_send_protocol_abort(error: &SerialYmodemCommandError) -> bool {
    !matches!(
        error,
        SerialYmodemCommandError::Protocol(YmodemError::RemoteCancelled)
    )
}

struct PendingReceiveFile {
    file: Option<tokio::fs::File>,
    path: PathBuf,
    committed: bool,
}

impl PendingReceiveFile {
    fn commit(&mut self) {
        self.file.take();
        self.committed = true;
    }
}

impl Drop for PendingReceiveFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn open_unique_destination(
    destination: &Path,
    file_name: &str,
    _total_bytes: u64,
) -> Result<PendingReceiveFile, SerialYmodemCommandError> {
    if file_name.is_empty() || file_name.len() > MAX_YMODEM_FILENAME_BYTES {
        return Err(SerialYmodemCommandError::SelectedPathInvalid);
    }
    let sanitized = sanitize_ymodem_filename(file_name)?;
    let parsed = Path::new(file_name);
    let mut components = parsed.components();
    if sanitized != file_name
        || parsed.is_absolute()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(SerialYmodemCommandError::SelectedPathInvalid);
    }
    let stem = parsed
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| file_name.to_owned());
    let extension = parsed
        .extension()
        .map(|value| value.to_string_lossy().into_owned());

    for attempt in 0..MAX_UNIQUE_DESTINATION_ATTEMPTS {
        let candidate_name = if attempt == 0 {
            file_name.to_owned()
        } else if let Some(extension) = extension.as_deref() {
            format!("{stem} ({attempt}).{extension}")
        } else {
            format!("{stem} ({attempt})")
        };
        if candidate_name.len() > MAX_YMODEM_FILENAME_BYTES {
            continue;
        }
        let candidate = destination.join(candidate_name);
        validate_native_path(&candidate)?;
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => {
                return Ok(PendingReceiveFile {
                    file: Some(file),
                    path: candidate,
                    committed: false,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(SerialYmodemCommandError::NativeFileFailed {
                    operation: NativeFileOperation::Open,
                });
            }
        }
    }
    Err(SerialYmodemCommandError::DestinationExists)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_dialog_locale_uses_english_only_for_the_exact_supported_value() {
        assert_eq!(
            serde_json::from_str::<SerialTransferDialogLocale>(r#""zh-CN""#).unwrap(),
            SerialTransferDialogLocale::ZhCn
        );
        assert_eq!(
            serde_json::from_str::<SerialTransferDialogLocale>(r#""en-US""#).unwrap(),
            SerialTransferDialogLocale::EnUs
        );
        assert_eq!(
            SerialTransferDialogLocale::default(),
            SerialTransferDialogLocale::ZhCn
        );
        assert_eq!(
            serde_json::from_str::<SerialTransferDialogLocale>(r#""zh-cn""#).unwrap(),
            SerialTransferDialogLocale::ZhCn
        );
        assert_eq!(
            serde_json::from_str::<SerialTransferDialogLocale>(r#""EN-US""#).unwrap(),
            SerialTransferDialogLocale::ZhCn
        );
        assert_eq!(
            serde_json::from_str::<SerialTransferDialogLocale>(r#""unsupported""#).unwrap(),
            SerialTransferDialogLocale::ZhCn
        );
        assert_eq!(
            serial_transfer_dialog_locale(None),
            SerialTransferDialogLocale::ZhCn
        );
        assert!(
            serde_json::from_str::<SerialTransferDialogLocale>("null").is_err(),
            "locale must remain a string when it is present"
        );

        let chinese = ymodem_dialog_text(SerialTransferDialogLocale::ZhCn);
        let english = ymodem_dialog_text(SerialTransferDialogLocale::EnUs);
        assert_eq!(chinese.all_files_filter, "所有文件");
        assert_eq!(english.all_files_filter, "All files");
    }

    #[test]
    fn command_errors_and_debug_never_expose_native_paths_or_payloads() {
        let marker = "PRIVATE-NATIVE-PATH";
        let error = SerialYmodemCommandError::NativeFileFailed {
            operation: NativeFileOperation::Read,
        };
        assert!(!format!("{error:?}").contains(marker));
        assert!(!command_error(error).contains(marker));
        let protocol = command_error(SerialYmodemCommandError::Protocol(
            YmodemError::InvalidSourceChunk {
                expected: 1024,
                actual: marker.len(),
            },
        ));
        assert!(!protocol.contains(marker));
    }

    #[test]
    fn response_contracts_never_serialize_destination_paths() {
        let response = ReceiveSerialYmodemResponse {
            canceled: false,
            files: vec![ReceivedSerialYmodemFile {
                file_name: "safe.bin".to_owned(),
                total_bytes: 3,
                written_bytes: 3,
            }],
            file_count: 1,
            total_bytes: 3,
            written_bytes: 3,
        };
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["files"][0]["fileName"], "safe.bin");
        assert!(json["files"][0].get("filePath").is_none());
        assert_eq!(
            serde_json::to_value(SendSerialYmodemResponse::canceled()).unwrap()["canceled"],
            true
        );
    }

    #[test]
    fn progress_and_cancel_contracts_use_one_canonical_transfer_id() {
        let raw = "123e4567-e89b-42d3-a456-426614174000";
        let transfer_id = parse_transfer_id(raw).unwrap();
        assert_eq!(transfer_id.as_str(), raw);
        assert!(matches!(
            parse_transfer_id("not-a-transfer-id"),
            Err(SerialYmodemCommandError::Runtime(
                SerialRuntimeError::InvalidTransferId
            ))
        ));

        let event = SerialYmodemProgressEvent {
            transfer_id: transfer_id.as_str().to_owned(),
            direction: SerialYmodemDirection::Send,
            stage: SerialYmodemProgressStage::Header,
            transferred_bytes: 0,
            total_bytes: 3,
            file_name: Some("safe.bin".to_owned()),
            file_count: 1,
        };
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["transferId"], raw);
        assert!(json.get("sessionId").is_none());
        assert!(json.get("filePath").is_none());
    }

    #[test]
    fn local_cancel_and_failures_require_exact_protocol_abort_but_remote_cancel_does_not() {
        assert!(should_send_protocol_abort(
            &SerialYmodemCommandError::Protocol(YmodemError::Cancelled)
        ));
        assert!(!should_send_protocol_abort(
            &SerialYmodemCommandError::Protocol(YmodemError::RemoteCancelled)
        ));
        assert!(should_send_protocol_abort(
            &SerialYmodemCommandError::Runtime(SerialRuntimeError::TransferCancelled)
        ));
    }

    #[tokio::test]
    async fn destination_creation_is_atomic_unique_and_failed_files_are_removed() {
        let directory = tempfile::tempdir().unwrap();
        tokio::fs::write(directory.path().join("firmware.bin"), b"existing")
            .await
            .unwrap();
        let mut pending = open_unique_destination(directory.path(), "firmware.bin", 3)
            .await
            .unwrap();
        assert_eq!(
            pending.path.file_name().unwrap().to_string_lossy(),
            "firmware (1).bin"
        );
        pending
            .file
            .as_mut()
            .unwrap()
            .write_all(b"bad")
            .await
            .unwrap();
        let failed_path = pending.path.clone();
        drop(pending);
        assert!(!failed_path.exists());
        assert_eq!(
            tokio::fs::read(directory.path().join("firmware.bin"))
                .await
                .unwrap(),
            b"existing"
        );
    }

    #[tokio::test]
    async fn destination_rejects_absolute_parent_current_and_multi_component_names() {
        let directory = tempfile::tempdir().unwrap();
        for unsafe_name in [
            "/absolute.bin",
            "../escape.bin",
            "./escape.bin",
            "nested/escape.bin",
            r"nested\escape.bin",
            ".",
            "..",
        ] {
            assert!(matches!(
                open_unique_destination(directory.path(), unsafe_name, 1).await,
                Err(SerialYmodemCommandError::SelectedPathInvalid)
            ));
        }
        assert!(directory.path().read_dir().unwrap().next().is_none());
    }

    #[tokio::test]
    async fn committed_destination_survives_guard_and_selected_source_is_streamable() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.bin");
        tokio::fs::write(&source_path, b"abc").await.unwrap();
        let (mut source, metadata) = open_send_source(&source_path).await.unwrap();
        assert_eq!(metadata.file_name(), "source.bin");
        assert_eq!(metadata.total_bytes(), 3);
        let mut body = [0_u8; 3];
        source.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"abc");

        let mut pending = open_unique_destination(directory.path(), "received.bin", 3)
            .await
            .unwrap();
        pending
            .file
            .as_mut()
            .unwrap()
            .write_all(b"abc")
            .await
            .unwrap();
        let committed_path = pending.path.clone();
        pending.commit();
        drop(pending);
        assert_eq!(tokio::fs::read(committed_path).await.unwrap(), b"abc");
    }
}
