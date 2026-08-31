use std::{
    collections::VecDeque,
    error::Error,
    fmt, io,
    path::{Component, Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use cap_std::{ambient_authority, fs::Dir};
use netcatty_serial::{
    MAX_ZMODEM_BATCH_FILES, MAX_ZMODEM_FILENAME_BYTES, SerialRawTransfer, SerialRawTransferEvent,
    SerialRuntimeError, SerialSessionId, SerialTransferId, ZMODEM_CANCEL_SEQUENCE,
    ZmodemBatchSummary, ZmodemBytes, ZmodemConfig, ZmodemError, ZmodemFileMetadata, ZmodemProgress,
    ZmodemProgressStage, ZmodemReceiver, ZmodemReceiverAction, ZmodemSender, ZmodemSenderAction,
    ZmodemTransferDirection, sanitize_zmodem_filename,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::DesktopState;
use super::serial_session::{SerialControlEvent, SerialZmodemDirection, SerialZmodemProgressStage};
use super::serial_ymodem::SerialTransferDialogLocale;

const MAX_NATIVE_PATH_BYTES: usize = 32 * 1024;
const MAX_UNIQUE_DESTINATION_ATTEMPTS: u32 = 10_000;
const MAX_STAGE_ATTEMPTS: u32 = 128;
const MAX_PICKER_BUFFER_EVENTS: usize = 64;
const MAX_PICKER_BUFFER_BYTES: usize = 2 * 1024 * 1024;

struct ZmodemDialogText {
    send_title: &'static str,
    receive_title: &'static str,
    all_files_filter: &'static str,
}

fn zmodem_dialog_text(locale: SerialTransferDialogLocale) -> ZmodemDialogText {
    match locale {
        SerialTransferDialogLocale::ZhCn => ZmodemDialogText {
            send_title: "选择要通过 ZMODEM 发送的文件",
            receive_title: "选择保存 ZMODEM 接收文件的文件夹",
            all_files_filter: "所有文件",
        },
        SerialTransferDialogLocale::EnUs => ZmodemDialogText {
            send_title: "Select files to send with ZMODEM",
            receive_title: "Select a folder for received ZMODEM files",
            all_files_filter: "All files",
        },
    }
}

#[derive(Clone, Copy)]
pub(crate) enum NativeFileOperation {
    Select,
    Inspect,
    Open,
    Seek,
    Read,
    Write,
    Flush,
    Metadata,
    Publish,
}

#[derive(Clone)]
pub(crate) enum SerialZmodemError {
    DialogFailed,
    SelectedPathInvalid,
    SelectedFileNotRegular,
    SelectedDestinationNotDirectory,
    SelectionTooLarge,
    SelectionBufferFull,
    DestinationExists,
    NativeFileFailed { operation: NativeFileOperation },
    Runtime(SerialRuntimeError),
    Protocol(ZmodemError),
    ControlChannelClosed,
    SerialClosed,
    InvalidState,
}

impl SerialZmodemError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::DialogFailed => "ZMODEM_DIALOG_FAILED",
            Self::SelectedPathInvalid => "ZMODEM_SELECTED_PATH_INVALID",
            Self::SelectedFileNotRegular => "ZMODEM_NOT_FILE",
            Self::SelectedDestinationNotDirectory => "ZMODEM_DESTINATION_NOT_DIRECTORY",
            Self::SelectionTooLarge => "ZMODEM_SELECTION_TOO_LARGE",
            Self::SelectionBufferFull => "ZMODEM_SELECTION_BUFFER_FULL",
            Self::DestinationExists => "ZMODEM_DESTINATION_EXISTS",
            Self::NativeFileFailed { .. } => "ZMODEM_FILE_IO_FAILED",
            Self::Runtime(SerialRuntimeError::TransferActive { .. }) => "ZMODEM_TRANSFER_BUSY",
            Self::Runtime(SerialRuntimeError::SessionNotFound) => "ZMODEM_NO_SERIAL",
            Self::Runtime(_) => "ZMODEM_SERIAL_RUNTIME_FAILED",
            Self::Protocol(error) => error.code(),
            Self::ControlChannelClosed => "ZMODEM_PROGRESS_CHANNEL_CLOSED",
            Self::SerialClosed => "ZMODEM_SERIAL_CLOSED",
            Self::InvalidState => "ZMODEM_INVALID_STATE",
        }
    }
}

impl fmt::Debug for SerialZmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SerialZmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DialogFailed => formatter.write_str("Native ZMODEM selection dialog failed"),
            Self::SelectedPathInvalid => formatter.write_str("Selected native path is invalid"),
            Self::SelectedFileNotRegular => formatter.write_str("Selected path is not a file"),
            Self::SelectedDestinationNotDirectory => {
                formatter.write_str("Selected destination is not a directory")
            }
            Self::SelectionTooLarge => formatter.write_str("Too many ZMODEM files were selected"),
            Self::SelectionBufferFull => {
                formatter.write_str("ZMODEM selection buffer reached its safe limit")
            }
            Self::DestinationExists => {
                formatter.write_str("Could not atomically choose a destination file name")
            }
            Self::NativeFileFailed { operation } => {
                write!(formatter, "ZMODEM native file {operation} failed")
            }
            Self::Runtime(error) => fmt::Display::fmt(error, formatter),
            Self::Protocol(error) => fmt::Display::fmt(error, formatter),
            Self::ControlChannelClosed => {
                formatter.write_str("ZMODEM progress receiver is unavailable")
            }
            Self::SerialClosed => formatter.write_str("Serial port closed during ZMODEM transfer"),
            Self::InvalidState => formatter.write_str("ZMODEM transfer state is invalid"),
        }
    }
}

impl fmt::Display for NativeFileOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Select => "selection",
            Self::Inspect => "inspection",
            Self::Open => "open",
            Self::Seek => "seek",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Metadata => "metadata update",
            Self::Publish => "publication",
        })
    }
}

impl Error for SerialZmodemError {}

impl From<SerialRuntimeError> for SerialZmodemError {
    fn from(error: SerialRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<ZmodemError> for SerialZmodemError {
    fn from(error: ZmodemError) -> Self {
        Self::Protocol(error)
    }
}

pub(crate) enum SerialZmodemOutcome {
    Completed(ZmodemBatchSummary),
    Canceled,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartSerialZmodemRequest {
    pub(crate) session_id: String,
    pub(crate) transfer_id: String,
    pub(crate) direction: SerialZmodemDirection,
    #[serde(default)]
    pub(crate) locale: SerialTransferDialogLocale,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SerialZmodemResponse {
    canceled: bool,
    file_count: usize,
    skipped_files: usize,
    total_bytes: u64,
    transferred_bytes: u64,
}

impl SerialZmodemResponse {
    fn canceled() -> Self {
        Self {
            canceled: true,
            file_count: 0,
            skipped_files: 0,
            total_bytes: 0,
            transferred_bytes: 0,
        }
    }
}

fn parse_session_id(value: &str) -> Result<SerialSessionId, SerialZmodemError> {
    if value.len() != 36 {
        return Err(SerialZmodemError::Runtime(
            SerialRuntimeError::InvalidSessionId,
        ));
    }
    SerialSessionId::parse(value).map_err(SerialZmodemError::Runtime)
}

fn parse_transfer_id(value: &str) -> Result<SerialTransferId, SerialZmodemError> {
    if value.len() != 36 {
        return Err(SerialZmodemError::Runtime(
            SerialRuntimeError::InvalidTransferId,
        ));
    }
    SerialTransferId::parse(value).map_err(SerialZmodemError::Runtime)
}

fn command_error(error: SerialZmodemError) -> String {
    format!("{}: {error}", error.code())
}

#[tauri::command]
pub(crate) async fn start_serial_zmodem(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartSerialZmodemRequest,
    on_control: Channel<SerialControlEvent>,
) -> Result<SerialZmodemResponse, String> {
    let session_id = parse_session_id(&request.session_id).map_err(command_error)?;
    let transfer_id = parse_transfer_id(&request.transfer_id).map_err(command_error)?;
    let direction = match request.direction {
        SerialZmodemDirection::Send => ZmodemTransferDirection::Send,
        SerialZmodemDirection::Receive => ZmodemTransferDirection::Receive,
    };
    let outcome = drive_detected_serial_zmodem(
        &window,
        state.inner(),
        &session_id,
        &transfer_id,
        direction,
        request.locale,
        &on_control,
    )
    .await;
    match outcome {
        Ok(SerialZmodemOutcome::Canceled) => {
            let _ = on_control.send(SerialControlEvent::SerialZmodemCanceled {
                session_id: session_id.as_str().to_owned(),
                transfer_id: transfer_id.as_str().to_owned(),
                direction: request.direction,
            });
            Ok(SerialZmodemResponse::canceled())
        }
        Ok(SerialZmodemOutcome::Completed(summary)) => {
            let _ = on_control.send(SerialControlEvent::SerialZmodemCompleted {
                session_id: session_id.as_str().to_owned(),
                transfer_id: transfer_id.as_str().to_owned(),
                direction: request.direction,
                file_count: summary.file_count,
                skipped_files: summary.skipped_files,
                total_bytes: summary.total_bytes,
                transferred_bytes: summary.transferred_bytes,
            });
            Ok(SerialZmodemResponse {
                canceled: false,
                file_count: summary.file_count,
                skipped_files: summary.skipped_files,
                total_bytes: summary.total_bytes,
                transferred_bytes: summary.transferred_bytes,
            })
        }
        Err(error) => {
            let _ = on_control.send(SerialControlEvent::SerialZmodemError {
                session_id: session_id.as_str().to_owned(),
                transfer_id: transfer_id.as_str().to_owned(),
                direction: request.direction,
                code: error.code().to_owned(),
                message: error.to_string(),
            });
            Err(command_error(error))
        }
    }
}

#[tauri::command]
pub(crate) fn cancel_serial_zmodem(
    state: State<'_, DesktopState>,
    session_id: String,
    transfer_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id).map_err(command_error)?;
    let transfer_id = parse_transfer_id(&transfer_id).map_err(command_error)?;
    state
        .serial_sessions
        .request_transfer_cancel_exact(&session_id, &transfer_id)
        .map_err(SerialZmodemError::from)
        .map_err(command_error)
}

/// Claims and drives one sentry-created ZMODEM reservation. Native paths and
/// file bodies stay entirely inside this function and its helpers.
pub(crate) async fn drive_detected_serial_zmodem(
    window: &WebviewWindow,
    state: &DesktopState,
    session_id: &SerialSessionId,
    transfer_id: &SerialTransferId,
    direction: ZmodemTransferDirection,
    locale: SerialTransferDialogLocale,
    on_control: &Channel<SerialControlEvent>,
) -> Result<SerialZmodemOutcome, SerialZmodemError> {
    let mut transfer =
        state
            .serial_sessions
            .claim_detected_zmodem(session_id, transfer_id, direction)?;

    let result = match direction {
        ZmodemTransferDirection::Send => {
            match wait_for_native_selection(&mut transfer, choose_send_files(window, locale)).await
            {
                Ok(Some((paths, mut pending_events))) => match wait_for_native_operation(
                    &mut transfer,
                    &mut pending_events,
                    open_send_sources(paths),
                )
                .await
                {
                    Ok(mut sources) => drive_sender(
                        &mut transfer,
                        &mut sources,
                        &mut pending_events,
                        session_id,
                        transfer_id,
                        direction,
                        on_control,
                    )
                    .await
                    .map(|completed| (SerialZmodemOutcome::Completed(completed.0), completed.1)),
                    Err(error) => Err(error),
                },
                Ok(None) => Ok((SerialZmodemOutcome::Canceled, Vec::new().into())),
                Err(error) => Err(error),
            }
        }
        ZmodemTransferDirection::Receive => {
            match wait_for_native_selection(&mut transfer, choose_receive_directory(window, locale))
                .await
            {
                Ok(Some((destination, mut pending_events))) => match wait_for_native_operation(
                    &mut transfer,
                    &mut pending_events,
                    open_destination_directory(&destination),
                )
                .await
                {
                    Ok(destination) => drive_receiver(
                        &mut transfer,
                        destination,
                        &mut pending_events,
                        session_id,
                        transfer_id,
                        direction,
                        on_control,
                    )
                    .await
                    .map(|completed| (SerialZmodemOutcome::Completed(completed.0), completed.1)),
                    Err(error) => Err(error),
                },
                Ok(None) => Ok((SerialZmodemOutcome::Canceled, Vec::new().into())),
                Err(error) => Err(error),
            }
        }
    };

    let result = match result {
        Err(SerialZmodemError::Runtime(SerialRuntimeError::TransferCancelled)) => {
            Ok((SerialZmodemOutcome::Canceled, Vec::new().into()))
        }
        result => result,
    };
    let should_abort = match &result {
        Ok((SerialZmodemOutcome::Canceled, _)) => true,
        Ok((SerialZmodemOutcome::Completed(_), _)) => false,
        Err(error) => should_send_cancel(error),
    };
    let abort = if should_abort {
        transfer
            .write_protocol_abort(&ZMODEM_CANCEL_SEQUENCE)
            .await
            .map_err(SerialZmodemError::from)
    } else {
        Ok(())
    };
    let finish = match &result {
        Ok((SerialZmodemOutcome::Completed(_), terminal_bytes)) => {
            transfer
                .finish_with_terminal_bytes(terminal_bytes.as_slice())
                .await
        }
        _ => transfer.finish().await,
    }
    .map_err(SerialZmodemError::from);
    match (result, abort, finish) {
        (Err(error), _, _) => Err(error),
        (Ok(_), Err(error), _) => Err(error),
        (Ok(_), Ok(()), Err(error)) => Err(error),
        (Ok((outcome, _)), Ok(()), Ok(())) => Ok(outcome),
    }
}

/// Keeps polling the exact raw-transfer cancel signal while the platform file
/// picker is open. Protocol bytes that arrive before selection are retained in
/// their original order and fed into the state machine only after selection.
#[derive(Default)]
struct PendingSerialEvents {
    events: VecDeque<SerialRawTransferEvent>,
    bytes: usize,
    cancel_requested: bool,
}

impl PendingSerialEvents {
    fn push(&mut self, event: SerialRawTransferEvent) -> Result<(), SerialZmodemError> {
        let bytes = match &event {
            SerialRawTransferEvent::Data(bytes) => bytes.len(),
            SerialRawTransferEvent::CancelRequested => {
                self.cancel_requested = true;
                return Ok(());
            }
        };
        if self.events.len() >= MAX_PICKER_BUFFER_EVENTS
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > MAX_PICKER_BUFFER_BYTES)
        {
            return Err(SerialZmodemError::SelectionBufferFull);
        }
        self.bytes += bytes;
        self.events.push_back(event);
        Ok(())
    }

    fn pop(&mut self) -> Option<SerialRawTransferEvent> {
        if self.take_cancel_request() {
            return Some(SerialRawTransferEvent::CancelRequested);
        }
        let event = self.events.pop_front()?;
        if let SerialRawTransferEvent::Data(bytes) = &event {
            self.bytes = self.bytes.saturating_sub(bytes.len());
        }
        Some(event)
    }

    fn request_cancel(&mut self) {
        self.cancel_requested = true;
    }

    fn take_cancel_request(&mut self) -> bool {
        std::mem::take(&mut self.cancel_requested)
    }
}

async fn wait_for_native_selection<T, F>(
    transfer: &mut SerialRawTransfer,
    selection: F,
) -> Result<Option<(T, PendingSerialEvents)>, SerialZmodemError>
where
    F: std::future::Future<Output = Result<Option<T>, SerialZmodemError>>,
{
    tokio::pin!(selection);
    let mut pending_events = PendingSerialEvents::default();
    loop {
        tokio::select! {
            biased;
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::CancelRequested) => return Ok(None),
                Some(event @ SerialRawTransferEvent::Data(_)) => pending_events.push(event)?,
                None => return Err(SerialZmodemError::SerialClosed),
            },
            selected = &mut selection => {
                return selected.map(|selected| {
                    selected.map(|value| (value, pending_events))
                });
            }
        }
    }
}

fn poll_exact_transfer_cancel(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
) -> Result<(), SerialZmodemError> {
    if pending_events.take_cancel_request() {
        return Err(SerialRuntimeError::TransferCancelled.into());
    }
    match transfer.try_recv() {
        Ok(SerialRawTransferEvent::CancelRequested) => {
            Err(SerialRuntimeError::TransferCancelled.into())
        }
        Ok(event @ SerialRawTransferEvent::Data(_)) => pending_events.push(event),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Ok(()),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            Err(SerialZmodemError::SerialClosed)
        }
    }
}

async fn wait_for_native_operation<T, F>(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
    operation: F,
) -> Result<T, SerialZmodemError>
where
    F: std::future::Future<Output = Result<T, SerialZmodemError>>,
{
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::CancelRequested) => {
                    let _ = operation.as_mut().await;
                    return Err(SerialRuntimeError::TransferCancelled.into());
                }
                Some(event @ SerialRawTransferEvent::Data(_)) => {
                    if let Err(error) = pending_events.push(event) {
                        let _ = operation.as_mut().await;
                        return Err(error);
                    }
                }
                None => {
                    let _ = operation.as_mut().await;
                    return Err(SerialZmodemError::SerialClosed);
                }
            },
            result = &mut operation => return result,
        }
    }
}

const PUBLISH_OPEN: u8 = 0;
const PUBLISH_CANCELLED: u8 = 1;
const PUBLISH_COMMITTING: u8 = 2;
const PUBLISH_CANCEL_REQUESTED: u8 = 3;
const PUBLISH_COMMITTED: u8 = 4;

#[derive(Default)]
struct PublishCancellation {
    state: AtomicU8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishCancelDisposition {
    CancellationWon,
    CommitWon,
}

impl PublishCancellation {
    fn request_cancel(&self) -> PublishCancelDisposition {
        loop {
            let state = self.state.load(Ordering::Acquire);
            let next = match state {
                PUBLISH_OPEN => PUBLISH_CANCELLED,
                PUBLISH_COMMITTING => PUBLISH_CANCEL_REQUESTED,
                PUBLISH_CANCELLED | PUBLISH_CANCEL_REQUESTED => {
                    return PublishCancelDisposition::CancellationWon;
                }
                PUBLISH_COMMITTED => return PublishCancelDisposition::CommitWon,
                // Atomic corruption or a future unrecognised state must stop
                // publication rather than panic the desktop process.
                _ => return PublishCancelDisposition::CancellationWon,
            };
            if self
                .state
                .compare_exchange(state, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return PublishCancelDisposition::CancellationWon;
            }
        }
    }

    fn begin_commit(&self) -> bool {
        self.state
            .compare_exchange(
                PUBLISH_OPEN,
                PUBLISH_COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn finish_commit(&self) -> bool {
        self.state
            .compare_exchange(
                PUBLISH_COMMITTING,
                PUBLISH_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn retry_after_name_conflict(&self) -> bool {
        match self.state.compare_exchange(
            PUBLISH_COMMITTING,
            PUBLISH_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(PUBLISH_CANCEL_REQUESTED) => {
                self.state.store(PUBLISH_CANCELLED, Ordering::Release);
                false
            }
            Err(_) => false,
        }
    }

    fn finish_cancelled_commit(&self) {
        self.state.store(PUBLISH_CANCELLED, Ordering::Release);
    }
}

struct CancelPublishOnDrop {
    cancellation: Arc<PublishCancellation>,
    armed: bool,
}

impl CancelPublishOnDrop {
    fn new(cancellation: Arc<PublishCancellation>) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelPublishOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cancellation.request_cancel();
        }
    }
}

async fn wait_for_native_publish<T, F>(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
    cancellation: &Arc<PublishCancellation>,
    operation: F,
) -> Result<T, SerialZmodemError>
where
    F: std::future::Future<Output = Result<T, SerialZmodemError>>,
{
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::CancelRequested) => {
                    let disposition = cancellation.request_cancel();
                    let result = operation.as_mut().await;
                    if disposition == PublishCancelDisposition::CommitWon {
                        pending_events.request_cancel();
                        return result;
                    }
                    return cancellation_won_publish_result(
                        result,
                        SerialRuntimeError::TransferCancelled.into(),
                    );
                }
                Some(event @ SerialRawTransferEvent::Data(_)) => {
                    if let Err(error) = pending_events.push(event) {
                        let disposition = cancellation.request_cancel();
                        let result = operation.as_mut().await;
                        return if disposition == PublishCancelDisposition::CommitWon {
                            committed_publish_interruption(result, error)
                        } else {
                            cancellation_won_publish_result(result, error)
                        };
                    }
                }
                None => {
                    let disposition = cancellation.request_cancel();
                    let result = operation.as_mut().await;
                    return if disposition == PublishCancelDisposition::CommitWon {
                        committed_publish_interruption(result, SerialZmodemError::SerialClosed)
                    } else {
                        cancellation_won_publish_result(result, SerialZmodemError::SerialClosed)
                    };
                }
            },
            result = &mut operation => return result,
        }
    }
}

fn cancellation_won_publish_result<T>(
    result: Result<T, SerialZmodemError>,
    interruption: SerialZmodemError,
) -> Result<T, SerialZmodemError> {
    match result {
        Err(SerialZmodemError::Runtime(SerialRuntimeError::TransferCancelled)) => Err(interruption),
        Err(cleanup_error) => Err(cleanup_error),
        Ok(_) => Err(SerialZmodemError::InvalidState),
    }
}

fn committed_publish_interruption<T>(
    result: Result<T, SerialZmodemError>,
    interruption: SerialZmodemError,
) -> Result<T, SerialZmodemError> {
    match result {
        Ok(_) => Err(interruption),
        Err(error) => Err(error),
    }
}

async fn wait_for_native_stage_open<T, F>(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
    cancellation: &Arc<AtomicBool>,
    operation: F,
) -> Result<T, SerialZmodemError>
where
    F: std::future::Future<Output = Result<T, SerialZmodemError>>,
{
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            event = transfer.recv() => match event {
                Some(SerialRawTransferEvent::CancelRequested) => {
                    cancellation.store(true, Ordering::Release);
                    let _ = operation.as_mut().await;
                    return Err(SerialRuntimeError::TransferCancelled.into());
                }
                Some(event @ SerialRawTransferEvent::Data(_)) => {
                    if let Err(error) = pending_events.push(event) {
                        cancellation.store(true, Ordering::Release);
                        let _ = operation.as_mut().await;
                        return Err(error);
                    }
                }
                None => {
                    cancellation.store(true, Ordering::Release);
                    let _ = operation.as_mut().await;
                    return Err(SerialZmodemError::SerialClosed);
                }
            },
            result = &mut operation => return result,
        }
    }
}

async fn choose_send_files(
    window: &WebviewWindow,
    locale: SerialTransferDialogLocale,
) -> Result<Option<Vec<PathBuf>>, SerialZmodemError> {
    let text = zmodem_dialog_text(locale);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .app_handle()
        .dialog()
        .file()
        .set_title(text.send_title)
        .add_filter(text.all_files_filter, &["*"])
        .set_parent(window)
        .pick_files(move |selected| {
            let selected = selected
                .map(|paths| {
                    paths
                        .into_iter()
                        .map(|path| path.into_path())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|_| SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Select,
                });
            let _ = sender.send(selected);
        });
    receiver
        .await
        .map_err(|_| SerialZmodemError::DialogFailed)?
}

async fn choose_receive_directory(
    window: &WebviewWindow,
    locale: SerialTransferDialogLocale,
) -> Result<Option<PathBuf>, SerialZmodemError> {
    let text = zmodem_dialog_text(locale);
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
                .map_err(|_| SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Select,
                });
            let _ = sender.send(selected);
        });
    receiver
        .await
        .map_err(|_| SerialZmodemError::DialogFailed)?
}

fn validate_native_path(path: &Path) -> Result<(), SerialZmodemError> {
    let length = path.as_os_str().to_string_lossy().len();
    if length == 0 || length > MAX_NATIVE_PATH_BYTES {
        Err(SerialZmodemError::SelectedPathInvalid)
    } else {
        Ok(())
    }
}

struct SendSource {
    file: tokio::fs::File,
    metadata: ZmodemFileMetadata,
}

async fn open_send_sources(paths: Vec<PathBuf>) -> Result<Vec<SendSource>, SerialZmodemError> {
    if paths.is_empty() || paths.len() > MAX_ZMODEM_BATCH_FILES {
        return Err(SerialZmodemError::SelectionTooLarge);
    }
    let mut sources = Vec::with_capacity(paths.len());
    for path in paths {
        sources.push(open_send_source(&path).await?);
    }
    Ok(sources)
}

async fn open_send_source(path: &Path) -> Result<SendSource, SerialZmodemError> {
    validate_native_path(path)?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or(SerialZmodemError::SelectedPathInvalid)?;
    let file =
        tokio::fs::File::open(path)
            .await
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Open,
            })?;
    let native_metadata =
        file.metadata()
            .await
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Inspect,
            })?;
    if !native_metadata.is_file() {
        return Err(SerialZmodemError::SelectedFileNotRegular);
    }
    let modified_time = native_metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs());
    let metadata = ZmodemFileMetadata::new(
        file_name,
        native_metadata.len(),
        modified_time,
        native_file_mode(&native_metadata),
    )?;
    Ok(SendSource { file, metadata })
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

async fn open_destination_directory(path: &Path) -> Result<Arc<Dir>, SerialZmodemError> {
    validate_native_path(path)?;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let directory = Dir::open_ambient_dir(&path, ambient_authority())
            .map_err(|_| SerialZmodemError::SelectedDestinationNotDirectory)?;
        let metadata = directory
            .dir_metadata()
            .map_err(|_| SerialZmodemError::SelectedDestinationNotDirectory)?;
        if metadata.is_dir() {
            Ok(Arc::new(directory))
        } else {
            Err(SerialZmodemError::SelectedDestinationNotDirectory)
        }
    })
    .await
    .map_err(|_| SerialZmodemError::NativeFileFailed {
        operation: NativeFileOperation::Open,
    })?
}

async fn drive_sender(
    transfer: &mut SerialRawTransfer,
    sources: &mut [SendSource],
    pending_events: &mut PendingSerialEvents,
    session_id: &SerialSessionId,
    transfer_id: &SerialTransferId,
    direction: ZmodemTransferDirection,
    on_control: &Channel<SerialControlEvent>,
) -> Result<(ZmodemBatchSummary, ZmodemBytes), SerialZmodemError> {
    let metadata = sources
        .iter()
        .map(|source| source.metadata.clone())
        .collect();
    let mut sender = ZmodemSender::new(metadata, ZmodemConfig::default())?;

    loop {
        while let Some(action) = sender.next_action() {
            poll_exact_transfer_cancel(transfer, pending_events)?;
            match action {
                ZmodemSenderAction::Write(bytes) => transfer.write(bytes.as_slice()).await?,
                ZmodemSenderAction::ReadSource {
                    file_index,
                    offset,
                    maximum_bytes,
                } => {
                    let source = sources
                        .get_mut(file_index)
                        .ok_or(SerialZmodemError::InvalidState)?;
                    let current_len = wait_for_native_operation(transfer, pending_events, async {
                        source
                            .file
                            .metadata()
                            .await
                            .map(|metadata| metadata.len())
                            .map_err(|_| SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Inspect,
                            })
                    })
                    .await?;
                    if current_len != source.metadata.total_bytes() {
                        return Err(ZmodemError::SourceLengthMismatch.into());
                    }
                    wait_for_native_operation(transfer, pending_events, async {
                        source
                            .file
                            .seek(io::SeekFrom::Start(offset))
                            .await
                            .map(|_| ())
                            .map_err(|_| SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Seek,
                            })
                    })
                    .await?;
                    let mut chunk = vec![0_u8; maximum_bytes];
                    let read = wait_for_native_operation(transfer, pending_events, async {
                        source.file.read(&mut chunk).await.map_err(|_| {
                            SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Read,
                            }
                        })
                    })
                    .await?;
                    chunk.truncate(read);
                    sender.provide_source_chunk(&chunk)?;
                }
                ZmodemSenderAction::Progress(progress) => emit_progress(
                    on_control,
                    session_id,
                    transfer_id,
                    direction,
                    progress,
                    sources
                        .get(progress.file_index)
                        .map(|source| source.metadata.file_name().to_owned()),
                )?,
                ZmodemSenderAction::FileCompleted(_) => {}
                ZmodemSenderAction::FileSkipped { .. } => {}
                ZmodemSenderAction::BatchCompleted {
                    summary,
                    terminal_bytes,
                } => return Ok((summary, terminal_bytes)),
                ZmodemSenderAction::Failed(error) => return Err(error.into()),
            }
        }
        wait_sender(transfer, pending_events, &mut sender).await?;
    }
}

async fn wait_sender(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
    sender: &mut ZmodemSender,
) -> Result<(), SerialZmodemError> {
    poll_exact_transfer_cancel(transfer, pending_events)?;
    if let Some(event) = pending_events.pop() {
        handle_sender_event(sender, Some(event))?;
        return Ok(());
    }
    if let Some(timeout) = sender.timeout() {
        tokio::select! {
            event = transfer.recv() => handle_sender_event(sender, event)?,
            _ = tokio::time::sleep(timeout) => sender.on_timeout()?,
        }
    } else {
        handle_sender_event(sender, transfer.recv().await)?;
    }
    Ok(())
}

fn handle_sender_event(
    sender: &mut ZmodemSender,
    event: Option<SerialRawTransferEvent>,
) -> Result<(), SerialZmodemError> {
    match event {
        Some(SerialRawTransferEvent::Data(bytes)) => sender.push_serial_bytes(bytes.as_slice())?,
        Some(SerialRawTransferEvent::CancelRequested) => sender.cancel()?,
        None => return Err(SerialZmodemError::SerialClosed),
    }
    Ok(())
}

async fn drive_receiver(
    transfer: &mut SerialRawTransfer,
    destination: Arc<Dir>,
    pending_events: &mut PendingSerialEvents,
    session_id: &SerialSessionId,
    transfer_id: &SerialTransferId,
    direction: ZmodemTransferDirection,
    on_control: &Channel<SerialControlEvent>,
) -> Result<(ZmodemBatchSummary, ZmodemBytes), SerialZmodemError> {
    let mut receiver = ZmodemReceiver::new(ZmodemConfig::default());
    let mut pending_file: Option<PendingReceiveFile> = None;

    loop {
        while let Some(action) = receiver.next_action() {
            poll_exact_transfer_cancel(transfer, pending_events)?;
            match action {
                ZmodemReceiverAction::Write(bytes) => transfer.write(bytes.as_slice()).await?,
                ZmodemReceiverAction::OfferFile {
                    file_index,
                    metadata,
                } => {
                    if pending_file.is_some() {
                        return Err(SerialZmodemError::InvalidState);
                    }
                    let cancellation = Arc::new(AtomicBool::new(false));
                    pending_file = Some(
                        wait_for_native_stage_open(
                            transfer,
                            pending_events,
                            &cancellation,
                            PendingReceiveFile::open(
                                destination.clone(),
                                file_index,
                                metadata,
                                cancellation.clone(),
                            ),
                        )
                        .await?,
                    );
                    receiver.accept_file()?;
                }
                ZmodemReceiverAction::BeginFile {
                    file_index,
                    metadata,
                } => {
                    let pending = pending_file
                        .as_ref()
                        .ok_or(SerialZmodemError::InvalidState)?;
                    if pending.file_index != file_index
                        || pending.metadata.file_name() != metadata.file_name()
                        || pending.metadata.total_bytes() != metadata.total_bytes()
                    {
                        return Err(SerialZmodemError::InvalidState);
                    }
                }
                ZmodemReceiverAction::WriteFile {
                    file_index,
                    offset,
                    bytes,
                } => {
                    let pending = pending_file
                        .as_mut()
                        .ok_or(SerialZmodemError::InvalidState)?;
                    if pending.file_index != file_index {
                        return Err(SerialZmodemError::InvalidState);
                    }
                    let file = pending
                        .file
                        .as_mut()
                        .ok_or(SerialZmodemError::InvalidState)?;
                    wait_for_native_operation(transfer, pending_events, async {
                        file.seek(io::SeekFrom::Start(offset))
                            .await
                            .map(|_| ())
                            .map_err(|_| SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Seek,
                            })
                    })
                    .await?;
                    wait_for_native_operation(transfer, pending_events, async {
                        file.write_all(bytes.as_slice()).await.map_err(|_| {
                            SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Write,
                            }
                        })
                    })
                    .await?;
                    receiver.confirm_file_write(bytes.len())?;
                }
                ZmodemReceiverAction::Progress(progress) => emit_progress(
                    on_control,
                    session_id,
                    transfer_id,
                    direction,
                    progress,
                    pending_file
                        .as_ref()
                        .map(|pending| pending.metadata.file_name().to_owned()),
                )?,
                ZmodemReceiverAction::FileCompleted(summary) => {
                    let pending = pending_file.take().ok_or(SerialZmodemError::InvalidState)?;
                    if pending.file_index != summary.file_index
                        || pending.metadata.total_bytes() != summary.total_bytes
                        || summary.transferred_bytes != summary.total_bytes
                    {
                        return Err(SerialZmodemError::InvalidState);
                    }
                    let cancellation = Arc::new(PublishCancellation::default());
                    let _published_name = wait_for_native_publish(
                        transfer,
                        pending_events,
                        &cancellation,
                        pending.publish(cancellation.clone()),
                    )
                    .await?;
                }
                ZmodemReceiverAction::BatchCompleted {
                    summary,
                    terminal_bytes,
                } => {
                    if pending_file.is_some() {
                        return Err(SerialZmodemError::InvalidState);
                    }
                    return Ok((summary, terminal_bytes));
                }
                ZmodemReceiverAction::Failed(error) => return Err(error.into()),
            }
        }
        wait_receiver(transfer, pending_events, &mut receiver).await?;
    }
}

async fn wait_receiver(
    transfer: &mut SerialRawTransfer,
    pending_events: &mut PendingSerialEvents,
    receiver: &mut ZmodemReceiver,
) -> Result<(), SerialZmodemError> {
    poll_exact_transfer_cancel(transfer, pending_events)?;
    if let Some(event) = pending_events.pop() {
        handle_receiver_event(receiver, Some(event))?;
        return Ok(());
    }
    if let Some(timeout) = receiver.timeout() {
        tokio::select! {
            event = transfer.recv() => handle_receiver_event(receiver, event)?,
            _ = tokio::time::sleep(timeout) => receiver.on_timeout()?,
        }
    } else {
        handle_receiver_event(receiver, transfer.recv().await)?;
    }
    Ok(())
}

fn handle_receiver_event(
    receiver: &mut ZmodemReceiver,
    event: Option<SerialRawTransferEvent>,
) -> Result<(), SerialZmodemError> {
    match event {
        Some(SerialRawTransferEvent::Data(bytes)) => {
            receiver.push_serial_bytes(bytes.as_slice())?
        }
        Some(SerialRawTransferEvent::CancelRequested) => receiver.cancel()?,
        None => return Err(SerialZmodemError::SerialClosed),
    }
    Ok(())
}

fn emit_progress(
    channel: &Channel<SerialControlEvent>,
    session_id: &SerialSessionId,
    transfer_id: &SerialTransferId,
    direction: ZmodemTransferDirection,
    progress: ZmodemProgress,
    file_name: Option<String>,
) -> Result<(), SerialZmodemError> {
    channel
        .send(SerialControlEvent::SerialZmodemProgress {
            session_id: session_id.as_str().to_owned(),
            transfer_id: transfer_id.as_str().to_owned(),
            direction: direction.into(),
            stage: match progress.stage {
                ZmodemProgressStage::Header => SerialZmodemProgressStage::Header,
                ZmodemProgressStage::Data => SerialZmodemProgressStage::Data,
                ZmodemProgressStage::Finalizing => SerialZmodemProgressStage::Finalizing,
                ZmodemProgressStage::Complete => SerialZmodemProgressStage::Complete,
            },
            transferred_bytes: progress.transferred_bytes,
            total_bytes: progress.total_bytes,
            file_name,
            file_index: progress.file_index,
            file_count: progress.file_count,
        })
        .map_err(|_| SerialZmodemError::ControlChannelClosed)
}

fn should_send_cancel(error: &SerialZmodemError) -> bool {
    !matches!(
        error,
        SerialZmodemError::Protocol(ZmodemError::RemoteCancelled | ZmodemError::RemoteAborted)
    )
}

struct CancelStageOpenOnDrop {
    cancellation: Arc<AtomicBool>,
    armed: bool,
}

impl CancelStageOpenOnDrop {
    fn new(cancellation: Arc<AtomicBool>) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelStageOpenOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Release);
        }
    }
}

struct CreatedReceiveStage {
    file: Option<std::fs::File>,
    stage_name: String,
    directory: Arc<Dir>,
    cleanup_armed: bool,
}

impl CreatedReceiveStage {
    fn into_pending(
        mut self,
        file_index: usize,
        metadata: ZmodemFileMetadata,
    ) -> PendingReceiveFile {
        let file = self.file.take().expect("created receive stage owns a file");
        let stage_name = self.stage_name.clone();
        let directory = self.directory.clone();
        self.cleanup_armed = false;
        PendingReceiveFile {
            file_index,
            metadata,
            file: Some(tokio::fs::File::from_std(file)),
            stage_name,
            directory,
            committed: false,
        }
    }
}

impl Drop for CreatedReceiveStage {
    fn drop(&mut self) {
        self.file.take();
        if self.cleanup_armed {
            let _ = self.directory.remove_file(&self.stage_name);
        }
    }
}

struct PublishReceiveStage {
    file: Option<std::fs::File>,
    stage_name: String,
    published_name: Option<String>,
    directory: Arc<Dir>,
    stage_present: bool,
    cleanup_armed: bool,
}

impl PublishReceiveStage {
    fn disarm_cleanup(&mut self) {
        self.cleanup_armed = false;
    }

    fn rollback(&mut self) -> Result<(), SerialZmodemError> {
        self.file.take();
        if let Some(published_name) = self.published_name.as_ref() {
            self.directory.remove_file(published_name).map_err(|_| {
                SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Publish,
                }
            })?;
            self.published_name = None;
        }
        if self.stage_present {
            self.directory.remove_file(&self.stage_name).map_err(|_| {
                SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Publish,
                }
            })?;
            self.stage_present = false;
        }
        sync_native_directory(&self.directory)
    }
}

impl Drop for PublishReceiveStage {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        self.file.take();
        if let Some(published_name) = self.published_name.take() {
            let _ = self.directory.remove_file(&published_name);
        }
        if self.stage_present {
            let _ = self.directory.remove_file(&self.stage_name);
        }
        let _ = sync_native_directory(&self.directory);
    }
}

struct PendingReceiveFile {
    file_index: usize,
    metadata: ZmodemFileMetadata,
    file: Option<tokio::fs::File>,
    stage_name: String,
    directory: Arc<Dir>,
    committed: bool,
}

impl PendingReceiveFile {
    async fn open(
        directory: Arc<Dir>,
        file_index: usize,
        metadata: ZmodemFileMetadata,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, SerialZmodemError> {
        validate_receive_name(metadata.file_name())?;
        let mut cancel_on_drop = CancelStageOpenOnDrop::new(cancellation.clone());
        for _ in 0..MAX_STAGE_ATTEMPTS {
            if cancellation.load(Ordering::Acquire) {
                return Err(SerialRuntimeError::TransferCancelled.into());
            }
            let open_directory = directory.clone();
            let open_name = format!(".netcatty-zmodem-{}.part", uuid::Uuid::new_v4());
            let open_cancellation = cancellation.clone();
            let opened = tokio::task::spawn_blocking(move || {
                let mut options = cap_std::fs::OpenOptions::new();
                options.read(true).write(true).create_new(true);
                let file = open_directory
                    .open_with(&open_name, &options)
                    .map(cap_std::fs::File::into_std)?;
                let stage = CreatedReceiveStage {
                    file: Some(file),
                    stage_name: open_name,
                    directory: open_directory,
                    cleanup_armed: true,
                };
                if open_cancellation.load(Ordering::Acquire) {
                    drop(stage);
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                Ok(stage)
            })
            .await
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Open,
            })?;
            match opened {
                Ok(stage) => {
                    if cancellation.load(Ordering::Acquire) {
                        drop(stage);
                        return Err(SerialRuntimeError::TransferCancelled.into());
                    }
                    cancel_on_drop.disarm();
                    return Ok(stage.into_pending(file_index, metadata));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && cancellation.load(Ordering::Acquire) =>
                {
                    return Err(SerialRuntimeError::TransferCancelled.into());
                }
                Err(_) => {
                    return Err(SerialZmodemError::NativeFileFailed {
                        operation: NativeFileOperation::Open,
                    });
                }
            }
        }
        Err(SerialZmodemError::DestinationExists)
    }

    async fn publish(
        mut self,
        cancellation: Arc<PublishCancellation>,
    ) -> Result<String, SerialZmodemError> {
        let mut cancel_on_drop = CancelPublishOnDrop::new(cancellation.clone());
        let mut file = self.file.take().ok_or(SerialZmodemError::InvalidState)?;
        file.flush()
            .await
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Flush,
            })?;
        file.sync_all()
            .await
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Flush,
            })?;
        let standard = file.into_std().await;
        let modified_time = self.metadata.modified_time();
        let mode = self.metadata.mode();
        let file_name = self.metadata.file_name().to_owned();
        let mut publish_stage = PublishReceiveStage {
            file: Some(standard),
            stage_name: self.stage_name.clone(),
            published_name: None,
            directory: self.directory.clone(),
            stage_present: true,
            cleanup_armed: true,
        };
        // Cleanup ownership is now inside the blocking job. If this async
        // future is dropped, its cancel-on-drop gate makes that job roll back.
        self.committed = true;
        let publish_cancellation = cancellation.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let standard = publish_stage
                .file
                .as_ref()
                .ok_or(SerialZmodemError::InvalidState)?;
            apply_native_metadata(standard, modified_time, mode)?;
            standard
                .sync_all()
                .map_err(|_| SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Flush,
                })?;

            // Bind the stage pathname back to the exact file handle that was
            // written. A concurrent unlink/replacement is rejected before any
            // destination name can be published.
            let named = publish_stage
                .directory
                .open(&publish_stage.stage_name)
                .map(cap_std::fs::File::into_std)
                .map_err(|_| SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Inspect,
                })?;
            if !same_open_native_file(standard, &named)? {
                return Err(SerialZmodemError::NativeFileFailed {
                    operation: NativeFileOperation::Inspect,
                });
            }
            drop(named);

            for attempt in 0..MAX_UNIQUE_DESTINATION_ATTEMPTS {
                let candidate_name = unique_destination_name(&file_name, attempt)?;
                if !publish_cancellation.begin_commit() {
                    return Err(SerialRuntimeError::TransferCancelled.into());
                }
                match publish_stage.directory.hard_link(
                    &publish_stage.stage_name,
                    &publish_stage.directory,
                    &candidate_name,
                ) {
                    Ok(()) => {
                        publish_stage.published_name = Some(candidate_name.clone());
                        let published = publish_stage
                            .directory
                            .open(&candidate_name)
                            .map(cap_std::fs::File::into_std)
                            .map_err(|_| SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Inspect,
                            })?;
                        if !same_open_native_file(standard, &published)? {
                            return Err(SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Inspect,
                            });
                        }
                        drop(published);
                        publish_stage
                            .directory
                            .remove_file(&publish_stage.stage_name)
                            .map_err(|_| SerialZmodemError::NativeFileFailed {
                                operation: NativeFileOperation::Publish,
                            })?;
                        publish_stage.stage_present = false;
                        sync_native_directory(&publish_stage.directory)?;
                        if publish_cancellation.finish_commit() {
                            publish_stage.disarm_cleanup();
                            return Ok(candidate_name);
                        }
                        let rollback = publish_stage.rollback();
                        publish_cancellation.finish_cancelled_commit();
                        rollback?;
                        return Err(SerialRuntimeError::TransferCancelled.into());
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if publish_cancellation.retry_after_name_conflict() {
                            continue;
                        }
                        return Err(SerialRuntimeError::TransferCancelled.into());
                    }
                    Err(_) => {
                        return Err(SerialZmodemError::NativeFileFailed {
                            operation: NativeFileOperation::Publish,
                        });
                    }
                }
            }
            Err(SerialZmodemError::DestinationExists)
        })
        .await;
        cancel_on_drop.disarm();
        joined.map_err(|_| SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Publish,
        })?
    }
}

impl Drop for PendingReceiveFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.committed {
            let _ = self.directory.remove_file(&self.stage_name);
        }
    }
}

fn validate_receive_name(file_name: &str) -> Result<(), SerialZmodemError> {
    if file_name.is_empty() || file_name.len() > MAX_ZMODEM_FILENAME_BYTES {
        return Err(SerialZmodemError::SelectedPathInvalid);
    }
    let sanitized = sanitize_zmodem_filename(file_name)?;
    let parsed = Path::new(file_name);
    let mut components = parsed.components();
    if sanitized != file_name
        || parsed.is_absolute()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(SerialZmodemError::SelectedPathInvalid);
    }
    Ok(())
}

fn unique_destination_name(file_name: &str, attempt: u32) -> Result<String, SerialZmodemError> {
    validate_receive_name(file_name)?;
    if attempt == 0 {
        return Ok(file_name.to_owned());
    }
    let parsed = Path::new(file_name);
    let stem = parsed
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "zmodem-received".to_owned());
    let mut extension = parsed
        .extension()
        .map(|value| value.to_string_lossy().into_owned());
    let suffix = format!(" ({attempt})");
    if extension
        .as_ref()
        .is_some_and(|value| value.len() + suffix.len() + 2 >= MAX_ZMODEM_FILENAME_BYTES)
    {
        extension = None;
    }
    let extension_bytes = extension.as_ref().map_or(0, |value| value.len() + 1);
    let stem_budget = MAX_ZMODEM_FILENAME_BYTES
        .checked_sub(suffix.len() + extension_bytes)
        .ok_or(SerialZmodemError::DestinationExists)?;
    let truncated = truncate_utf8(&stem, stem_budget);
    let base = if truncated.is_empty() {
        truncate_utf8("zmodem", stem_budget)
    } else {
        truncated
    };
    let candidate = if let Some(extension) = extension {
        format!("{base}{suffix}.{extension}")
    } else {
        format!("{base}{suffix}")
    };
    validate_receive_name(&candidate)?;
    Ok(candidate)
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn apply_native_metadata(
    file: &std::fs::File,
    modified_time: u64,
    mode: u32,
) -> Result<(), SerialZmodemError> {
    if modified_time > 0 {
        let modified = UNIX_EPOCH
            .checked_add(Duration::from_secs(modified_time))
            .ok_or(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Metadata,
            })?;
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .map_err(|_| SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Metadata,
            })?;
    }
    apply_native_mode(file, mode)
}

#[cfg(unix)]
fn same_open_native_file(
    left: &std::fs::File,
    right: &std::fs::File,
) -> Result<bool, SerialZmodemError> {
    use std::os::unix::fs::MetadataExt;
    let left = left
        .metadata()
        .map_err(|_| SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Inspect,
        })?;
    let right = right
        .metadata()
        .map_err(|_| SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Inspect,
        })?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino() && left.is_file())
}

#[cfg(windows)]
fn same_open_native_file(
    left: &std::fs::File,
    right: &std::fs::File,
) -> Result<bool, SerialZmodemError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    fn identity(file: &std::fs::File) -> Result<(u32, u64), SerialZmodemError> {
        let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: `file` owns a live handle for the duration of the call and
        // Windows initializes the full output structure on success.
        let success =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if success == 0 {
            return Err(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Inspect,
            });
        }
        // SAFETY: guarded by the successful API result above.
        let information = unsafe { information.assume_init() };
        Ok((
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ))
    }

    Ok(identity(left)? == identity(right)?)
}

#[cfg(not(any(unix, windows)))]
fn same_open_native_file(
    _left: &std::fs::File,
    _right: &std::fs::File,
) -> Result<bool, SerialZmodemError> {
    Ok(false)
}

#[cfg(unix)]
fn sync_native_directory(directory: &Dir) -> Result<(), SerialZmodemError> {
    directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().sync_all())
        .map_err(|_| SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Publish,
        })
}

#[cfg(not(unix))]
fn sync_native_directory(_directory: &Dir) -> Result<(), SerialZmodemError> {
    Ok(())
}

#[cfg(unix)]
fn apply_native_mode(file: &std::fs::File, mode: u32) -> Result<(), SerialZmodemError> {
    use std::os::unix::fs::PermissionsExt;
    // Never accept setuid, setgid, or sticky bits from an untrusted peer.
    file.set_permissions(std::fs::Permissions::from_mode(mode & 0o0777))
        .map_err(|_| SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Metadata,
        })
}

#[cfg(not(unix))]
fn apply_native_mode(_file: &std::fs::File, _mode: u32) -> Result<(), SerialZmodemError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_dialog_text_matches_the_resolved_request_locale() {
        let chinese = zmodem_dialog_text(SerialTransferDialogLocale::ZhCn);
        let english = zmodem_dialog_text(SerialTransferDialogLocale::EnUs);
        assert_eq!(chinese.send_title, "选择要通过 ZMODEM 发送的文件");
        assert_eq!(chinese.receive_title, "选择保存 ZMODEM 接收文件的文件夹");
        assert_eq!(chinese.all_files_filter, "所有文件");
        assert_eq!(english.send_title, "Select files to send with ZMODEM");
        assert_eq!(
            english.receive_title,
            "Select a folder for received ZMODEM files"
        );
        assert_eq!(english.all_files_filter, "All files");
    }

    #[test]
    fn zmodem_request_defaults_only_locale_to_simplified_chinese() {
        let missing_locale: StartSerialZmodemRequest = serde_json::from_value(serde_json::json!({
            "sessionId": "session-id",
            "transferId": "transfer-id",
            "direction": "send"
        }))
        .expect("missing locale must use the product fallback");
        assert_eq!(missing_locale.locale, SerialTransferDialogLocale::ZhCn);

        for locale in ["zh-cn", "EN-US", "unsupported"] {
            let request: StartSerialZmodemRequest = serde_json::from_value(serde_json::json!({
                "sessionId": "session-id",
                "transferId": "transfer-id",
                "direction": "receive",
                "locale": locale
            }))
            .expect("non-English locale strings must use the product fallback");
            assert_eq!(request.locale, SerialTransferDialogLocale::ZhCn);
        }

        let english: StartSerialZmodemRequest = serde_json::from_value(serde_json::json!({
            "sessionId": "session-id",
            "transferId": "transfer-id",
            "direction": "send",
            "locale": "en-US"
        }))
        .expect("exact English locale");
        assert_eq!(english.locale, SerialTransferDialogLocale::EnUs);

        assert!(
            serde_json::from_value::<StartSerialZmodemRequest>(serde_json::json!({
                "sessionId": "session-id",
                "transferId": "transfer-id"
            }))
            .is_err(),
            "all non-locale request fields must remain required"
        );
        assert!(
            serde_json::from_value::<StartSerialZmodemRequest>(serde_json::json!({
                "sessionId": "session-id",
                "transferId": "transfer-id",
                "direction": "send",
                "locale": true
            }))
            .is_err(),
            "a present locale must remain a string"
        );
        assert!(
            serde_json::from_value::<StartSerialZmodemRequest>(serde_json::json!({
                "sessionId": "session-id",
                "transferId": "transfer-id",
                "direction": "send",
                "unexpected": true
            }))
            .is_err(),
            "unknown request fields must remain rejected"
        );
    }

    #[test]
    fn command_errors_and_debug_never_expose_paths_or_payloads() {
        let marker = "PRIVATE-ZMODEM-PATH-OR-BODY";
        let error = SerialZmodemError::NativeFileFailed {
            operation: NativeFileOperation::Read,
        };
        assert!(!format!("{error:?}").contains(marker));
        let protocol = SerialZmodemError::Protocol(ZmodemError::InvalidSourceChunk {
            maximum_bytes: 1,
            actual: marker.len(),
        });
        assert!(!format!("{protocol:?}").contains(marker));
    }

    #[test]
    fn destination_names_are_single_component_bounded_and_keep_both() {
        assert_eq!(
            unique_destination_name("firmware.bin", 0).unwrap(),
            "firmware.bin"
        );
        assert_eq!(
            unique_destination_name("firmware.bin", 3).unwrap(),
            "firmware (3).bin"
        );
        let long = format!("{}.bin", "界".repeat(83));
        let candidate = unique_destination_name(&long, 9999).unwrap();
        assert!(candidate.len() <= MAX_ZMODEM_FILENAME_BYTES);
        assert!(candidate.ends_with(" (9999).bin"));
        for invalid in [
            "../escape",
            "./escape",
            "nested/name",
            r"nested\name",
            ".",
            "..",
        ] {
            assert!(unique_destination_name(invalid, 0).is_err());
        }
    }

    #[tokio::test]
    async fn staged_receive_is_atomic_no_overwrite_and_failure_cleans_partial() {
        let directory = tempfile::tempdir().unwrap();
        tokio::fs::write(directory.path().join("firmware.bin"), b"existing")
            .await
            .unwrap();
        let destination =
            Arc::new(Dir::open_ambient_dir(directory.path(), ambient_authority()).unwrap());
        let metadata = ZmodemFileMetadata::new("firmware.bin", 3, 0, 0o100644).unwrap();
        let mut pending = PendingReceiveFile::open(
            destination.clone(),
            0,
            metadata.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let stage = directory.path().join(&pending.stage_name);
        pending
            .file
            .as_mut()
            .unwrap()
            .write_all(b"bad")
            .await
            .unwrap();
        drop(pending);
        assert!(!stage.exists());

        let mut pending =
            PendingReceiveFile::open(destination, 0, metadata, Arc::new(AtomicBool::new(false)))
                .await
                .unwrap();
        pending
            .file
            .as_mut()
            .unwrap()
            .write_all(b"new")
            .await
            .unwrap();
        let published = pending
            .publish(Arc::new(PublishCancellation::default()))
            .await
            .unwrap();
        assert_eq!(published, "firmware (1).bin");
        assert_eq!(
            tokio::fs::read(directory.path().join("firmware.bin"))
                .await
                .unwrap(),
            b"existing"
        );
        assert_eq!(
            tokio::fs::read(directory.path().join(published))
                .await
                .unwrap(),
            b"new"
        );
    }

    #[tokio::test]
    async fn cancellation_during_stage_create_leaves_no_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination =
            Arc::new(Dir::open_ambient_dir(directory.path(), ambient_authority()).unwrap());
        let metadata = ZmodemFileMetadata::new("cancelled.bin", 3, 0, 0o100644).unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(PendingReceiveFile::open(
            destination,
            0,
            metadata,
            cancellation.clone(),
        ));
        cancellation.store(true, Ordering::Release);
        if let Ok(pending) = task.await.unwrap() {
            drop(pending);
        }

        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(names.is_empty(), "cancelled stage creation left an orphan");
    }

    #[tokio::test]
    async fn cancelled_publish_creates_neither_destination_nor_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination =
            Arc::new(Dir::open_ambient_dir(directory.path(), ambient_authority()).unwrap());
        let metadata = ZmodemFileMetadata::new("cancelled.bin", 3, 0, 0o100644).unwrap();
        let mut pending =
            PendingReceiveFile::open(destination, 0, metadata, Arc::new(AtomicBool::new(false)))
                .await
                .unwrap();
        pending
            .file
            .as_mut()
            .unwrap()
            .write_all(b"new")
            .await
            .unwrap();
        let cancellation = Arc::new(PublishCancellation::default());
        assert_eq!(
            cancellation.request_cancel(),
            PublishCancelDisposition::CancellationWon
        );
        assert!(matches!(
            pending.publish(cancellation).await,
            Err(SerialZmodemError::Runtime(
                SerialRuntimeError::TransferCancelled
            ))
        ));

        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            names.is_empty(),
            "cancelled publish left a final or partial file"
        );
    }

    #[test]
    fn cancellation_linearizes_against_publish_commit() {
        let cancellation = PublishCancellation::default();
        assert!(cancellation.begin_commit());
        assert_eq!(
            cancellation.request_cancel(),
            PublishCancelDisposition::CancellationWon
        );
        assert!(!cancellation.finish_commit());
        cancellation.finish_cancelled_commit();
        assert_eq!(
            cancellation.request_cancel(),
            PublishCancelDisposition::CancellationWon
        );

        let committed = PublishCancellation::default();
        assert!(committed.begin_commit());
        assert!(committed.finish_commit());
        assert_eq!(
            committed.request_cancel(),
            PublishCancelDisposition::CommitWon
        );
    }

    #[test]
    fn interrupted_publish_never_hides_cleanup_failure() {
        let cleanup_failure = cancellation_won_publish_result::<String>(
            Err(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Publish,
            }),
            SerialRuntimeError::TransferCancelled.into(),
        );
        assert!(matches!(
            cleanup_failure,
            Err(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Publish
            })
        ));

        let expected_cancel = cancellation_won_publish_result::<String>(
            Err(SerialRuntimeError::TransferCancelled.into()),
            SerialZmodemError::SerialClosed,
        );
        assert!(matches!(
            expected_cancel,
            Err(SerialZmodemError::SerialClosed)
        ));
        assert!(matches!(
            cancellation_won_publish_result(
                Ok("unexpected publication".to_owned()),
                SerialRuntimeError::TransferCancelled.into(),
            ),
            Err(SerialZmodemError::InvalidState)
        ));

        let committed = committed_publish_interruption(
            Ok("published".to_owned()),
            SerialZmodemError::SelectionBufferFull,
        );
        assert!(matches!(
            committed,
            Err(SerialZmodemError::SelectionBufferFull)
        ));
        let committed_cleanup = committed_publish_interruption::<String>(
            Err(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Flush,
            }),
            SerialZmodemError::SerialClosed,
        );
        assert!(matches!(
            committed_cleanup,
            Err(SerialZmodemError::NativeFileFailed {
                operation: NativeFileOperation::Flush
            })
        ));
    }

    #[tokio::test]
    async fn selected_sources_are_open_streams_and_batch_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        tokio::fs::write(&source, b"abc").await.unwrap();
        let mut opened = open_send_sources(vec![source]).await.unwrap();
        assert_eq!(opened[0].metadata.file_name(), "source.bin");
        assert_eq!(opened[0].metadata.total_bytes(), 3);
        let mut body = [0_u8; 3];
        opened[0].file.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"abc");
        assert!(matches!(
            open_send_sources(Vec::new()).await,
            Err(SerialZmodemError::SelectionTooLarge)
        ));
    }
}
