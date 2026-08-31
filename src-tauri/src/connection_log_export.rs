use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use netcatty_log_export::{
    ExportFormat, HtmlExportLabels, LocalDateTime, default_export_file_name,
    export_format_for_path, render_export_with_html_labels,
};
use netcatty_vault::SavedConnectionLog;
use serde::{Deserialize, Serialize};

const MAX_LOG_ID_BYTES: usize = 512;

// Keep the final authorization check and filesystem commit indivisible between
// concurrent exports from this process. External changes are detected by the
// dialog-time target fingerprint immediately before the atomic OS operation.
static EXPORT_COMMIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ConnectionLogExportDialogLocale {
    #[default]
    ZhCn,
    EnUs,
}

impl<'de> Deserialize<'de> for ConnectionLogExportDialogLocale {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let locale = String::deserialize(deserializer)?;
        Ok(if locale == "en-US" {
            Self::EnUs
        } else {
            // Simplified Chinese is the product fallback for missing, malformed,
            // or future renderer locale values.
            Self::ZhCn
        })
    }
}

pub(crate) struct ConnectionLogExportDialogText {
    pub(crate) title: &'static str,
    pub(crate) text_files_filter: &'static str,
    pub(crate) log_files_filter: &'static str,
    pub(crate) html_files_filter: &'static str,
    pub(crate) all_files_filter: &'static str,
}

pub(crate) const fn connection_log_export_dialog_text(
    locale: ConnectionLogExportDialogLocale,
) -> ConnectionLogExportDialogText {
    match locale {
        ConnectionLogExportDialogLocale::ZhCn => ConnectionLogExportDialogText {
            title: "导出连接日志",
            text_files_filter: "文本文件",
            log_files_filter: "日志文件",
            html_files_filter: "HTML 文件",
            all_files_filter: "所有文件",
        },
        ConnectionLogExportDialogLocale::EnUs => ConnectionLogExportDialogText {
            title: "Export Connection Log",
            text_files_filter: "Text Files",
            log_files_filter: "Log Files",
            html_files_filter: "HTML Files",
            all_files_filter: "All Files",
        },
    }
}

const fn connection_log_export_html_labels(
    locale: ConnectionLogExportDialogLocale,
) -> HtmlExportLabels<'static> {
    match locale {
        ConnectionLogExportDialogLocale::ZhCn => {
            HtmlExportLabels::new("会话日志", "主机：", "日期：", "未知主机")
        }
        ConnectionLogExportDialogLocale::EnUs => {
            HtmlExportLabels::new("Session Log", "Host: ", "Date: ", "Unknown")
        }
    }
}

pub(crate) const CONNECTION_LOG_EXPORT_INVALID: &str = "CONNECTION_LOG_EXPORT_INVALID";
pub(crate) const CONNECTION_LOG_EXPORT_UNAVAILABLE: &str = "CONNECTION_LOG_EXPORT_UNAVAILABLE";
pub(crate) const CONNECTION_LOG_EXPORT_DIALOG_FAILED: &str = "CONNECTION_LOG_EXPORT_DIALOG_FAILED";
pub(crate) const CONNECTION_LOG_EXPORT_STORAGE_FAILED: &str =
    "CONNECTION_LOG_EXPORT_STORAGE_FAILED";
pub(crate) const CONNECTION_LOG_EXPORT_WRITE_FAILED: &str = "CONNECTION_LOG_EXPORT_WRITE_FAILED";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExportConnectionLogRequest {
    log_id: String,
    #[serde(default)]
    locale: ConnectionLogExportDialogLocale,
}

impl ExportConnectionLogRequest {
    pub(crate) fn into_parts(
        self,
    ) -> Result<(String, ConnectionLogExportDialogLocale), ConnectionLogExportError> {
        if self.log_id.is_empty()
            || self.log_id.len() > MAX_LOG_ID_BYTES
            || self.log_id.chars().any(char::is_control)
        {
            return Err(ConnectionLogExportError::invalid());
        }
        Ok((self.log_id, self.locale))
    }
}

impl fmt::Debug for ExportConnectionLogRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportConnectionLogRequest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExportConnectionLogResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    canceled: Option<bool>,
}

impl ExportConnectionLogResponse {
    pub(crate) const fn success() -> Self {
        Self {
            success: true,
            canceled: None,
        }
    }

    pub(crate) const fn canceled() -> Self {
        Self {
            success: false,
            canceled: Some(true),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionLogExportErrorCode {
    Invalid,
    Unavailable,
    DialogFailed,
    StorageFailed,
    WriteFailed,
}

impl ConnectionLogExportErrorCode {
    const fn command_code(self) -> &'static str {
        match self {
            Self::Invalid => CONNECTION_LOG_EXPORT_INVALID,
            Self::Unavailable => CONNECTION_LOG_EXPORT_UNAVAILABLE,
            Self::DialogFailed => CONNECTION_LOG_EXPORT_DIALOG_FAILED,
            Self::StorageFailed => CONNECTION_LOG_EXPORT_STORAGE_FAILED,
            Self::WriteFailed => CONNECTION_LOG_EXPORT_WRITE_FAILED,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Connection-log export request is invalid",
            Self::Unavailable => "No captured terminal data is available for this log",
            Self::DialogFailed => "Connection-log export dialog failed",
            Self::StorageFailed => "Connection-log export storage failed",
            Self::WriteFailed => "Connection-log export could not be written",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionLogExportError {
    code: ConnectionLogExportErrorCode,
}

impl ConnectionLogExportError {
    pub(crate) const fn invalid() -> Self {
        Self {
            code: ConnectionLogExportErrorCode::Invalid,
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            code: ConnectionLogExportErrorCode::Unavailable,
        }
    }

    pub(crate) const fn dialog_failed() -> Self {
        Self {
            code: ConnectionLogExportErrorCode::DialogFailed,
        }
    }

    pub(crate) const fn storage_failed() -> Self {
        Self {
            code: ConnectionLogExportErrorCode::StorageFailed,
        }
    }

    const fn write_failed() -> Self {
        Self {
            code: ConnectionLogExportErrorCode::WriteFailed,
        }
    }
}

impl fmt::Debug for ConnectionLogExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionLogExportError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ConnectionLogExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl std::error::Error for ConnectionLogExportError {}

pub(crate) fn connection_log_export_command_error(error: ConnectionLogExportError) -> String {
    format!("{}: {error}", error.code.command_code())
}

/// The small metadata subset needed after the authoritative catalog lookup.
/// Debug remains redacted because labels and endpoints can be sensitive.
pub(crate) struct ConnectionLogExportMetadata {
    host_label: String,
    hostname: String,
    start_time: u64,
}

impl ConnectionLogExportMetadata {
    pub(crate) fn from_log(log: &SavedConnectionLog) -> Result<Self, ConnectionLogExportError> {
        log.validate()
            .map_err(|_| ConnectionLogExportError::invalid())?;
        Ok(Self {
            host_label: log.host_label.clone(),
            hostname: log.hostname.clone(),
            start_time: log.start_time,
        })
    }

    pub(crate) fn default_file_name(&self) -> Result<String, ConnectionLogExportError> {
        let (local, _) = local_date_time(self.start_time)?;
        Ok(default_export_file_name(
            &self.host_label,
            &self.hostname,
            local,
            ExportFormat::PlainText,
        ))
    }

    fn render(
        &self,
        terminal_data: &str,
        path: &Path,
        locale: ConnectionLogExportDialogLocale,
    ) -> Result<String, ConnectionLogExportError> {
        if terminal_data.is_empty() {
            return Err(ConnectionLogExportError::unavailable());
        }
        let (_, localized_date) = local_date_time(self.start_time)?;
        Ok(render_export_with_html_labels(
            export_format_for_path(path, ExportFormat::PlainText),
            terminal_data,
            &self.host_label,
            &localized_date,
            connection_log_export_html_labels(locale),
        ))
    }
}

impl fmt::Debug for ConnectionLogExportMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLogExportMetadata([REDACTED])")
    }
}

pub(crate) fn authoritative_export_metadata(
    logs: &[SavedConnectionLog],
    requested_log_id: &str,
) -> Result<ConnectionLogExportMetadata, ConnectionLogExportError> {
    let log = logs
        .iter()
        .find(|log| log.id == requested_log_id)
        .ok_or_else(ConnectionLogExportError::unavailable)?;
    ConnectionLogExportMetadata::from_log(log)
}

fn local_date_time(
    timestamp_millis: u64,
) -> Result<(LocalDateTime, String), ConnectionLogExportError> {
    let timestamp_millis =
        i64::try_from(timestamp_millis).map_err(|_| ConnectionLogExportError::invalid())?;
    let utc: DateTime<Utc> = DateTime::from_timestamp_millis(timestamp_millis)
        .ok_or_else(ConnectionLogExportError::invalid)?;
    let local = utc.with_timezone(&Local);
    let year = u16::try_from(local.year()).map_err(|_| ConnectionLogExportError::invalid())?;
    let components = LocalDateTime::new(
        year,
        u8::try_from(local.month()).map_err(|_| ConnectionLogExportError::invalid())?,
        u8::try_from(local.day()).map_err(|_| ConnectionLogExportError::invalid())?,
        u8::try_from(local.hour()).map_err(|_| ConnectionLogExportError::invalid())?,
        u8::try_from(local.minute()).map_err(|_| ConnectionLogExportError::invalid())?,
        u8::try_from(local.second()).map_err(|_| ConnectionLogExportError::invalid())?,
    )
    .map_err(|_| ConnectionLogExportError::invalid())?;
    Ok((
        components,
        local.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
    ))
}

/// Converts the trusted native-dialog result into an export target. A path is
/// never serialized or accepted from renderer JSON.
pub(crate) fn selected_export_target(
    selected: Option<PathBuf>,
) -> Result<Option<ConnectionLogExportTarget>, ConnectionLogExportError> {
    let Some(path) = selected else {
        return Ok(None);
    };
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ConnectionLogExportError::dialog_failed());
    }
    Ok(Some(ConnectionLogExportTarget::capture(path)?))
}

/// A renderer-inaccessible authorization token captured as soon as the native
/// save dialog confirms its selection. A missing target may only be created;
/// an existing target may only be replaced while its filesystem identity and
/// write-relevant metadata are unchanged.
#[derive(Clone)]
pub(crate) struct ConnectionLogExportTarget {
    path: PathBuf,
    authorization: ExportTargetAuthorization,
}

impl ConnectionLogExportTarget {
    fn capture(path: PathBuf) -> Result<Self, ConnectionLogExportError> {
        let authorization = capture_target_authorization(&path)
            .map_err(|_| ConnectionLogExportError::write_failed())?;
        Ok(Self {
            path,
            authorization,
        })
    }

    fn authorize_commit(&self) -> Result<ExportCommitMode, ConnectionLogExportError> {
        let current = capture_target_authorization(&self.path)
            .map_err(|_| ConnectionLogExportError::write_failed())?;
        match (&self.authorization, current) {
            (ExportTargetAuthorization::Missing, ExportTargetAuthorization::Missing) => {
                Ok(ExportCommitMode::CreateNew)
            }
            (
                ExportTargetAuthorization::Existing(expected),
                ExportTargetAuthorization::Existing(current),
            ) if *expected == current => Ok(ExportCommitMode::ReplaceExisting),
            _ => Err(ConnectionLogExportError::write_failed()),
        }
    }
}

impl fmt::Debug for ConnectionLogExportTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLogExportTarget([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ExportTargetAuthorization {
    Missing,
    Existing(ExportTargetFingerprint),
}

#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct ExportTargetFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(windows)]
#[derive(Clone, PartialEq, Eq)]
struct ExportTargetFingerprint {
    volume_serial_number: Option<u32>,
    file_index: Option<u64>,
    length: u64,
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, PartialEq, Eq)]
struct ExportTargetFingerprint {
    length: u64,
    modified: Option<std::time::SystemTime>,
    is_file: bool,
    is_directory: bool,
    is_symlink: bool,
    readonly: bool,
}

fn capture_target_authorization(path: &Path) -> std::io::Result<ExportTargetAuthorization> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(ExportTargetAuthorization::Existing(
            ExportTargetFingerprint::from_metadata(path, &metadata)?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(ExportTargetAuthorization::Missing)
        }
        Err(error) => Err(error),
    }
}

impl ExportTargetFingerprint {
    #[cfg(unix)]
    fn from_metadata(_path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    #[cfg(windows)]
    fn from_metadata(path: &Path, _metadata: &std::fs::Metadata) -> std::io::Result<Self> {
        use std::mem::MaybeUninit;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GetFileInformationByHandle, OPEN_EXISTING,
        };

        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let read = unsafe { GetFileInformationByHandle(handle, information.as_mut_ptr()) };
        let read_error = if read == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        let closed = unsafe { CloseHandle(handle) };
        if let Some(error) = read_error {
            return Err(error);
        }
        if closed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let information = unsafe { information.assume_init() };

        Ok(Self {
            volume_serial_number: Some(information.dwVolumeSerialNumber),
            file_index: Some(
                (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            ),
            length: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
            attributes: information.dwFileAttributes,
            creation_time: file_time_u64(information.ftCreationTime),
            last_write_time: file_time_u64(information.ftLastWriteTime),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn from_metadata(_path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<Self> {
        let file_type = metadata.file_type();
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            is_file: file_type.is_file(),
            is_directory: file_type.is_dir(),
            is_symlink: file_type.is_symlink(),
            readonly: metadata.permissions().readonly(),
        })
    }
}

#[cfg(windows)]
fn file_time_u64(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportCommitMode {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionLogExportWriteOutcome {
    Durable,
    CommittedUncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportFileCommitOutcome {
    Complete,
    #[cfg(any(
        test,
        all(unix, not(any(target_os = "linux", target_os = "macos"))),
        not(any(unix, windows))
    ))]
    TemporaryCleanupUncertain,
}

#[cfg(test)]
pub(crate) fn render_and_write_export(
    target: &ConnectionLogExportTarget,
    metadata: &ConnectionLogExportMetadata,
    terminal_data: &str,
) -> Result<ConnectionLogExportWriteOutcome, ConnectionLogExportError> {
    render_and_write_export_with_locale(
        target,
        metadata,
        terminal_data,
        ConnectionLogExportDialogLocale::ZhCn,
    )
}

pub(crate) fn render_and_write_export_with_locale(
    target: &ConnectionLogExportTarget,
    metadata: &ConnectionLogExportMetadata,
    terminal_data: &str,
    locale: ConnectionLogExportDialogLocale,
) -> Result<ConnectionLogExportWriteOutcome, ConnectionLogExportError> {
    let rendered = metadata.render(terminal_data, &target.path, locale)?;
    atomic_write(target, rendered.as_bytes())
}

fn atomic_write(
    target: &ConnectionLogExportTarget,
    contents: &[u8],
) -> Result<ConnectionLogExportWriteOutcome, ConnectionLogExportError> {
    let path = &target.path;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(ConnectionLogExportError::write_failed)?;
    if path.file_name().is_none() {
        return Err(ConnectionLogExportError::write_failed());
    }

    let (temporary_path, mut temporary_file) = create_temporary_sibling(parent)?;
    let mut cleanup = TemporaryExportCleanup::new(temporary_path.clone());
    temporary_file
        .write_all(contents)
        .and_then(|_| temporary_file.sync_all())
        .map_err(|_| ConnectionLogExportError::write_failed())?;
    drop(temporary_file);

    let _commit_guard = EXPORT_COMMIT_LOCK
        .lock()
        .map_err(|_| ConnectionLogExportError::write_failed())?;
    let file_commit = match target.authorize_commit()? {
        ExportCommitMode::CreateNew => atomic_create_new(&temporary_path, path),
        ExportCommitMode::ReplaceExisting => {
            atomic_replace(&temporary_path, path).map(|()| ExportFileCommitOutcome::Complete)
        }
    }
    .map_err(|_| ConnectionLogExportError::write_failed())?;
    // Every successful file-commit outcome means the destination is already
    // visible. In particular, the portable hard-link fallback may be unable
    // to unlink its source name after publishing the destination. Do not let
    // the cleanup guard retry that path deletion: another process could have
    // replaced the source name by then. Report committed uncertainty instead
    // of a false pre-commit failure that invites an unsafe retry.
    cleanup.committed = true;

    // The target is already atomically visible at this point. A directory
    // fsync or portable temporary-link cleanup failure means final state is
    // uncertain, not that the export failed or that retrying is safe.
    Ok(post_commit_outcome(
        file_commit,
        sync_parent_directory(parent),
    ))
}

fn post_commit_outcome(
    file_commit: ExportFileCommitOutcome,
    sync_result: std::io::Result<()>,
) -> ConnectionLogExportWriteOutcome {
    match (file_commit, sync_result) {
        (ExportFileCommitOutcome::Complete, Ok(())) => ConnectionLogExportWriteOutcome::Durable,
        _ => ConnectionLogExportWriteOutcome::CommittedUncertain,
    }
}

#[cfg(any(
    test,
    all(unix, not(any(target_os = "linux", target_os = "macos"))),
    not(any(unix, windows))
))]
fn hard_link_cleanup_outcome(cleanup_result: std::io::Result<()>) -> ExportFileCommitOutcome {
    match cleanup_result {
        Ok(()) => ExportFileCommitOutcome::Complete,
        Err(_) => ExportFileCommitOutcome::TemporaryCleanupUncertain,
    }
}

fn create_temporary_sibling(parent: &Path) -> Result<(PathBuf, File), ConnectionLogExportError> {
    for _ in 0..16 {
        let path = parent.join(format!(
            ".netcatty-export-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ConnectionLogExportError::write_failed()),
        }
    }
    Err(ConnectionLogExportError::write_failed())
}

struct TemporaryExportCleanup {
    path: PathBuf,
    committed: bool,
}

impl TemporaryExportCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for TemporaryExportCleanup {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(target_os = "linux")]
fn atomic_create_new(
    source: &Path,
    destination: &Path,
) -> std::io::Result<ExportFileCommitOutcome> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let renamed = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed == 0 {
        Ok(ExportFileCommitOutcome::Complete)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn atomic_create_new(
    source: &Path,
    destination: &Path,
) -> std::io::Result<ExportFileCommitOutcome> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let renamed =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if renamed == 0 {
        Ok(ExportFileCommitOutcome::Complete)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn atomic_create_new(
    source: &Path,
    destination: &Path,
) -> std::io::Result<ExportFileCommitOutcome> {
    std::fs::hard_link(source, destination)?;
    Ok(hard_link_cleanup_outcome(std::fs::remove_file(source)))
}

#[cfg(windows)]
fn atomic_create_new(
    source: &Path,
    destination: &Path,
) -> std::io::Result<ExportFileCommitOutcome> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ExportFileCommitOutcome::Complete)
    }
}

#[cfg(not(any(unix, windows)))]
fn atomic_create_new(
    source: &Path,
    destination: &Path,
) -> std::io::Result<ExportFileCommitOutcome> {
    std::fs::hard_link(source, destination)?;
    Ok(hard_link_cleanup_outcome(std::fs::remove_file(source)))
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    File::open(parent).and_then(|directory| directory.sync_all())
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use netcatty_vault::SavedConnectionLogProtocol;
    use serde_json::json;

    use super::*;

    fn log() -> SavedConnectionLog {
        SavedConnectionLog {
            id: "export-log".to_owned(),
            session_id: Some("export-session".to_owned()),
            host_id: "export-host".to_owned(),
            host_label: "server/name".to_owned(),
            hostname: "server.example.test".to_owned(),
            username: "remote-user".to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            host_os: None,
            host_distro: None,
            host_icon_mode: None,
            host_icon_id: None,
            host_icon_color_mode: None,
            host_icon_color: None,
            host_icon_color_custom: None,
            start_time: 1_700_000_000_000,
            end_time: Some(1_700_000_001_000),
            local_username: "local-user".to_owned(),
            local_hostname: "local-host".to_owned(),
            saved: false,
            theme_id: None,
            font_size: None,
        }
    }

    fn export_target(path: PathBuf) -> ConnectionLogExportTarget {
        selected_export_target(Some(path))
            .expect("valid native selection")
            .expect("selected target")
    }

    #[test]
    fn request_is_strict_and_debug_is_redacted() {
        let request: ExportConnectionLogRequest = serde_json::from_value(json!({
            "logId": "private-log-id",
            "locale": "en-US"
        }))
        .expect("request");
        let diagnostics = format!("{request:?}");
        assert!(!diagnostics.contains("private-log-id"));
        let (log_id, locale) = request.into_parts().expect("request parts");
        assert_eq!(log_id, "private-log-id");
        assert_eq!(locale, ConnectionLogExportDialogLocale::EnUs);
        assert!(
            serde_json::from_value::<ExportConnectionLogRequest>(json!({
                "logId": "private-log-id",
                "locale": "zh-CN",
                "path": "C:/private/export.txt"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ExportConnectionLogRequest>(json!({
                "logId": "private-log-id",
                "locale": "zh-CN",
                "terminalData": "private-terminal-data"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ExportConnectionLogRequest>(json!({
                "logId": "private-log-id",
                "locale": "zh-CN",
                "unexpected": true
            }))
            .is_err()
        );
    }

    #[test]
    fn request_locale_recognizes_english_and_falls_back_to_simplified_chinese() {
        for value in [json!("zh-CN"), json!("zh-cn"), json!("unsupported")] {
            let request: ExportConnectionLogRequest = serde_json::from_value(json!({
                "logId": "export-log",
                "locale": value
            }))
            .expect("string locale");
            assert_eq!(
                request.into_parts().expect("request parts").1,
                ConnectionLogExportDialogLocale::ZhCn
            );
        }

        let missing: ExportConnectionLogRequest =
            serde_json::from_value(json!({ "logId": "export-log" })).expect("missing locale");
        assert_eq!(
            missing.into_parts().expect("request parts").1,
            ConnectionLogExportDialogLocale::ZhCn
        );
        assert!(
            serde_json::from_value::<ExportConnectionLogRequest>(json!({
                "logId": "export-log",
                "locale": 1
            }))
            .is_err(),
            "non-string locale metadata must remain invalid"
        );
    }

    #[test]
    fn native_dialog_title_and_filters_follow_the_normalized_locale() {
        let chinese = connection_log_export_dialog_text(ConnectionLogExportDialogLocale::ZhCn);
        assert_eq!(chinese.title, "导出连接日志");
        assert_eq!(chinese.text_files_filter, "文本文件");
        assert_eq!(chinese.log_files_filter, "日志文件");
        assert_eq!(chinese.html_files_filter, "HTML 文件");
        assert_eq!(chinese.all_files_filter, "所有文件");

        let english = connection_log_export_dialog_text(ConnectionLogExportDialogLocale::EnUs);
        assert_eq!(english.title, "Export Connection Log");
        assert_eq!(english.text_files_filter, "Text Files");
        assert_eq!(english.log_files_filter, "Log Files");
        assert_eq!(english.html_files_filter, "HTML Files");
        assert_eq!(english.all_files_filter, "All Files");
    }

    #[test]
    fn html_export_content_follows_the_normalized_locale() {
        let metadata = ConnectionLogExportMetadata {
            host_label: String::new(),
            hostname: "server.example.test".to_owned(),
            start_time: 1_700_000_000_000,
        };
        let path = Path::new("session.html");

        let chinese = metadata
            .render("done", path, ConnectionLogExportDialogLocale::ZhCn)
            .expect("Chinese HTML export");
        assert!(chinese.contains("<title>会话日志 - 未知主机</title>"));
        assert!(chinese.contains("主机：未知主机<br>"));
        assert!(chinese.contains("日期："));
        assert!(!chinese.contains("Session Log"));

        let english = metadata
            .render("done", path, ConnectionLogExportDialogLocale::EnUs)
            .expect("English HTML export");
        assert!(english.contains("<title>Session Log - Unknown</title>"));
        assert!(english.contains("Host: Unknown<br>"));
        assert!(english.contains("Date: "));
        assert!(!english.contains("会话日志"));
    }

    #[test]
    fn canceled_response_is_path_free_and_success_omits_canceled() {
        assert_eq!(
            serde_json::to_value(ExportConnectionLogResponse::canceled()).expect("cancel JSON"),
            json!({ "success": false, "canceled": true })
        );
        assert_eq!(
            serde_json::to_value(ExportConnectionLogResponse::success()).expect("success JSON"),
            json!({ "success": true })
        );
        assert!(
            selected_export_target(None)
                .expect("cancel selection")
                .is_none()
        );
    }

    #[test]
    fn metadata_helper_builds_safe_plain_text_default_name() {
        let logs = vec![log()];
        let metadata = authoritative_export_metadata(&logs, "export-log").expect("metadata");
        let name = metadata.default_file_name().expect("default name");
        assert!(name.starts_with("server_name_"));
        assert!(name.ends_with(".txt"));
        assert!(!name.contains('/'));
        let diagnostics = format!("{metadata:?}");
        assert!(!diagnostics.contains("server.example.test"));
        assert!(!diagnostics.contains("server/name"));
    }

    #[test]
    fn authoritative_helper_rejects_a_log_removed_while_dialog_was_open() {
        let mut logs = vec![log()];
        assert!(authoritative_export_metadata(&logs, "export-log").is_ok());
        logs.clear();
        let error = authoritative_export_metadata(&logs, "export-log")
            .expect_err("deleted log must no longer be exportable");
        assert_eq!(
            connection_log_export_command_error(error),
            "CONNECTION_LOG_EXPORT_UNAVAILABLE: No captured terminal data is available for this log"
        );
    }

    #[test]
    fn writes_utf8_and_atomically_overwrites_an_existing_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("session.txt");
        fs::write(&target_path, b"old-content").expect("old target");
        let target = export_target(target_path.clone());
        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        render_and_write_export(&target, &metadata, "hello\rWORLD\n\u{4f60}\u{597d}")
            .expect("write export");
        assert_eq!(
            fs::read_to_string(&target_path).expect("read export"),
            "WORLD\n\u{4f60}\u{597d}"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("list directory")
                .count(),
            1
        );
    }

    #[test]
    fn creates_a_new_target_without_replacing_a_late_arrival() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("private-late-arrival.txt");
        let target = export_target(target_path.clone());
        fs::write(&target_path, "do-not-clobber").expect("late target");

        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        let error = render_and_write_export(&target, &metadata, "private-terminal-marker")
            .expect_err("late target must require another native confirmation");

        assert_eq!(
            fs::read_to_string(&target_path).expect("late target preserved"),
            "do-not-clobber"
        );
        let diagnostics = format!("{target:?} {error:?} {error}");
        assert!(!diagnostics.contains("private-late-arrival"));
        assert!(!diagnostics.contains("private-terminal-marker"));
        assert_eq!(
            connection_log_export_command_error(error),
            "CONNECTION_LOG_EXPORT_WRITE_FAILED: Connection-log export could not be written"
        );
    }

    #[test]
    fn refuses_to_replace_a_target_swapped_after_dialog_confirmation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("session.txt");
        let original_path = directory.path().join("confirmed-original.txt");
        fs::write(&target_path, "confirmed-content").expect("confirmed target");
        let target = export_target(target_path.clone());

        fs::rename(&target_path, &original_path).expect("move confirmed target");
        fs::write(&target_path, "replacement-from-another-process").expect("swapped target");

        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        render_and_write_export(&target, &metadata, "netcatty-export")
            .expect_err("swapped target must require another confirmation");
        assert_eq!(
            fs::read_to_string(&target_path).expect("swapped target preserved"),
            "replacement-from-another-process"
        );
        assert_eq!(
            fs::read_to_string(&original_path).expect("confirmed target preserved"),
            "confirmed-content"
        );
    }

    #[test]
    fn refuses_to_replace_an_in_place_modified_confirmed_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("session.txt");
        fs::write(&target_path, "short").expect("confirmed target");
        let target = export_target(target_path.clone());
        fs::write(&target_path, "longer-content-from-another-process").expect("modified target");

        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        render_and_write_export(&target, &metadata, "netcatty-export")
            .expect_err("modified target must require another confirmation");
        assert_eq!(
            fs::read_to_string(&target_path).expect("modified target preserved"),
            "longer-content-from-another-process"
        );
    }

    #[test]
    fn concurrent_new_target_exports_allow_exactly_one_commit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("session.txt");
        let first_target = export_target(target_path.clone());
        let second_target = first_target.clone();

        let first = std::thread::spawn(move || {
            let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
            render_and_write_export(&first_target, &metadata, "first")
        });
        let second = std::thread::spawn(move || {
            let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
            render_and_write_export(&second_target, &metadata, "second")
        });
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let contents = fs::read_to_string(&target_path).expect("committed target");
        assert!(contents == "first" || contents == "second");
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("list directory")
                .count(),
            1
        );
    }

    #[test]
    fn post_commit_sync_failure_reports_committed_but_uncertain() {
        assert_eq!(
            post_commit_outcome(ExportFileCommitOutcome::Complete, Ok(())),
            ConnectionLogExportWriteOutcome::Durable
        );
        assert_eq!(
            post_commit_outcome(
                ExportFileCommitOutcome::Complete,
                Err(std::io::Error::other("injected sync failure")),
            ),
            ConnectionLogExportWriteOutcome::CommittedUncertain
        );
    }

    #[test]
    fn portable_hard_link_unlink_failure_is_a_committed_uncertain_success() {
        let file_commit = hard_link_cleanup_outcome(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected temporary unlink failure",
        )));
        assert_eq!(
            file_commit,
            ExportFileCommitOutcome::TemporaryCleanupUncertain
        );
        assert_eq!(
            post_commit_outcome(file_commit, Ok(())),
            ConnectionLogExportWriteOutcome::CommittedUncertain
        );
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_replaces_a_symlink_and_keeps_unix_mode_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("temporary directory");
        let referent = directory.path().join("referent.txt");
        let target_path = directory.path().join("session.txt");
        fs::write(&referent, "do-not-change").expect("referent");
        symlink(&referent, &target_path).expect("symlink");
        let target = export_target(target_path.clone());
        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        render_and_write_export(&target, &metadata, "replacement").expect("write export");
        assert!(
            !fs::symlink_metadata(&target_path)
                .expect("target metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&referent).expect("referent unchanged"),
            "do-not-change"
        );
        assert_eq!(
            fs::read_to_string(&target_path).expect("target"),
            "replacement"
        );
        assert_eq!(
            fs::metadata(&target_path)
                .expect("permissions")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_overwrite_replaces_a_symlink_instead_of_following_it() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().expect("temporary directory");
        let referent = directory.path().join("referent.txt");
        let target_path = directory.path().join("session.txt");
        fs::write(&referent, "do-not-change").expect("referent");
        if let Err(error) = symlink_file(&referent, &target_path) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("symlink failed: {error}");
        }
        let target = export_target(target_path.clone());
        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        render_and_write_export(&target, &metadata, "replacement").expect("write export");
        assert!(
            !fs::symlink_metadata(&target_path)
                .expect("target metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&referent).expect("referent unchanged"),
            "do-not-change"
        );
        assert_eq!(
            fs::read_to_string(&target_path).expect("target"),
            "replacement"
        );
    }

    #[test]
    fn failures_never_echo_target_path_or_terminal_data() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target_path = directory.path().join("private-path-marker");
        fs::create_dir(&target_path).expect("directory target");
        let target = export_target(target_path);
        let metadata = ConnectionLogExportMetadata::from_log(&log()).expect("metadata");
        let error = render_and_write_export(&target, &metadata, "private-terminal-marker")
            .expect_err("directory replacement must fail");
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains("private-path-marker"));
        assert!(!diagnostics.contains("private-terminal-marker"));
        assert_eq!(
            connection_log_export_command_error(error),
            "CONNECTION_LOG_EXPORT_WRITE_FAILED: Connection-log export could not be written"
        );
    }
}
