use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netcatty_credentials::OsMasterKeyStore;
use netcatty_replay_store::{
    ConnectionLogReplayStore, ConnectionLogReplayStoreError, ConnectionLogReplayStoreErrorCode,
};
use netcatty_vault::{
    MAX_CONNECTION_LOG_REPLAY_BYTES, SavedConnectionLog, SavedConnectionLogReplay,
};
use serde::{Deserialize, Serialize};

pub(crate) const CONNECTION_LOG_REPLAY_INVALID: &str = "CONNECTION_LOG_REPLAY_INVALID";
pub(crate) const CONNECTION_LOG_REPLAY_SESSION_MISSING: &str =
    "CONNECTION_LOG_REPLAY_SESSION_MISSING";
pub(crate) const CONNECTION_LOG_REPLAY_SESSION_CONFLICT: &str =
    "CONNECTION_LOG_REPLAY_SESSION_CONFLICT";
pub(crate) const CONNECTION_LOG_REPLAY_STORAGE_FAILED: &str =
    "CONNECTION_LOG_REPLAY_STORAGE_FAILED";
pub(crate) const CONNECTION_LOG_REPLAY_WORKER_FAILED: &str = "CONNECTION_LOG_REPLAY_WORKER_FAILED";
const MAX_CONNECTION_LOG_ID_BYTES: usize = 512;
const MAX_FINISH_FAILURES: u8 = 3;
const SESSION_REPLAY_INITIALIZATION_WAIT: Duration = Duration::from_secs(1);
#[cfg(not(test))]
const FAILED_CAPTURE_RETENTION: Duration = Duration::from_secs(60);
#[cfg(test)]
const FAILED_CAPTURE_RETENTION: Duration = Duration::from_millis(100);

/// Strict Tauri request for one replay. Its custom `Debug` never reveals the
/// requested log ID.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadConnectionLogReplayRequest {
    log_id: String,
}

impl ReadConnectionLogReplayRequest {
    pub(crate) fn new(log_id: String) -> Self {
        Self { log_id }
    }

    /// Validates the untrusted renderer ID before any catalog or replay-store
    /// I/O. Reusing the Vault replay model keeps this boundary aligned with
    /// the durable 512-byte, non-empty, control-free ID contract.
    pub(crate) fn into_log_id(self) -> Result<String, ConnectionLogReplayAdapterError> {
        // Reject an oversized renderer allocation before making the small
        // validation copy required by the shared replay model.
        if self.log_id.len() > MAX_CONNECTION_LOG_ID_BYTES {
            return Err(ConnectionLogReplayAdapterError::new(
                ConnectionLogReplayAdapterErrorCode::InvalidInput,
            ));
        }
        SavedConnectionLogReplay::new(self.log_id.clone(), String::new()).map_err(|_| {
            ConnectionLogReplayAdapterError::new(ConnectionLogReplayAdapterErrorCode::InvalidInput)
        })?;
        Ok(self.log_id)
    }
}

impl fmt::Debug for ReadConnectionLogReplayRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadConnectionLogReplayRequest([REDACTED])")
    }
}

/// Renderer response for exactly one requested replay. No metadata catalog,
/// path, locator, or encryption state crosses IPC.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadConnectionLogReplayResponse {
    log_id: String,
    terminal_data: String,
}

impl ReadConnectionLogReplayResponse {
    pub(crate) fn terminal_data(&self) -> &str {
        &self.terminal_data
    }

    #[cfg(test)]
    pub(crate) fn log_id(&self) -> &str {
        &self.log_id
    }
}

impl fmt::Debug for ReadConnectionLogReplayResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadConnectionLogReplayResponse([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionLogReplayAdapterErrorCode {
    InvalidInput,
    SessionMissing,
    SessionConflict,
    StorageFailed,
    WorkerFailed,
}

impl ConnectionLogReplayAdapterErrorCode {
    const fn command_code(self) -> &'static str {
        match self {
            Self::InvalidInput => CONNECTION_LOG_REPLAY_INVALID,
            Self::SessionMissing => CONNECTION_LOG_REPLAY_SESSION_MISSING,
            Self::SessionConflict => CONNECTION_LOG_REPLAY_SESSION_CONFLICT,
            Self::StorageFailed => CONNECTION_LOG_REPLAY_STORAGE_FAILED,
            Self::WorkerFailed => CONNECTION_LOG_REPLAY_WORKER_FAILED,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "Connection-log replay request is invalid",
            Self::SessionMissing => "Connection-log replay session is unavailable",
            Self::SessionConflict => "Connection-log replay session already exists",
            Self::StorageFailed => "Connection-log replay storage failed",
            Self::WorkerFailed => "Connection-log replay worker failed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionLogReplayAdapterError {
    code: ConnectionLogReplayAdapterErrorCode,
}

impl ConnectionLogReplayAdapterError {
    const fn new(code: ConnectionLogReplayAdapterErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    const fn code(&self) -> ConnectionLogReplayAdapterErrorCode {
        self.code
    }
}

impl fmt::Debug for ConnectionLogReplayAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionLogReplayAdapterError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ConnectionLogReplayAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl std::error::Error for ConnectionLogReplayAdapterError {}

/// Maps an adapter failure to the existing renderer-safe `CODE: message`
/// command convention without including a log/session ID or terminal bytes.
pub(crate) fn connection_log_replay_command_error(
    error: ConnectionLogReplayAdapterError,
) -> String {
    format!("{}: {error}", error.code.command_code())
}

type ConnectionLogReplayOpener =
    dyn Fn() -> Result<ConnectionLogReplayManager, ConnectionLogReplayAdapterError> + Send + Sync;

type ConnectionLogReplayInitialization =
    Result<ConnectionLogReplayManager, ConnectionLogReplayAdapterError>;

struct ConnectionLogReplayRuntimeInner {
    opener: Arc<ConnectionLogReplayOpener>,
    initialization: tokio::sync::watch::Sender<Option<ConnectionLogReplayInitialization>>,
    initialization_started: AtomicBool,
}

/// Lazily opens replay custody exactly once on a blocking worker.
///
/// Construction performs no filesystem, file-lock, or OS-keyring work, so a
/// Tauri setup callback can publish this runtime and return immediately.
/// Concurrent readers share the same initialization result; a failed open is
/// retained for the current process and retried normally on the next launch.
#[derive(Clone)]
pub(crate) struct ConnectionLogReplayRuntime {
    inner: Arc<ConnectionLogReplayRuntimeInner>,
}

impl ConnectionLogReplayRuntime {
    pub(crate) fn new(app_data_dir: impl AsRef<Path>) -> Self {
        let app_data_dir = PathBuf::from(app_data_dir.as_ref());
        Self::with_opener(move || ConnectionLogReplayManager::open(&app_data_dir))
    }

    #[cfg(test)]
    pub(crate) fn new_with_master_key_store(
        app_data_dir: impl AsRef<Path>,
        master_keys: OsMasterKeyStore,
    ) -> Self {
        let app_data_dir = PathBuf::from(app_data_dir.as_ref());
        Self::with_opener(move || {
            ConnectionLogReplayManager::open_with_master_key_store(
                &app_data_dir,
                master_keys.clone(),
            )
        })
    }

    fn with_opener<F>(opener: F) -> Self
    where
        F: Fn() -> Result<ConnectionLogReplayManager, ConnectionLogReplayAdapterError>
            + Send
            + Sync
            + 'static,
    {
        let (initialization, _) = tokio::sync::watch::channel(None);
        Self {
            inner: Arc::new(ConnectionLogReplayRuntimeInner {
                opener: Arc::new(opener),
                initialization,
                initialization_started: AtomicBool::new(false),
            }),
        }
    }

    /// Starts the single detached initialization flight. The detached task is
    /// intentional: canceling or timing out any waiter must not cancel the
    /// blocking keyring/file-lock opener and allow another opener to race it.
    fn start_initialization(&self) {
        if self
            .inner
            .initialization_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let inner = self.inner.clone();
        tokio::spawn(async move {
            let opener = inner.opener.clone();
            let result = tokio::task::spawn_blocking(move || opener())
                .await
                .map_err(|_| {
                    ConnectionLogReplayAdapterError::new(
                        ConnectionLogReplayAdapterErrorCode::WorkerFailed,
                    )
                })
                .and_then(std::convert::identity);
            inner.initialization.send_replace(Some(result));
        });
    }

    /// Waits asynchronously for the one detached blocking initialization
    /// worker. This is used by replay-only commands and startup maintenance;
    /// SSH session starts use the bounded waiter below.
    pub(crate) async fn manager(
        &self,
    ) -> Result<ConnectionLogReplayManager, ConnectionLogReplayAdapterError> {
        let mut initialization = self.inner.initialization.subscribe();
        self.start_initialization();
        loop {
            if let Some(result) = initialization.borrow().clone() {
                return result;
            }
            initialization.changed().await.map_err(|_| {
                ConnectionLogReplayAdapterError::new(
                    ConnectionLogReplayAdapterErrorCode::WorkerFailed,
                )
            })?;
        }
    }

    /// Gives normal replay initialization a short opportunity to finish, but
    /// never lets OS-keyring or replay file-lock latency gate `sessions.begin`.
    /// A timeout or initialization failure degrades only this session's replay
    /// capture; the detached single flight continues for later sessions.
    pub(crate) async fn manager_for_session(&self) -> Option<ConnectionLogReplayManager> {
        self.manager_for_session_with_wait(SESSION_REPLAY_INITIALIZATION_WAIT)
            .await
    }

    async fn manager_for_session_with_wait(
        &self,
        wait: Duration,
    ) -> Option<ConnectionLogReplayManager> {
        tokio::time::timeout(wait, self.manager())
            .await
            .ok()
            .and_then(Result::ok)
    }

    /// Non-blocking probe for ordinary SSH and metadata paths. Startup owns
    /// initialization/reconciliation, so these paths never wait on keyring or
    /// replay file locks and simply omit replay work until custody is ready.
    pub(crate) fn ready_manager(&self) -> Option<ConnectionLogReplayManager> {
        self.inner
            .initialization
            .borrow()
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned()
    }
}

impl fmt::Debug for ConnectionLogReplayRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLogReplayRuntime([REDACTED])")
    }
}

/// Thread-safe session buffer plus blocking encrypted-store adapter.
///
/// `append_session_bytes` performs no filesystem/keyring operation. Only
/// `finish_session`, `read_one`, and `reconcile_catalog` enter a blocking
/// worker, keeping terminal event forwarding off storage latency.
#[derive(Clone)]
pub(crate) struct ConnectionLogReplayManager {
    store: Arc<ConnectionLogReplayStore>,
    active: Arc<Mutex<HashMap<String, SessionReplayCapture>>>,
}

impl fmt::Debug for ConnectionLogReplayManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLogReplayManager([REDACTED])")
    }
}

impl ConnectionLogReplayManager {
    /// `app_data_dir` is the Tauri application data directory, not the Vault
    /// directory. Replay custody is rooted at its dedicated sibling folder.
    pub(crate) fn open(
        app_data_dir: impl AsRef<Path>,
    ) -> Result<Self, ConnectionLogReplayAdapterError> {
        Self::open_with_master_key_store(app_data_dir, OsMasterKeyStore::new())
    }

    fn open_with_master_key_store(
        app_data_dir: impl AsRef<Path>,
        master_keys: OsMasterKeyStore,
    ) -> Result<Self, ConnectionLogReplayAdapterError> {
        let store = ConnectionLogReplayStore::open_with_master_key_store(
            app_data_dir.as_ref().join("connection-log-replays"),
            master_keys,
        )
        .map_err(map_store_error)?;
        Ok(Self {
            store: Arc::new(store),
            active: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Starts in-memory capture after a real session ID is assigned. The log's
    /// own `sessionId` must exactly match, preventing cross-session attachment.
    pub(crate) fn begin_session(
        &self,
        session_id: String,
        log: SavedConnectionLog,
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        log.validate().map_err(|_| {
            ConnectionLogReplayAdapterError::new(ConnectionLogReplayAdapterErrorCode::InvalidInput)
        })?;
        if log.session_id.as_deref() != Some(session_id.as_str()) {
            return Err(ConnectionLogReplayAdapterError::new(
                ConnectionLogReplayAdapterErrorCode::InvalidInput,
            ));
        }
        let mut active = self.lock_active()?;
        if active.contains_key(&session_id) {
            return Err(ConnectionLogReplayAdapterError::new(
                ConnectionLogReplayAdapterErrorCode::SessionConflict,
            ));
        }
        active.insert(session_id, SessionReplayCapture::new(log));
        Ok(())
    }

    /// Appends an arbitrary SSH output byte chunk using incremental lossy UTF-8
    /// decoding. A split valid codepoint remains intact; invalid input becomes
    /// U+FFFD. Memory remains bounded to approximately one replay plus three
    /// pending UTF-8 bytes.
    pub(crate) fn append_session_bytes(
        &self,
        session_id: &str,
        bytes: &[u8],
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        let mut active = self.lock_active()?;
        let capture = active.get_mut(session_id).ok_or_else(|| {
            ConnectionLogReplayAdapterError::new(
                ConnectionLogReplayAdapterErrorCode::SessionMissing,
            )
        })?;
        capture.buffer.append_bytes(bytes);
        Ok(())
    }

    /// Text-specialized append for future local/Telnet/serial adapters.
    pub(crate) fn append_session_text(
        &self,
        session_id: &str,
        text: &str,
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        let mut active = self.lock_active()?;
        let capture = active.get_mut(session_id).ok_or_else(|| {
            ConnectionLogReplayAdapterError::new(
                ConnectionLogReplayAdapterErrorCode::SessionMissing,
            )
        })?;
        capture.buffer.append_text(text);
        Ok(())
    }

    /// Persists one final snapshot on a blocking worker. Capture remains in
    /// memory when persistence fails, allowing a safe retry without data loss.
    pub(crate) async fn finish_session(
        &self,
        session_id: &str,
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        let (log, terminal_data) = {
            let active = self.lock_active()?;
            let capture = active.get(session_id).ok_or_else(|| {
                ConnectionLogReplayAdapterError::new(
                    ConnectionLogReplayAdapterErrorCode::SessionMissing,
                )
            })?;
            (capture.log.clone(), capture.buffer.snapshot())
        };
        let captured_log_id = log.id.clone();
        let replay =
            SavedConnectionLogReplay::new(&captured_log_id, terminal_data).map_err(|_| {
                ConnectionLogReplayAdapterError::new(
                    ConnectionLogReplayAdapterErrorCode::InvalidInput,
                )
            })?;
        let store = self.store.clone();
        if let Err(error) = run_blocking(move || store.replace(&log, replay)).await {
            self.retain_failed_finish_for_retry(session_id, &captured_log_id)?;
            return Err(error);
        }

        let mut active = self.lock_active()?;
        if active
            .get(session_id)
            .is_some_and(|capture| capture.log.id == captured_log_id)
        {
            active.remove(session_id);
        }
        Ok(())
    }

    pub(crate) fn discard_session(
        &self,
        session_id: &str,
    ) -> Result<bool, ConnectionLogReplayAdapterError> {
        Ok(self.lock_active()?.remove(session_id).is_some())
    }

    /// Strict one-record Tauri adapter. A missing replay returns the requested
    /// ID with empty terminal data; the command never returns a replay catalog
    /// or nullable response shape.
    pub(crate) async fn read_one(
        &self,
        request: ReadConnectionLogReplayRequest,
    ) -> Result<ReadConnectionLogReplayResponse, ConnectionLogReplayAdapterError> {
        let log_id = request.into_log_id()?;
        let response_log_id = log_id.clone();
        let store = self.store.clone();
        run_blocking(move || store.read(&log_id))
            .await
            .map(|replay| ReadConnectionLogReplayResponse {
                log_id: response_log_id,
                terminal_data: replay
                    .map(SavedConnectionLogReplay::into_terminal_data)
                    .unwrap_or_default(),
            })
    }

    /// Applies the complete durable Vault catalog to replay retention on a
    /// blocking worker. Call after metadata replace/bookmark/delete/clear.
    pub(crate) async fn reconcile_catalog(
        &self,
        logs: Vec<SavedConnectionLog>,
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        let store = self.store.clone();
        run_blocking(move || store.reconcile(&logs)).await
    }

    fn lock_active(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<String, SessionReplayCapture>>,
        ConnectionLogReplayAdapterError,
    > {
        self.active.lock().map_err(|_| {
            ConnectionLogReplayAdapterError::new(ConnectionLogReplayAdapterErrorCode::WorkerFailed)
        })
    }

    fn retain_failed_finish_for_retry(
        &self,
        session_id: &str,
        expected_log_id: &str,
    ) -> Result<(), ConnectionLogReplayAdapterError> {
        let (failure_generation, remove_now) = {
            let mut active = self.lock_active()?;
            let Some(capture) = active
                .get_mut(session_id)
                .filter(|capture| capture.log.id == expected_log_id)
            else {
                return Ok(());
            };
            capture.finish_failures = capture.finish_failures.saturating_add(1);
            capture.failure_generation = capture.failure_generation.wrapping_add(1).max(1);
            (
                capture.failure_generation,
                capture.finish_failures >= MAX_FINISH_FAILURES,
            )
        };
        if remove_now {
            let mut active = self.lock_active()?;
            if active.get(session_id).is_some_and(|capture| {
                capture.log.id == expected_log_id
                    && capture.failure_generation == failure_generation
            }) {
                active.remove(session_id);
            }
            return Ok(());
        }

        let active = self.active.clone();
        let session_id = session_id.to_owned();
        let expected_log_id = expected_log_id.to_owned();
        tokio::spawn(async move {
            tokio::time::sleep(FAILED_CAPTURE_RETENTION).await;
            let Ok(mut captures) = active.lock() else {
                return;
            };
            if captures.get(&session_id).is_some_and(|capture| {
                capture.log.id == expected_log_id
                    && capture.failure_generation == failure_generation
            }) {
                captures.remove(&session_id);
            }
        });
        Ok(())
    }
}

struct SessionReplayCapture {
    log: SavedConnectionLog,
    buffer: BoundedReplayBuffer,
    finish_failures: u8,
    failure_generation: u64,
}

impl SessionReplayCapture {
    fn new(log: SavedConnectionLog) -> Self {
        Self {
            log,
            buffer: BoundedReplayBuffer::default(),
            finish_failures: 0,
            failure_generation: 0,
        }
    }
}

impl fmt::Debug for SessionReplayCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionReplayCapture")
            .field("buffered_bytes", &self.buffer.bytes)
            .field("pending_utf8_bytes", &self.buffer.pending_utf8.len())
            .field("finish_failures", &self.finish_failures)
            .finish()
    }
}

#[derive(Default)]
struct BoundedReplayBuffer {
    chunks: VecDeque<String>,
    bytes: usize,
    pending_utf8: Vec<u8>,
}

impl fmt::Debug for BoundedReplayBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedReplayBuffer")
            .field("bytes", &self.bytes)
            .field("chunks", &self.chunks.len())
            .field("pending_utf8_bytes", &self.pending_utf8.len())
            .finish()
    }
}

impl BoundedReplayBuffer {
    fn append_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if text.len() >= MAX_CONNECTION_LOG_REPLAY_BYTES {
            let suffix = newest_utf8_suffix(text, MAX_CONNECTION_LOG_REPLAY_BYTES);
            self.chunks.clear();
            self.bytes = suffix.len();
            self.chunks.push_back(suffix.to_owned());
            return;
        }
        self.bytes += text.len();
        self.chunks.push_back(text.to_owned());
        self.trim_front();
    }

    fn append_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let maximum_input = MAX_CONNECTION_LOG_REPLAY_BYTES.saturating_add(3);
        let bytes = if bytes.len() > maximum_input {
            self.chunks.clear();
            self.bytes = 0;
            self.pending_utf8.clear();
            &bytes[bytes.len() - maximum_input..]
        } else {
            bytes
        };
        let mut combined = Vec::with_capacity(self.pending_utf8.len() + bytes.len());
        combined.append(&mut self.pending_utf8);
        combined.extend_from_slice(bytes);
        let mut cursor = 0;
        while cursor < combined.len() {
            match std::str::from_utf8(&combined[cursor..]) {
                Ok(text) => {
                    self.append_text(text);
                    cursor = combined.len();
                }
                Err(error) => {
                    let valid_end = cursor + error.valid_up_to();
                    if valid_end > cursor {
                        // `valid_up_to` guarantees this prefix is UTF-8.
                        let valid = std::str::from_utf8(&combined[cursor..valid_end])
                            .expect("validated UTF-8 prefix");
                        self.append_text(valid);
                    }
                    match error.error_len() {
                        Some(invalid_bytes) => {
                            self.append_text("\u{fffd}");
                            cursor = valid_end + invalid_bytes;
                        }
                        None => {
                            self.pending_utf8.extend_from_slice(&combined[valid_end..]);
                            debug_assert!(self.pending_utf8.len() <= 3);
                            break;
                        }
                    }
                }
            }
        }
    }

    fn snapshot(&self) -> String {
        let pending = String::from_utf8_lossy(&self.pending_utf8);
        let capacity = self.bytes.saturating_add(pending.len());
        let mut value = String::with_capacity(capacity);
        for chunk in &self.chunks {
            value.push_str(chunk);
        }
        value.push_str(&pending);
        if value.len() > MAX_CONNECTION_LOG_REPLAY_BYTES {
            newest_utf8_suffix(&value, MAX_CONNECTION_LOG_REPLAY_BYTES).to_owned()
        } else {
            value
        }
    }

    fn trim_front(&mut self) {
        let mut excess = self.bytes.saturating_sub(MAX_CONNECTION_LOG_REPLAY_BYTES);
        while excess > 0 {
            let Some(front) = self.chunks.front_mut() else {
                self.bytes = 0;
                return;
            };
            if excess >= front.len() {
                excess -= front.len();
                self.bytes -= front.len();
                self.chunks.pop_front();
                continue;
            }
            let mut remove = excess;
            while !front.is_char_boundary(remove) {
                remove += 1;
            }
            front.drain(..remove);
            self.bytes -= remove;
            excess = 0;
        }
    }
}

async fn run_blocking<T, F>(operation: F) -> Result<T, ConnectionLogReplayAdapterError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ConnectionLogReplayStoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            ConnectionLogReplayAdapterError::new(ConnectionLogReplayAdapterErrorCode::WorkerFailed)
        })?
        .map_err(map_store_error)
}

fn map_store_error(error: ConnectionLogReplayStoreError) -> ConnectionLogReplayAdapterError {
    let code = match error.code() {
        ConnectionLogReplayStoreErrorCode::InvalidInput => {
            ConnectionLogReplayAdapterErrorCode::InvalidInput
        }
        _ => ConnectionLogReplayAdapterErrorCode::StorageFailed,
    };
    ConnectionLogReplayAdapterError::new(code)
}

fn newest_utf8_suffix(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut start = value.len() - maximum;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    &value[start..]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    use netcatty_credentials::CredentialErrorCode;
    use netcatty_credentials::test_support::{
        CredentialOperation, FailureTiming, in_memory_master_key_store,
    };
    use netcatty_vault::{
        MAX_CONNECTION_LOG_REPLAY_BYTES, SavedConnectionLog, SavedConnectionLogHostOs,
        SavedConnectionLogProtocol,
    };
    use serde_json::json;

    use super::{
        BoundedReplayBuffer, ConnectionLogReplayAdapterErrorCode, ConnectionLogReplayManager,
        ConnectionLogReplayRuntime, ReadConnectionLogReplayRequest,
        connection_log_replay_command_error,
    };

    fn log(id: &str, session_id: &str) -> SavedConnectionLog {
        SavedConnectionLog {
            id: id.to_owned(),
            session_id: Some(session_id.to_owned()),
            host_id: "host-1".to_owned(),
            host_label: "Production".to_owned(),
            hostname: "server.example.test".to_owned(),
            username: "operator".to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            host_os: Some(SavedConnectionLogHostOs::Linux),
            host_distro: None,
            host_icon_mode: None,
            host_icon_id: None,
            host_icon_color_mode: None,
            host_icon_color: None,
            host_icon_color_custom: None,
            start_time: 1,
            end_time: None,
            local_username: "local-user".to_owned(),
            local_hostname: "workstation".to_owned(),
            saved: false,
            theme_id: None,
            font_size: None,
        }
    }

    fn blob_count(path: &std::path::Path) -> usize {
        fs::read_dir(path).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .map(|path| {
                    if path.is_dir() {
                        blob_count(&path)
                    } else {
                        usize::from(
                            path.extension().and_then(|value| value.to_str()) == Some("ncsb"),
                        )
                    }
                })
                .sum()
        })
    }

    #[test]
    fn request_is_strict_response_has_only_requested_record_and_debug_is_redacted() {
        let request: ReadConnectionLogReplayRequest = serde_json::from_value(json!({
            "logId": "private-log-id"
        }))
        .expect("strict request");
        assert!(!format!("{request:?}").contains("private-log-id"));
        assert!(
            serde_json::from_value::<ReadConnectionLogReplayRequest>(json!({
                "logId": "private-log-id",
                "includeCatalog": true
            }))
            .is_err()
        );
        let response = super::ReadConnectionLogReplayResponse {
            log_id: "private-log-id".to_owned(),
            terminal_data: "terminal-secret".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&response).expect("response JSON"),
            json!({"logId": "private-log-id", "terminalData": "terminal-secret"})
        );
        assert!(!format!("{response:?}").contains("terminal-secret"));
    }

    #[test]
    fn request_rejects_invalid_log_ids_with_one_fixed_error_before_store_use() {
        let maximum = format!("{}ab", "界".repeat(170));
        assert_eq!(maximum.len(), 512);
        let validated = ReadConnectionLogReplayRequest::new(maximum.clone())
            .into_log_id()
            .expect("512-byte UTF-8 ID");
        assert_eq!(validated, maximum);

        for invalid in [
            String::new(),
            "x".repeat(513),
            "界".repeat(171),
            "private\nlog-id".to_owned(),
        ] {
            let error = ReadConnectionLogReplayRequest::new(invalid.clone())
                .into_log_id()
                .expect_err("invalid ID");
            assert_eq!(
                error.code(),
                ConnectionLogReplayAdapterErrorCode::InvalidInput
            );
            let rendered = connection_log_replay_command_error(error);
            assert_eq!(
                rendered,
                "CONNECTION_LOG_REPLAY_INVALID: Connection-log replay request is invalid"
            );
            if !invalid.is_empty() {
                assert!(!rendered.contains(&invalid));
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_initialization_is_single_flight_and_runs_off_the_async_runtime_thread() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, _) = in_memory_master_key_store();
        let app_data_dir = directory.path().to_owned();
        let manager = tokio::task::spawn_blocking(move || {
            ConnectionLogReplayManager::open_with_master_key_store(app_data_dir, keys)
        })
        .await
        .expect("manager worker")
        .expect("test manager");
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_thread = Arc::new(Mutex::new(None));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let runtime = ConnectionLogReplayRuntime::with_opener({
            let calls = calls.clone();
            let worker_thread = worker_thread.clone();
            let release = release.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                *worker_thread.lock().expect("worker thread slot") = Some(thread::current().id());
                let (released, wake) = &*release;
                let mut released = released.lock().expect("release gate");
                while !*released {
                    released = wake.wait(released).expect("release wait");
                }
                Ok(manager.clone())
            }
        });
        let runtime_thread = thread::current().id();
        let release_thread = {
            let release = release.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                let (released, wake) = &*release;
                *released.lock().expect("release gate") = true;
                wake.notify_all();
            })
        };

        let first = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.manager().await })
        };
        let second = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.manager().await })
        };
        let (first, second) = tokio::join!(first, second);
        release_thread.join().expect("release worker");
        let first = first.expect("first task").expect("first manager");
        let second = second.expect("second task").expect("second manager");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_ne!(
            worker_thread
                .lock()
                .expect("worker thread slot")
                .expect("worker thread"),
            runtime_thread
        );
        assert!(Arc::ptr_eq(&first.store, &second.store));
        assert!(runtime.ready_manager().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_timeout_degrades_capture_without_canceling_or_restarting_initialization() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, _) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("test manager");
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                let (released, wake) = &*self.0;
                *released.lock().expect("release gate") = true;
                wake.notify_all();
            }
        }
        let release_on_drop = ReleaseOnDrop(release.clone());
        let runtime = ConnectionLogReplayRuntime::with_opener({
            let calls = calls.clone();
            let release = release.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                let (released, wake) = &*release;
                let mut released = released.lock().expect("release gate");
                while !*released {
                    released = wake.wait(released).expect("release wait");
                }
                Ok(manager.clone())
            }
        });
        runtime.start_initialization();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking opener must start");

        let first = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .manager_for_session_with_wait(Duration::from_millis(25))
                    .await
            })
        };
        let second = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .manager_for_session_with_wait(Duration::from_millis(25))
                    .await
            })
        };
        let first = first.await;
        let second = second.await;

        // More timed-out session starts join the already-running flight. They
        // must not create one blocking keyring/file-lock worker per session.
        let third = runtime
            .manager_for_session_with_wait(Duration::from_millis(25))
            .await;
        let calls_before_release = calls.load(Ordering::SeqCst);
        let ready_before_release = runtime.ready_manager().is_some();

        drop(release_on_drop);
        let initialized = tokio::time::timeout(Duration::from_secs(1), runtime.manager())
            .await
            .expect("detached initialization must continue after waiter timeout")
            .expect("initialized manager");
        assert!(first.expect("first waiter").is_none());
        assert!(second.expect("second waiter").is_none());
        assert!(third.is_none());
        assert_eq!(calls_before_release, 1);
        assert!(!ready_before_release);
        assert!(runtime.ready_manager().is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Once normal initialization completes, a later session gets the
        // exact ready manager and can begin capture without another open.
        let for_session = runtime
            .manager_for_session_with_wait(Duration::from_millis(25))
            .await
            .expect("ready session manager");
        assert!(Arc::ptr_eq(&initialized.store, &for_session.store));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn chunk_buffer_preserves_split_utf8_replaces_invalid_and_keeps_newest_suffix() {
        let mut buffer = BoundedReplayBuffer::default();
        let chinese = "日".as_bytes();
        buffer.append_bytes(&chinese[..1]);
        buffer.append_bytes(&chinese[1..]);
        buffer.append_bytes(&[0xff]);
        buffer.append_text(&"x".repeat(MAX_CONNECTION_LOG_REPLAY_BYTES));
        buffer.append_text("-newest-日");
        let value = buffer.snapshot();
        assert!(value.len() <= MAX_CONNECTION_LOG_REPLAY_BYTES);
        assert!(value.ends_with("-newest-日"));
        assert!(std::str::from_utf8(value.as_bytes()).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_capture_stays_in_memory_until_finish_then_reads_one_record() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, _) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("open manager");
        let metadata = log("log-private", "session-private");
        manager
            .begin_session("session-private".to_owned(), metadata)
            .expect("begin capture");
        let split = "你好".as_bytes();
        manager
            .append_session_bytes("session-private", &split[..2])
            .expect("first split");
        manager
            .append_session_bytes("session-private", &split[2..])
            .expect("second split");
        assert_eq!(blob_count(directory.path()), 0);
        manager
            .finish_session("session-private")
            .await
            .expect("finish capture");
        assert!(blob_count(directory.path()) >= 4);

        let request =
            serde_json::from_value(json!({"logId": "log-private"})).expect("read request");
        let response = manager.read_one(request).await.expect("read replay");
        assert_eq!(response.log_id(), "log-private");
        assert_eq!(response.terminal_data(), "你好");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_finish_retains_buffer_for_retry_and_errors_never_echo_ids_or_data() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, controller) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("open manager");
        manager
            .begin_session(
                "retry-session-private".to_owned(),
                log("retry-log-private", "retry-session-private"),
            )
            .expect("begin capture");
        manager
            .append_session_text("retry-session-private", "retry-terminal-secret")
            .expect("append capture");
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        let error = manager
            .finish_session("retry-session-private")
            .await
            .expect_err("finish fault");
        assert_eq!(
            error.code(),
            ConnectionLogReplayAdapterErrorCode::StorageFailed
        );
        let rendered = format!(
            "{error:?} {error} {}",
            connection_log_replay_command_error(error)
        );
        for forbidden in [
            "retry-session-private",
            "retry-log-private",
            "retry-terminal-secret",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        controller.clear_failures();
        manager
            .finish_session("retry-session-private")
            .await
            .expect("retry finish");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_finish_failures_then_recovery_persists_exact_replay_and_clears_active_capture() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, controller) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("open manager");
        manager
            .begin_session(
                "recovering-session".to_owned(),
                log("recovering-log", "recovering-session"),
            )
            .expect("begin capture");
        manager
            .append_session_text("recovering-session", "first-")
            .expect("append first chunk");
        manager
            .append_session_text("recovering-session", "second-secret")
            .expect("append second chunk");

        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        controller.add_failure(
            CredentialOperation::Resolve,
            2,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        for attempt in 1..=2 {
            let error = manager
                .finish_session("recovering-session")
                .await
                .expect_err("scheduled finish failure");
            assert_eq!(
                error.code(),
                ConnectionLogReplayAdapterErrorCode::StorageFailed,
                "attempt {attempt} must remain retryable"
            );
        }

        manager
            .finish_session("recovering-session")
            .await
            .expect("third finish recovers");
        assert!(
            !manager
                .discard_session("recovering-session")
                .expect("inspect active cleanup")
        );
        let response = manager
            .read_one(ReadConnectionLogReplayRequest::new(
                "recovering-log".to_owned(),
            ))
            .await
            .expect("read recovered replay");
        assert_eq!(response.log_id(), "recovering-log");
        assert_eq!(response.terminal_data(), "first-second-secret");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_catalog_reconcile_removes_deleted_replay() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, _) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("open manager");
        manager
            .begin_session(
                "delete-session".to_owned(),
                log("delete-log", "delete-session"),
            )
            .expect("begin capture");
        manager
            .append_session_text("delete-session", "delete-secret")
            .expect("append capture");
        manager
            .finish_session("delete-session")
            .await
            .expect("finish capture");
        manager
            .reconcile_catalog(Vec::new())
            .await
            .expect("reconcile deletion");
        let request = serde_json::from_value(json!({"logId": "delete-log"})).expect("read request");
        let response = manager.read_one(request).await.expect("read replay");
        assert_eq!(response.log_id(), "delete-log");
        assert_eq!(response.terminal_data(), "");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_finish_buffer_expires_when_caller_does_not_retry_or_discard() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let (keys, controller) = in_memory_master_key_store();
        let manager = tokio::task::block_in_place(|| {
            ConnectionLogReplayManager::open_with_master_key_store(directory.path(), keys)
        })
        .expect("open manager");
        manager
            .begin_session(
                "expiring-session".to_owned(),
                log("expiring-log", "expiring-session"),
            )
            .expect("begin capture");
        manager
            .append_session_text("expiring-session", "bounded-secret")
            .expect("append capture");
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        manager
            .finish_session("expiring-session")
            .await
            .expect_err("finish fault");
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let error = manager
            .append_session_text("expiring-session", "late")
            .expect_err("failed capture must expire");
        assert_eq!(
            error.code(),
            ConnectionLogReplayAdapterErrorCode::SessionMissing
        );
    }

    #[test]
    fn manager_is_send_sync_and_debug_is_redacted() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<ConnectionLogReplayManager>();
    }
}
