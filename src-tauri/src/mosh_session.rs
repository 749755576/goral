use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use netcatty_mosh::{
    MAX_INPUT_FRAME_BYTES, MoshAction, MoshBackendOperation, MoshCloseReason, MoshError, MoshEvent,
    MoshIoTarget, MoshPhase, MoshSessionConfig, MoshSessionCore, MoshSessionId, MoshStartRequest,
    MoshWindowSize, TrustedMoshClient,
};
use netcatty_ssh::{
    DirectConnector, ResolvedSshEndpoint, ShellEvent, SshConnection, SshShell, TerminalSize,
};
use netcatty_vault::{SavedHostId, project_saved_host_connection};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeBody, Request, Response};
use tauri::{State, WebviewWindow};
use tokio::sync::mpsc;

use super::connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_started_connection_log,
};
use super::{
    ClientAttemptId, DesktopState, PreparedSavedHostSession, StartSavedHostSessionRequest,
    build_resolved_ssh_endpoint, confirm_current_saved_host_snapshot,
    connection_log_replay_manager_for_session, current_unix_millis, finalize_connection_log_replay,
    frame_data, load_connection_known_hosts, prepare_saved_host_session_operation,
    saved_host_invalid, saved_host_not_found, saved_host_repair_required,
    saved_host_revision_conflict, take_ephemeral_ssh_password, validate_connection,
};

const MOSH_SESSION_ID_BYTES: usize = 36;
const MAX_ACTIVE_MOSH_SESSIONS: usize = 64;
const MAX_COMMANDS: usize = 128;
const MAX_RUNTIME_EVENTS: usize = 256;
const MAX_NATIVE_IO_COMMANDS: usize = 128;
const MAX_NATIVE_PROCESS_EVENTS: usize = 128;
const NATIVE_READ_CHUNK_BYTES: usize = 64 * 1_024;
const MAX_VERSION_MANIFEST_BYTES: u64 = 64;
const MOSH_MINIMUM_VERSION: (u64, u64, u64) = (0, 1, 7);
const MOSH_UNAVAILABLE: &str =
    "MOSH_CLIENT_UNAVAILABLE: Bundled MoshCatty 0.1.7 or newer is unavailable";
const MOSH_PROXY_UNSUPPORTED: &str =
    "MOSH_PROXY_UNSUPPORTED: Mosh does not support this saved proxy configuration";
const MOSH_CHAIN_UNSUPPORTED: &str =
    "MOSH_JUMP_CHAIN_UNSUPPORTED: Mosh does not support saved jump-host chains";
const MOSH_NOT_ENABLED: &str = "MOSH_NOT_ENABLED: Mosh is not enabled for this saved SSH host";
const VIEWPORT_RESET: &[u8] = b"\x1b[2J\x1b[H";
const EXIT_MODE_RESET: &[u8] =
    b"\x1b[0m\x1b[?1l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MoshClientAvailabilityError {
    ResourceUnavailable,
    UnsupportedPlatform,
    InvalidVersion,
    InvalidClient,
}

impl fmt::Display for MoshClientAvailabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MOSH_UNAVAILABLE)
    }
}

impl std::error::Error for MoshClientAvailabilityError {}

pub(crate) fn resolve_trusted_mosh_client(
    resource_dir: &Path,
) -> Result<TrustedMoshClient, MoshClientAvailabilityError> {
    if !resource_dir.is_absolute() {
        return Err(MoshClientAvailabilityError::ResourceUnavailable);
    }
    let mosh_root = resource_dir.join("mosh");
    verify_packaged_version(&mosh_root.join("moshcatty.version"))?;
    let relative = platform_client_relative_path()?;
    let executable = mosh_root.join(relative);
    let metadata = std::fs::symlink_metadata(&executable)
        .map_err(|_| MoshClientAvailabilityError::ResourceUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(MoshClientAvailabilityError::InvalidClient);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(MoshClientAvailabilityError::InvalidClient);
        }
    }
    TrustedMoshClient::from_native_path(executable)
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)
}

fn verify_packaged_version(path: &Path) -> Result<(), MoshClientAvailabilityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| MoshClientAvailabilityError::ResourceUnavailable)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_VERSION_MANIFEST_BYTES {
        return Err(MoshClientAvailabilityError::InvalidVersion);
    }
    let value =
        std::fs::read_to_string(path).map_err(|_| MoshClientAvailabilityError::InvalidVersion)?;
    let version = parse_version(value.trim())?;
    if version < MOSH_MINIMUM_VERSION {
        return Err(MoshClientAvailabilityError::InvalidVersion);
    }
    Ok(())
}

fn parse_version(value: &str) -> Result<(u64, u64, u64), MoshClientAvailabilityError> {
    let mut parts = value.split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(MoshClientAvailabilityError::InvalidVersion)?;
    let minor = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(MoshClientAvailabilityError::InvalidVersion)?;
    let patch = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(MoshClientAvailabilityError::InvalidVersion)?;
    if parts.next().is_some() {
        return Err(MoshClientAvailabilityError::InvalidVersion);
    }
    Ok((major, minor, patch))
}

fn platform_client_relative_path() -> Result<PathBuf, MoshClientAvailabilityError> {
    #[cfg(target_os = "windows")]
    return Ok(PathBuf::from("mosh-client.exe"));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return Ok(PathBuf::from("mosh-client"));
    #[allow(unreachable_code)]
    Err(MoshClientAvailabilityError::UnsupportedPlatform)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MoshTerminalSize {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

impl MoshTerminalSize {
    fn validate(self) -> Result<Self, String> {
        MoshWindowSize::new(self.columns, self.rows).map_err(|error| error.to_string())?;
        Ok(self)
    }

    fn ssh_size(self) -> TerminalSize {
        TerminalSize {
            columns: self.columns,
            rows: self.rows,
            pixel_width: self.pixel_width,
            pixel_height: self.pixel_height,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartMoshSessionRequest {
    config: netcatty_ssh::SshConnectionConfig,
    credential_reference: netcatty_credentials::EphemeralCredentialReference,
    #[serde(default)]
    known_hosts: Vec<netcatty_ssh::KnownHost>,
    #[serde(default = "super::default_true")]
    verify_host_keys: bool,
    size: MoshTerminalSize,
}

impl fmt::Debug for StartMoshSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartMoshSessionRequest")
            .field("config", &"[redacted SSH endpoint]")
            .field("has_credential_reference", &true)
            .field("known_host_count", &self.known_hosts.len())
            .field("verify_host_keys", &self.verify_host_keys)
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartSavedMoshSessionRequest {
    host_id: String,
    expected_revision: u64,
    #[serde(default)]
    credential_reference: Option<netcatty_credentials::EphemeralCredentialReference>,
    #[serde(default)]
    proxy_credential_reference: Option<netcatty_credentials::EphemeralCredentialReference>,
    #[serde(default)]
    key_passphrase_reference: Option<netcatty_credentials::EphemeralCredentialReference>,
    #[serde(default)]
    selected_identity_file_paths: Vec<String>,
    #[serde(default)]
    known_hosts: Vec<netcatty_ssh::KnownHost>,
    #[serde(default = "super::default_true")]
    verify_host_keys: bool,
    size: MoshTerminalSize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartedMoshSession {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum MoshControlEvent {
    Connecting,
    Connected,
    Ready,
    Error { code: String, message: String },
    ExitStatus { status: u32 },
    Closed,
}

#[derive(Clone)]
pub(crate) struct MoshSessionManager {
    inner: Arc<MoshSessionManagerInner>,
}

struct MoshSessionManagerInner {
    sessions: Mutex<HashMap<String, MoshSessionEntry>>,
}

#[derive(Clone)]
struct MoshSessionEntry {
    generation: uuid::Uuid,
    commands: mpsc::Sender<SessionCommand>,
}

impl Default for MoshSessionManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(MoshSessionManagerInner {
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }
}

struct MoshSessionStart {
    session_id: String,
    events: mpsc::Receiver<MoshRuntimeEvent>,
}

enum SessionCommand {
    Input(Vec<u8>),
    Resize(MoshTerminalSize),
    Close,
    Cancel,
}

enum MoshRuntimeEvent {
    Connecting,
    Connected,
    Ready,
    Data(Vec<u8>),
    Error { code: String, message: String },
    Exited { status: Option<u32> },
}

impl MoshSessionManager {
    fn start(
        &self,
        client: TrustedMoshClient,
        endpoint: ResolvedSshEndpoint,
        size: MoshTerminalSize,
    ) -> Result<MoshSessionStart, String> {
        let size = size.validate()?;
        let config = MoshSessionConfig::resolve(
            client,
            MoshStartRequest::new(endpoint.config.hostname.clone(), size.columns, size.rows),
        )
        .map_err(|error| error.to_string())?;
        let core = MoshSessionCore::new(config);
        let session_id = core.session_id().as_str().to_owned();
        let generation = uuid::Uuid::new_v4();
        let (command_tx, command_rx) = mpsc::channel(MAX_COMMANDS);
        let (event_tx, event_rx) = mpsc::channel(MAX_RUNTIME_EVENTS);
        {
            let mut sessions =
                self.inner.sessions.lock().map_err(|_| {
                    "MOSH_RUNTIME_UNAVAILABLE: Mosh runtime is unavailable".to_owned()
                })?;
            if sessions.len() >= MAX_ACTIVE_MOSH_SESSIONS {
                return Err("MOSH_SESSION_LIMIT: Too many Mosh sessions are active".to_owned());
            }
            if sessions
                .insert(
                    session_id.clone(),
                    MoshSessionEntry {
                        generation,
                        commands: command_tx,
                    },
                )
                .is_some()
            {
                return Err("MOSH_RUNTIME_UNAVAILABLE: Duplicate Mosh session ID".to_owned());
            }
        }

        let manager = self.clone();
        let task_session_id = session_id.clone();
        tauri::async_runtime::spawn(async move {
            run_mosh_session(core, endpoint, size, command_rx, event_tx).await;
            manager.remove_exact(&task_session_id, generation);
        });

        Ok(MoshSessionStart {
            session_id,
            events: event_rx,
        })
    }

    fn input(&self, session_id: &MoshSessionId, input: &[u8]) -> Result<(), String> {
        if input.len() > MAX_INPUT_FRAME_BYTES {
            return Err(format!(
                "MOSH_INPUT_TOO_LARGE: Mosh input exceeds {MAX_INPUT_FRAME_BYTES} bytes"
            ));
        }
        self.send(session_id, SessionCommand::Input(input.to_vec()))
    }

    fn resize(&self, session_id: &MoshSessionId, size: MoshTerminalSize) -> Result<(), String> {
        self.send(session_id, SessionCommand::Resize(size.validate()?))
    }

    fn close(&self, session_id: &MoshSessionId) -> Result<(), String> {
        self.send(session_id, SessionCommand::Close)
    }

    fn cancel(&self, session_id: &MoshSessionId) -> Result<(), String> {
        self.send(session_id, SessionCommand::Cancel)
    }

    fn send(&self, session_id: &MoshSessionId, command: SessionCommand) -> Result<(), String> {
        let sender = self
            .inner
            .sessions
            .lock()
            .map_err(|_| "MOSH_RUNTIME_UNAVAILABLE: Mosh runtime is unavailable".to_owned())?
            .get(session_id.as_str())
            .map(|entry| entry.commands.clone())
            .ok_or_else(|| "MOSH_SESSION_NOT_FOUND: Mosh session was not found".to_owned())?;
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                "MOSH_INPUT_BACKPRESSURE: Mosh command queue is full".to_owned()
            }
            mpsc::error::TrySendError::Closed(_) => {
                "MOSH_SESSION_NOT_FOUND: Mosh session was not found".to_owned()
            }
        })
    }

    fn remove_exact(&self, session_id: &str, generation: uuid::Uuid) {
        let Ok(mut sessions) = self.inner.sessions.lock() else {
            return;
        };
        if sessions
            .get(session_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            sessions.remove(session_id);
        }
    }
}

#[tauri::command]
pub(crate) async fn start_mosh_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartMoshSessionRequest,
    on_control: Channel<MoshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedMoshSession, String> {
    let client = available_client(state.inner())?;
    let size = request.size.validate()?;
    let validation = validate_connection(request.config.clone());
    let normalized = validation.normalized.ok_or_else(|| {
        validation
            .errors
            .into_iter()
            .map(|issue| issue.message)
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    reject_unsupported_route(
        normalized.proxy.is_some(),
        !normalized.jump_hosts.is_empty(),
    )?;
    let credentials =
        take_ephemeral_ssh_password(state.inner(), window.label(), &request.credential_reference)
            .await?;
    let known_hosts = load_connection_known_hosts(state.inner(), request.known_hosts).await?;
    let client_attempt_id = ClientAttemptId::internal("mosh-quick");
    let endpoint = build_resolved_ssh_endpoint(
        &window,
        state.inner(),
        &client_attempt_id,
        request.config,
        credentials,
        known_hosts,
        request.verify_host_keys,
    )?;
    let connection_log =
        ConnectionLogCapture::quick_mosh(&endpoint.config.hostname, &endpoint.config.username);
    begin_mosh_session(
        state.inner(),
        client,
        endpoint,
        size,
        connection_log,
        on_control,
        on_data,
    )
    .await
}

#[tauri::command]
pub(crate) async fn start_saved_mosh_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartSavedMoshSessionRequest,
    on_control: Channel<MoshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedMoshSession, String> {
    let client = available_client(state.inner())?;
    let size = request.size.validate()?;
    let host_id =
        SavedHostId::from_opaque(request.host_id.clone()).map_err(|_| saved_host_invalid())?;
    if request.expected_revision == 0 {
        return Err(saved_host_invalid());
    }
    ensure_saved_mosh_enabled(state.inner(), &host_id, request.expected_revision).await?;

    let ssh_request = StartSavedHostSessionRequest {
        client_attempt_id: ClientAttemptId::internal("mosh-saved"),
        host_id: request.host_id,
        expected_revision: request.expected_revision,
        credential_reference: request.credential_reference,
        proxy_credential_reference: request.proxy_credential_reference,
        key_passphrase_reference: request.key_passphrase_reference,
        selected_identity_file_paths: request.selected_identity_file_paths,
        known_hosts: request.known_hosts,
        verify_host_keys: request.verify_host_keys,
        shell: None,
    };
    let owner = window.label().to_owned();
    let prepared =
        prepare_saved_host_session_operation(state.inner().clone(), owner, ssh_request).await?;
    begin_prepared_saved_mosh_session(
        &window,
        state.inner(),
        client,
        size,
        prepared,
        on_control,
        on_data,
    )
    .await
}

async fn ensure_saved_mosh_enabled(
    state: &DesktopState,
    host_id: &SavedHostId,
    expected_revision: u64,
) -> Result<(), String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let mut matches = snapshot
        .graph()
        .hosts()
        .iter()
        .filter(|host| &host.id == host_id);
    let host = matches.next().ok_or_else(saved_host_not_found)?;
    if matches.next().is_some() {
        return Err(saved_host_repair_required());
    }
    if host.revision != expected_revision {
        return Err(saved_host_revision_conflict());
    }
    let projection = project_saved_host_connection(host, snapshot.graph().groups())
        .map_err(|_| saved_host_repair_required())?;
    if !effective_mosh_enabled(projection.effective_host()) {
        return Err(MOSH_NOT_ENABLED.to_owned());
    }
    Ok(())
}

pub(crate) fn effective_mosh_enabled(host: &netcatty_vault::SavedHost) -> bool {
    host.protocol.is_ssh()
        && matches!(
            host.compatibility_fields().get("moshEnabled"),
            Some(serde_json::Value::Bool(true))
        )
}

fn available_client(state: &DesktopState) -> Result<TrustedMoshClient, String> {
    match state.mosh_client.as_ref().as_ref() {
        Ok(client) => Ok(client.clone()),
        Err(error) => Err(error.to_string()),
    }
}

fn reject_unsupported_route(has_proxy: bool, has_chain: bool) -> Result<(), String> {
    if has_chain {
        return Err(MOSH_CHAIN_UNSUPPORTED.to_owned());
    }
    if has_proxy {
        return Err(MOSH_PROXY_UNSUPPORTED.to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn begin_prepared_saved_mosh_session(
    window: &WebviewWindow,
    state: &DesktopState,
    client: TrustedMoshClient,
    size: MoshTerminalSize,
    prepared: PreparedSavedHostSession,
    on_control: Channel<MoshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedMoshSession, String> {
    let PreparedSavedHostSession {
        client_attempt_id,
        config,
        credentials,
        jump_hosts,
        known_hosts,
        verify_host_keys,
        shell: _,
        connection_log,
        effective_mosh_enabled,
    } = prepared;
    if !effective_mosh_enabled {
        return Err(MOSH_NOT_ENABLED.to_owned());
    }
    reject_unsupported_route(
        config.proxy.is_some(),
        !config.jump_hosts.is_empty() || !jump_hosts.is_empty(),
    )?;
    let endpoint = build_resolved_ssh_endpoint(
        window,
        state,
        &client_attempt_id,
        config,
        credentials,
        known_hosts,
        verify_host_keys,
    )?;
    begin_mosh_session(
        state,
        client,
        endpoint,
        size,
        connection_log.into_mosh(),
        on_control,
        on_data,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn begin_mosh_session(
    state: &DesktopState,
    client: TrustedMoshClient,
    endpoint: ResolvedSshEndpoint,
    size: MoshTerminalSize,
    connection_log: ConnectionLogCapture,
    on_control: Channel<MoshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedMoshSession, String> {
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let started = state.mosh_sessions.start(client, endpoint, size)?;
    let session_id = started.session_id.clone();
    forward_mosh_events(
        state.clone(),
        session_id.clone(),
        started.events,
        connection_log,
        replay_manager,
        on_control,
        on_data,
    );
    Ok(StartedMoshSession { session_id })
}

#[tauri::command]
pub(crate) fn mosh_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("Mosh input must use the raw IPC body".to_owned()),
    };
    let (session_id, input) = parse_input_envelope(bytes)?;
    state.mosh_sessions.input(&session_id, input)
}

#[tauri::command]
pub(crate) fn resize_mosh_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: MoshTerminalSize,
) -> Result<(), String> {
    state
        .mosh_sessions
        .resize(&parse_session_id(&session_id)?, size)
}

#[tauri::command]
pub(crate) fn close_mosh_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state.mosh_sessions.close(&parse_session_id(&session_id)?)
}

#[tauri::command]
pub(crate) fn cancel_mosh_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state.mosh_sessions.cancel(&parse_session_id(&session_id)?)
}

fn parse_session_id(value: &str) -> Result<MoshSessionId, String> {
    if value.len() != MOSH_SESSION_ID_BYTES {
        return Err("Invalid Mosh session ID".to_owned());
    }
    MoshSessionId::parse(value).map_err(|_| "Invalid Mosh session ID".to_owned())
}

fn parse_input_envelope(bytes: &[u8]) -> Result<(MoshSessionId, &[u8]), String> {
    const HEADER_BYTES: usize = 2;
    const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MOSH_SESSION_ID_BYTES + MAX_INPUT_FRAME_BYTES;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err("Mosh input exceeds the session limit".to_owned());
    }
    let length = bytes
        .get(..HEADER_BYTES)
        .and_then(|header| <[u8; HEADER_BYTES]>::try_from(header).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| "Invalid Mosh input envelope".to_owned())?;
    if length != MOSH_SESSION_ID_BYTES {
        return Err("Invalid Mosh session ID".to_owned());
    }
    let id_end = HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| "Invalid Mosh input envelope".to_owned())?;
    let session_id = bytes
        .get(HEADER_BYTES..id_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "Invalid Mosh session ID".to_owned())?;
    let input = bytes
        .get(id_end..)
        .ok_or_else(|| "Invalid Mosh input envelope".to_owned())?;
    Ok((parse_session_id(session_id)?, input))
}

async fn run_mosh_session(
    mut core: MoshSessionCore,
    endpoint: ResolvedSshEndpoint,
    initial_size: MoshTerminalSize,
    mut commands: mpsc::Receiver<SessionCommand>,
    events: mpsc::Sender<MoshRuntimeEvent>,
) {
    if !emit_core_events(&mut core, &events).await {
        return;
    }
    let connector = DirectConnector::new();
    let connect = connector.connect(
        &endpoint.config,
        &endpoint.auth,
        &endpoint.credentials,
        endpoint.verifier,
        endpoint.interactive,
    );
    tokio::pin!(connect);
    let connection = loop {
        tokio::select! {
            result = &mut connect => {
                match result {
                    Ok(connection) => break connection,
                    Err(_) if core.phase() == MoshPhase::Closing => {
                        let _ = core.on_handshake_exit(None, true);
                        let _ = emit_core_events(&mut core, &events).await;
                        return;
                    }
                    Err(_) => {
                        core.backend_failed(MoshBackendOperation::StartSshHandshake);
                        let _ = emit_core_events(&mut core, &events).await;
                        return;
                    }
                }
            }
            command = commands.recv() => {
                if !apply_command(&mut core, command) {
                    connector.cancel();
                }
                if core.phase() == MoshPhase::Closing {
                    connector.cancel();
                }
                if !emit_core_events(&mut core, &events).await {
                    connector.cancel();
                    return;
                }
            }
        }
    };

    if core.phase() == MoshPhase::Closing {
        let _ = connection.disconnect().await;
        let _ = core.on_handshake_exit(None, true);
        let _ = emit_core_events(&mut core, &events).await;
        return;
    }
    if events.send(MoshRuntimeEvent::Connected).await.is_err() {
        let _ = connection.disconnect().await;
        return;
    }
    let mut shell = match connection.open_mosh_server(initial_size.ssh_size()).await {
        Ok(shell) => shell,
        Err(_) => {
            core.backend_failed(MoshBackendOperation::StartSshHandshake);
            let _ = emit_core_events(&mut core, &events).await;
            let _ = connection.disconnect().await;
            return;
        }
    };
    if process_handshake(&mut core, &mut shell, &connection, &mut commands, &events)
        .await
        .is_err()
    {
        return;
    }
    if core.phase() == MoshPhase::Closed {
        return;
    }

    let Some(launch) = take_client_launch(&mut core) else {
        core.backend_failed(MoshBackendOperation::StartClient);
        let _ = emit_core_events(&mut core, &events).await;
        return;
    };
    let spawn = tokio::task::spawn_blocking(move || spawn_native_client(launch));
    tokio::pin!(spawn);
    let mut close_while_starting = false;
    let native = loop {
        tokio::select! {
            result = &mut spawn => {
                match result {
                    Ok(Ok(native)) => break Some(native),
                    _ => break None,
                }
            }
            command = commands.recv() => {
                apply_command(&mut core, command);
                if core.phase() == MoshPhase::Closing {
                    close_while_starting = true;
                }
                discard_unavailable_client_actions(&mut core);
                if !emit_core_events(&mut core, &events).await {
                    return;
                }
            }
        }
    };
    let Some(mut native) = native else {
        if core.phase() == MoshPhase::Closing {
            let _ = core.on_client_exit(None, true);
        } else {
            let _ = core.on_client_spawn_failed();
        }
        let _ = emit_core_events(&mut core, &events).await;
        return;
    };
    if close_while_starting || core.phase() == MoshPhase::Closing {
        native.terminate();
        let _ = core.on_client_exit(None, true);
        let _ = emit_core_events(&mut core, &events).await;
        return;
    }
    if core.on_client_started().is_err() {
        native.terminate();
        let _ = emit_core_events(&mut core, &events).await;
        return;
    }
    if !drain_client_actions(&mut core, &mut native) {
        core.backend_failed(MoshBackendOperation::StartClient);
        native.terminate();
    }
    if !emit_core_events(&mut core, &events).await {
        native.terminate();
        return;
    }

    loop {
        tokio::select! {
            command = commands.recv() => {
                apply_command(&mut core, command);
                if !drain_client_actions(&mut core, &mut native) {
                    core.backend_failed(MoshBackendOperation::Write);
                    native.terminate();
                }
                if !emit_core_events(&mut core, &events).await {
                    native.terminate();
                    return;
                }
                if core.phase() == MoshPhase::Closing {
                    native.terminate();
                    let _ = core.on_client_exit(None, true);
                    let _ = emit_core_events(&mut core, &events).await;
                    return;
                }
            }
            native_event = native.events.recv() => {
                match native_event {
                    Some(NativeProcessEvent::Output(data)) => {
                        if core.on_client_output(&data).is_err() {
                            native.terminate();
                        }
                    }
                    Some(NativeProcessEvent::Exited(status)) => {
                        let _ = core.on_client_exit(status.map(|value| value as i32), false);
                    }
                    Some(NativeProcessEvent::Failed(operation)) => {
                        core.backend_failed(operation);
                        native.terminate();
                    }
                    None => {
                        if core.phase() != MoshPhase::Closed {
                            core.backend_failed(MoshBackendOperation::Wait);
                        }
                    }
                }
                if !emit_core_events(&mut core, &events).await {
                    native.terminate();
                    return;
                }
                if core.phase() == MoshPhase::Closed {
                    return;
                }
            }
        }
    }
}

fn apply_command(core: &mut MoshSessionCore, command: Option<SessionCommand>) -> bool {
    let result = match command {
        Some(SessionCommand::Input(input)) => core.input(&input),
        Some(SessionCommand::Resize(size)) => core.resize(size.columns, size.rows),
        Some(SessionCommand::Close) => core.close(),
        Some(SessionCommand::Cancel) | None => core.cancel(),
    };
    result.is_ok()
}

async fn process_handshake(
    core: &mut MoshSessionCore,
    shell: &mut SshShell,
    connection: &SshConnection,
    commands: &mut mpsc::Receiver<SessionCommand>,
    events: &mpsc::Sender<MoshRuntimeEvent>,
) -> Result<(), ()> {
    let mut exit_status = None;
    loop {
        if !drain_handshake_actions(core, shell).await {
            core.backend_failed(MoshBackendOperation::Write);
        }
        if !emit_core_events(core, events).await {
            let _ = shell.close().await;
            let _ = connection.disconnect().await;
            return Err(());
        }
        if core.phase() == MoshPhase::Closing {
            let _ = shell.close().await;
            let _ = connection.disconnect().await;
            let _ = core.on_handshake_exit(exit_status, true);
            let _ = emit_core_events(core, events).await;
            return Err(());
        }
        if core.phase() == MoshPhase::Closed {
            let _ = shell.close().await;
            let _ = connection.disconnect().await;
            return Err(());
        }
        tokio::select! {
            command = commands.recv() => {
                apply_command(core, command);
            }
            event = shell.next_event() => {
                match event {
                    Ok(ShellEvent::Data(data))
                    | Ok(ShellEvent::ExtendedData { data, .. }) => {
                        if core.on_handshake_output(&data).is_err() {
                            let _ = shell.close().await;
                        }
                    }
                    Ok(ShellEvent::ExitStatus(status)) => {
                        exit_status = i32::try_from(status).ok();
                    }
                    Ok(ShellEvent::Eof) => {}
                    Ok(ShellEvent::Closed) => {
                        let _ = connection.disconnect().await;
                        let result = core.on_handshake_exit(exit_status, false);
                        let _ = emit_core_events(core, events).await;
                        return result.map_err(|_| ());
                    }
                    Err(_) => {
                        core.backend_failed(MoshBackendOperation::Wait);
                        let _ = emit_core_events(core, events).await;
                        let _ = connection.disconnect().await;
                        return Err(());
                    }
                }
            }
        }
    }
}

async fn drain_handshake_actions(core: &mut MoshSessionCore, shell: &SshShell) -> bool {
    while let Some(action) = core.pop_action() {
        let result = match action {
            MoshAction::Write {
                target: MoshIoTarget::SshHandshake,
                bytes,
            } => shell.write(bytes.as_slice()).await,
            MoshAction::Resize {
                target: MoshIoTarget::SshHandshake,
                size,
            } => {
                shell
                    .resize(TerminalSize {
                        columns: u32::from(size.columns()),
                        rows: u32::from(size.rows()),
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .await
            }
            MoshAction::Terminate {
                target: MoshIoTarget::SshHandshake,
                ..
            } => shell.close().await,
            other => {
                // StartClient and client-targeted actions are consumed only
                // after the SSH bootstrap has exited.
                return matches!(other, MoshAction::StartClient(_));
            }
        };
        if result.is_err() {
            return false;
        }
    }
    true
}

fn take_client_launch(core: &mut MoshSessionCore) -> Option<netcatty_mosh::MoshClientLaunch> {
    while let Some(action) = core.pop_action() {
        if let MoshAction::StartClient(launch) = action {
            return Some(launch);
        }
    }
    None
}

fn discard_unavailable_client_actions(core: &mut MoshSessionCore) {
    while core.pop_action().is_some() {}
}

fn drain_client_actions(core: &mut MoshSessionCore, native: &mut NativeClient) -> bool {
    while let Some(action) = core.pop_action() {
        let command = match action {
            MoshAction::Write {
                target: MoshIoTarget::MoshClient,
                bytes,
            } => NativeIoCommand::Write(bytes.into_vec()),
            MoshAction::Resize {
                target: MoshIoTarget::MoshClient,
                size,
            } => NativeIoCommand::Resize(to_pty_size(size)),
            MoshAction::Terminate {
                target: MoshIoTarget::MoshClient,
                reason,
            } => {
                let _reason: MoshCloseReason = reason;
                native.terminate();
                continue;
            }
            _ => return false,
        };
        if native.io.try_send(command).is_err() {
            return false;
        }
    }
    true
}

async fn emit_core_events(
    core: &mut MoshSessionCore,
    events: &mpsc::Sender<MoshRuntimeEvent>,
) -> bool {
    while let Some(event) = core.pop_event() {
        let runtime = match event {
            MoshEvent::PhaseChanged(MoshPhase::SshHandshake) => Some(MoshRuntimeEvent::Connecting),
            MoshEvent::Output(bytes) => Some(MoshRuntimeEvent::Data(bytes.into_vec())),
            MoshEvent::Ready => {
                if events
                    .send(MoshRuntimeEvent::Data(VIEWPORT_RESET.to_vec()))
                    .await
                    .is_err()
                {
                    return false;
                }
                Some(MoshRuntimeEvent::Ready)
            }
            MoshEvent::Error(error) => Some(MoshRuntimeEvent::Error {
                code: mosh_error_code(&error).to_owned(),
                message: error.to_string(),
            }),
            MoshEvent::Exited(exit) => Some(MoshRuntimeEvent::Exited {
                status: exit.exit_code().and_then(|value| u32::try_from(value).ok()),
            }),
            MoshEvent::PhaseChanged(_) | MoshEvent::HandshakeAccepted { .. } => None,
        };
        if let Some(runtime) = runtime
            && events.send(runtime).await.is_err()
        {
            return false;
        }
    }
    true
}

fn mosh_error_code(error: &MoshError) -> &'static str {
    match error {
        MoshError::InvalidSessionId | MoshError::InvalidConfiguration(_) => "invalidRequest",
        MoshError::InputTooLarge { .. }
        | MoshError::InputQueueFull { .. }
        | MoshError::TooManyPendingInputs { .. }
        | MoshError::ActionQueueFull { .. }
        | MoshError::EventQueueFull { .. }
        | MoshError::OutputQueueFull { .. } => "inputBackpressure",
        MoshError::Parser(_) | MoshError::MissingConnect => "handshakeFailed",
        MoshError::ClientStartFailed => "clientUnavailable",
        MoshError::SessionNotReady
        | MoshError::SessionClosing
        | MoshError::SessionClosed
        | MoshError::InvalidTransition => "sessionState",
        MoshError::OutputTooLarge { .. } | MoshError::BackendFailed { .. } => "transportError",
        _ => "moshError",
    }
}

struct NativeClient {
    io: std::sync::mpsc::SyncSender<NativeIoCommand>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    events: mpsc::Receiver<NativeProcessEvent>,
}

impl NativeClient {
    fn terminate(&mut self) {
        let _ = self.io.try_send(NativeIoCommand::Shutdown);
        let _ = self.killer.kill();
    }
}

enum NativeIoCommand {
    Write(Vec<u8>),
    Resize(PtySize),
    Shutdown,
}

enum NativeProcessEvent {
    Output(Vec<u8>),
    Exited(Option<u32>),
    Failed(MoshBackendOperation),
}

fn spawn_native_client(
    launch: netcatty_mosh::MoshClientLaunch,
) -> Result<NativeClient, MoshClientAvailabilityError> {
    let parts = launch.into_parts();
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(to_pty_size(parts.window_size))
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)?;
    let mut command = CommandBuilder::new(&parts.executable);
    command.arg(&parts.host);
    command.arg(parts.port.to_string());
    command.env("MOSH_KEY", parts.key.expose_secret());
    command.env("TERM", netcatty_mosh::MoshClientLaunchParts::TERM);
    command.env(
        "MOSH_NO_TERM_INIT",
        netcatty_mosh::MoshClientLaunchParts::MOSH_NO_TERM_INIT,
    );
    match parts.fallback_host {
        Some(fallback) => command.env("MOSH_FALLBACK_HOST", fallback),
        None => command.env_remove("MOSH_FALLBACK_HOST"),
    }
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)?;
    drop(pair.slave);
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)?;
    let killer = child.clone_killer();
    let (io_tx, io_rx) = std::sync::mpsc::sync_channel(MAX_NATIVE_IO_COMMANDS);
    let (event_tx, event_rx) = mpsc::channel(MAX_NATIVE_PROCESS_EVENTS);
    spawn_native_io_thread(pair.master, writer, io_rx, event_tx.clone());
    spawn_native_reader_thread(reader, event_tx.clone());
    std::thread::Builder::new()
        .name("netcatty-mosh-wait".to_owned())
        .spawn(move || {
            let event = match child.wait() {
                Ok(status) => NativeProcessEvent::Exited(Some(status.exit_code())),
                Err(_) => NativeProcessEvent::Failed(MoshBackendOperation::Wait),
            };
            let _ = event_tx.blocking_send(event);
        })
        .map_err(|_| MoshClientAvailabilityError::InvalidClient)?;
    Ok(NativeClient {
        io: io_tx,
        killer,
        events: event_rx,
    })
}

fn spawn_native_io_thread(
    master: Box<dyn MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    commands: std::sync::mpsc::Receiver<NativeIoCommand>,
    events: mpsc::Sender<NativeProcessEvent>,
) {
    let _ = std::thread::Builder::new()
        .name("netcatty-mosh-pty-io".to_owned())
        .spawn(move || {
            while let Ok(command) = commands.recv() {
                let result = match command {
                    NativeIoCommand::Write(bytes) => writer
                        .write_all(&bytes)
                        .and_then(|_| writer.flush())
                        .map_err(|_| MoshBackendOperation::Write),
                    NativeIoCommand::Resize(size) => master
                        .resize(size)
                        .map_err(|_| MoshBackendOperation::Resize),
                    NativeIoCommand::Shutdown => break,
                };
                if let Err(operation) = result {
                    let _ = events.blocking_send(NativeProcessEvent::Failed(operation));
                    break;
                }
            }
        });
}

fn spawn_native_reader_thread(
    mut reader: Box<dyn Read + Send>,
    events: mpsc::Sender<NativeProcessEvent>,
) {
    let _ = std::thread::Builder::new()
        .name("netcatty-mosh-pty-read".to_owned())
        .spawn(move || {
            let mut buffer = vec![0_u8; NATIVE_READ_CHUNK_BYTES];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        if events
                            .blocking_send(NativeProcessEvent::Output(buffer[..length].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = events
                            .blocking_send(NativeProcessEvent::Failed(MoshBackendOperation::Wait));
                        break;
                    }
                }
            }
        });
}

fn to_pty_size(size: MoshWindowSize) -> PtySize {
    PtySize {
        rows: size.rows(),
        cols: size.columns(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn forward_mosh_events(
    state: DesktopState,
    session_id: String,
    mut events: mpsc::Receiver<MoshRuntimeEvent>,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<super::connection_log_replay::ConnectionLogReplayManager>,
    on_control: Channel<MoshControlEvent>,
    on_data: Channel<Response>,
) {
    let captured_session_id = session_id;
    let started_log = current_unix_millis().ok().and_then(|start_time| {
        connection_log
            .into_started_log(&captured_session_id, start_time)
            .ok()
    });
    let captured_log_id = started_log.as_ref().map(|log| log.id.clone());
    let replay_capture = replay_manager.and_then(|replays| {
        let log = started_log.as_ref()?.clone();
        replays
            .begin_session(captured_session_id.clone(), log)
            .ok()?;
        Some(replays)
    });

    tauri::async_runtime::spawn(async move {
        let start_state = state.clone();
        let start_capture = tauri::async_runtime::spawn(async move {
            if let Some(log) = started_log {
                persist_started_connection_log(start_state, log)
                    .await
                    .is_ok()
            } else {
                false
            }
        });
        while let Some(event) = events.recv().await {
            let result = match event {
                MoshRuntimeEvent::Connecting => on_control.send(MoshControlEvent::Connecting),
                MoshRuntimeEvent::Connected => on_control.send(MoshControlEvent::Connected),
                MoshRuntimeEvent::Ready => on_control.send(MoshControlEvent::Ready),
                MoshRuntimeEvent::Data(data) => {
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, &data);
                    }
                    on_data.send(Response::new(frame_data(0, None, data)))
                }
                MoshRuntimeEvent::Error { code, message } => {
                    on_control.send(MoshControlEvent::Error { code, message })
                }
                MoshRuntimeEvent::Exited { status } => {
                    if let Some(status) = status
                        && on_control
                            .send(MoshControlEvent::ExitStatus { status })
                            .is_err()
                    {
                        break;
                    }
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, EXIT_MODE_RESET);
                    }
                    let _ =
                        on_data.send(Response::new(frame_data(0, None, EXIT_MODE_RESET.to_vec())));
                    let _ = on_control.send(MoshControlEvent::Closed);
                    break;
                }
            };
            if result.is_err() {
                break;
            }
        }

        let started_persisted = start_capture.await.unwrap_or(false);
        if !started_persisted {
            if let Some(replays) = replay_capture {
                let _ = replays.discard_session(&captured_session_id);
            }
            return;
        }
        let (Some(log_id), Ok(end_time)) = (captured_log_id, current_unix_millis()) else {
            if let Some(replays) = replay_capture {
                let _ = replays.discard_session(&captured_session_id);
            }
            return;
        };
        if let Some(replays) = replay_capture {
            finalize_connection_log_replay(state, replays, log_id, captured_session_id, end_time)
                .await;
        } else {
            let _ =
                persist_finished_connection_log(state, log_id, captured_session_id, end_time).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    #[test]
    fn version_floor_is_strict() {
        assert_eq!(parse_version("0.1.7").unwrap(), (0, 1, 7));
        assert!(parse_version("0.1.6").unwrap() < MOSH_MINIMUM_VERSION);
        assert!(parse_version("0.1.7-beta").is_err());
        assert!(parse_version("0.1").is_err());
    }

    #[test]
    fn quick_and_saved_requests_reject_renderer_launch_authority() {
        let quick = json!({
            "config": {
                "hostname": "example.test",
                "port": 22,
                "username": "operator",
                "auth": { "method": "password", "hasPassword": true }
            },
            "credentialReference": netcatty_credentials::EphemeralCredentialReference::new(),
            "size": { "columns": 80, "rows": 24 }
        });
        assert!(serde_json::from_value::<StartMoshSessionRequest>(quick.clone()).is_ok());
        for field in ["command", "moshClientPath", "moshKey", "environment"] {
            let mut invalid = quick.clone();
            invalid[field] = json!("renderer-owned");
            assert!(serde_json::from_value::<StartMoshSessionRequest>(invalid).is_err());
        }

        let saved = json!({
            "hostId": "saved-host",
            "expectedRevision": 1,
            "size": { "columns": 80, "rows": 24 }
        });
        assert!(serde_json::from_value::<StartSavedMoshSessionRequest>(saved.clone()).is_ok());
        let mut invalid = saved;
        invalid["shell"] = json!({ "command": "renderer-owned" });
        assert!(serde_json::from_value::<StartSavedMoshSessionRequest>(invalid).is_err());
    }

    #[test]
    fn raw_input_envelope_is_canonical_and_bounded() {
        let mut envelope = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        envelope.extend_from_slice(SESSION_ID.as_bytes());
        envelope.extend_from_slice(b"whoami\r");
        let (id, input) = parse_input_envelope(&envelope).unwrap();
        assert_eq!(id.as_str(), SESSION_ID);
        assert_eq!(input, b"whoami\r");
        envelope.resize(2 + SESSION_ID.len() + MAX_INPUT_FRAME_BYTES + 1, b'x');
        assert!(parse_input_envelope(&envelope).is_err());
    }

    #[test]
    fn route_rejection_is_explicit() {
        assert_eq!(
            reject_unsupported_route(false, true),
            Err(MOSH_CHAIN_UNSUPPORTED.to_owned())
        );
        assert_eq!(
            reject_unsupported_route(true, false),
            Err(MOSH_PROXY_UNSUPPORTED.to_owned())
        );
        assert!(reject_unsupported_route(false, false).is_ok());
    }
}
