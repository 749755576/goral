use netcatty_local_pty::{
    CustomShellRegistration, DiscoveredShell, LocalPtyConfig, LocalPtyError, LocalPtyIoOperation,
    LocalPtyRequest, LocalPtyRuntimeEvent, LocalPtySessionId, MAX_INPUT_BYTES, ShellCatalog,
    ShellDiscoveryError,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::{Channel, InvokeBody, Request, Response};

use super::connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_started_connection_log,
};
use super::settings_catalog::LocalTerminalSettings;
use super::{
    DesktopState, connection_log_replay_manager_for_session, current_unix_millis,
    finalize_connection_log_replay, frame_data,
};

const LOCAL_PTY_SESSION_ID_BYTES: usize = 36;
const MAX_LOCAL_PTY_FRAME_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalPtyTerminalSize {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartedLocalPtySession {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum LocalPtyControlEvent {
    Connecting,
    Connected,
    Error { code: String, message: String },
    ExitStatus { status: u32 },
    Closed,
}

#[tauri::command]
pub(crate) fn list_local_shells(
    state: State<'_, DesktopState>,
) -> Result<Vec<DiscoveredShell>, String> {
    Ok(configured_shell_catalog(state.inner())?.shells().to_vec())
}

#[tauri::command]
pub(crate) async fn start_local_pty_session(
    state: State<'_, DesktopState>,
    request: LocalPtyRequest,
    on_control: Channel<LocalPtyControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedLocalPtySession, String> {
    let settings = state
        .settings
        .load()
        .ok()
        .map(|snapshot| snapshot.local_terminal_settings());
    let request = request.with_default_cwd(settings.as_ref().and_then(|settings| {
        (!settings.start_directory.is_empty()).then(|| settings.start_directory.clone())
    }));
    let catalog = configured_shell_catalog_with_settings(state.inner(), settings.as_ref())?;
    let config = LocalPtyConfig::resolve(&catalog, request)
        .map_err(|error| redacted_discovery_error(&error))?;
    let connection_log = catalog
        .get(config.shell_id())
        .map(|shell| ConnectionLogCapture::quick_local_named(shell.name()))
        .unwrap_or_else(ConnectionLogCapture::quick_local);
    begin_local_pty_session(state.inner(), config, connection_log, on_control, on_data).await
}

async fn begin_local_pty_session(
    state: &DesktopState,
    config: LocalPtyConfig,
    connection_log: ConnectionLogCapture,
    on_control: Channel<LocalPtyControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedLocalPtySession, String> {
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let runtime = state
        .local_pty_sessions
        .start(config)
        .map_err(redacted_runtime_error)?;
    let (session_id, events) = runtime.into_parts();
    let session_id_text = session_id.as_str().to_owned();

    forward_local_pty_events(
        state.clone(),
        session_id_text.clone(),
        events,
        connection_log,
        replay_manager,
        on_control,
        on_data,
    );

    Ok(StartedLocalPtySession {
        session_id: session_id_text,
    })
}

#[tauri::command]
pub(crate) fn local_pty_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("Local PTY input must use the raw IPC body".to_owned()),
    };
    let (session_id, input) = parse_input_envelope(bytes)?;
    state
        .local_pty_sessions
        .input(&session_id, input)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn resize_local_pty_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: LocalPtyTerminalSize,
) -> Result<(), String> {
    // Pixel dimensions remain part of the shared renderer envelope. Native
    // PTY backends resize by character cells, matching the legacy behavior.
    let _pixel_size = (size.pixel_width, size.pixel_height);
    let session_id = parse_session_id(&session_id)?;
    state
        .local_pty_sessions
        .resize(&session_id, size.columns, size.rows)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn close_local_pty_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .local_pty_sessions
        .close(&session_id)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn cancel_local_pty_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .local_pty_sessions
        .cancel(&session_id)
        .map_err(redacted_runtime_error)
}

fn available_shell_catalog(state: &DesktopState) -> Result<&ShellCatalog, String> {
    state
        .local_shells
        .as_ref()
        .as_ref()
        .map_err(redacted_discovery_error)
}

fn configured_shell_catalog(state: &DesktopState) -> Result<ShellCatalog, String> {
    let settings = state
        .settings
        .load()
        .ok()
        .map(|snapshot| snapshot.local_terminal_settings());
    configured_shell_catalog_with_settings(state, settings.as_ref())
}

fn configured_shell_catalog_with_settings(
    state: &DesktopState,
    settings: Option<&LocalTerminalSettings>,
) -> Result<ShellCatalog, String> {
    let discovered = available_shell_catalog(state)?.clone();
    let Some(settings) = settings else {
        return Ok(discovered);
    };
    if settings.shell.is_empty() {
        return Ok(discovered);
    }
    if settings.shell_args.is_empty() && discovered.get(&settings.shell).is_some() {
        return discovered
            .with_default_shell(&settings.shell)
            .map_err(|error| redacted_discovery_error(&error));
    }
    let Ok(custom) =
        CustomShellRegistration::new(settings.shell.clone(), settings.shell_args.clone())
    else {
        // A removed or temporarily unavailable configured executable must not
        // make every built-in shell unusable. Settings keeps the value so the
        // user can repair it, while Local Terminal safely falls back.
        return Ok(discovered);
    };
    discovered
        .with_custom_shell(custom)
        .map_err(|error| redacted_discovery_error(&error))
}

fn parse_session_id(value: &str) -> Result<LocalPtySessionId, String> {
    if value.len() != LOCAL_PTY_SESSION_ID_BYTES {
        return Err("Invalid Local PTY session ID".to_owned());
    }
    LocalPtySessionId::parse(value).map_err(|_| "Invalid Local PTY session ID".to_owned())
}

fn parse_input_envelope(bytes: &[u8]) -> Result<(LocalPtySessionId, &[u8]), String> {
    const HEADER_BYTES: usize = 2;
    const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + LOCAL_PTY_SESSION_ID_BYTES + MAX_INPUT_BYTES;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err("Local PTY input exceeds the session limit".to_owned());
    }
    let length = bytes
        .get(..HEADER_BYTES)
        .and_then(|header| <[u8; HEADER_BYTES]>::try_from(header).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| "Invalid Local PTY input envelope".to_owned())?;
    if length != LOCAL_PTY_SESSION_ID_BYTES {
        return Err("Invalid Local PTY session ID".to_owned());
    }
    let id_end = HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| "Invalid Local PTY input envelope".to_owned())?;
    let session_id = bytes
        .get(HEADER_BYTES..id_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "Invalid Local PTY session ID".to_owned())?;
    let input = bytes
        .get(id_end..)
        .ok_or_else(|| "Invalid Local PTY input envelope".to_owned())?;
    Ok((parse_session_id(session_id)?, input))
}

fn redacted_discovery_error(error: &ShellDiscoveryError) -> String {
    error.to_string()
}

fn redacted_runtime_error(error: LocalPtyError) -> String {
    error.to_string()
}

fn runtime_error_event(error: LocalPtyError) -> LocalPtyControlEvent {
    let code = match &error {
        LocalPtyError::Config(ShellDiscoveryError::NoShellsFound)
        | LocalPtyError::Config(ShellDiscoveryError::CustomShellUnavailable) => "shellUnavailable",
        LocalPtyError::Config(_)
        | LocalPtyError::InvalidSessionId
        | LocalPtyError::InputTooLarge { .. } => "invalidRequest",
        LocalPtyError::InputQueueFull { .. } | LocalPtyError::CommandQueueFull { .. } => {
            "inputBackpressure"
        }
        LocalPtyError::SessionNotFound => "sessionNotFound",
        LocalPtyError::SessionClosing => "sessionClosing",
        LocalPtyError::RuntimeThreadUnavailable => "runtimeUnavailable",
        LocalPtyError::BackendFailed {
            operation: LocalPtyIoOperation::Open | LocalPtyIoOperation::Spawn,
        } => "connectionFailed",
        LocalPtyError::BackendFailed { .. } | LocalPtyError::IoFailed { .. } => "transportError",
        LocalPtyError::FinalOutputDrainTimedOut { .. } => "drainTimeout",
        _ => "localPtyError",
    };
    LocalPtyControlEvent::Error {
        code: code.to_owned(),
        message: redacted_runtime_error(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn forward_local_pty_events(
    state: DesktopState,
    session_id: String,
    mut events: tokio::sync::mpsc::Receiver<LocalPtyRuntimeEvent>,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<super::connection_log_replay::ConnectionLogReplayManager>,
    on_control: Channel<LocalPtyControlEvent>,
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

        let mut pending = None;
        loop {
            let event = if let Some(event) = pending.take() {
                event
            } else {
                let Some(event) = events.recv().await else {
                    break;
                };
                event
            };
            let result = match event {
                LocalPtyRuntimeEvent::Starting => on_control.send(LocalPtyControlEvent::Connecting),
                LocalPtyRuntimeEvent::Started { .. } => {
                    on_control.send(LocalPtyControlEvent::Connected)
                }
                LocalPtyRuntimeEvent::Data(data) => {
                    let mut data = data.into_vec();
                    while data.len() < MAX_LOCAL_PTY_FRAME_BYTES {
                        match events.try_recv() {
                            Ok(LocalPtyRuntimeEvent::Data(next))
                                if data
                                    .len()
                                    .checked_add(next.len())
                                    .is_some_and(|length| length <= MAX_LOCAL_PTY_FRAME_BYTES) =>
                            {
                                data.extend_from_slice(next.as_slice());
                            }
                            Ok(event) => {
                                pending = Some(event);
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, &data);
                    }
                    on_data.send(Response::new(frame_data(0, None, data)))
                }
                LocalPtyRuntimeEvent::Error(error) => on_control.send(runtime_error_event(error)),
                LocalPtyRuntimeEvent::Exited(exit) => {
                    if let Some(status) = exit.exit_code()
                        && on_control
                            .send(LocalPtyControlEvent::ExitStatus { status })
                            .is_err()
                    {
                        break;
                    }
                    let _ = on_control.send(LocalPtyControlEvent::Closed);
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
    use netcatty_local_pty::{
        LocalPtyError, LocalPtyIoErrorKind, LocalPtyIoOperation, LocalPtyRequest, MAX_INPUT_BYTES,
    };
    use serde_json::json;

    use super::{
        LOCAL_PTY_SESSION_ID_BYTES, LocalPtyControlEvent, LocalPtyTerminalSize,
        parse_input_envelope, runtime_error_event,
    };

    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    #[test]
    fn start_and_resize_requests_are_strict_and_renderer_cannot_supply_a_command() {
        assert!(
            serde_json::from_value::<LocalPtyRequest>(json!({
                "shellId": "pwsh",
                "cwd": "C:\\work",
                "columns": 80,
                "rows": 24,
                "environment": { "term": "xterm-256color", "colorTerm": "truecolor" }
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<LocalPtyRequest>(json!({
                "command": "private-shell.exe",
                "columns": 80,
                "rows": 24
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<LocalPtyRequest>(json!({
                "columns": 80,
                "rows": 24,
                "environment": { "PATH": "renderer-owned" }
            }))
            .is_err()
        );

        let size: LocalPtyTerminalSize = serde_json::from_value(json!({
            "columns": 120,
            "rows": 40,
            "pixelWidth": 0,
            "pixelHeight": 0
        }))
        .expect("resize request");
        assert_eq!((size.columns, size.rows), (120, 40));
        assert!(
            serde_json::from_value::<LocalPtyTerminalSize>(json!({
                "columns": 120,
                "rows": 40,
                "untrusted": true
            }))
            .is_err()
        );
    }

    #[test]
    fn raw_input_envelope_is_canonical_and_bounded() {
        assert_eq!(SESSION_ID.len(), LOCAL_PTY_SESSION_ID_BYTES);
        let mut envelope = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        envelope.extend_from_slice(SESSION_ID.as_bytes());
        envelope.extend_from_slice(b"dir\r");
        let (id, input) = parse_input_envelope(&envelope).expect("valid envelope");
        assert_eq!(id.as_str(), SESSION_ID);
        assert_eq!(input, b"dir\r");

        let mut oversized = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        oversized.extend_from_slice(SESSION_ID.as_bytes());
        oversized.resize(2 + SESSION_ID.len() + MAX_INPUT_BYTES + 1, b'x');
        assert!(parse_input_envelope(&oversized).is_err());
        assert!(parse_input_envelope(&[]).is_err());
    }

    #[test]
    fn runtime_errors_and_control_events_are_renderer_safe() {
        let event = runtime_error_event(LocalPtyError::InputQueueFull {
            maximum_bytes: 256 * 1_024,
        });
        assert_eq!(
            event,
            LocalPtyControlEvent::Error {
                code: "inputBackpressure".to_owned(),
                message: "Local PTY queued input reached its 262144-byte limit".to_owned(),
            }
        );

        let marker = "private-native-path-sentinel";
        let event = runtime_error_event(LocalPtyError::IoFailed {
            operation: LocalPtyIoOperation::Read,
            kind: LocalPtyIoErrorKind::Other,
        });
        let encoded = serde_json::to_string(&event).expect("safe control event");
        assert!(encoded.contains("transportError"));
        assert!(!encoded.contains(marker));
        assert_eq!(
            serde_json::to_value(LocalPtyControlEvent::ExitStatus { status: 7 })
                .expect("exit status"),
            json!({ "type": "exitStatus", "status": 7 })
        );
    }
}
