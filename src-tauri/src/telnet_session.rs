use netcatty_credentials::EphemeralCredentialReference;
use netcatty_telnet::{
    MAX_INPUT_BYTES, TelnetCharset, TelnetRuntimeConfig, TelnetRuntimeError, TelnetRuntimeEvent,
    TelnetSessionId,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeBody, Request, Response};
use tauri::{State, WebviewWindow};

use super::connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_started_connection_log,
};
use super::{
    DesktopState, connection_log_replay_manager_for_session, current_unix_millis,
    finalize_connection_log_replay, frame_data,
};

const DEFAULT_TELNET_PORT: u16 = 23;
const DEFAULT_TERMINAL_TYPE: &str = "xterm-256color";
const MAX_CHARSET_NAME_BYTES: usize = 32;
const TELNET_SESSION_ID_BYTES: usize = 36;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartTelnetSessionRequest {
    hostname: String,
    #[serde(default = "default_telnet_port")]
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default = "default_terminal_type")]
    terminal: String,
    size: TelnetTerminalSize,
    #[serde(default)]
    charset: Option<String>,
    #[serde(default)]
    startup_command: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TelnetTerminalSize {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartedTelnetSession {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum TelnetControlEvent {
    Connecting,
    Connected,
    TelnetEchoMode { remote_echo: bool, local_echo: bool },
    Error { code: String, message: String },
    Closed,
}

#[tauri::command]
pub(crate) async fn start_telnet_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartTelnetSessionRequest,
    on_control: Channel<TelnetControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedTelnetSession, String> {
    // Validate every non-secret field before claiming the one-shot password,
    // so a renderer typo does not consume a credential that can still be used
    // for a corrected request.
    let effective_username = request.username.as_deref().unwrap_or("").to_owned();
    let mut config = build_runtime_config_without_password(&request)?;

    if let Some(reference) = request.credential_reference {
        let secret = state
            .ephemeral_credentials
            .take(window.label(), &reference)
            .await
            .map_err(|error| error.to_string())?;
        let password = secret
            .as_utf8()
            .map_err(|error| error.to_string())?
            .to_owned();
        config = config
            .with_password(password)
            .map_err(redacted_runtime_error)?;
    }

    let connection_log = ConnectionLogCapture::quick_telnet(&request.hostname, &effective_username);
    begin_telnet_session(state.inner(), config, connection_log, on_control, on_data).await
}

/// Starts a Telnet runtime from already validated, Rust-owned inputs.
///
/// SavedHost callers should resolve effective group defaults and credential
/// custody first, construct `TelnetRuntimeConfig` plus
/// `ConnectionLogCapture::saved_telnet`, and call this function directly.
/// They must not construct the renderer-facing Quick Connect request DTO.
pub(crate) async fn begin_telnet_session(
    state: &DesktopState,
    config: TelnetRuntimeConfig,
    connection_log: ConnectionLogCapture,
    on_control: Channel<TelnetControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedTelnetSession, String> {
    // Replay initialization is asynchronous and failure-tolerant, matching
    // SSH: it must never hold up or reject an otherwise valid Telnet session.
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let runtime = state
        .telnet_sessions
        .start(config)
        .map_err(redacted_runtime_error)?;
    let (session_id, events) = runtime.into_parts();
    let session_id_text = session_id.as_str().to_owned();

    forward_telnet_events(
        state.clone(),
        session_id_text.clone(),
        events,
        connection_log,
        replay_manager,
        on_control,
        on_data,
    );

    Ok(StartedTelnetSession {
        session_id: session_id_text,
    })
}

#[tauri::command]
pub(crate) fn telnet_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("Telnet input must use the raw IPC body".to_owned()),
    };
    let (session_id, input) = parse_input_envelope(bytes)?;
    state
        .telnet_sessions
        .input(&session_id, input)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn resize_telnet_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: TelnetTerminalSize,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .telnet_sessions
        .resize(&session_id, size.columns, size.rows)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn close_telnet_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .telnet_sessions
        .close(&session_id)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn cancel_telnet_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .telnet_sessions
        .cancel(&session_id)
        .map_err(redacted_runtime_error)
}

fn default_telnet_port() -> u16 {
    DEFAULT_TELNET_PORT
}

fn default_terminal_type() -> String {
    DEFAULT_TERMINAL_TYPE.to_owned()
}

fn build_runtime_config_without_password(
    request: &StartTelnetSessionRequest,
) -> Result<TelnetRuntimeConfig, String> {
    // Pixel dimensions are part of the shared renderer size envelope. Telnet
    // NAWS transmits character cells only, so retain but deliberately ignore
    // these two bounded integers.
    let _pixel_size = (request.size.pixel_width, request.size.pixel_height);
    let charset = parse_charset(request.charset.as_deref())?;
    let mut config = TelnetRuntimeConfig::new(
        request.hostname.clone(),
        request.port,
        request.size.columns,
        request.size.rows,
    )
    .map_err(redacted_runtime_error)?
    .with_terminal_type(&request.terminal)
    .map_err(redacted_runtime_error)?
    .with_charset(charset);

    if let Some(username) = request.username.as_ref() {
        config = config
            .with_username(username.clone())
            .map_err(redacted_runtime_error)?;
    }
    if let Some(startup_command) = request.startup_command.as_ref() {
        config = config
            .with_startup_command(startup_command.clone())
            .map_err(redacted_runtime_error)?;
    }
    Ok(config)
}

fn parse_charset(value: Option<&str>) -> Result<TelnetCharset, String> {
    let Some(value) = value else {
        return Ok(TelnetCharset::Utf8);
    };
    if value.is_empty()
        || value.len() > MAX_CHARSET_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("Telnet charset is invalid".to_owned());
    }
    Ok(TelnetCharset::parse_label(value))
}

fn parse_session_id(value: &str) -> Result<TelnetSessionId, String> {
    if value.len() != TELNET_SESSION_ID_BYTES {
        return Err("Invalid Telnet session ID".to_owned());
    }
    TelnetSessionId::parse(value).map_err(|_| "Invalid Telnet session ID".to_owned())
}

fn parse_input_envelope(bytes: &[u8]) -> Result<(TelnetSessionId, &[u8]), String> {
    const HEADER_BYTES: usize = 2;
    const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + TELNET_SESSION_ID_BYTES + MAX_INPUT_BYTES;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err("Telnet input exceeds the session limit".to_owned());
    }
    let length = bytes
        .get(..HEADER_BYTES)
        .and_then(|header| <[u8; HEADER_BYTES]>::try_from(header).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| "Invalid Telnet input envelope".to_owned())?;
    if length != TELNET_SESSION_ID_BYTES {
        return Err("Invalid Telnet session ID".to_owned());
    }
    let id_end = HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| "Invalid Telnet input envelope".to_owned())?;
    let session_id = bytes
        .get(HEADER_BYTES..id_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "Invalid Telnet session ID".to_owned())?;
    let input = bytes
        .get(id_end..)
        .ok_or_else(|| "Invalid Telnet input envelope".to_owned())?;
    Ok((parse_session_id(session_id)?, input))
}

fn redacted_runtime_error(error: TelnetRuntimeError) -> String {
    error.to_string()
}

fn runtime_error_event(error: TelnetRuntimeError) -> TelnetControlEvent {
    let code = match &error {
        TelnetRuntimeError::InvalidHostname { .. }
        | TelnetRuntimeError::InvalidSessionId
        | TelnetRuntimeError::InvalidPort
        | TelnetRuntimeError::StartupCommandTooLarge { .. } => "invalidRequest",
        TelnetRuntimeError::RuntimeUnavailable => "runtimeUnavailable",
        TelnetRuntimeError::SessionNotFound => "sessionNotFound",
        TelnetRuntimeError::SessionClosing => "sessionClosing",
        TelnetRuntimeError::CommandQueueFull { .. } => "inputBackpressure",
        TelnetRuntimeError::EventQueueFull { .. } => "outputBackpressure",
        TelnetRuntimeError::ConnectionTimeout { .. } => "connectionTimeout",
        TelnetRuntimeError::ConnectionFailed { .. } => "connectionFailed",
        TelnetRuntimeError::Protocol(_) => "protocolError",
        TelnetRuntimeError::Session(_) => "transportError",
        TelnetRuntimeError::AutoLogin(_) => "autoLoginError",
        _ => "telnetError",
    };
    TelnetControlEvent::Error {
        code: code.to_owned(),
        message: redacted_runtime_error(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn forward_telnet_events(
    state: DesktopState,
    session_id: String,
    mut events: tokio::sync::mpsc::Receiver<TelnetRuntimeEvent>,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<super::connection_log_replay::ConnectionLogReplayManager>,
    on_control: Channel<TelnetControlEvent>,
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

        // The legacy Telnet defaults before RFC 854 ECHO negotiation.
        let mut remote_echo = true;
        let mut local_echo = false;
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
                TelnetRuntimeEvent::Connecting => on_control.send(TelnetControlEvent::Connecting),
                TelnetRuntimeEvent::Connected => {
                    let connected = on_control.send(TelnetControlEvent::Connected);
                    if connected.is_ok() {
                        on_control.send(TelnetControlEvent::TelnetEchoMode {
                            remote_echo,
                            local_echo,
                        })
                    } else {
                        connected
                    }
                }
                TelnetRuntimeEvent::Data(data) => {
                    const MAX_FRAME_BYTES: usize = 64 * 1024;
                    let mut data = data.into_vec();
                    while data.len() < MAX_FRAME_BYTES {
                        match events.try_recv() {
                            Ok(TelnetRuntimeEvent::Data(next))
                                if data
                                    .len()
                                    .checked_add(next.len())
                                    .is_some_and(|length| length <= MAX_FRAME_BYTES) =>
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
                TelnetRuntimeEvent::RemoteEcho { enabled } => {
                    remote_echo = enabled;
                    on_control.send(TelnetControlEvent::TelnetEchoMode {
                        remote_echo,
                        local_echo,
                    })
                }
                TelnetRuntimeEvent::LocalEcho { enabled } => {
                    local_echo = enabled;
                    on_control.send(TelnetControlEvent::TelnetEchoMode {
                        remote_echo,
                        local_echo,
                    })
                }
                TelnetRuntimeEvent::AutoLoginCompleted
                | TelnetRuntimeEvent::AutoLoginCancelled
                | TelnetRuntimeEvent::AutoLoginTimedOut => {
                    // These are internal lifecycle notifications. The runtime
                    // has already sent a startup command exactly once on
                    // completion, and cancellation/timeout must not run it.
                    continue;
                }
                TelnetRuntimeEvent::Error(error) => on_control.send(runtime_error_event(error)),
                TelnetRuntimeEvent::Closed { .. } => {
                    let _ = on_control.send(TelnetControlEvent::Closed);
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
    use std::time::Duration;

    use netcatty_telnet::{
        MAX_INPUT_BYTES, TelnetCharset, TelnetRuntimeConfig, TelnetRuntimeError, command, option,
    };
    use netcatty_vault::SavedConnectionLogProtocol;
    use serde_json::json;
    use tauri::ipc::{Channel, InvokeResponseBody};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::{
        ConnectionLogCapture, DEFAULT_TELNET_PORT, StartTelnetSessionRequest, TelnetControlEvent,
        forward_telnet_events, parse_charset, parse_input_envelope, parse_session_id,
        runtime_error_event,
    };
    use crate::DesktopState;

    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    async fn recv_ipc(
        receiver: &mut mpsc::UnboundedReceiver<InvokeResponseBody>,
    ) -> InvokeResponseBody {
        timeout(TEST_TIMEOUT, receiver.recv())
            .await
            .expect("desktop bridge event timeout")
            .expect("desktop bridge channel closed")
    }

    async fn recv_control(
        receiver: &mut mpsc::UnboundedReceiver<InvokeResponseBody>,
    ) -> serde_json::Value {
        match recv_ipc(receiver).await {
            InvokeResponseBody::Json(value) => {
                serde_json::from_str(&value).expect("control event JSON")
            }
            InvokeResponseBody::Raw(_) => panic!("control event must use JSON"),
        }
    }

    #[test]
    fn request_defaults_match_quick_connect_and_preserve_omission() {
        let request: StartTelnetSessionRequest = serde_json::from_value(json!({
            "hostname": "switch.example.test",
            "size": { "columns": 80, "rows": 24, "pixelWidth": 0, "pixelHeight": 0 }
        }))
        .expect("request");
        assert_eq!(request.port, DEFAULT_TELNET_PORT);
        assert!(request.username.is_none());
        assert!(request.credential_reference.is_none());
        assert_eq!(request.terminal, "xterm-256color");
        assert!(request.charset.is_none());
        assert!(request.startup_command.is_none());

        let explicit_empty: StartTelnetSessionRequest = serde_json::from_value(json!({
            "hostname": "switch.example.test",
            "username": "",
            "charset": "UTF-8",
            "size": { "columns": 80, "rows": 24 }
        }))
        .expect("explicit empty username");
        assert_eq!(explicit_empty.username.as_deref(), Some(""));
        assert!(parse_charset(explicit_empty.charset.as_deref()).is_ok());
    }

    #[test]
    fn request_rejects_unknown_fields_and_out_of_range_ports() {
        let unknown = json!({
            "hostname": "switch.example.test",
            "size": { "columns": 80, "rows": 24 },
            "password": "must-never-enter-json"
        });
        assert!(serde_json::from_value::<StartTelnetSessionRequest>(unknown).is_err());
        let bad_port = json!({
            "hostname": "switch.example.test",
            "port": 65536,
            "size": { "columns": 80, "rows": 24 }
        });
        assert!(serde_json::from_value::<StartTelnetSessionRequest>(bad_port).is_err());
        let unknown_size = json!({
            "hostname": "switch.example.test",
            "size": { "columns": 80, "rows": 24, "secretPixels": 1 }
        });
        assert!(serde_json::from_value::<StartTelnetSessionRequest>(unknown_size).is_err());
    }

    #[test]
    fn raw_input_envelope_is_canonical_and_bounded() {
        let mut envelope = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        envelope.extend_from_slice(SESSION_ID.as_bytes());
        envelope.extend_from_slice(b"show version\r");
        let (id, input) = parse_input_envelope(&envelope).expect("valid envelope");
        assert_eq!(id.as_str(), SESSION_ID);
        assert_eq!(input, b"show version\r");

        let upper = SESSION_ID.to_uppercase();
        let mut noncanonical = Vec::from((upper.len() as u16).to_be_bytes());
        noncanonical.extend_from_slice(upper.as_bytes());
        assert!(parse_input_envelope(&noncanonical).is_err());
        assert!(parse_input_envelope(&[]).is_err());
        assert!(parse_input_envelope(&[0, 0]).is_err());

        let mut oversized = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        oversized.extend_from_slice(SESSION_ID.as_bytes());
        oversized.resize(2 + SESSION_ID.len() + MAX_INPUT_BYTES + 1, b'x');
        assert!(parse_input_envelope(&oversized).is_err());
    }

    #[test]
    fn session_and_charset_validation_do_not_echo_attacker_input() {
        let session_marker = "private-session-marker\n";
        let charset_marker = "private-charset-marker";
        let session_error = parse_session_id(session_marker).expect_err("invalid session");
        assert!(!session_error.contains(session_marker));
        assert_eq!(
            parse_charset(Some(charset_marker)).unwrap(),
            TelnetCharset::Utf8
        );
        assert_eq!(
            parse_charset(Some("zh_CN.GBK")).unwrap(),
            TelnetCharset::Gb18030
        );
        assert_eq!(
            parse_charset(Some("utf-16le")).unwrap(),
            TelnetCharset::Utf8
        );
        assert!(parse_charset(Some(&"x".repeat(33))).is_err());
        assert!(parse_charset(Some("gbk\nprivate")).is_err());
    }

    #[test]
    fn runtime_errors_map_to_renderer_safe_control_events() {
        let marker = "private-host-or-secret-marker";
        let event = runtime_error_event(TelnetRuntimeError::InvalidHostname {
            maximum_bytes: marker.len(),
        });
        let json = serde_json::to_string(&event).expect("event JSON");
        assert_eq!(
            event,
            TelnetControlEvent::Error {
                code: "invalidRequest".to_owned(),
                message: format!(
                    "Telnet hostname is invalid or exceeds {} bytes",
                    marker.len()
                ),
            }
        );
        assert!(!json.contains(marker));

        assert_eq!(
            serde_json::to_value(TelnetControlEvent::TelnetEchoMode {
                remote_echo: true,
                local_echo: false,
            })
            .expect("echo JSON"),
            json!({ "type": "telnetEchoMode", "remoteEcho": true, "localEcho": false })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_runtime_crosses_desktop_channels_and_finishes_telnet_log() {
        let temporary = tempfile::Builder::new()
            .prefix("netcatty-telnet-desktop-")
            .tempdir()
            .expect("temporary test directory");
        let state = DesktopState::open(temporary.path()).expect("desktop state");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");

        let runtime = state
            .telnet_sessions
            .start(
                TelnetRuntimeConfig::new("127.0.0.1", address.port(), 80, 24)
                    .expect("runtime config"),
            )
            .expect("runtime start");
        let (session_id, events) = runtime.into_parts();
        let session_id_text = session_id.as_str().to_owned();

        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let on_control = Channel::<TelnetControlEvent>::new(move |body| {
            let _ = control_tx.send(body);
            Ok(())
        });
        let (data_tx, mut data_rx) = mpsc::unbounded_channel();
        let on_data = Channel::<tauri::ipc::Response>::new(move |body| {
            let _ = data_tx.send(body);
            Ok(())
        });
        forward_telnet_events(
            state.clone(),
            session_id_text.clone(),
            events,
            ConnectionLogCapture::quick_telnet("127.0.0.1", "operator"),
            None,
            on_control,
            on_data,
        );

        let (mut server, _) = timeout(TEST_TIMEOUT, listener.accept())
            .await
            .expect("loopback accept timeout")
            .expect("loopback accept");
        assert_eq!(
            recv_control(&mut control_rx).await,
            json!({ "type": "connecting" })
        );
        assert_eq!(
            recv_control(&mut control_rx).await,
            json!({ "type": "connected" })
        );
        assert_eq!(
            recv_control(&mut control_rx).await,
            json!({ "type": "telnetEchoMode", "remoteEcho": true, "localEcho": false })
        );

        server
            .write_all(&[
                command::IAC,
                command::WILL,
                option::ECHO,
                b'r',
                b'e',
                b'a',
                b'd',
                b'y',
            ])
            .await
            .expect("server negotiation and data");
        let mut negotiation = [0_u8; 12];
        timeout(TEST_TIMEOUT, server.read_exact(&mut negotiation))
            .await
            .expect("echo acknowledgement timeout")
            .expect("echo acknowledgement");
        assert!(
            negotiation
                .chunks_exact(3)
                .any(|reply| reply == [command::IAC, command::DO, option::ECHO])
        );
        assert_eq!(
            recv_control(&mut control_rx).await,
            json!({ "type": "telnetEchoMode", "remoteEcho": true, "localEcho": false })
        );
        match recv_ipc(&mut data_rx).await {
            InvokeResponseBody::Raw(frame) => assert_eq!(frame, b"\0ready"),
            InvokeResponseBody::Json(_) => panic!("terminal frame must use raw IPC"),
        }

        state
            .telnet_sessions
            .input(&session_id, b"whoami\r")
            .expect("queue terminal input");
        let mut input = [0_u8; 8];
        timeout(TEST_TIMEOUT, server.read_exact(&mut input))
            .await
            .expect("terminal input timeout")
            .expect("terminal input");
        assert_eq!(&input, b"whoami\r\n");

        state
            .telnet_sessions
            .close(&session_id)
            .expect("close runtime");
        assert_eq!(
            recv_control(&mut control_rx).await,
            json!({ "type": "closed" })
        );
        let mut eof = [0_u8; 1];
        assert_eq!(
            timeout(TEST_TIMEOUT, server.read(&mut eof))
                .await
                .expect("server EOF timeout")
                .expect("server EOF"),
            0
        );

        timeout(TEST_TIMEOUT, async {
            loop {
                let catalog = state
                    .saved_hosts
                    .connection_log_catalog()
                    .expect("connection log catalog");
                if let Some(log) = catalog
                    .logs()
                    .iter()
                    .find(|log| log.session_id.as_deref() == Some(session_id_text.as_str()))
                {
                    if log.end_time.is_some() {
                        assert_eq!(log.protocol, SavedConnectionLogProtocol::Telnet);
                        assert_eq!(log.hostname, "127.0.0.1");
                        assert_eq!(log.username, "operator");
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finished Telnet connection log timeout");
    }
}
