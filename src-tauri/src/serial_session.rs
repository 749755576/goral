use netcatty_serial::{
    MAX_INPUT_BYTES, SerialCharset, SerialConfig, SerialPortInfo, SerialRuntimeConfig,
    SerialRuntimeError, SerialRuntimeEvent, SerialSessionId, ZmodemTransferDirection,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::{Channel, InvokeBody, Request, Response};

use super::connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_started_connection_log,
};
use super::{
    DesktopState, connection_log_replay_manager_for_session, current_unix_millis,
    finalize_connection_log_replay, frame_data,
};

const MAX_CHARSET_NAME_BYTES: usize = 32;
const SERIAL_SESSION_ID_BYTES: usize = 36;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartSerialSessionRequest {
    config: SerialConfig,
    size: SerialTerminalSize,
    #[serde(default)]
    charset: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SerialTerminalSize {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartedSerialSession {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum SerialControlEvent {
    Connecting,
    Connected,
    SerialZmodemDetected {
        session_id: String,
        transfer_id: String,
        direction: SerialZmodemDirection,
    },
    SerialZmodemProgress {
        session_id: String,
        transfer_id: String,
        direction: SerialZmodemDirection,
        stage: SerialZmodemProgressStage,
        transferred_bytes: u64,
        total_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_name: Option<String>,
        file_index: usize,
        file_count: usize,
    },
    SerialZmodemCompleted {
        session_id: String,
        transfer_id: String,
        direction: SerialZmodemDirection,
        file_count: usize,
        skipped_files: usize,
        total_bytes: u64,
        transferred_bytes: u64,
    },
    SerialZmodemCanceled {
        session_id: String,
        transfer_id: String,
        direction: SerialZmodemDirection,
    },
    SerialZmodemError {
        session_id: String,
        transfer_id: String,
        direction: SerialZmodemDirection,
        code: String,
        message: String,
    },
    Error {
        code: String,
        message: String,
    },
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SerialZmodemDirection {
    Send,
    Receive,
}

impl From<ZmodemTransferDirection> for SerialZmodemDirection {
    fn from(value: ZmodemTransferDirection) -> Self {
        match value {
            ZmodemTransferDirection::Send => Self::Send,
            ZmodemTransferDirection::Receive => Self::Receive,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SerialZmodemProgressStage {
    Header,
    Data,
    Finalizing,
    Complete,
}

#[tauri::command]
pub(crate) async fn list_serial_ports() -> Result<Vec<SerialPortInfo>, String> {
    netcatty_serial::list_serial_ports_async()
        .await
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) async fn start_serial_session(
    state: State<'_, DesktopState>,
    request: StartSerialSessionRequest,
    on_control: Channel<SerialControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSerialSession, String> {
    let path = request.config.path.clone();
    let config = build_runtime_config(request.config, request.size, request.charset.as_deref())?;
    begin_serial_session(
        state.inner(),
        config,
        ConnectionLogCapture::quick_serial(&path),
        on_control,
        on_data,
    )
    .await
}

/// Starts a Serial runtime from validated Rust-owned inputs. SavedHost callers
/// resolve the durable Serial config and effective Group charset first, then
/// enter through this boundary instead of rebuilding the renderer request.
pub(crate) async fn begin_serial_session(
    state: &DesktopState,
    config: SerialRuntimeConfig,
    connection_log: ConnectionLogCapture,
    on_control: Channel<SerialControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSerialSession, String> {
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let runtime = state
        .serial_sessions
        .start(config)
        .map_err(redacted_runtime_error)?;
    let (session_id, events) = runtime.into_parts();
    let session_id_text = session_id.as_str().to_owned();

    forward_serial_events(
        state.clone(),
        session_id_text.clone(),
        events,
        connection_log,
        replay_manager,
        on_control,
        on_data,
    );

    Ok(StartedSerialSession {
        session_id: session_id_text,
    })
}

#[tauri::command]
pub(crate) fn serial_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("Serial input must use the raw IPC body".to_owned()),
    };
    let (session_id, input) = parse_input_envelope(bytes)?;
    state
        .serial_sessions
        .input(&session_id, input)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn resize_serial_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: SerialTerminalSize,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .serial_sessions
        .resize(&session_id, size.columns, size.rows)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn close_serial_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .serial_sessions
        .close(&session_id)
        .map_err(redacted_runtime_error)
}

#[tauri::command]
pub(crate) fn cancel_serial_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_session_id(&session_id)?;
    state
        .serial_sessions
        .cancel(&session_id)
        .map_err(redacted_runtime_error)
}

pub(crate) fn build_runtime_config(
    config: SerialConfig,
    size: SerialTerminalSize,
    charset: Option<&str>,
) -> Result<SerialRuntimeConfig, String> {
    // Pixel dimensions share the renderer's terminal envelope but Serial has
    // no resize protocol. Character cells are retained by the runtime only.
    let _pixel_size = (size.pixel_width, size.pixel_height);
    Ok(SerialRuntimeConfig::new(config, size.columns, size.rows)
        .map_err(redacted_runtime_error)?
        .with_charset(parse_charset(charset)?))
}

fn parse_charset(value: Option<&str>) -> Result<SerialCharset, String> {
    let Some(value) = value else {
        return Ok(SerialCharset::Utf8);
    };
    if value.is_empty()
        || value.len() > MAX_CHARSET_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("Serial charset is invalid".to_owned());
    }
    Ok(SerialCharset::parse_label(value))
}

fn parse_session_id(value: &str) -> Result<SerialSessionId, String> {
    if value.len() != SERIAL_SESSION_ID_BYTES {
        return Err("Invalid Serial session ID".to_owned());
    }
    SerialSessionId::parse(value).map_err(|_| "Invalid Serial session ID".to_owned())
}

fn parse_input_envelope(bytes: &[u8]) -> Result<(SerialSessionId, &[u8]), String> {
    const HEADER_BYTES: usize = 2;
    const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + SERIAL_SESSION_ID_BYTES + MAX_INPUT_BYTES;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err("Serial input exceeds the session limit".to_owned());
    }
    let length = bytes
        .get(..HEADER_BYTES)
        .and_then(|header| <[u8; HEADER_BYTES]>::try_from(header).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| "Invalid Serial input envelope".to_owned())?;
    if length != SERIAL_SESSION_ID_BYTES {
        return Err("Invalid Serial session ID".to_owned());
    }
    let id_end = HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| "Invalid Serial input envelope".to_owned())?;
    let session_id = bytes
        .get(HEADER_BYTES..id_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "Invalid Serial session ID".to_owned())?;
    let input = bytes
        .get(id_end..)
        .ok_or_else(|| "Invalid Serial input envelope".to_owned())?;
    Ok((parse_session_id(session_id)?, input))
}

fn redacted_runtime_error(error: SerialRuntimeError) -> String {
    error.to_string()
}

fn runtime_error_event(error: SerialRuntimeError) -> SerialControlEvent {
    let code = match &error {
        SerialRuntimeError::Config(_)
        | SerialRuntimeError::InvalidSessionId
        | SerialRuntimeError::InvalidWindowSize { .. }
        | SerialRuntimeError::InputTooLarge { .. }
        | SerialRuntimeError::InvalidInputEncoding
        | SerialRuntimeError::EncodedInputTooLarge { .. } => "invalidRequest",
        SerialRuntimeError::RuntimeUnavailable | SerialRuntimeError::RuntimeTaskFailed { .. } => {
            "runtimeUnavailable"
        }
        SerialRuntimeError::SessionNotFound => "sessionNotFound",
        SerialRuntimeError::SessionClosing => "sessionClosing",
        SerialRuntimeError::CommandQueueFull { .. } => "inputBackpressure",
        SerialRuntimeError::EventQueueFull { .. }
        | SerialRuntimeError::EventDataTooLarge { .. } => "outputBackpressure",
        SerialRuntimeError::OpenTimeout { .. } => "connectionTimeout",
        SerialRuntimeError::ConnectionFailed { .. } => "connectionFailed",
        SerialRuntimeError::IoFailed { .. } => "transportError",
        SerialRuntimeError::PortInventoryTooLarge { .. }
        | SerialRuntimeError::InvalidPortMetadata { .. } => "enumerationFailed",
        _ => "serialError",
    };
    SerialControlEvent::Error {
        code: code.to_owned(),
        message: redacted_runtime_error(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn forward_serial_events(
    state: DesktopState,
    session_id: String,
    mut events: tokio::sync::mpsc::Receiver<SerialRuntimeEvent>,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<super::connection_log_replay::ConnectionLogReplayManager>,
    on_control: Channel<SerialControlEvent>,
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
                SerialRuntimeEvent::Connecting => on_control.send(SerialControlEvent::Connecting),
                SerialRuntimeEvent::Connected => on_control.send(SerialControlEvent::Connected),
                SerialRuntimeEvent::Data(data) => {
                    const MAX_FRAME_BYTES: usize = 64 * 1024;
                    let mut data = data.into_vec();
                    while data.len() < MAX_FRAME_BYTES {
                        match events.try_recv() {
                            Ok(SerialRuntimeEvent::Data(next))
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
                SerialRuntimeEvent::ZmodemDetected {
                    transfer_id,
                    direction,
                } => on_control.send(SerialControlEvent::SerialZmodemDetected {
                    session_id: captured_session_id.clone(),
                    transfer_id: transfer_id.as_str().to_owned(),
                    direction: direction.into(),
                }),
                SerialRuntimeEvent::Error(error) => on_control.send(runtime_error_event(error)),
                SerialRuntimeEvent::Closed { .. } => {
                    let _ = on_control.send(SerialControlEvent::Closed);
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
    use netcatty_serial::{MAX_INPUT_BYTES, SerialConfigError, SerialRuntimeError, SerialStopBits};
    use serde_json::json;

    use super::{
        SERIAL_SESSION_ID_BYTES, SerialControlEvent, StartSerialSessionRequest, parse_charset,
        parse_input_envelope, runtime_error_event,
    };

    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    #[test]
    fn request_defaults_match_legacy_serial_and_reject_unknown_fields() {
        let request: StartSerialSessionRequest = serde_json::from_value(json!({
            "config": { "path": "COM3" },
            "size": { "columns": 80, "rows": 24 }
        }))
        .expect("Serial request");
        assert_eq!(request.config.baud_rate, 115_200);
        assert_eq!(request.config.data_bits.value(), 8);
        assert_eq!(request.config.stop_bits, SerialStopBits::One);
        assert!(request.charset.is_none());

        assert!(
            serde_json::from_value::<StartSerialSessionRequest>(json!({
                "config": { "path": "COM3", "secret": "never" },
                "size": { "columns": 80, "rows": 24 }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<StartSerialSessionRequest>(json!({
                "config": { "path": "COM3" },
                "size": { "columns": 80, "rows": 24, "secretPixels": 1 }
            }))
            .is_err()
        );
    }

    #[test]
    fn raw_input_envelope_is_canonical_and_bounded() {
        assert_eq!(SESSION_ID.len(), SERIAL_SESSION_ID_BYTES);
        let mut envelope = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        envelope.extend_from_slice(SESSION_ID.as_bytes());
        envelope.extend_from_slice(b"show version\r");
        let (id, input) = parse_input_envelope(&envelope).expect("valid envelope");
        assert_eq!(id.as_str(), SESSION_ID);
        assert_eq!(input, b"show version\r");

        let mut oversized = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        oversized.extend_from_slice(SESSION_ID.as_bytes());
        oversized.resize(2 + SESSION_ID.len() + MAX_INPUT_BYTES + 1, b'x');
        assert!(parse_input_envelope(&oversized).is_err());
        assert!(parse_input_envelope(&[]).is_err());
    }

    #[test]
    fn charset_and_runtime_errors_are_renderer_safe() {
        assert!(parse_charset(Some("gbk\nprivate")).is_err());
        assert!(parse_charset(Some(&"x".repeat(33))).is_err());
        assert_eq!(
            parse_charset(Some("zh_CN.GBK"))
                .expect("GBK alias")
                .normalized_label(),
            "gb18030"
        );

        let marker = "private-device-marker";
        let event =
            runtime_error_event(SerialRuntimeError::Config(SerialConfigError::InvalidPath {
                maximum_bytes: marker.len(),
            }));
        let encoded = serde_json::to_string(&event).expect("safe event JSON");
        assert_eq!(
            event,
            SerialControlEvent::Error {
                code: "invalidRequest".to_owned(),
                message: format!(
                    "Serial configuration error: Serial device path is invalid or exceeds {} bytes",
                    marker.len()
                ),
            }
        );
        assert!(!encoded.contains(marker));
    }
}
