use std::fmt;

use netcatty_vault::{
    SavedConnectionLog, SavedConnectionLogHostOs, SavedConnectionLogIconColorId,
    SavedConnectionLogIconColorMode, SavedConnectionLogIconId, SavedConnectionLogIconMode,
    SavedConnectionLogProtocol, SavedHost, SavedVaultCommitDurability, StoreError,
};
use serde::de::DeserializeOwned;

use super::{DesktopState, run_connection_logs_vault, run_saved_host_operation};

const MAX_CAPTURE_TEXT_BYTES: usize = 512;
const MAX_LOCAL_IDENTITY_BYTES: usize = 4 * 1_024;

/// Secret-free metadata needed to create one SSH history record after the
/// session manager has assigned its real session ID.
///
/// The custom `Debug` implementation deliberately omits host IDs, endpoints,
/// labels, and usernames. Capture failures are background-only and must never
/// turn a successfully started SSH session into a failed invoke.
#[derive(Clone)]
pub(crate) struct ConnectionLogCapture {
    saved_host_id: Option<String>,
    host_label: String,
    hostname: String,
    username: String,
    protocol: SavedConnectionLogProtocol,
    visual: SavedHostVisualSnapshot,
}

impl fmt::Debug for ConnectionLogCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionLogCapture")
            .field("is_saved_host", &self.saved_host_id.is_some())
            .field("has_host_os", &self.visual.host_os.is_some())
            .field("has_host_distro", &self.visual.host_distro.is_some())
            .field("has_custom_icon", &self.visual.host_icon_id.is_some())
            .finish()
    }
}

impl ConnectionLogCapture {
    pub(crate) fn quick_ssh(hostname: &str, effective_username: &str) -> Self {
        Self {
            saved_host_id: None,
            host_label: hostname.to_owned(),
            hostname: hostname.to_owned(),
            username: effective_username.to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            visual: SavedHostVisualSnapshot::default(),
        }
    }

    pub(crate) fn quick_telnet(hostname: &str, effective_username: &str) -> Self {
        Self {
            saved_host_id: None,
            host_label: hostname.to_owned(),
            hostname: hostname.to_owned(),
            username: effective_username.to_owned(),
            protocol: SavedConnectionLogProtocol::Telnet,
            visual: SavedHostVisualSnapshot::default(),
        }
    }

    pub(crate) fn quick_mosh(hostname: &str, effective_username: &str) -> Self {
        Self {
            saved_host_id: None,
            host_label: hostname.to_owned(),
            hostname: hostname.to_owned(),
            username: effective_username.to_owned(),
            protocol: SavedConnectionLogProtocol::Mosh,
            visual: SavedHostVisualSnapshot::default(),
        }
    }

    pub(crate) fn quick_serial(path: &str) -> Self {
        Self {
            saved_host_id: None,
            host_label: path.to_owned(),
            hostname: path.to_owned(),
            // Serial history uses the local OS identity.  The exact value is
            // filled from the same bounded snapshot as `local_username` when
            // the started record is built.
            username: String::new(),
            protocol: SavedConnectionLogProtocol::Serial,
            visual: SavedHostVisualSnapshot::default(),
        }
    }

    pub(crate) fn quick_local() -> Self {
        Self::quick_local_named("Local Terminal")
    }

    pub(crate) fn quick_local_named(shell_name: &str) -> Self {
        Self {
            saved_host_id: None,
            host_label: shell_name.to_owned(),
            hostname: "localhost".to_owned(),
            // Local history uses the local OS identity, just like Serial.
            // The bounded value is filled when the started record is built.
            username: String::new(),
            protocol: SavedConnectionLogProtocol::Local,
            visual: SavedHostVisualSnapshot::default(),
        }
    }

    pub(crate) fn saved_ssh(host: &SavedHost, effective_username: &str) -> Self {
        Self {
            saved_host_id: Some(host.id.as_str().to_owned()),
            host_label: host.label.clone(),
            hostname: host.hostname.clone(),
            username: effective_username.to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            visual: SavedHostVisualSnapshot::from_saved_host(host),
        }
    }

    pub(crate) fn into_mosh(mut self) -> Self {
        self.protocol = SavedConnectionLogProtocol::Mosh;
        self
    }

    pub(crate) fn into_et(mut self) -> Self {
        self.protocol = SavedConnectionLogProtocol::Et;
        self
    }

    pub(crate) fn saved_telnet(host: &SavedHost, effective_username: &str) -> Self {
        Self {
            saved_host_id: Some(host.id.as_str().to_owned()),
            host_label: host.label.clone(),
            hostname: host.hostname.clone(),
            username: effective_username.to_owned(),
            protocol: SavedConnectionLogProtocol::Telnet,
            visual: SavedHostVisualSnapshot::from_saved_host(host),
        }
    }

    pub(crate) fn saved_serial(host: &SavedHost) -> Self {
        Self {
            saved_host_id: Some(host.id.as_str().to_owned()),
            host_label: host.label.clone(),
            hostname: host.hostname.clone(),
            username: String::new(),
            protocol: SavedConnectionLogProtocol::Serial,
            visual: SavedHostVisualSnapshot::from_saved_host(host),
        }
    }

    pub(crate) fn into_started_log(
        self,
        session_id: &str,
        start_time: u64,
    ) -> Result<SavedConnectionLog, ConnectionLogCaptureError> {
        self.into_started_log_with_local_identity(session_id, start_time, LocalIdentity::current())
    }

    fn into_started_log_with_local_identity(
        self,
        session_id: &str,
        start_time: u64,
        local: LocalIdentity,
    ) -> Result<SavedConnectionLog, ConnectionLogCaptureError> {
        let host_id = self
            .saved_host_id
            .unwrap_or_else(|| format!("quick-connect:{session_id}"));
        let username = if matches!(
            self.protocol,
            SavedConnectionLogProtocol::Serial | SavedConnectionLogProtocol::Local
        ) {
            local.username.clone()
        } else {
            self.username
        };
        let log = SavedConnectionLog {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: Some(session_id.to_owned()),
            host_id,
            host_label: self.host_label,
            hostname: self.hostname,
            username,
            protocol: self.protocol,
            host_os: self.visual.host_os,
            host_distro: self.visual.host_distro,
            host_icon_mode: self.visual.host_icon_mode,
            host_icon_id: self.visual.host_icon_id,
            host_icon_color_mode: self.visual.host_icon_color_mode,
            host_icon_color: self.visual.host_icon_color,
            host_icon_color_custom: self.visual.host_icon_color_custom,
            start_time,
            end_time: None,
            local_username: local.username,
            local_hostname: local.hostname,
            saved: false,
            theme_id: None,
            font_size: None,
        };
        log.validate()
            .map_err(|_| ConnectionLogCaptureError::InvalidMetadata)?;
        Ok(log)
    }
}

#[derive(Clone, Default)]
struct SavedHostVisualSnapshot {
    host_os: Option<SavedConnectionLogHostOs>,
    host_distro: Option<String>,
    host_icon_mode: Option<SavedConnectionLogIconMode>,
    host_icon_id: Option<SavedConnectionLogIconId>,
    host_icon_color_mode: Option<SavedConnectionLogIconColorMode>,
    host_icon_color: Option<SavedConnectionLogIconColorId>,
    host_icon_color_custom: Option<String>,
}

impl SavedHostVisualSnapshot {
    fn from_saved_host(host: &SavedHost) -> Self {
        let fields = host.compatibility_fields();
        let host_os = optional_enum(fields.get("os"));

        let detected_distro = optional_normalized_text(fields.get("distro"));
        let manual_distro = optional_normalized_text(fields.get("manualDistro"));
        let host_distro =
            if fields.get("distroMode").and_then(|value| value.as_str()) == Some("manual") {
                manual_distro.or(detected_distro)
            } else {
                detected_distro
            };

        let requested_icon_mode = optional_enum(fields.get("iconMode"));
        let requested_icon_id = optional_enum(fields.get("iconId"));
        let requested_color_mode = optional_enum(fields.get("iconColorMode"));
        let requested_color = optional_enum(fields.get("iconColor"));
        let requested_custom_color = fields
            .get("iconColorCustom")
            .and_then(|value| value.as_str())
            .filter(|value| is_hex_color(value))
            .map(ToOwned::to_owned);

        // Mirrors the legacy sanitizeHostIconFields behavior. Invalid or stale
        // compatibility values are ignored instead of making SSH log capture
        // (or the SSH session itself) fail.
        let has_implicit_manual_color = requested_color_mode.is_none()
            && (requested_color.is_some() || requested_custom_color.is_some());
        let manual_color = requested_color_mode == Some(SavedConnectionLogIconColorMode::Manual)
            || has_implicit_manual_color;
        let color_mode = manual_color.then_some(SavedConnectionLogIconColorMode::Manual);
        let color = manual_color.then_some(requested_color).flatten();
        let custom_color = manual_color.then_some(requested_custom_color).flatten();

        let (
            host_icon_mode,
            host_icon_id,
            host_icon_color_mode,
            host_icon_color,
            host_icon_color_custom,
        ) = match (requested_icon_mode, requested_icon_id) {
            (Some(SavedConnectionLogIconMode::Custom), Some(icon_id)) => (
                Some(SavedConnectionLogIconMode::Custom),
                Some(icon_id),
                color_mode,
                color,
                custom_color,
            ),
            (Some(SavedConnectionLogIconMode::Custom), None) => (None, None, None, None, None),
            (_, _) if manual_color => (
                Some(SavedConnectionLogIconMode::Auto),
                None,
                color_mode,
                color,
                custom_color,
            ),
            _ => (None, None, None, None, None),
        };

        Self {
            host_os,
            host_distro,
            host_icon_mode,
            host_icon_id,
            host_icon_color_mode,
            host_icon_color,
            host_icon_color_custom,
        }
    }
}

fn optional_enum<T: DeserializeOwned>(value: Option<&serde_json::Value>) -> Option<T> {
    serde_json::from_value(value?.clone()).ok()
}

fn optional_normalized_text(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?.as_str()?.trim().to_lowercase();
    (!value.is_empty() && value.len() <= MAX_CAPTURE_TEXT_BYTES).then_some(value)
}

fn is_hex_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
}

struct LocalIdentity {
    username: String,
    hostname: String,
}

impl LocalIdentity {
    fn current() -> Self {
        Self {
            username: first_environment_value(&["USERNAME", "USER", "LOGNAME"])
                .unwrap_or_else(|| "unknown".to_owned()),
            hostname: platform_hostname()
                .or_else(|| first_environment_value(&["COMPUTERNAME", "HOSTNAME"]))
                .unwrap_or_else(|| "localhost".to_owned()),
        }
    }
}

fn first_environment_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        let value = std::env::var(name).ok()?;
        bounded_local_identity(value)
    })
}

fn bounded_local_identity(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.len() <= MAX_LOCAL_IDENTITY_BYTES {
        return Some(value.to_owned());
    }
    let mut end = MAX_LOCAL_IDENTITY_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Some(value[..end].to_owned())
}

#[cfg(unix)]
fn platform_hostname() -> Option<String> {
    let mut bytes = [0_u8; 256];
    // SAFETY: `bytes` is writable for its complete length and libc writes at
    // most that supplied length. A missing NUL terminator is handled below.
    let result = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) };
    if result != 0 {
        return None;
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bounded_local_identity(String::from_utf8(bytes[..end].to_vec()).ok()?)
}

#[cfg(not(unix))]
fn platform_hostname() -> Option<String> {
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionLogCaptureError {
    InvalidMetadata,
    Persistence,
}

impl fmt::Debug for ConnectionLogCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMetadata => "ConnectionLogCaptureError::InvalidMetadata",
            Self::Persistence => "ConnectionLogCaptureError::Persistence",
        })
    }
}

impl fmt::Display for ConnectionLogCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMetadata => "Connection log capture metadata is invalid",
            Self::Persistence => "Connection log capture storage failed",
        })
    }
}

impl std::error::Error for ConnectionLogCaptureError {}

pub(crate) async fn persist_started_connection_log(
    state: DesktopState,
    log: SavedConnectionLog,
) -> Result<(), ConnectionLogCaptureError> {
    mutate_connection_logs(state, move |logs| {
        if logs.iter().any(|existing| existing.id == log.id) {
            return false;
        }
        logs.push(log);
        true
    })
    .await
}

pub(crate) async fn persist_finished_connection_log(
    state: DesktopState,
    log_id: String,
    session_id: String,
    end_time: u64,
) -> Result<(), ConnectionLogCaptureError> {
    run_saved_host_operation(state, move |state| async move {
        persist_finished_connection_log_locked(state, log_id, session_id, end_time)
            .await
            .map(|_| ())
            .map_err(|_| ConnectionLogCaptureError::Persistence.to_string())
    })
    .await
    .map_err(|_| ConnectionLogCaptureError::Persistence)
}

/// Completes a log while the caller already owns the saved-host coordinator.
/// This keeps cross-store replay finalization linearizable without attempting
/// to recursively acquire the same process/cross-process locks.
pub(crate) async fn persist_finished_connection_log_locked(
    state: DesktopState,
    log_id: String,
    session_id: String,
    end_time: u64,
) -> Result<Vec<SavedConnectionLog>, ConnectionLogCaptureError> {
    mutate_connection_logs_locked(state, move |logs| {
        complete_open_connection_log(logs, &log_id, &session_id, end_time)
    })
    .await
}

async fn mutate_connection_logs<F>(
    state: DesktopState,
    mutation: F,
) -> Result<(), ConnectionLogCaptureError>
where
    F: FnOnce(&mut Vec<SavedConnectionLog>) -> bool + Send + 'static,
{
    run_saved_host_operation(state, move |state| async move {
        mutate_connection_logs_locked(state, mutation)
            .await
            .map(|_| ())
            .map_err(|_| ConnectionLogCaptureError::Persistence.to_string())
    })
    .await
    .map_err(|_| ConnectionLogCaptureError::Persistence)
}

async fn mutate_connection_logs_locked<F>(
    state: DesktopState,
    mutation: F,
) -> Result<Vec<SavedConnectionLog>, ConnectionLogCaptureError>
where
    F: FnOnce(&mut Vec<SavedConnectionLog>) -> bool + Send + 'static,
{
    let store = state.saved_hosts.clone();
    run_connection_logs_vault(move || {
        let snapshot = store.confirm_current_snapshot_durability()?;
        let expected_inventory_revision = snapshot.revision().clone();
        let mut logs = snapshot.connection_logs().to_vec();
        if !mutation(&mut logs) {
            return Ok(logs);
        }
        let committed = store.replace_connection_logs(expected_inventory_revision, logs)?;
        if committed.durability() == SavedVaultCommitDurability::Durable {
            return Ok(committed.logs().to_vec());
        }
        let confirmed = store.confirm_current_snapshot_durability()?;
        if confirmed.revision() != committed.revision()
            || confirmed.connection_logs() != committed.logs()
        {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        Ok(confirmed.connection_logs().to_vec())
    })
    .await
    .map_err(|_| ConnectionLogCaptureError::Persistence)
}

fn complete_open_connection_log(
    logs: &mut [SavedConnectionLog],
    log_id: &str,
    session_id: &str,
    end_time: u64,
) -> bool {
    let Some(log) = logs.iter_mut().find(|log| {
        log.id == log_id && log.session_id.as_deref() == Some(session_id) && log.end_time.is_none()
    }) else {
        return false;
    };
    log.end_time = Some(end_time.max(log.start_time));
    true
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionLogCapture, LocalIdentity, complete_open_connection_log,
        persist_finished_connection_log, persist_started_connection_log,
    };
    use crate::DesktopState;
    use netcatty_vault::{
        SavedConnectionLogHostOs, SavedConnectionLogIconColorId, SavedConnectionLogIconColorMode,
        SavedConnectionLogIconId, SavedConnectionLogIconMode, SavedConnectionLogProtocol,
        SavedHost, SavedHostDraft,
    };
    use serde_json::json;

    fn started_saved_log(session_id: &str, start_time: u64) -> netcatty_vault::SavedConnectionLog {
        let host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "saved-host-capture",
            "revision": 1,
            "label": "Sensitive host label",
            "hostname": "sensitive.example.test",
            "port": 22,
            "username": "stored-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "hasSavedCredential": false,
            "os": "linux",
            "distro": "Ubuntu",
            "distroMode": "manual",
            "manualDistro": "Rocky",
            "iconMode": "custom",
            "iconId": "server-cog",
            "iconColorMode": "manual",
            "iconColor": "teal",
            "iconColorCustom": "#12Ab34"
        }))
        .expect("saved host");
        ConnectionLogCapture::saved_ssh(&host, "effective-user")
            .into_started_log_with_local_identity(
                session_id,
                start_time,
                LocalIdentity {
                    username: "local-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("started log")
    }

    #[test]
    fn saved_capture_uses_effective_username_and_visual_snapshot() {
        let log = started_saved_log("session-real", 100);
        assert_eq!(log.session_id.as_deref(), Some("session-real"));
        assert_eq!(log.host_id, "saved-host-capture");
        assert_eq!(log.username, "effective-user");
        assert_eq!(log.host_os, Some(SavedConnectionLogHostOs::Linux));
        assert_eq!(log.host_distro.as_deref(), Some("rocky"));
        assert_eq!(log.host_icon_mode, Some(SavedConnectionLogIconMode::Custom));
        assert_eq!(log.host_icon_id, Some(SavedConnectionLogIconId::ServerCog));
        assert_eq!(
            log.host_icon_color_mode,
            Some(SavedConnectionLogIconColorMode::Manual)
        );
        assert_eq!(
            log.host_icon_color,
            Some(SavedConnectionLogIconColorId::Teal)
        );
        assert_eq!(log.host_icon_color_custom.as_deref(), Some("#12Ab34"));
        assert_eq!(log.end_time, None);
        assert!(!log.saved);
    }

    #[test]
    fn quick_telnet_capture_uses_telnet_protocol_without_a_saved_host() {
        let log = ConnectionLogCapture::quick_telnet("switch.example.test", "operator")
            .into_started_log_with_local_identity(
                "telnet-session",
                200,
                LocalIdentity {
                    username: "local-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("started log");
        assert_eq!(log.protocol, SavedConnectionLogProtocol::Telnet);
        assert_eq!(log.host_id, "quick-connect:telnet-session");
        assert_eq!(log.hostname, "switch.example.test");
        assert_eq!(log.username, "operator");
    }

    #[test]
    fn quick_serial_capture_uses_device_path_and_local_username() {
        let log = ConnectionLogCapture::quick_serial(r"\\.\COM12")
            .into_started_log_with_local_identity(
                "serial-session",
                201,
                LocalIdentity {
                    username: "local-serial-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("started serial log");
        assert_eq!(log.protocol, SavedConnectionLogProtocol::Serial);
        assert_eq!(log.host_id, "quick-connect:serial-session");
        assert_eq!(log.host_label, r"\\.\COM12");
        assert_eq!(log.hostname, r"\\.\COM12");
        assert_eq!(log.username, "local-serial-user");
        assert_eq!(log.local_username, "local-serial-user");
    }

    #[test]
    fn quick_local_capture_uses_legacy_label_and_local_identity() {
        let capture = ConnectionLogCapture::quick_local();
        let rendered = format!("{capture:?}");
        assert!(!rendered.contains("Local Terminal"));
        assert!(!rendered.contains("localhost"));

        let log = capture
            .into_started_log_with_local_identity(
                "local-session",
                202,
                LocalIdentity {
                    username: "local-terminal-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("started local log");
        assert_eq!(log.protocol, SavedConnectionLogProtocol::Local);
        assert_eq!(log.host_id, "quick-connect:local-session");
        assert_eq!(log.host_label, "Local Terminal");
        assert_eq!(log.hostname, "localhost");
        assert_eq!(log.username, "local-terminal-user");
        assert_eq!(log.local_username, "local-terminal-user");

        let named = ConnectionLogCapture::quick_local_named("PowerShell 7")
            .into_started_log_with_local_identity(
                "named-local-session",
                203,
                LocalIdentity {
                    username: "local-terminal-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("named local log");
        assert_eq!(named.host_label, "PowerShell 7");
        assert_eq!(named.protocol, SavedConnectionLogProtocol::Local);
    }

    #[test]
    fn quick_capture_gets_a_session_scoped_nonempty_host_id() {
        let log = ConnectionLogCapture::quick_ssh("quick.example.test", "quick-user")
            .into_started_log_with_local_identity(
                "session-quick",
                101,
                LocalIdentity {
                    username: "local-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect("quick log");
        assert_eq!(log.host_id, "quick-connect:session-quick");
        assert_eq!(log.host_label, "quick.example.test");
        assert_eq!(log.hostname, "quick.example.test");
        assert_eq!(log.username, "quick-user");
        assert!(log.validate().is_ok());
    }

    #[test]
    fn capture_debug_and_errors_do_not_echo_connection_metadata() {
        let capture = ConnectionLogCapture::quick_ssh(
            "debug-endpoint-sentinel.example.test",
            "debug-user-sentinel",
        );
        let rendered = format!("{capture:?}");
        assert!(!rendered.contains("debug-endpoint-sentinel"));
        assert!(!rendered.contains("debug-user-sentinel"));
        let invalid = capture
            .into_started_log_with_local_identity(
                "session-debug",
                0,
                LocalIdentity {
                    username: "local-user".to_owned(),
                    hostname: "local-machine".to_owned(),
                },
            )
            .expect_err("zero timestamp must fail");
        let rendered = format!("{invalid:?} {invalid}");
        assert!(!rendered.contains("debug-endpoint-sentinel"));
        assert!(!rendered.contains("debug-user-sentinel"));
    }

    #[test]
    fn finish_updates_only_the_exact_open_record_and_is_idempotent() {
        let mut older = started_saved_log("session-shared", 100);
        let mut closed = started_saved_log("session-shared", 200);
        closed.end_time = Some(250);
        let newest = started_saved_log("session-shared", 300);
        let newest_id = newest.id.clone();
        let older_id = older.id.clone();
        older.session_id = Some("session-shared".to_owned());
        let mut logs = vec![older, closed, newest];
        assert!(complete_open_connection_log(
            &mut logs,
            &newest_id,
            "session-shared",
            280
        ));
        assert_eq!(logs[0].end_time, None);
        assert_eq!(logs[1].end_time, Some(250));
        assert_eq!(logs[2].end_time, Some(300));
        assert!(complete_open_connection_log(
            &mut logs,
            &older_id,
            "session-shared",
            400
        ));
        assert_eq!(logs[0].end_time, Some(400));
        assert!(!complete_open_connection_log(
            &mut logs,
            &older_id,
            "session-shared",
            500
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_session_mutations_do_not_lose_records_or_end_times() {
        let directory = tempfile::tempdir().expect("temp directory");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let retained_host = state
            .saved_hosts
            .create(SavedHostDraft::ssh_password(
                "retained.example.test",
                "retained-user",
            ))
            .expect("retained host");
        let mut starts = Vec::new();
        for index in 0..12_u64 {
            let state = state.clone();
            let session_id = format!("concurrent-session-{index}");
            let log = ConnectionLogCapture::quick_ssh("concurrent.example.test", "remote-user")
                .into_started_log_with_local_identity(
                    &session_id,
                    1_000 + index,
                    LocalIdentity {
                        username: "local-user".to_owned(),
                        hostname: "local-machine".to_owned(),
                    },
                )
                .expect("started log");
            starts.push(tokio::spawn(async move {
                persist_started_connection_log(state, log).await
            }));
        }
        for start in starts {
            start.await.expect("start task").expect("persist start");
        }

        let started = state
            .saved_hosts
            .connection_log_catalog()
            .expect("started catalog");
        assert_eq!(started.logs().len(), 12);
        assert!(started.logs().iter().all(|log| log.end_time.is_none()));

        let mut finishes = Vec::new();
        for log in started.logs() {
            let state = state.clone();
            let log_id = log.id.clone();
            let session_id = log.session_id.clone().expect("session ID");
            let index = log.start_time - 1_000;
            finishes.push(tokio::spawn(async move {
                persist_finished_connection_log(state, log_id, session_id, 2_000 + index).await
            }));
        }
        for finish in finishes {
            finish.await.expect("finish task").expect("persist finish");
        }

        let finished = state
            .saved_hosts
            .connection_log_catalog()
            .expect("finished catalog");
        assert_eq!(finished.logs().len(), 12);
        assert!(finished.logs().iter().all(|log| log.end_time.is_some()));
        let hosts = state.saved_hosts.list().expect("preserved host catalog");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].id, retained_host.id);
    }
}
