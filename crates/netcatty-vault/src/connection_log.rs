use std::collections::HashSet;
use std::fmt;

use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer, Serialize};

/// Legacy retention limit for transient, non-bookmarked connection history.
pub const MAX_UNSAVED_CONNECTION_LOGS: usize = 500;
/// A defensive ceiling for bookmarked plus transient metadata records.
pub const MAX_CONNECTION_LOG_RECORDS: usize = 10_000;
/// Legacy side-store limit for transient terminal replay buffers.
pub const MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS: usize = 50;
/// Matches the legacy append-only terminal capture's one-million-character cap.
///
/// Rust applies the limit to UTF-8 bytes so persisted/native memory is bounded
/// even for multi-byte input. The newest complete UTF-8 suffix is retained.
pub const MAX_CONNECTION_LOG_REPLAY_BYTES: usize = 1_000_000;

const MAX_ID_BYTES: usize = 512;
const MAX_LABEL_BYTES: usize = 4 * 1_024;
const MAX_ENDPOINT_BYTES: usize = 4 * 1_024;
const MAX_ICON_TEXT_BYTES: usize = 512;
const MAX_CATALOG_TEXT_BYTES: usize = 32 * 1_024 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedConnectionLogProtocol {
    Ssh,
    Telnet,
    Local,
    Mosh,
    Et,
    Serial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedConnectionLogHostOs {
    Linux,
    Windows,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedConnectionLogIconMode {
    Auto,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedConnectionLogIconColorMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SavedConnectionLogIconId {
    Server,
    Terminal,
    Database,
    Cloud,
    Router,
    Shield,
    Code,
    Box,
    Globe,
    Cpu,
    HardDrive,
    Network,
    Wifi,
    Lock,
    Key,
    Monitor,
    Container,
    Activity,
    Zap,
    ServerCog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedConnectionLogIconColorId {
    Blue,
    Green,
    Red,
    Amber,
    Purple,
    Cyan,
    Orange,
    Slate,
    Violet,
    Pink,
    Rose,
    Lime,
    Teal,
    Sky,
    Indigo,
    Zinc,
}

/// Renderer-safe connection-history metadata matching the legacy field shape.
///
/// `terminalData` is intentionally not a member of this serializable record.
/// Legacy JSON may contain that field, but deserialization consumes it as
/// [`IgnoredAny`] and serialization never emits it. Replay bytes belong in a
/// separately protected store represented by [`SavedConnectionLogReplay`].
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedConnectionLog {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub host_id: String,
    pub host_label: String,
    pub hostname: String,
    pub username: String,
    pub protocol: SavedConnectionLogProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_os: Option<SavedConnectionLogHostOs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_distro: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_icon_mode: Option<SavedConnectionLogIconMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_icon_id: Option<SavedConnectionLogIconId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_icon_color_mode: Option<SavedConnectionLogIconColorMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_icon_color: Option<SavedConnectionLogIconColorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_icon_color_custom: Option<String>,
    pub start_time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
    pub local_username: String,
    pub local_hostname: String,
    #[serde(default)]
    pub saved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f64>,
}

impl fmt::Debug for SavedConnectionLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedConnectionLog")
            .field("protocol", &self.protocol)
            .field("saved", &self.saved)
            .field("start_time", &self.start_time)
            .field("has_end_time", &self.end_time.is_some())
            .field("has_session_id", &self.session_id.is_some())
            .field("has_host_icon", &self.host_icon_id.is_some())
            .field("has_theme", &self.theme_id.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedConnectionLogDocument {
    id: String,
    #[serde(default)]
    session_id: Option<String>,
    host_id: String,
    host_label: String,
    hostname: String,
    username: String,
    protocol: SavedConnectionLogProtocol,
    #[serde(default)]
    host_os: Option<SavedConnectionLogHostOs>,
    #[serde(default)]
    host_distro: Option<String>,
    #[serde(default)]
    host_icon_mode: Option<SavedConnectionLogIconMode>,
    #[serde(default)]
    host_icon_id: Option<SavedConnectionLogIconId>,
    #[serde(default)]
    host_icon_color_mode: Option<SavedConnectionLogIconColorMode>,
    #[serde(default)]
    host_icon_color: Option<SavedConnectionLogIconColorId>,
    #[serde(default)]
    host_icon_color_custom: Option<String>,
    start_time: u64,
    #[serde(default)]
    end_time: Option<u64>,
    local_username: String,
    local_hostname: String,
    #[serde(default)]
    saved: bool,
    #[serde(default)]
    terminal_data: Option<IgnoredAny>,
    #[serde(default)]
    theme_id: Option<String>,
    #[serde(default)]
    font_size: Option<f64>,
}

impl<'de> Deserialize<'de> for SavedConnectionLog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = SavedConnectionLogDocument::deserialize(deserializer)?;
        let _ = document.terminal_data;
        let record = Self {
            id: document.id,
            session_id: document.session_id,
            host_id: document.host_id,
            host_label: document.host_label,
            hostname: document.hostname,
            username: document.username,
            protocol: document.protocol,
            host_os: document.host_os,
            host_distro: document.host_distro,
            host_icon_mode: document.host_icon_mode,
            host_icon_id: document.host_icon_id,
            host_icon_color_mode: document.host_icon_color_mode,
            host_icon_color: document.host_icon_color,
            host_icon_color_custom: document.host_icon_color_custom,
            start_time: document.start_time,
            end_time: document.end_time,
            local_username: document.local_username,
            local_hostname: document.local_hostname,
            saved: document.saved,
            theme_id: document.theme_id,
            font_size: document.font_size,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl SavedConnectionLog {
    pub fn validate(&self) -> Result<(), SavedConnectionLogError> {
        bounded_required(&self.id, MAX_ID_BYTES)?;
        bounded_optional(self.session_id.as_deref(), MAX_ID_BYTES)?;
        if self.protocol == SavedConnectionLogProtocol::Local {
            bounded_allow_empty(&self.host_id, MAX_ID_BYTES)?;
        } else {
            bounded_required(&self.host_id, MAX_ID_BYTES)?;
        }
        bounded_required(&self.host_label, MAX_LABEL_BYTES)?;
        bounded_required(&self.hostname, MAX_ENDPOINT_BYTES)?;
        bounded_required(&self.username, MAX_ENDPOINT_BYTES)?;
        bounded_optional(self.host_distro.as_deref(), MAX_ICON_TEXT_BYTES)?;
        bounded_optional(self.host_icon_color_custom.as_deref(), MAX_ICON_TEXT_BYTES)?;
        bounded_required(&self.local_username, MAX_ENDPOINT_BYTES)?;
        bounded_required(&self.local_hostname, MAX_ENDPOINT_BYTES)?;
        bounded_optional(self.theme_id.as_deref(), MAX_ID_BYTES)?;
        if self.start_time == 0 || self.end_time.is_some_and(|end| end < self.start_time) {
            return Err(SavedConnectionLogError::InvalidRecord);
        }
        if self
            .font_size
            .is_some_and(|size| !size.is_finite() || !(4.0..=256.0).contains(&size))
        {
            return Err(SavedConnectionLogError::InvalidRecord);
        }
        Ok(())
    }

    fn text_bytes(&self) -> Option<usize> {
        [
            Some(self.id.as_str()),
            self.session_id.as_deref(),
            Some(self.host_id.as_str()),
            Some(self.host_label.as_str()),
            Some(self.hostname.as_str()),
            Some(self.username.as_str()),
            self.host_distro.as_deref(),
            self.host_icon_color_custom.as_deref(),
            Some(self.local_username.as_str()),
            Some(self.local_hostname.as_str()),
            self.theme_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .try_fold(0usize, |total, value| total.checked_add(value.len()))
    }
}

/// Validated metadata catalog. Historical host IDs intentionally need not
/// resolve against the current Vault: logs survive host deletion in legacy
/// Netcatty, and local terminals legitimately carry an empty `hostId`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedConnectionLogCatalog {
    pub logs: Vec<SavedConnectionLog>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedConnectionLogCatalogDocument {
    #[serde(default)]
    logs: Vec<SavedConnectionLog>,
}

impl<'de> Deserialize<'de> for SavedConnectionLogCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = SavedConnectionLogCatalogDocument::deserialize(deserializer)?;
        Self::new(document.logs).map_err(serde::de::Error::custom)
    }
}

impl SavedConnectionLogCatalog {
    pub fn new(logs: Vec<SavedConnectionLog>) -> Result<Self, SavedConnectionLogError> {
        validate_saved_connection_logs(&logs)?;
        Ok(Self { logs })
    }

    /// Apply the legacy retention rule: all bookmarked records plus only the
    /// newest 500 transient records, globally ordered newest first.
    pub fn with_legacy_retention(
        logs: impl IntoIterator<Item = SavedConnectionLog>,
    ) -> Result<Self, SavedConnectionLogError> {
        let mut saved = Vec::new();
        let mut unsaved = Vec::new();
        for log in logs {
            if log.saved {
                saved.push(log);
            } else {
                unsaved.push(log);
            }
        }
        unsaved.sort_by(|left, right| right.start_time.cmp(&left.start_time));
        unsaved.truncate(MAX_UNSAVED_CONNECTION_LOGS);
        saved.extend(unsaved);
        saved.sort_by(|left, right| right.start_time.cmp(&left.start_time));
        Self::new(saved)
    }
}

pub fn validate_saved_connection_logs(
    logs: &[SavedConnectionLog],
) -> Result<(), SavedConnectionLogError> {
    if logs.len() > MAX_CONNECTION_LOG_RECORDS {
        return Err(SavedConnectionLogError::CatalogTooLarge);
    }
    let mut ids = HashSet::with_capacity(logs.len());
    let mut unsaved = 0usize;
    let mut text_bytes = 0usize;
    for log in logs {
        log.validate()?;
        if !ids.insert(log.id.as_str()) {
            return Err(SavedConnectionLogError::DuplicateId);
        }
        if !log.saved {
            unsaved += 1;
            if unsaved > MAX_UNSAVED_CONNECTION_LOGS {
                return Err(SavedConnectionLogError::TooManyUnsaved);
            }
        }
        text_bytes = text_bytes
            .checked_add(
                log.text_bytes()
                    .ok_or(SavedConnectionLogError::CatalogTextTooLarge)?,
            )
            .ok_or(SavedConnectionLogError::CatalogTextTooLarge)?;
        if text_bytes > MAX_CATALOG_TEXT_BYTES {
            return Err(SavedConnectionLogError::CatalogTextTooLarge);
        }
    }
    Ok(())
}

/// Secret-bearing replay data kept outside ordinary Vault JSON and Debug.
/// A later encrypted replay store may persist this type by explicit accessors;
/// it deliberately implements neither `Serialize` nor `Deserialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedConnectionLogReplay {
    log_id: String,
    terminal_data: String,
}

impl fmt::Debug for SavedConnectionLogReplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedConnectionLogReplay")
            .field("log_id", &"[redacted]")
            .field("terminal_data", &"[redacted]")
            .field("utf8_bytes", &self.terminal_data.len())
            .finish()
    }
}

impl SavedConnectionLogReplay {
    pub fn new(
        log_id: impl Into<String>,
        terminal_data: impl Into<String>,
    ) -> Result<Self, SavedConnectionLogError> {
        let log_id = log_id.into();
        bounded_required(&log_id, MAX_ID_BYTES)?;
        let terminal_data =
            newest_utf8_suffix(terminal_data.into(), MAX_CONNECTION_LOG_REPLAY_BYTES);
        Ok(Self {
            log_id,
            terminal_data,
        })
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn terminal_data(&self) -> &str {
        &self.terminal_data
    }

    pub fn append(&mut self, chunk: &str) {
        if chunk.is_empty() {
            return;
        }
        if chunk.len() >= MAX_CONNECTION_LOG_REPLAY_BYTES {
            self.terminal_data =
                newest_utf8_suffix(chunk.to_owned(), MAX_CONNECTION_LOG_REPLAY_BYTES);
            return;
        }
        self.terminal_data.push_str(chunk);
        if self.terminal_data.len() > MAX_CONNECTION_LOG_REPLAY_BYTES {
            self.terminal_data = newest_utf8_suffix(
                std::mem::take(&mut self.terminal_data),
                MAX_CONNECTION_LOG_REPLAY_BYTES,
            );
        }
    }

    pub fn into_terminal_data(self) -> String {
        self.terminal_data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedConnectionLogError {
    InvalidRecord,
    DuplicateId,
    CatalogTooLarge,
    TooManyUnsaved,
    CatalogTextTooLarge,
}

impl fmt::Display for SavedConnectionLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecord => "connection-log record is invalid",
            Self::DuplicateId => "connection-log ID is duplicated",
            Self::CatalogTooLarge => "connection-log catalog is too large",
            Self::TooManyUnsaved => "connection-log transient retention limit is exceeded",
            Self::CatalogTextTooLarge => "connection-log catalog text is too large",
        })
    }
}

impl std::error::Error for SavedConnectionLogError {}

fn bounded_required(value: &str, max: usize) -> Result<(), SavedConnectionLogError> {
    if value.is_empty() {
        return Err(SavedConnectionLogError::InvalidRecord);
    }
    bounded_allow_empty(value, max)
}

fn bounded_optional(value: Option<&str>, max: usize) -> Result<(), SavedConnectionLogError> {
    match value {
        Some(value) => bounded_required(value, max),
        None => Ok(()),
    }
}

fn bounded_allow_empty(value: &str, max: usize) -> Result<(), SavedConnectionLogError> {
    if value.len() > max || value.chars().any(char::is_control) {
        return Err(SavedConnectionLogError::InvalidRecord);
    }
    Ok(())
}

fn newest_utf8_suffix(value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut start = value.len() - max_bytes;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        MAX_CONNECTION_LOG_REPLAY_BYTES, MAX_UNSAVED_CONNECTION_LOGS, SavedConnectionLog,
        SavedConnectionLogCatalog, SavedConnectionLogError, SavedConnectionLogHostOs,
        SavedConnectionLogIconColorId, SavedConnectionLogIconColorMode, SavedConnectionLogIconId,
        SavedConnectionLogIconMode, SavedConnectionLogProtocol, SavedConnectionLogReplay,
        validate_saved_connection_logs,
    };

    fn log(id: &str, start_time: u64, saved: bool) -> SavedConnectionLog {
        SavedConnectionLog {
            id: id.to_owned(),
            session_id: Some(format!("session-{id}")),
            host_id: "host-1".to_owned(),
            host_label: "Production".to_owned(),
            hostname: "example.test".to_owned(),
            username: "operator".to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            host_os: Some(SavedConnectionLogHostOs::Linux),
            host_distro: Some("ubuntu".to_owned()),
            host_icon_mode: Some(SavedConnectionLogIconMode::Custom),
            host_icon_id: Some(SavedConnectionLogIconId::Database),
            host_icon_color_mode: Some(SavedConnectionLogIconColorMode::Manual),
            host_icon_color: Some(SavedConnectionLogIconColorId::Violet),
            host_icon_color_custom: Some("#7c3aed".to_owned()),
            start_time,
            end_time: Some(start_time + 1),
            local_username: "local-user".to_owned(),
            local_hostname: "workstation".to_owned(),
            saved,
            theme_id: Some("netcatty-dark".to_owned()),
            font_size: Some(13.0),
        }
    }

    #[test]
    fn exact_legacy_metadata_shape_round_trips_without_terminal_data() {
        let value = serde_json::to_value(log("log-1", 100, true)).expect("log JSON");
        assert_eq!(value["sessionId"], "session-log-1");
        assert_eq!(value["hostIconId"], "database");
        assert_eq!(value["hostIconColor"], "violet");
        assert_eq!(value["startTime"], 100);
        assert!(value.get("terminalData").is_none());
        let decoded: SavedConnectionLog = serde_json::from_value(value).expect("decode log");
        assert_eq!(decoded, log("log-1", 100, true));
    }

    #[test]
    fn legacy_terminal_data_is_consumed_but_never_republished_or_debugged() {
        let secret = "TOP-SECRET-password";
        let mut value = serde_json::to_value(log("log-1", 100, true)).expect("log JSON");
        value["terminalData"] = json!(secret);
        let decoded: SavedConnectionLog = serde_json::from_value(value).expect("legacy decode");
        let persisted = serde_json::to_string(&decoded).expect("safe persistence");
        let debug = format!("{decoded:?}");
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("terminalData"));
        assert!(!debug.contains(secret));
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("operator"));
    }

    #[test]
    fn local_logs_keep_the_legacy_empty_host_id_exception() {
        let mut local = log("local", 100, false);
        local.protocol = SavedConnectionLogProtocol::Local;
        local.host_id.clear();
        local.hostname = "localhost".to_owned();
        assert!(local.validate().is_ok());
        local.protocol = SavedConnectionLogProtocol::Ssh;
        assert_eq!(
            local.validate(),
            Err(SavedConnectionLogError::InvalidRecord)
        );
    }

    #[test]
    fn catalog_rejects_duplicates_invalid_times_and_excess_transient_logs() {
        assert_eq!(
            validate_saved_connection_logs(&[log("same", 1, false), log("same", 2, false)]),
            Err(SavedConnectionLogError::DuplicateId)
        );
        let mut invalid = log("invalid", 10, false);
        invalid.end_time = Some(9);
        assert_eq!(
            invalid.validate(),
            Err(SavedConnectionLogError::InvalidRecord)
        );

        let logs = (0..=MAX_UNSAVED_CONNECTION_LOGS)
            .map(|index| log(&format!("log-{index}"), index as u64 + 1, false))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_saved_connection_logs(&logs),
            Err(SavedConnectionLogError::TooManyUnsaved)
        );
    }

    #[test]
    fn legacy_retention_keeps_all_bookmarks_and_newest_500_transient_records() {
        let mut logs = (0..(MAX_UNSAVED_CONNECTION_LOGS + 10))
            .map(|index| log(&format!("transient-{index}"), index as u64 + 1, false))
            .collect::<Vec<_>>();
        logs.push(log("bookmark", 1, true));
        let catalog =
            SavedConnectionLogCatalog::with_legacy_retention(logs).expect("bounded catalog");
        assert_eq!(catalog.logs.len(), MAX_UNSAVED_CONNECTION_LOGS + 1);
        assert!(catalog.logs.iter().any(|entry| entry.id == "bookmark"));
        assert!(!catalog.logs.iter().any(|entry| entry.id == "transient-0"));
        assert!(catalog.logs.iter().any(|entry| entry.id == "transient-509"));
    }

    #[test]
    fn replay_retains_only_the_newest_complete_utf8_suffix() {
        let prefix = "x".repeat(MAX_CONNECTION_LOG_REPLAY_BYTES - 2);
        let mut replay = SavedConnectionLogReplay::new("log-1", prefix).expect("replay");
        replay.append("旧-data");
        assert!(replay.terminal_data().len() <= MAX_CONNECTION_LOG_REPLAY_BYTES);
        assert!(replay.terminal_data().ends_with("旧-data"));
    }

    #[test]
    fn replay_debug_redacts_id_and_terminal_contents() {
        let replay =
            SavedConnectionLogReplay::new("private-log-id", "password=secret").expect("replay");
        let debug = format!("{replay:?}");
        assert!(!debug.contains("private-log-id"));
        assert!(!debug.contains("password"));
        assert!(!debug.contains("secret"));
        assert_eq!(replay.log_id(), "private-log-id");
    }

    #[test]
    fn unknown_runtime_fields_and_unsafe_metadata_fail_without_echoing_values() {
        let mut value = serde_json::to_value(log("log-1", 100, false)).expect("log JSON");
        value["runtimeState"] = json!("connected");
        assert!(serde_json::from_value::<SavedConnectionLog>(value).is_err());

        let mut invalid = log("do-not-echo-this", 100, false);
        invalid.hostname = "secret\nvalue".to_owned();
        let error = invalid.validate().expect_err("invalid metadata");
        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("do-not-echo-this"));
    }
}
