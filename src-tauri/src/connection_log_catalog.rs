use netcatty_vault::{
    SavedConnectionLog, SavedConnectionLogCatalogCommit, SavedConnectionLogCatalogState,
    SavedConnectionLogHostOs, SavedConnectionLogIconColorId, SavedConnectionLogIconColorMode,
    SavedConnectionLogIconId, SavedConnectionLogIconMode, SavedConnectionLogProtocol,
    SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};

pub(crate) const CONNECTION_LOGS_INVALID: &str = "CONNECTION_LOGS_INVALID";
pub(crate) const CONNECTION_LOGS_INVENTORY_CHANGED: &str = "CONNECTION_LOGS_INVENTORY_CHANGED";
pub(crate) const CONNECTION_LOGS_PUBLICATION_FAILED: &str = "CONNECTION_LOGS_PUBLICATION_FAILED";
pub(crate) const CONNECTION_LOGS_REPAIR_REQUIRED: &str = "CONNECTION_LOGS_REPAIR_REQUIRED";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplaceConnectionLogsRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    logs: Vec<ConnectionLogRequest>,
}

impl ReplaceConnectionLogsRequest {
    pub(crate) fn into_parts(self) -> (SavedVaultInventoryRevision, Vec<SavedConnectionLog>) {
        (
            self.expected_inventory_revision,
            self.logs.into_iter().map(Into::into).collect(),
        )
    }
}

/// Strict renderer request shape. The durable model intentionally accepts a
/// legacy `terminalData` field while reading old snapshots, so the native IPC
/// boundary uses this separate DTO to reject replay contents and every other
/// unknown field before they reach the Vault store.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionLogRequest {
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
    theme_id: Option<String>,
    #[serde(default)]
    font_size: Option<f64>,
}

impl From<ConnectionLogRequest> for SavedConnectionLog {
    fn from(log: ConnectionLogRequest) -> Self {
        Self {
            id: log.id,
            session_id: log.session_id,
            host_id: log.host_id,
            host_label: log.host_label,
            hostname: log.hostname,
            username: log.username,
            protocol: log.protocol,
            host_os: log.host_os,
            host_distro: log.host_distro,
            host_icon_mode: log.host_icon_mode,
            host_icon_id: log.host_icon_id,
            host_icon_color_mode: log.host_icon_color_mode,
            host_icon_color: log.host_icon_color,
            host_icon_color_custom: log.host_icon_color_custom,
            start_time: log.start_time,
            end_time: log.end_time,
            local_username: log.local_username,
            local_hostname: log.local_hostname,
            saved: log.saved,
            theme_id: log.theme_id,
            font_size: log.font_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionLogsCatalog {
    pub(crate) inventory_revision: SavedVaultInventoryRevision,
    pub(crate) logs: Vec<SavedConnectionLog>,
}

impl ConnectionLogsCatalog {
    pub(crate) fn from_loaded(catalog: &SavedConnectionLogCatalogState) -> Self {
        Self {
            inventory_revision: catalog.revision().clone(),
            logs: catalog.logs().to_vec(),
        }
    }

    pub(crate) fn from_commit(commit: &SavedConnectionLogCatalogCommit) -> Self {
        Self {
            inventory_revision: commit.revision().clone(),
            logs: commit.logs().to_vec(),
        }
    }
}

pub(crate) fn connection_logs_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn connection_logs_invalid() -> String {
    connection_logs_error(
        CONNECTION_LOGS_INVALID,
        "The Connection Logs catalog is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CONNECTION_LOGS_INVALID, ConnectionLogsCatalog, ReplaceConnectionLogsRequest,
        connection_logs_invalid,
    };
    use serde_json::json;

    #[test]
    fn renderer_contract_is_camel_case_strict_and_replay_free() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let store = netcatty_vault::SavedHostStore::open(directory.path()).expect("open Vault");
        let loaded = store
            .connection_log_catalog()
            .expect("Connection Logs catalog");
        let catalog = ConnectionLogsCatalog::from_loaded(&loaded);
        let value = serde_json::to_value(&catalog).expect("catalog JSON");
        assert!(value.get("inventoryRevision").is_some());
        assert_eq!(value["logs"], json!([]));
        assert!(value.get("terminalData").is_none());

        let valid = json!({
            "expectedInventoryRevision": value["inventoryRevision"].clone(),
            "logs": [{
                "id": "log-contract",
                "sessionId": "session-contract",
                "hostId": "host-contract",
                "hostLabel": "Production",
                "hostname": "host.example.test",
                "username": "deploy",
                "protocol": "ssh",
                "startTime": 1,
                "localUsername": "local-user",
                "localHostname": "local-host",
                "saved": false
            }]
        });
        assert!(serde_json::from_value::<ReplaceConnectionLogsRequest>(valid.clone()).is_ok());

        let mut replay_leak = valid;
        replay_leak["logs"][0]["terminalData"] = json!("private-terminal-output");
        let error = serde_json::from_value::<ReplaceConnectionLogsRequest>(replay_leak)
            .err()
            .expect("replay field must fail")
            .to_string();
        assert!(!error.contains("private-terminal-output"));
        assert!(connection_logs_invalid().starts_with(CONNECTION_LOGS_INVALID));
    }
}
