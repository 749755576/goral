use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{SavedHost, SavedHostId};

pub const MAX_SAVED_PORT_FORWARD_RULES: usize = 10_000;

const MAX_RULE_ID_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 512;
const MAX_BIND_ADDRESS_BYTES: usize = 1_024;
const MAX_REMOTE_HOST_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedPortForwardKind {
    Local,
    Remote,
    Dynamic,
}

/// Durable, renderer-safe port-forward configuration.
///
/// Runtime phase and errors deliberately do not belong to this record. The
/// custom deserializer accepts and drops those two legacy fields so old
/// local-storage/sync documents can be migrated without making stale runtime
/// authority durable again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedPortForwardRule {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: SavedPortForwardKind,
    pub local_port: u16,
    pub bind_address: String,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub host_id: SavedHostId,
    #[serde(default)]
    pub auto_start: bool,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub order: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedPortForwardRuleDocument {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: SavedPortForwardKind,
    local_port: u16,
    bind_address: String,
    remote_host: Option<String>,
    remote_port: Option<u16>,
    host_id: String,
    #[serde(default)]
    auto_start: bool,
    created_at: u64,
    last_used_at: Option<u64>,
    order: Option<i64>,
    #[serde(default)]
    status: Option<LegacyPortForwardStatus>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum LegacyPortForwardStatus {
    Inactive,
    Connecting,
    Active,
    Error,
    Unknown,
}

impl<'de> Deserialize<'de> for SavedPortForwardRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = SavedPortForwardRuleDocument::deserialize(deserializer)?;
        let _ = (document.status, document.error);
        Self::new(
            document.id,
            document.label,
            document.kind,
            document.local_port,
            document.bind_address,
            document.remote_host,
            document.remote_port,
            document.host_id,
            document.auto_start,
            document.created_at,
            document.last_used_at,
            document.order,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl SavedPortForwardRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        kind: SavedPortForwardKind,
        local_port: u16,
        bind_address: impl Into<String>,
        remote_host: Option<String>,
        remote_port: Option<u16>,
        host_id: impl Into<String>,
        auto_start: bool,
        created_at: u64,
        last_used_at: Option<u64>,
        order: Option<i64>,
    ) -> Result<Self, SavedPortForwardRuleError> {
        let id = normalize_required_text(id.into(), MAX_RULE_ID_BYTES, false)?;
        let label = normalize_required_text(label.into(), MAX_LABEL_BYTES, false)?;
        let bind_address =
            normalize_required_text(bind_address.into(), MAX_BIND_ADDRESS_BYTES, true)?;
        let host_id = normalize_required_text(host_id.into(), MAX_RULE_ID_BYTES, false)?;
        let host_id = SavedHostId::from_opaque(host_id)
            .map_err(|_| SavedPortForwardRuleError::InvalidRule)?;
        if local_port == 0 {
            return Err(SavedPortForwardRuleError::InvalidRule);
        }

        let (remote_host, remote_port) = match kind {
            SavedPortForwardKind::Dynamic => {
                if remote_host
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                    || remote_port.is_some()
                {
                    return Err(SavedPortForwardRuleError::InvalidRule);
                }
                (None, None)
            }
            SavedPortForwardKind::Local | SavedPortForwardKind::Remote => {
                let remote_host = remote_host
                    .ok_or(SavedPortForwardRuleError::InvalidRule)
                    .and_then(|value| {
                        normalize_required_text(value, MAX_REMOTE_HOST_BYTES, false)
                    })?;
                let remote_port = remote_port
                    .filter(|port| *port > 0)
                    .ok_or(SavedPortForwardRuleError::InvalidRule)?;
                (Some(remote_host), Some(remote_port))
            }
        };

        Ok(Self {
            id,
            label,
            kind,
            local_port,
            bind_address,
            remote_host,
            remote_port,
            host_id,
            auto_start,
            created_at,
            last_used_at,
            order,
        })
    }

    pub fn with_last_used_at(mut self, last_used_at: u64) -> Self {
        self.last_used_at = Some(last_used_at);
        self
    }

    pub(crate) fn normalized(&self) -> Result<Self, SavedPortForwardRuleError> {
        Self::new(
            self.id.clone(),
            self.label.clone(),
            self.kind,
            self.local_port,
            self.bind_address.clone(),
            self.remote_host.clone(),
            self.remote_port,
            self.host_id.as_str().to_owned(),
            self.auto_start,
            self.created_at,
            self.last_used_at,
            self.order,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedPortForwardRuleError {
    InvalidRule,
    CatalogTooLarge,
    DuplicateRule,
    HostUnavailable,
    HostUnsupported,
}

impl fmt::Display for SavedPortForwardRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRule => "port-forward rule is invalid",
            Self::CatalogTooLarge => "port-forward rule catalog exceeds its limit",
            Self::DuplicateRule => "port-forward rule catalog contains a duplicate",
            Self::HostUnavailable => "port-forward rule host is unavailable",
            Self::HostUnsupported => "port-forward rule host does not support SSH forwarding",
        })
    }
}

impl std::error::Error for SavedPortForwardRuleError {}

pub(crate) fn normalize_and_validate_port_forward_rules(
    rules: &mut [SavedPortForwardRule],
    hosts: &[SavedHost],
) -> Result<(), SavedPortForwardRuleError> {
    if rules.len() > MAX_SAVED_PORT_FORWARD_RULES {
        return Err(SavedPortForwardRuleError::CatalogTooLarge);
    }
    let mut ids = HashSet::with_capacity(rules.len());
    for rule in rules {
        *rule = rule.normalized()?;
        if !ids.insert(rule.id.clone()) {
            return Err(SavedPortForwardRuleError::DuplicateRule);
        }
        let host = hosts
            .iter()
            .find(|host| host.id == rule.host_id)
            .ok_or(SavedPortForwardRuleError::HostUnavailable)?;
        if !host.protocol.is_ssh() {
            return Err(SavedPortForwardRuleError::HostUnsupported);
        }
    }
    Ok(())
}

fn normalize_required_text(
    value: String,
    max_bytes: usize,
    reject_whitespace: bool,
) -> Result<String, SavedPortForwardRuleError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || (reject_whitespace && value.chars().any(char::is_whitespace))
    {
        return Err(SavedPortForwardRuleError::InvalidRule);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        SavedPortForwardKind, SavedPortForwardRule, SavedPortForwardRuleError,
        normalize_and_validate_port_forward_rules,
    };
    use crate::SavedHostDraft;

    fn host() -> crate::SavedHost {
        crate::SavedHost::from_draft(SavedHostDraft::ssh_password("example.test", "tester"), 1)
            .expect("saved host")
    }

    fn local_rule(id: &str, host_id: &str) -> SavedPortForwardRule {
        SavedPortForwardRule::new(
            id,
            "Web",
            SavedPortForwardKind::Local,
            8080,
            "127.0.0.1",
            Some("127.0.0.1".to_owned()),
            Some(80),
            host_id,
            false,
            10,
            None,
            Some(1),
        )
        .expect("local rule")
    }

    #[test]
    fn exact_legacy_shape_round_trips_without_runtime_authority() {
        let document = json!({
            "id": " rule-1 ",
            "label": " Web ",
            "type": "local",
            "localPort": 8080,
            "bindAddress": "127.0.0.1",
            "remoteHost": " localhost ",
            "remotePort": 80,
            "hostId": "host-1",
            "autoStart": true,
            "createdAt": 10,
            "lastUsedAt": 20,
            "order": 3,
            "status": "active",
            "error": "stale runtime detail"
        });
        let rule: SavedPortForwardRule = serde_json::from_value(document).expect("legacy rule");
        assert_eq!(rule.id, "rule-1");
        assert_eq!(rule.remote_host.as_deref(), Some("localhost"));
        let persisted = serde_json::to_value(rule).expect("persisted rule");
        assert!(persisted.get("status").is_none());
        assert!(persisted.get("error").is_none());
    }

    #[test]
    fn kind_specific_fields_are_strict() {
        assert!(
            SavedPortForwardRule::new(
                "dynamic",
                "SOCKS",
                SavedPortForwardKind::Dynamic,
                1080,
                "127.0.0.1",
                None,
                None,
                "host-1",
                false,
                1,
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            SavedPortForwardRule::new(
                "bad-dynamic",
                "SOCKS",
                SavedPortForwardKind::Dynamic,
                1080,
                "127.0.0.1",
                Some("example.test".to_owned()),
                None,
                "host-1",
                false,
                1,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            SavedPortForwardRule::new(
                "bad-local",
                "Local",
                SavedPortForwardKind::Local,
                8080,
                "127.0.0.1",
                None,
                Some(80),
                "host-1",
                false,
                1,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_rejects_duplicates_and_missing_hosts_without_echoing_ids() {
        let hosts = vec![host()];
        let host_id = hosts[0].id.as_str();
        let mut duplicate = vec![local_rule("same", host_id), local_rule("same", host_id)];
        assert_eq!(
            normalize_and_validate_port_forward_rules(&mut duplicate, &hosts),
            Err(SavedPortForwardRuleError::DuplicateRule)
        );

        let mut dangling = vec![local_rule("rule", "missing")];
        let error = normalize_and_validate_port_forward_rules(&mut dangling, &hosts)
            .expect_err("dangling host");
        assert_eq!(error, SavedPortForwardRuleError::HostUnavailable);
        assert!(!error.to_string().contains("missing"));
    }
}
