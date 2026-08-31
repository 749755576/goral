use russh::keys::ssh_key::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub id: String,
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveHostKey {
    pub key_type: String,
    pub fingerprint: String,
    pub public_key: String,
}

impl LiveHostKey {
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self {
            key_type: key.algorithm().to_string(),
            fingerprint: normalize_fingerprint(&key.fingerprint(HashAlg::Sha256).to_string()),
            public_key: key.to_openssh().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HostKeyStatus {
    Trusted,
    Changed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyClassification {
    pub status: HostKeyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
}

#[must_use]
pub fn classify_host_key(
    known_hosts: &[KnownHost],
    hostname: &str,
    port: u16,
    live: &LiveHostKey,
) -> HostKeyClassification {
    let candidates: Vec<_> = known_hosts
        .iter()
        .filter(|known| matches_host_and_port(known, hostname, port))
        .filter_map(|known| known_fingerprint(known).map(|fingerprint| (known, fingerprint)))
        .collect();
    let live_fingerprint = normalize_fingerprint(&live.fingerprint);

    if let Some((known, _)) = candidates
        .iter()
        .find(|(_, fingerprint)| *fingerprint == live_fingerprint)
    {
        return HostKeyClassification {
            status: HostKeyStatus::Trusted,
            known_host_id: Some(known.id.clone()),
            expected_fingerprint: None,
        };
    }

    let key_type = live.key_type.trim();
    if !key_type.is_empty() && key_type != "unknown" {
        if let Some((known, fingerprint)) = candidates
            .iter()
            .find(|(known, _)| known.key_type.trim() == key_type)
        {
            return HostKeyClassification {
                status: HostKeyStatus::Changed,
                known_host_id: Some(known.id.clone()),
                expected_fingerprint: Some(fingerprint.clone()),
            };
        }
    }

    HostKeyClassification {
        status: HostKeyStatus::Unknown,
        known_host_id: None,
        expected_fingerprint: None,
    }
}

#[must_use]
pub fn normalize_fingerprint(value: &str) -> String {
    let value = value.trim();
    let value = value
        .strip_prefix("SHA256:")
        .or_else(|| value.strip_prefix("sha256:"))
        .unwrap_or(value);
    value.trim_end_matches('=').to_owned()
}

fn matches_host_and_port(known: &KnownHost, hostname: &str, port: u16) -> bool {
    let (known_hostname, embedded_port) = parse_known_host_pattern(&known.hostname);
    if known_hostname.is_empty() || known_hostname == "(hashed)" {
        return false;
    }
    known_hostname.eq_ignore_ascii_case(hostname.trim())
        && known.port.or(embedded_port).unwrap_or(22) == port
}

fn parse_known_host_pattern(value: &str) -> (String, Option<u16>) {
    let first = value.trim().split(',').next().unwrap_or_default();
    if let Some(rest) = first.strip_prefix('[') {
        if let Some((hostname, port_text)) = rest.split_once("]:") {
            return (
                hostname.trim().to_ascii_lowercase(),
                port_text.parse::<u16>().ok(),
            );
        }
    }
    (first.to_ascii_lowercase(), None)
}

fn known_fingerprint(known: &KnownHost) -> Option<String> {
    let explicit = known
        .fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .filter(|value| !value.is_empty());
    if explicit.is_some() {
        return explicit;
    }

    let public_key = known.public_key.as_deref()?.trim();
    if public_key.to_ascii_lowercase().starts_with("sha256:") {
        let normalized = normalize_fingerprint(public_key);
        return (!normalized.is_empty()).then_some(normalized);
    }
    PublicKey::from_openssh(public_key)
        .ok()
        .map(|key| normalize_fingerprint(&key.fingerprint(HashAlg::Sha256).to_string()))
}

#[cfg(test)]
mod tests {
    use super::{HostKeyStatus, KnownHost, LiveHostKey, classify_host_key, normalize_fingerprint};

    fn known(id: &str, key_type: &str, fingerprint: &str) -> KnownHost {
        KnownHost {
            id: id.to_owned(),
            hostname: "switch.local".to_owned(),
            port: Some(22),
            key_type: key_type.to_owned(),
            fingerprint: Some(fingerprint.to_owned()),
            public_key: None,
        }
    }

    fn live(key_type: &str, fingerprint: &str) -> LiveHostKey {
        LiveHostKey {
            key_type: key_type.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key: String::new(),
        }
    }

    #[test]
    fn unknown_host_is_not_trusted() {
        assert_eq!(
            classify_host_key(&[], "switch.local", 22, &live("ssh-ed25519", "new")).status,
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn fingerprint_is_ground_truth_even_when_key_type_differs() {
        let decision = classify_host_key(
            &[known("kh-1", "ssh-rsa", "SHA256:trusted===")],
            "SWITCH.LOCAL",
            22,
            &live("ssh-ed25519", "trusted"),
        );

        assert_eq!(decision.status, HostKeyStatus::Trusted);
        assert_eq!(decision.known_host_id.as_deref(), Some("kh-1"));
    }

    #[test]
    fn same_type_mismatch_is_changed() {
        let decision = classify_host_key(
            &[known("kh-1", "ssh-ed25519", "old")],
            "switch.local",
            22,
            &live("ssh-ed25519", "new"),
        );

        assert_eq!(decision.status, HostKeyStatus::Changed);
        assert_eq!(decision.expected_fingerprint.as_deref(), Some("old"));
    }

    #[test]
    fn different_type_mismatch_is_unknown() {
        let decision = classify_host_key(
            &[known("kh-rsa", "ssh-rsa", "old")],
            "switch.local",
            22,
            &live("ssh-ed25519", "new"),
        );

        assert_eq!(decision.status, HostKeyStatus::Unknown);
    }

    #[test]
    fn hostname_port_patterns_are_supported() {
        let mut record = known("kh-1", "ssh-ed25519", "trusted");
        record.hostname = "[switch.local]:2222,alias".to_owned();
        record.port = None;

        assert_eq!(
            classify_host_key(
                &[record.clone()],
                "switch.local",
                2222,
                &live("ssh-ed25519", "trusted")
            )
            .status,
            HostKeyStatus::Trusted
        );
        assert_eq!(
            classify_host_key(
                &[record],
                "switch.local",
                22,
                &live("ssh-ed25519", "trusted")
            )
            .status,
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn fingerprint_normalization_matches_legacy_behavior() {
        assert_eq!(normalize_fingerprint(" SHA256:abc123=== "), "abc123");
    }
}
