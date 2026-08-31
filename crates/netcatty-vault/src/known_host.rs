use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_SAVED_KNOWN_HOSTS: usize = 10_000;
const MAX_ID_BYTES: usize = 512;
const MAX_HOSTNAME_BYTES: usize = 1_024;
const MAX_KEY_TYPE_BYTES: usize = 128;
const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1_024;
const MAX_FINGERPRINT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedKnownHost {
    pub id: String,
    pub hostname: String,
    pub port: u16,
    pub key_type: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub discovered_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub converted_to_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedKnownHostError {
    InvalidRecord,
    DuplicateId,
    CatalogTooLarge,
}

impl fmt::Display for SavedKnownHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecord => "known-host record is invalid",
            Self::DuplicateId => "known-host ID is duplicated",
            Self::CatalogTooLarge => "known-host catalog is too large",
        })
    }
}

impl std::error::Error for SavedKnownHostError {}

impl SavedKnownHost {
    pub fn validate(&self) -> Result<(), SavedKnownHostError> {
        bounded(&self.id, MAX_ID_BYTES)?;
        bounded(&self.hostname, MAX_HOSTNAME_BYTES)?;
        bounded(&self.key_type, MAX_KEY_TYPE_BYTES)?;
        bounded(&self.public_key, MAX_PUBLIC_KEY_BYTES)?;
        if self.port == 0 || self.discovered_at == 0 {
            return Err(SavedKnownHostError::InvalidRecord);
        }
        if let Some(value) = &self.fingerprint {
            bounded(value, MAX_FINGERPRINT_BYTES)?;
        }
        if let Some(value) = &self.converted_to_host_id {
            bounded(value, MAX_ID_BYTES)?;
        }
        Ok(())
    }

    pub fn same_selector(&self, other: &Self) -> bool {
        self.hostname
            .trim()
            .eq_ignore_ascii_case(other.hostname.trim())
            && self.port == other.port
            && self.key_type == other.key_type
    }
}

pub fn validate_saved_known_hosts(hosts: &[SavedKnownHost]) -> Result<(), SavedKnownHostError> {
    if hosts.len() > MAX_SAVED_KNOWN_HOSTS {
        return Err(SavedKnownHostError::CatalogTooLarge);
    }
    let mut ids = HashSet::with_capacity(hosts.len());
    for host in hosts {
        host.validate()?;
        if !ids.insert(host.id.as_str()) {
            return Err(SavedKnownHostError::DuplicateId);
        }
    }
    Ok(())
}

fn bounded(value: &str, max: usize) -> Result<(), SavedKnownHostError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return Err(SavedKnownHostError::InvalidRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SavedKnownHost, SavedKnownHostError, validate_saved_known_hosts};

    fn host(id: &str) -> SavedKnownHost {
        SavedKnownHost {
            id: id.to_owned(),
            hostname: "Example.COM".to_owned(),
            port: 22,
            key_type: "ssh-ed25519".to_owned(),
            public_key: "ssh-ed25519 AAAA".to_owned(),
            fingerprint: Some("fingerprint".to_owned()),
            discovered_at: 1,
            last_seen: None,
            converted_to_host_id: None,
            order: None,
        }
    }

    #[test]
    fn exact_legacy_shape_round_trips_and_selector_is_case_insensitive() {
        let value = serde_json::to_value(host("kh-1")).expect("known host JSON");
        assert_eq!(value["keyType"], "ssh-ed25519");
        assert_eq!(value["discoveredAt"], 1);
        let mut other = host("kh-2");
        other.hostname = " example.com ".to_owned();
        assert!(host("kh-1").same_selector(&other));
    }

    #[test]
    fn catalog_rejects_duplicate_ids_and_invalid_records() {
        assert_eq!(
            validate_saved_known_hosts(&[host("same"), host("same")]),
            Err(SavedKnownHostError::DuplicateId)
        );
        let mut invalid = host("kh-invalid");
        invalid.port = 0;
        assert_eq!(invalid.validate(), Err(SavedKnownHostError::InvalidRecord));
    }
}
