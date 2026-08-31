use std::io::Read;
use std::path::PathBuf;

use base64::Engine as _;
use netcatty_vault::{
    MAX_SAVED_KNOWN_HOSTS, SavedKnownHost, SavedKnownHostCatalog, SavedKnownHostCatalogCommit,
    SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const KNOWN_HOSTS_INVALID: &str = "KNOWN_HOSTS_INVALID";
pub(crate) const KNOWN_HOSTS_INVENTORY_CHANGED: &str = "KNOWN_HOSTS_INVENTORY_CHANGED";
pub(crate) const KNOWN_HOSTS_PUBLICATION_FAILED: &str = "KNOWN_HOSTS_PUBLICATION_FAILED";
pub(crate) const KNOWN_HOSTS_REPAIR_REQUIRED: &str = "KNOWN_HOSTS_REPAIR_REQUIRED";
pub(crate) const KNOWN_HOSTS_SCAN_FAILED: &str = "KNOWN_HOSTS_SCAN_FAILED";
pub(crate) const KNOWN_HOSTS_SCAN_TOO_LARGE: &str = "KNOWN_HOSTS_SCAN_TOO_LARGE";

const MAX_SYSTEM_KNOWN_HOSTS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SYSTEM_KNOWN_HOST_LINE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplaceKnownHostsRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) known_hosts: Vec<SavedKnownHost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KnownHostsCatalog {
    pub(crate) inventory_revision: SavedVaultInventoryRevision,
    pub(crate) known_hosts: Vec<SavedKnownHost>,
}

impl KnownHostsCatalog {
    pub(crate) fn from_loaded(catalog: &SavedKnownHostCatalog) -> Self {
        Self {
            inventory_revision: catalog.revision().clone(),
            known_hosts: catalog.known_hosts().to_vec(),
        }
    }

    pub(crate) fn from_commit(commit: &SavedKnownHostCatalogCommit) -> Self {
        Self {
            inventory_revision: commit.revision().clone(),
            known_hosts: commit.known_hosts().to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemKnownHostsScan {
    pub(crate) source_count: u32,
    pub(crate) known_hosts: Vec<SavedKnownHost>,
    pub(crate) omitted_count: u32,
}

pub(crate) fn scan_system_known_hosts(now: u64) -> Result<SystemKnownHostsScan, String> {
    let mut source_count = 0_u32;
    let mut total_bytes = 0_u64;
    let mut hosts = Vec::new();
    let mut omitted_count = 0_u32;

    for path in system_known_hosts_paths() {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(known_hosts_scan_too_large)?;
        if total_bytes > MAX_SYSTEM_KNOWN_HOSTS_BYTES {
            return Err(known_hosts_scan_too_large());
        }
        let mut file = std::fs::File::open(&path).map_err(|_| known_hosts_scan_failed())?;
        let mut bytes = Vec::with_capacity(metadata.len().min(256 * 1024) as usize);
        file.by_ref()
            .take(metadata.len().saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| known_hosts_scan_failed())?;
        if bytes.len() as u64 != metadata.len() {
            return Err(known_hosts_scan_failed());
        }
        let content = String::from_utf8_lossy(&bytes);
        if content.trim().is_empty() {
            continue;
        }
        source_count = source_count.saturating_add(1);
        let remaining = MAX_SAVED_KNOWN_HOSTS.saturating_sub(hosts.len());
        let parsed = parse_known_hosts_content(&content, now, remaining);
        hosts.extend(parsed.known_hosts);
        omitted_count = omitted_count.saturating_add(parsed.omitted_count);
    }

    Ok(SystemKnownHostsScan {
        source_count,
        known_hosts: hosts,
        omitted_count,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedKnownHosts {
    known_hosts: Vec<SavedKnownHost>,
    omitted_count: u32,
}

fn parse_known_hosts_content(content: &str, now: u64, limit: usize) -> ParsedKnownHosts {
    let mut known_hosts = Vec::new();
    let mut omitted_count = 0_u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("@cert-authority ") {
            continue;
        }
        if trimmed.starts_with('@') {
            // `@revoked` and unknown OpenSSH markers must never become trust
            // records merely because their following columns resemble a key.
            omitted_count = omitted_count.saturating_add(1);
            continue;
        }
        if trimmed.len() > MAX_SYSTEM_KNOWN_HOST_LINE_BYTES || known_hosts.len() >= limit {
            omitted_count = omitted_count.saturating_add(1);
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(host_pattern), Some(key_type), Some(key_body)) =
            (parts.next(), parts.next(), parts.next())
        else {
            omitted_count = omitted_count.saturating_add(1);
            continue;
        };
        let Some((hostname, port)) = parse_host_pattern(host_pattern) else {
            omitted_count = omitted_count.saturating_add(1);
            continue;
        };
        let public_key = format!("{key_type} {key_body}");
        let fingerprint = fingerprint_from_key_body(key_body);
        let candidate = SavedKnownHost {
            id: format!("kh-{now}-{}", uuid::Uuid::new_v4().simple()),
            hostname,
            port,
            key_type: key_type.to_owned(),
            public_key,
            fingerprint,
            discovered_at: now,
            last_seen: None,
            converted_to_host_id: None,
            order: None,
        };
        if candidate.validate().is_err() {
            omitted_count = omitted_count.saturating_add(1);
            continue;
        }
        known_hosts.push(candidate);
    }
    ParsedKnownHosts {
        known_hosts,
        omitted_count,
    }
}

fn parse_host_pattern(pattern: &str) -> Option<(String, u16)> {
    if let Some(rest) = pattern.strip_prefix('[')
        && let Some((hostname, port)) = rest.split_once("]:")
    {
        let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
        return Some((hostname.to_owned(), port));
    }
    let hostname = pattern.split(',').next().unwrap_or_default();
    if hostname.is_empty() {
        return None;
    }
    Some((
        if hostname.starts_with("|1|") {
            "(hashed)".to_owned()
        } else {
            hostname.to_owned()
        },
        22,
    ))
}

fn fingerprint_from_key_body(key_body: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_body)
        .ok()?;
    let digest = Sha256::digest(decoded);
    Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

fn system_known_hosts_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = platform_home_directory() {
        paths.push(home.join(".ssh").join("known_hosts"));
    }
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        paths.push(program_data.join("ssh").join("known_hosts"));
    }
    #[cfg(not(windows))]
    paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    paths
}

fn platform_home_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

pub(crate) fn known_hosts_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn known_hosts_invalid() -> String {
    known_hosts_error(KNOWN_HOSTS_INVALID, "The Known Hosts catalog is invalid")
}

pub(crate) fn known_hosts_scan_failed() -> String {
    known_hosts_error(
        KNOWN_HOSTS_SCAN_FAILED,
        "System known_hosts files could not be read",
    )
}

pub(crate) fn known_hosts_scan_too_large() -> String {
    known_hosts_error(
        KNOWN_HOSTS_SCAN_TOO_LARGE,
        "System known_hosts files exceed the safe scan limit",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        KNOWN_HOSTS_INVALID, KnownHostsCatalog, MAX_SYSTEM_KNOWN_HOSTS_BYTES,
        ReplaceKnownHostsRequest, known_hosts_invalid, parse_known_hosts_content,
    };
    use serde_json::json;

    #[test]
    fn parser_preserves_legacy_patterns_and_computes_fingerprints() {
        let parsed = parse_known_hosts_content(
            "# comment\n@cert-authority ca.test ssh-ed25519 a2V5\n@revoked bad.test ssh-ed25519 a2V5\nserver.test ssh-ed25519 aGVsbG8=\n[alt.test]:2222 ssh-rsa d29ybGQ=\n|1|salt|hash ssh-ed25519 a2V5\n",
            42,
            10,
        );
        assert_eq!(parsed.known_hosts.len(), 3);
        assert_eq!(parsed.known_hosts[0].hostname, "server.test");
        assert_eq!(
            parsed.known_hosts[0].fingerprint.as_deref(),
            Some("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ")
        );
        assert_eq!(parsed.known_hosts[1].port, 2222);
        assert_eq!(parsed.known_hosts[2].hostname, "(hashed)");
        assert_eq!(parsed.omitted_count, 1);
    }

    #[test]
    fn parser_is_bounded_and_omits_invalid_lines_without_echoing_them() {
        let parsed = parse_known_hosts_content(
            "invalid\nfirst ssh-ed25519 a2V5\nsecond ssh-ed25519 a2V5\n",
            1,
            1,
        );
        assert_eq!(parsed.known_hosts.len(), 1);
        assert_eq!(parsed.omitted_count, 2);
        assert_eq!(MAX_SYSTEM_KNOWN_HOSTS_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn renderer_contract_is_camel_case_strict_and_secret_field_free() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let store = netcatty_vault::SavedHostStore::open(directory.path()).expect("open Vault");
        let loaded = store.known_host_catalog().expect("Known Hosts catalog");
        let catalog = KnownHostsCatalog::from_loaded(&loaded);
        let value = serde_json::to_value(&catalog).expect("catalog JSON");
        assert!(value.get("inventoryRevision").is_some());
        assert_eq!(value["knownHosts"], json!([]));

        let valid = json!({
            "expectedInventoryRevision": value["inventoryRevision"].clone(),
            "knownHosts": [{
                "id": "kh-contract",
                "hostname": "host.example.test",
                "port": 22,
                "keyType": "ssh-ed25519",
                "publicKey": "ssh-ed25519 a2V5",
                "fingerprint": "fingerprint",
                "discoveredAt": 1
            }]
        });
        assert!(serde_json::from_value::<ReplaceKnownHostsRequest>(valid.clone()).is_ok());
        let mut leaked = valid;
        leaked["knownHosts"][0]["password"] = json!("secret-body-marker");
        let error = serde_json::from_value::<ReplaceKnownHostsRequest>(leaked)
            .err()
            .expect("unknown secret field must fail")
            .to_string();
        assert!(!error.contains("secret-body-marker"));
        assert!(known_hosts_invalid().starts_with(KNOWN_HOSTS_INVALID));
    }
}
