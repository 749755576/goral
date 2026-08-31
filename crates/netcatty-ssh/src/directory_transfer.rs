use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, block_api::compress256};

pub const EMPTY_DIRECTORY_MANIFEST_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const EMPTY_DIRECTORY_MANIFEST_STATE_V2: &str =
    "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
pub const DIRECTORY_RESUME_CHECKPOINT_VERSION: u8 = 2;
pub const MAX_SFTP_FOLLOWED_SYMLINK_DEPTH: usize = 32;
pub const MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES: u64 = 50_000;
pub const MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES: u64 = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryTraversalError {
    DirectoryLimitExceeded,
    EntryLimitExceeded,
    InvalidCheckpoint,
    InvalidIdentity,
}

impl fmt::Display for DirectoryTraversalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DirectoryLimitExceeded => "SFTP directory traversal directory limit exceeded",
            Self::EntryLimitExceeded => "SFTP directory traversal entry limit exceeded",
            Self::InvalidCheckpoint => "SFTP directory resume checkpoint is invalid",
            Self::InvalidIdentity => "SFTP directory manifest identity is invalid",
        })
    }
}

impl std::error::Error for DirectoryTraversalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryTraversalBudget {
    pub active_canonical_directories: HashSet<String>,
    pub visited_directories: u64,
    pub visited_entries: u64,
    pub max_directories: u64,
    pub max_entries: u64,
}

impl Default for DirectoryTraversalBudget {
    fn default() -> Self {
        Self::new(
            MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES,
            MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES,
        )
    }
}

impl DirectoryTraversalBudget {
    #[must_use]
    pub fn new(max_directories: u64, max_entries: u64) -> Self {
        Self {
            active_canonical_directories: HashSet::new(),
            visited_directories: 0,
            visited_entries: 0,
            max_directories,
            max_entries,
        }
    }

    pub fn claim(
        &mut self,
        canonical_path: &str,
        branch_ancestors: Option<&mut HashSet<String>>,
    ) -> Result<Option<String>, DirectoryTraversalError> {
        let normalized = normalize_canonical_directory_path(canonical_path);
        let ancestors = branch_ancestors.unwrap_or(&mut self.active_canonical_directories);
        if ancestors.contains(&normalized) {
            return Ok(None);
        }
        if self.visited_directories >= self.max_directories {
            return Err(DirectoryTraversalError::DirectoryLimitExceeded);
        }
        self.visited_directories += 1;
        ancestors.insert(normalized.clone());
        Ok(Some(normalized))
    }

    pub fn release(&mut self, claimed: &str, branch_ancestors: Option<&mut HashSet<String>>) {
        branch_ancestors
            .unwrap_or(&mut self.active_canonical_directories)
            .remove(claimed);
    }

    pub fn account_entries(&mut self, count: u64) -> Result<(), DirectoryTraversalError> {
        let next = self
            .visited_entries
            .checked_add(count)
            .ok_or(DirectoryTraversalError::EntryLimitExceeded)?;
        if next > self.max_entries {
            return Err(DirectoryTraversalError::EntryLimitExceeded);
        }
        self.visited_entries = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResumeCheckpoint {
    pub version: u8,
    pub covered_entries: u64,
    pub completed_entries: u64,
    pub manifest_hash: String,
}

impl DirectoryResumeCheckpoint {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: DIRECTORY_RESUME_CHECKPOINT_VERSION,
            covered_entries: 0,
            completed_entries: 0,
            manifest_hash: EMPTY_DIRECTORY_MANIFEST_STATE_V2.to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), DirectoryTraversalError> {
        if !matches!(self.version, 1 | 2)
            || self.completed_entries > self.covered_entries
            || !is_lower_hex_256(&self.manifest_hash)
        {
            return Err(DirectoryTraversalError::InvalidCheckpoint);
        }
        Ok(())
    }

    pub fn append(&mut self, entry_identity: &str) -> Result<(), DirectoryTraversalError> {
        self.validate()?;
        self.manifest_hash =
            append_directory_manifest_identity(self.version, &self.manifest_hash, entry_identity)?;
        self.covered_entries = self
            .covered_entries
            .checked_add(1)
            .ok_or(DirectoryTraversalError::InvalidCheckpoint)?;
        Ok(())
    }

    pub fn matches_prefix(&self, identities: &[String]) -> Result<bool, DirectoryTraversalError> {
        self.validate()?;
        let covered = usize::try_from(self.covered_entries)
            .map_err(|_| DirectoryTraversalError::InvalidCheckpoint)?;
        if covered > identities.len() {
            return Ok(false);
        }
        let mut rebuilt = match self.version {
            1 => Self {
                version: 1,
                covered_entries: 0,
                completed_entries: 0,
                manifest_hash: EMPTY_DIRECTORY_MANIFEST_HASH.to_owned(),
            },
            2 => Self::empty(),
            _ => return Err(DirectoryTraversalError::InvalidCheckpoint),
        };
        for identity in &identities[..covered] {
            rebuilt.append(identity)?;
        }
        Ok(rebuilt.manifest_hash == self.manifest_hash)
    }

    pub fn migrate_to_v2(&self, identities: &[String]) -> Result<Self, DirectoryTraversalError> {
        if !self.matches_prefix(identities)? {
            return Err(DirectoryTraversalError::InvalidCheckpoint);
        }
        if self.version == 2 {
            return Ok(self.clone());
        }
        let covered = usize::try_from(self.covered_entries)
            .map_err(|_| DirectoryTraversalError::InvalidCheckpoint)?;
        let mut migrated = Self::empty();
        for identity in &identities[..covered] {
            migrated.append(identity)?;
        }
        migrated.completed_entries = self.completed_entries;
        Ok(migrated)
    }
}

#[must_use]
pub fn normalize_canonical_directory_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let normalized = normalized.trim_end_matches('/');
    if normalized.is_empty() {
        "/".to_owned()
    } else {
        normalized.to_owned()
    }
}

#[must_use]
pub const fn should_follow_symlink_directory(depth: usize) -> bool {
    depth < MAX_SFTP_FOLLOWED_SYMLINK_DEPTH
}

pub fn create_directory_entry_identity(
    source_path: &str,
    target_path: &str,
    size: u64,
    modified_at: u64,
) -> Result<String, DirectoryTraversalError> {
    let encoded = serde_json::to_vec(&(source_path, target_path, size, modified_at))
        .map_err(|_| DirectoryTraversalError::InvalidIdentity)?;
    Ok(sha256_hex(encoded))
}

pub fn append_directory_manifest_identity(
    version: u8,
    manifest_hash: &str,
    entry_identity: &str,
) -> Result<String, DirectoryTraversalError> {
    if !is_lower_hex_256(manifest_hash) || !is_lower_hex_256(entry_identity) {
        return Err(DirectoryTraversalError::InvalidIdentity);
    }
    match version {
        1 => Ok(sha256_hex(format!("{manifest_hash}:{entry_identity}"))),
        2 => {
            let mut state = [0_u32; 8];
            for (index, word) in state.iter_mut().enumerate() {
                *word = u32::from_str_radix(&manifest_hash[index * 8..index * 8 + 8], 16)
                    .map_err(|_| DirectoryTraversalError::InvalidIdentity)?;
            }
            let mut block = [0_u8; 64];
            block.copy_from_slice(entry_identity.as_bytes());
            compress256(&mut state, &[block]);
            Ok(state.iter().map(|word| format!("{word:08x}")).collect())
        }
        _ => Err(DirectoryTraversalError::InvalidCheckpoint),
    }
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_budget_rejects_cycles_and_limits_but_allows_released_aliases() {
        let mut budget = DirectoryTraversalBudget::new(3, 3);
        let root = budget.claim("/srv/root/", None).unwrap().unwrap();
        budget.account_entries(2).unwrap();
        assert_eq!(budget.claim("/srv/root", None), Ok(None));
        let alias = budget.claim("/srv/shared", None).unwrap().unwrap();
        budget.release(&alias, None);
        assert!(budget.claim("/srv/shared", None).unwrap().is_some());
        assert_eq!(
            budget.account_entries(2),
            Err(DirectoryTraversalError::EntryLimitExceeded)
        );
        assert_eq!(
            budget.claim("/srv/third", None),
            Err(DirectoryTraversalError::DirectoryLimitExceeded)
        );
        budget.release(&root, None);
    }

    #[test]
    fn parallel_branches_keep_cycle_ancestors_independent() {
        let mut budget = DirectoryTraversalBudget::new(8, 8);
        let mut root_ancestors = HashSet::new();
        let root = budget
            .claim("/srv/root", Some(&mut root_ancestors))
            .unwrap()
            .unwrap();
        let mut branch_a = root_ancestors.clone();
        let mut branch_b = root_ancestors.clone();
        assert!(
            budget
                .claim("/srv/shared", Some(&mut branch_a))
                .unwrap()
                .is_some()
        );
        assert!(
            budget
                .claim("/srv/shared", Some(&mut branch_b))
                .unwrap()
                .is_some()
        );
        assert_eq!(budget.claim("/srv/root", Some(&mut branch_a)), Ok(None));
        budget.release(&root, Some(&mut root_ancestors));
    }

    #[test]
    fn directory_manifests_are_deterministic_ordered_and_v1_compatible() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let mut original = DirectoryResumeCheckpoint::empty();
        original.append(&first).unwrap();
        original.append(&second).unwrap();
        let mut repeated = DirectoryResumeCheckpoint::empty();
        repeated.append(&first).unwrap();
        repeated.append(&second).unwrap();
        assert_eq!(original, repeated);
        let mut reordered = DirectoryResumeCheckpoint::empty();
        reordered.append(&second).unwrap();
        reordered.append(&first).unwrap();
        assert_ne!(original.manifest_hash, reordered.manifest_hash);

        let expected = sha256_hex(format!("{}:{}", EMPTY_DIRECTORY_MANIFEST_HASH, first));
        assert_eq!(
            append_directory_manifest_identity(1, EMPTY_DIRECTORY_MANIFEST_HASH, &first).unwrap(),
            expected
        );

        let legacy = DirectoryResumeCheckpoint {
            version: 1,
            covered_entries: 1,
            completed_entries: 1,
            manifest_hash: expected,
        };
        let identities = vec![first, second];
        assert!(legacy.matches_prefix(&identities).unwrap());
        let migrated = legacy.migrate_to_v2(&identities).unwrap();
        assert_eq!(migrated.version, 2);
        assert_eq!(migrated.covered_entries, 1);
        assert_eq!(migrated.completed_entries, 1);
        assert!(migrated.matches_prefix(&identities).unwrap());
    }

    #[test]
    fn entry_identity_matches_the_legacy_json_tuple_contract() {
        let expected = sha256_hex(br#"["/source","/target",42,1700000000]"#);
        assert_eq!(
            create_directory_entry_identity("/source", "/target", 42, 1_700_000_000).unwrap(),
            expected
        );
        assert!(should_follow_symlink_directory(31));
        assert!(!should_follow_symlink_directory(32));
    }
}
