use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::directory_transfer::{
    DirectoryResumeCheckpoint, DirectoryTraversalBudget, DirectoryTraversalError,
    EMPTY_DIRECTORY_MANIFEST_HASH, MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES,
    MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES, create_directory_entry_identity,
    should_follow_symlink_directory,
};
use crate::sftp::{SftpClient, SftpEntry, SftpEntryKind, SftpError, SftpMetadata};
use crate::transfer_path::{
    TransferPathError, join_local_transfer_target, join_remote_transfer_target,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RemoteTreeOptions {
    /// Only remote-to-local downloads may opt into expanding directory links.
    pub follow_directory_symlinks: bool,
    pub max_directories: u64,
    pub max_entries: u64,
}

impl Default for RemoteTreeOptions {
    fn default() -> Self {
        Self {
            follow_directory_symlinks: false,
            max_directories: MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES,
            max_entries: MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTreeDirectoryEntry {
    pub relative_path: String,
    pub source_path: String,
    pub target_path: String,
    pub is_symlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTreeFileEntry {
    pub relative_path: String,
    pub source_path: String,
    pub target_path: String,
    pub size: u64,
    /// Milliseconds since the Unix epoch. SFTP exposes whole seconds.
    pub modified_at: u64,
    pub is_symlink: bool,
    pub directory_entry_index: u64,
    pub directory_entry_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemoteTreeSkipReason {
    DirectorySymlinkNotFollowed,
    SymlinkDepthExceeded,
    CycleDetected,
    UnsupportedFileType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTreeSkippedEntry {
    pub relative_path: String,
    pub source_path: String,
    pub reason: RemoteTreeSkipReason,
}

/// A deterministic remote-to-local directory transfer plan.
///
/// The root and every empty child directory appear in `directories`. Files use
/// the legacy DFS order: sorted child directory trees first, then sorted files
/// in the current directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTreeManifest {
    pub source_root: String,
    pub target_root: String,
    pub directories: Vec<RemoteTreeDirectoryEntry>,
    pub files: Vec<RemoteTreeFileEntry>,
    pub skipped_entries: Vec<RemoteTreeSkippedEntry>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub visited_directories: u64,
    pub visited_entries: u64,
    /// Version-2 hash of the complete discovered sequence; discovery completes
    /// no transfers, so `completed_entries` is always zero here.
    pub manifest_checkpoint: DirectoryResumeCheckpoint,
}

impl RemoteTreeManifest {
    pub fn checkpoint_for_prefix(
        &self,
        version: u8,
        covered_entries: u64,
        completed_entries: u64,
    ) -> Result<DirectoryResumeCheckpoint, RemoteTreeError> {
        if !matches!(version, 1 | 2)
            || completed_entries > covered_entries
            || covered_entries > self.total_files
        {
            return Err(RemoteTreeError::Traversal(
                DirectoryTraversalError::InvalidCheckpoint,
            ));
        }

        let mut checkpoint = if version == 1 {
            DirectoryResumeCheckpoint {
                version,
                covered_entries: 0,
                completed_entries: 0,
                manifest_hash: EMPTY_DIRECTORY_MANIFEST_HASH.to_owned(),
            }
        } else {
            DirectoryResumeCheckpoint::empty()
        };
        for entry in self.files.iter().take(covered_entries as usize) {
            checkpoint.append(&entry.directory_entry_identity)?;
        }
        checkpoint.completed_entries = completed_entries;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn matches_checkpoint(
        &self,
        checkpoint: &DirectoryResumeCheckpoint,
    ) -> Result<bool, RemoteTreeError> {
        checkpoint.validate()?;
        if checkpoint.covered_entries > self.total_files {
            return Ok(false);
        }
        let rebuilt = self.checkpoint_for_prefix(
            checkpoint.version,
            checkpoint.covered_entries,
            checkpoint.completed_entries,
        )?;
        Ok(rebuilt.manifest_hash == checkpoint.manifest_hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTreeError {
    Source(SftpError),
    Traversal(DirectoryTraversalError),
    UnsafeEntryName(TransferPathError),
    UnsafeTargetPath(TransferPathError),
    EntryNameContainsSeparator,
    DuplicateEntryName,
    NonUnicodeTargetPath,
    TotalFileCountOverflow,
    TotalByteCountOverflow,
}

impl fmt::Display for RemoteTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source(_) => "remote directory discovery failed",
            Self::Traversal(DirectoryTraversalError::DirectoryLimitExceeded) => {
                "SFTP directory traversal directory limit exceeded"
            }
            Self::Traversal(DirectoryTraversalError::EntryLimitExceeded) => {
                "SFTP directory traversal entry limit exceeded"
            }
            Self::Traversal(DirectoryTraversalError::InvalidCheckpoint) => {
                "SFTP directory resume checkpoint is invalid"
            }
            Self::Traversal(DirectoryTraversalError::InvalidIdentity) => {
                "SFTP directory manifest identity is invalid"
            }
            Self::UnsafeEntryName(_) => "SFTP server returned an unsafe directory entry name",
            Self::UnsafeTargetPath(_) => {
                "SFTP directory entry cannot be represented below the local target root"
            }
            Self::EntryNameContainsSeparator => {
                "SFTP server returned a directory entry name containing a path separator"
            }
            Self::DuplicateEntryName => {
                "SFTP server returned duplicate names in one directory listing"
            }
            Self::NonUnicodeTargetPath => "local directory target path is not valid Unicode",
            Self::TotalFileCountOverflow => "remote tree file count overflow",
            Self::TotalByteCountOverflow => "remote tree byte count overflow",
        })
    }
}

impl std::error::Error for RemoteTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(source) => Some(source),
            Self::Traversal(source) => Some(source),
            Self::UnsafeEntryName(source) | Self::UnsafeTargetPath(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SftpError> for RemoteTreeError {
    fn from(value: SftpError) -> Self {
        Self::Source(value)
    }
}

impl From<DirectoryTraversalError> for RemoteTreeError {
    fn from(value: DirectoryTraversalError) -> Self {
        Self::Traversal(value)
    }
}

/// Minimal discovery interface, kept separate from transfer I/O so directory
/// planning can be tested without a live SSH transport.
#[async_trait]
pub trait RemoteTreeSource: Send + Sync {
    async fn canonicalize(&self, path: &str) -> Result<String, SftpError>;
    async fn read_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError>;
    async fn followed_metadata(&self, path: &str) -> Result<SftpMetadata, SftpError>;
}

#[async_trait]
impl RemoteTreeSource for SftpClient {
    async fn canonicalize(&self, path: &str) -> Result<String, SftpError> {
        SftpClient::canonicalize(self, path).await
    }

    async fn read_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
        SftpClient::read_dir(self, path).await
    }

    async fn followed_metadata(&self, path: &str) -> Result<SftpMetadata, SftpError> {
        SftpClient::followed_metadata(self, path).await
    }
}

pub async fn discover_remote_tree<S: RemoteTreeSource + ?Sized>(
    source: &S,
    source_root: impl AsRef<str>,
    target_root: impl AsRef<Path>,
    options: RemoteTreeOptions,
) -> Result<RemoteTreeManifest, RemoteTreeError> {
    let source_root = normalize_remote_root(source_root.as_ref());
    // Validate both roots even when the remote tree is empty.
    join_remote_transfer_target(&source_root, ".netcatty-root-validation")
        .map_err(RemoteTreeError::UnsafeEntryName)?;
    join_local_transfer_target(target_root.as_ref(), ".netcatty-root-validation")
        .map_err(RemoteTreeError::UnsafeTargetPath)?;
    let target_root = target_root.as_ref().to_path_buf();
    let target_root_text = local_path_text(&target_root)?;

    let mut state = RemoteDiscovery {
        source,
        options,
        target_root,
        budget: DirectoryTraversalBudget::new(options.max_directories, options.max_entries),
        directories: Vec::new(),
        files: Vec::new(),
        skipped_entries: Vec::new(),
        total_files: 0,
        total_bytes: 0,
        manifest_checkpoint: DirectoryResumeCheckpoint::empty(),
    };
    state
        .walk_directory(source_root.clone(), String::new(), false, 0)
        .await?;

    Ok(RemoteTreeManifest {
        source_root,
        target_root: target_root_text,
        directories: state.directories,
        files: state.files,
        skipped_entries: state.skipped_entries,
        total_files: state.total_files,
        total_bytes: state.total_bytes,
        visited_directories: state.budget.visited_directories,
        visited_entries: state.budget.visited_entries,
        manifest_checkpoint: state.manifest_checkpoint,
    })
}

struct RemoteDiscovery<'a, S: RemoteTreeSource + ?Sized> {
    source: &'a S,
    options: RemoteTreeOptions,
    target_root: PathBuf,
    budget: DirectoryTraversalBudget,
    directories: Vec<RemoteTreeDirectoryEntry>,
    files: Vec<RemoteTreeFileEntry>,
    skipped_entries: Vec<RemoteTreeSkippedEntry>,
    total_files: u64,
    total_bytes: u64,
    manifest_checkpoint: DirectoryResumeCheckpoint,
}

impl<S: RemoteTreeSource + ?Sized> RemoteDiscovery<'_, S> {
    fn walk_directory(
        &mut self,
        source_path: String,
        relative_path: String,
        is_symlink: bool,
        symlink_depth: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteTreeError>> + Send + '_>> {
        Box::pin(async move {
            let canonical = self.source.canonicalize(&source_path).await?;
            let Some(claimed) = self.budget.claim(&canonical, None)? else {
                self.skipped_entries.push(RemoteTreeSkippedEntry {
                    relative_path,
                    source_path,
                    reason: RemoteTreeSkipReason::CycleDetected,
                });
                return Ok(());
            };

            let result = self
                .walk_claimed_directory(source_path, relative_path, is_symlink, symlink_depth)
                .await;
            self.budget.release(&claimed, None);
            result
        })
    }

    async fn walk_claimed_directory(
        &mut self,
        source_path: String,
        relative_path: String,
        is_symlink: bool,
        symlink_depth: usize,
    ) -> Result<(), RemoteTreeError> {
        let target_path = if relative_path.is_empty() {
            self.target_root.clone()
        } else {
            join_local_transfer_target(&self.target_root, &relative_path)
                .map_err(RemoteTreeError::UnsafeTargetPath)?
        };
        self.directories.push(RemoteTreeDirectoryEntry {
            relative_path: relative_path.clone(),
            source_path: source_path.clone(),
            target_path: local_path_text(&target_path)?,
            is_symlink,
        });

        let mut listed = self.source.read_directory(&source_path).await?;
        listed.retain(|entry| entry.name != "." && entry.name != "..");
        self.budget.account_entries(
            u64::try_from(listed.len()).map_err(|_| RemoteTreeError::TotalFileCountOverflow)?,
        )?;
        listed.sort_by(|left, right| left.name.cmp(&right.name));
        if listed.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(RemoteTreeError::DuplicateEntryName);
        }

        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut unsupported = Vec::new();
        for entry in listed {
            let pending = self
                .classify_entry(&source_path, &relative_path, entry)
                .await?;
            match pending.kind {
                PendingKind::Directory => directories.push(pending),
                PendingKind::File => files.push(pending),
                PendingKind::Unsupported => unsupported.push(pending),
            }
        }

        for entry in directories {
            if entry.is_symlink && !self.options.follow_directory_symlinks {
                self.skip(&entry, RemoteTreeSkipReason::DirectorySymlinkNotFollowed);
                continue;
            }
            if entry.is_symlink && !should_follow_symlink_directory(symlink_depth) {
                self.skip(&entry, RemoteTreeSkipReason::SymlinkDepthExceeded);
                continue;
            }
            self.walk_directory(
                entry.source_path,
                entry.relative_path,
                entry.is_symlink,
                symlink_depth + usize::from(entry.is_symlink),
            )
            .await?;
        }
        for entry in files {
            self.append_file(entry)?;
        }
        for entry in unsupported {
            self.skip(&entry, RemoteTreeSkipReason::UnsupportedFileType);
        }
        Ok(())
    }

    async fn classify_entry(
        &self,
        parent_source: &str,
        parent_relative: &str,
        entry: SftpEntry,
    ) -> Result<PendingEntry, RemoteTreeError> {
        if entry.name.contains('/') {
            return Err(RemoteTreeError::EntryNameContainsSeparator);
        }
        let source_path = join_remote_transfer_target(parent_source, &entry.name)
            .map_err(RemoteTreeError::UnsafeEntryName)?;
        let relative_path = safe_relative_child(parent_relative, &entry.name)?;
        let target_path = join_local_transfer_target(&self.target_root, &relative_path)
            .map_err(RemoteTreeError::UnsafeTargetPath)?;
        let is_symlink = entry.metadata.kind == SftpEntryKind::Symlink;
        let metadata = if is_symlink {
            self.source.followed_metadata(&source_path).await?
        } else {
            entry.metadata
        };
        let kind = match metadata.kind {
            SftpEntryKind::Directory => PendingKind::Directory,
            SftpEntryKind::File => PendingKind::File,
            SftpEntryKind::Symlink | SftpEntryKind::Other => PendingKind::Unsupported,
        };
        Ok(PendingEntry {
            source_path,
            relative_path,
            target_path,
            metadata,
            kind,
            is_symlink,
        })
    }

    fn append_file(&mut self, entry: PendingEntry) -> Result<(), RemoteTreeError> {
        let size = entry.metadata.size;
        let modified_at = u64::from(entry.metadata.modified_at.unwrap_or(0)).saturating_mul(1_000);
        let target_path = local_path_text(&entry.target_path)?;
        let directory_entry_identity =
            create_directory_entry_identity(&entry.source_path, &target_path, size, modified_at)?;
        let directory_entry_index = self.total_files;
        self.total_files = self
            .total_files
            .checked_add(1)
            .ok_or(RemoteTreeError::TotalFileCountOverflow)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or(RemoteTreeError::TotalByteCountOverflow)?;
        self.manifest_checkpoint.append(&directory_entry_identity)?;
        self.files.push(RemoteTreeFileEntry {
            relative_path: entry.relative_path,
            source_path: entry.source_path,
            target_path,
            size,
            modified_at,
            is_symlink: entry.is_symlink,
            directory_entry_index,
            directory_entry_identity,
        });
        Ok(())
    }

    fn skip(&mut self, entry: &PendingEntry, reason: RemoteTreeSkipReason) {
        self.skipped_entries.push(RemoteTreeSkippedEntry {
            relative_path: entry.relative_path.clone(),
            source_path: entry.source_path.clone(),
            reason,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Directory,
    File,
    Unsupported,
}

struct PendingEntry {
    source_path: String,
    relative_path: String,
    target_path: PathBuf,
    metadata: SftpMetadata,
    kind: PendingKind,
    is_symlink: bool,
}

fn normalize_remote_root(root: &str) -> String {
    let trimmed = root.trim_end_matches('/');
    if trimmed.is_empty() && root.starts_with('/') {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn safe_relative_child(parent: &str, name: &str) -> Result<String, RemoteTreeError> {
    let candidate = if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    };
    let validated =
        join_remote_transfer_target("/", &candidate).map_err(RemoteTreeError::UnsafeEntryName)?;
    Ok(validated.trim_start_matches('/').to_owned())
}

fn local_path_text(path: &Path) -> Result<String, RemoteTreeError> {
    let text = path.to_str().ok_or(RemoteTreeError::NonUnicodeTargetPath)?;
    #[cfg(windows)]
    {
        Ok(text.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        Ok(text.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct MockRemoteTree {
        directories: HashMap<String, Vec<SftpEntry>>,
        canonical: HashMap<String, String>,
        followed: HashMap<String, SftpMetadata>,
    }

    #[async_trait]
    impl RemoteTreeSource for MockRemoteTree {
        async fn canonicalize(&self, path: &str) -> Result<String, SftpError> {
            Ok(self
                .canonical
                .get(path)
                .cloned()
                .unwrap_or_else(|| path.to_owned()))
        }

        async fn read_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
            self.directories
                .get(path)
                .cloned()
                .ok_or(SftpError::OperationFailed)
        }

        async fn followed_metadata(&self, path: &str) -> Result<SftpMetadata, SftpError> {
            self.followed
                .get(path)
                .cloned()
                .ok_or(SftpError::OperationFailed)
        }
    }

    fn metadata(kind: SftpEntryKind, size: u64, modified_at: Option<u32>) -> SftpMetadata {
        SftpMetadata {
            kind,
            size,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            accessed_at: None,
            modified_at,
        }
    }

    fn entry(name: &str, kind: SftpEntryKind, size: u64, modified_at: u32) -> SftpEntry {
        SftpEntry {
            name: name.to_owned(),
            // Deliberately hostile: discovery must never trust this field.
            path: "../../server-controlled-path".to_owned(),
            metadata: metadata(kind, size, Some(modified_at)),
        }
    }

    fn deterministic_tree() -> MockRemoteTree {
        let mut source = MockRemoteTree::default();
        source.directories.insert(
            "/root".to_owned(),
            vec![
                entry("z.txt", SftpEntryKind::File, 1, 7),
                entry("empty", SftpEntryKind::Directory, 0, 0),
                entry("alpha", SftpEntryKind::Directory, 0, 0),
                entry(".", SftpEntryKind::Directory, 0, 0),
                entry("..", SftpEntryKind::Directory, 0, 0),
            ],
        );
        source.directories.insert(
            "/root/alpha".to_owned(),
            vec![
                entry("b.txt", SftpEntryKind::File, 2, 8),
                entry("nested", SftpEntryKind::Directory, 0, 0),
            ],
        );
        source.directories.insert(
            "/root/alpha/nested".to_owned(),
            vec![entry("a.txt", SftpEntryKind::File, 3, 9)],
        );
        source
            .directories
            .insert("/root/empty".to_owned(), Vec::new());
        source
    }

    #[tokio::test]
    async fn discovery_is_directory_first_deterministic_and_serializable() {
        let source = deterministic_tree();
        let first = discover_remote_tree(
            &source,
            "/root/",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions::default(),
        )
        .await
        .unwrap();
        let repeated = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(first, repeated);
        assert_eq!(
            first
                .directories
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["", "alpha", "alpha/nested", "empty"]
        );
        assert_eq!(
            first
                .files
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["alpha/nested/a.txt", "alpha/b.txt", "z.txt"]
        );
        assert_eq!(first.files[0].source_path, "/root/alpha/nested/a.txt");
        assert_eq!(first.files[0].modified_at, 9_000);
        assert_eq!(first.total_files, 3);
        assert_eq!(first.total_bytes, 6);
        assert_eq!(first.visited_entries, 6);
        assert_eq!(first.manifest_checkpoint.covered_entries, 3);
        assert!(
            first
                .matches_checkpoint(&first.manifest_checkpoint)
                .unwrap()
        );
        let legacy = first.checkpoint_for_prefix(1, 2, 1).unwrap();
        assert!(first.matches_checkpoint(&legacy).unwrap());
        let encoded = serde_json::to_vec(&first).unwrap();
        let decoded: RemoteTreeManifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, first);
    }

    #[tokio::test]
    async fn directory_symlinks_are_opt_in_and_cycles_are_branch_local() {
        let mut source = MockRemoteTree::default();
        source.directories.insert(
            "/root".to_owned(),
            vec![
                entry("alias", SftpEntryKind::Symlink, 0, 0),
                entry("real", SftpEntryKind::Directory, 0, 0),
            ],
        );
        for directory in ["/root/alias", "/root/real"] {
            source.directories.insert(
                directory.to_owned(),
                vec![
                    entry("loop", SftpEntryKind::Symlink, 0, 0),
                    entry("file.txt", SftpEntryKind::File, 4, 10),
                ],
            );
            source.followed.insert(
                format!("{directory}/loop"),
                metadata(SftpEntryKind::Directory, 0, None),
            );
            source
                .canonical
                .insert(format!("{directory}/loop"), "/root".to_owned());
        }
        source.followed.insert(
            "/root/alias".to_owned(),
            metadata(SftpEntryKind::Directory, 0, None),
        );
        source
            .canonical
            .insert("/root/alias".to_owned(), "/root/real".to_owned());

        let default_manifest = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            default_manifest
                .files
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["real/file.txt"]
        );

        let followed = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions {
                follow_directory_symlinks: true,
                ..RemoteTreeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            followed
                .files
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["alias/file.txt", "real/file.txt"]
        );
        assert_eq!(
            followed
                .skipped_entries
                .iter()
                .filter(|entry| entry.reason == RemoteTreeSkipReason::CycleDetected)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn followed_directory_symlinks_stop_at_the_shared_depth_limit() {
        let mut source = MockRemoteTree::default();
        source.directories.insert(
            "/root".to_owned(),
            vec![entry("start", SftpEntryKind::Symlink, 0, 0)],
        );
        source.followed.insert(
            "/root/start".to_owned(),
            metadata(SftpEntryKind::Directory, 0, None),
        );

        let mut current = "/root/start".to_owned();
        for depth in 1..=32 {
            let next = format!("{current}/next");
            let mut entries = vec![entry("next", SftpEntryKind::Symlink, 0, 0)];
            if depth == 32 {
                entries.push(entry("visible.txt", SftpEntryKind::File, 7, 11));
            }
            source.directories.insert(current, entries);
            source
                .followed
                .insert(next.clone(), metadata(SftpEntryKind::Directory, 0, None));
            current = next;
        }

        let manifest = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions {
                follow_directory_symlinks: true,
                ..RemoteTreeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(manifest.total_files, 1);
        assert!(manifest.files[0].relative_path.ends_with("visible.txt"));
        assert_eq!(manifest.files[0].modified_at, 11_000);
        assert_eq!(
            manifest
                .skipped_entries
                .iter()
                .filter(|entry| entry.reason == RemoteTreeSkipReason::SymlinkDepthExceeded)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn discovery_enforces_shared_entry_and_directory_budgets() {
        let mut source = MockRemoteTree::default();
        source.directories.insert(
            "/root".to_owned(),
            vec![
                entry("a", SftpEntryKind::File, 1, 0),
                entry("b", SftpEntryKind::File, 1, 0),
            ],
        );
        let entry_error = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions {
                max_entries: 1,
                ..RemoteTreeOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            entry_error,
            RemoteTreeError::Traversal(DirectoryTraversalError::EntryLimitExceeded)
        ));

        source.directories.insert(
            "/root".to_owned(),
            vec![entry("child", SftpEntryKind::Directory, 0, 0)],
        );
        source
            .directories
            .insert("/root/child".to_owned(), Vec::new());
        let directory_error = discover_remote_tree(
            &source,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions {
                max_directories: 1,
                ..RemoteTreeOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            directory_error,
            RemoteTreeError::Traversal(DirectoryTraversalError::DirectoryLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn hostile_server_names_cannot_escape_or_reinterpret_the_local_root() {
        for hostile in [
            "../outside",
            "nested/file",
            "/absolute",
            "C:/outside",
            r"..\outside",
            "name:stream",
            "trailing. ",
            "",
        ] {
            let mut source = MockRemoteTree::default();
            source.directories.insert(
                "/root".to_owned(),
                vec![entry(hostile, SftpEntryKind::File, 1, 0)],
            );
            let result = discover_remote_tree(
                &source,
                "/root",
                Path::new(r"C:\downloads"),
                RemoteTreeOptions::default(),
            )
            .await;
            assert!(result.is_err(), "hostile entry {hostile:?} was accepted");
        }

        let mut dot_entries = MockRemoteTree::default();
        dot_entries.directories.insert(
            "/root".to_owned(),
            vec![
                entry(".", SftpEntryKind::Directory, 0, 0),
                entry("..", SftpEntryKind::Directory, 0, 0),
            ],
        );
        let manifest = discover_remote_tree(
            &dot_entries,
            "/root",
            Path::new(r"C:\downloads"),
            RemoteTreeOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(manifest.directories.len(), 1);
        assert!(manifest.files.is_empty());
        assert_eq!(manifest.visited_entries, 0);
    }
}
