use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::directory_transfer::{
    DirectoryResumeCheckpoint, DirectoryTraversalBudget, DirectoryTraversalError,
    EMPTY_DIRECTORY_MANIFEST_HASH, MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES,
    MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES, create_directory_entry_identity,
    should_follow_symlink_directory,
};

/// Policy and safety limits for one local directory discovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LocalTreeOptions {
    /// Directory links are deliberately not expanded unless the caller opts in.
    pub follow_directory_symlinks: bool,
    pub max_directories: u64,
    pub max_entries: u64,
}

impl Default for LocalTreeOptions {
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
pub struct LocalTreeDirectoryEntry {
    pub relative_path: String,
    pub source_path: String,
    pub target_path: String,
    pub is_symlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTreeFileEntry {
    pub relative_path: String,
    pub source_path: String,
    pub target_path: String,
    pub size: u64,
    /// Milliseconds since the Unix epoch, matching the legacy local-file bridge.
    pub modified_at: u64,
    pub is_symlink: bool,
    pub directory_entry_index: u64,
    pub directory_entry_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalTreeSkipReason {
    DirectorySymlinkNotFollowed,
    SymlinkDepthExceeded,
    CycleDetected,
    UnsupportedFileType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTreeSkippedEntry {
    pub relative_path: String,
    pub source_path: String,
    pub reason: LocalTreeSkipReason,
}

/// A point-in-time, deterministically ordered transfer plan for a local tree.
///
/// `directories` includes the source root as its first entry. `files` follows
/// the legacy resume order: recursively visit sorted child directories first,
/// then append the current directory's sorted files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTreeManifest {
    pub source_root: String,
    pub target_root: String,
    pub directories: Vec<LocalTreeDirectoryEntry>,
    pub files: Vec<LocalTreeFileEntry>,
    pub skipped_entries: Vec<LocalTreeSkippedEntry>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub visited_directories: u64,
    pub visited_entries: u64,
    /// Version-2 hash of the complete discovered file sequence.
    ///
    /// Completion remains zero because discovery alone does not transfer data.
    pub manifest_checkpoint: DirectoryResumeCheckpoint,
}

impl LocalTreeManifest {
    /// Rebuild a compact resume checkpoint for a prefix of this manifest.
    /// Version 1 is retained for persisted legacy transfer history.
    pub fn checkpoint_for_prefix(
        &self,
        version: u8,
        covered_entries: u64,
        completed_entries: u64,
    ) -> Result<DirectoryResumeCheckpoint, LocalTreeError> {
        if !matches!(version, 1 | 2)
            || completed_entries > covered_entries
            || covered_entries > self.total_files
        {
            return Err(LocalTreeError::Traversal(
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

    /// Verify that an existing V1/V2 checkpoint still describes this tree's
    /// ordered prefix. An oversized prefix is a stale plan, not a parse error.
    pub fn matches_checkpoint(
        &self,
        checkpoint: &DirectoryResumeCheckpoint,
    ) -> Result<bool, LocalTreeError> {
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

#[derive(Debug)]
pub enum LocalTreeError {
    Io { path: PathBuf, source: io::Error },
    NotDirectory(PathBuf),
    NonUnicodePath(PathBuf),
    TotalFileCountOverflow,
    TotalByteCountOverflow,
    Traversal(DirectoryTraversalError),
}

impl fmt::Display for LocalTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "local tree I/O failed at {}: {source}",
                    path.display()
                )
            }
            Self::NotDirectory(path) => {
                write!(
                    formatter,
                    "local tree root is not a directory: {}",
                    path.display()
                )
            }
            Self::NonUnicodePath(path) => {
                write!(
                    formatter,
                    "local tree path is not valid Unicode: {}",
                    path.display()
                )
            }
            Self::TotalFileCountOverflow => formatter.write_str("local tree file count overflow"),
            Self::TotalByteCountOverflow => formatter.write_str("local tree byte count overflow"),
            Self::Traversal(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for LocalTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Traversal(source) => Some(source),
            _ => None,
        }
    }
}

impl From<DirectoryTraversalError> for LocalTreeError {
    fn from(value: DirectoryTraversalError) -> Self {
        Self::Traversal(value)
    }
}

/// Discover a local directory without following directory symlinks by default.
///
/// `target_root` participates in each legacy-compatible entry identity, so the
/// same source planned for a different destination intentionally has a
/// different resume manifest.
pub fn discover_local_tree(
    source_root: impl AsRef<Path>,
    target_root: impl AsRef<str>,
    options: LocalTreeOptions,
) -> Result<LocalTreeManifest, LocalTreeError> {
    let source_root = source_root.as_ref().to_path_buf();
    let root_metadata = fs::metadata(&source_root).map_err(|source| LocalTreeError::Io {
        path: source_root.clone(),
        source,
    })?;
    if !root_metadata.is_dir() {
        return Err(LocalTreeError::NotDirectory(source_root));
    }
    let root_is_symlink = fs::symlink_metadata(&source_root)
        .map_err(|source| LocalTreeError::Io {
            path: source_root.clone(),
            source,
        })?
        .file_type()
        .is_symlink();
    let source_root_text = local_path_text(&source_root)?;
    let target_root_text = normalize_target_root(target_root.as_ref());

    let mut state = DiscoveryState {
        options,
        target_root: target_root_text.clone(),
        budget: DirectoryTraversalBudget::new(options.max_directories, options.max_entries),
        directories: Vec::new(),
        files: Vec::new(),
        skipped_entries: Vec::new(),
        total_files: 0,
        total_bytes: 0,
        manifest_checkpoint: DirectoryResumeCheckpoint::empty(),
    };
    state.walk_directory(&source_root, "", root_is_symlink, 0)?;

    Ok(LocalTreeManifest {
        source_root: source_root_text,
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

struct DiscoveryState {
    options: LocalTreeOptions,
    target_root: String,
    budget: DirectoryTraversalBudget,
    directories: Vec<LocalTreeDirectoryEntry>,
    files: Vec<LocalTreeFileEntry>,
    skipped_entries: Vec<LocalTreeSkippedEntry>,
    total_files: u64,
    total_bytes: u64,
    manifest_checkpoint: DirectoryResumeCheckpoint,
}

impl DiscoveryState {
    fn walk_directory(
        &mut self,
        source_path: &Path,
        relative_path: &str,
        is_symlink: bool,
        symlink_depth: usize,
    ) -> Result<(), LocalTreeError> {
        let canonical = fs::canonicalize(source_path).map_err(|source| LocalTreeError::Io {
            path: source_path.to_path_buf(),
            source,
        })?;
        let canonical_text = local_path_text(&canonical)?;
        let Some(claimed) = self.budget.claim(&canonical_text, None)? else {
            self.skip(
                source_path,
                relative_path,
                LocalTreeSkipReason::CycleDetected,
            )?;
            return Ok(());
        };

        let result =
            self.walk_claimed_directory(source_path, relative_path, is_symlink, symlink_depth);
        self.budget.release(&claimed, None);
        result
    }

    fn walk_claimed_directory(
        &mut self,
        source_path: &Path,
        relative_path: &str,
        is_symlink: bool,
        symlink_depth: usize,
    ) -> Result<(), LocalTreeError> {
        self.directories.push(LocalTreeDirectoryEntry {
            relative_path: relative_path.to_owned(),
            source_path: local_path_text(source_path)?,
            target_path: join_target_path(&self.target_root, relative_path),
            is_symlink,
        });

        let reader = fs::read_dir(source_path).map_err(|source| LocalTreeError::Io {
            path: source_path.to_path_buf(),
            source,
        })?;
        let mut entries = Vec::new();
        for result in reader {
            self.budget.account_entries(1)?;
            let entry = result.map_err(|source| LocalTreeError::Io {
                path: source_path.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| LocalTreeError::NonUnicodePath(path.clone()))?;
            let file_type = entry.file_type().map_err(|source| LocalTreeError::Io {
                path: path.clone(),
                source,
            })?;
            let (kind, is_symlink) = if file_type.is_symlink() {
                let target = fs::metadata(&path).map_err(|source| LocalTreeError::Io {
                    path: path.clone(),
                    source,
                })?;
                if target.is_dir() {
                    (PendingKind::Directory, true)
                } else if target.is_file() {
                    (PendingKind::File, true)
                } else {
                    (PendingKind::Unsupported, true)
                }
            } else if file_type.is_dir() {
                (PendingKind::Directory, false)
            } else if file_type.is_file() {
                (PendingKind::File, false)
            } else {
                (PendingKind::Unsupported, false)
            };
            entries.push(PendingEntry {
                name,
                path,
                kind,
                is_symlink,
            });
        }
        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));

        // Preserve the legacy resume order: all sorted child directory trees
        // complete before files belonging to this directory are appended.
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == PendingKind::Directory)
        {
            let child_relative = join_relative_path(relative_path, &entry.name);
            if entry.is_symlink && !self.options.follow_directory_symlinks {
                self.skip(
                    &entry.path,
                    &child_relative,
                    LocalTreeSkipReason::DirectorySymlinkNotFollowed,
                )?;
                continue;
            }
            if entry.is_symlink && !should_follow_symlink_directory(symlink_depth) {
                self.skip(
                    &entry.path,
                    &child_relative,
                    LocalTreeSkipReason::SymlinkDepthExceeded,
                )?;
                continue;
            }
            self.walk_directory(
                &entry.path,
                &child_relative,
                entry.is_symlink,
                symlink_depth + usize::from(entry.is_symlink),
            )?;
        }

        for entry in entries
            .iter()
            .filter(|entry| entry.kind == PendingKind::File)
        {
            self.append_file(entry, relative_path)?;
        }
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == PendingKind::Unsupported)
        {
            let child_relative = join_relative_path(relative_path, &entry.name);
            self.skip(
                &entry.path,
                &child_relative,
                LocalTreeSkipReason::UnsupportedFileType,
            )?;
        }
        Ok(())
    }

    fn append_file(
        &mut self,
        entry: &PendingEntry,
        parent_relative_path: &str,
    ) -> Result<(), LocalTreeError> {
        // Follow file symlinks just as opening them for upload will do.
        let metadata = fs::metadata(&entry.path).map_err(|source| LocalTreeError::Io {
            path: entry.path.clone(),
            source,
        })?;
        let size = metadata.len();
        let modified_at = modified_millis(&metadata);
        let relative_path = join_relative_path(parent_relative_path, &entry.name);
        let source_path = local_path_text(&entry.path)?;
        let target_path = join_target_path(&self.target_root, &relative_path);
        let directory_entry_identity =
            create_directory_entry_identity(&source_path, &target_path, size, modified_at)?;
        let directory_entry_index = self.total_files;

        self.total_files = self
            .total_files
            .checked_add(1)
            .ok_or(LocalTreeError::TotalFileCountOverflow)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or(LocalTreeError::TotalByteCountOverflow)?;
        self.manifest_checkpoint.append(&directory_entry_identity)?;
        self.files.push(LocalTreeFileEntry {
            relative_path,
            source_path,
            target_path,
            size,
            modified_at,
            is_symlink: entry.is_symlink,
            directory_entry_index,
            directory_entry_identity,
        });
        Ok(())
    }

    fn skip(
        &mut self,
        source_path: &Path,
        relative_path: &str,
        reason: LocalTreeSkipReason,
    ) -> Result<(), LocalTreeError> {
        self.skipped_entries.push(LocalTreeSkippedEntry {
            relative_path: relative_path.to_owned(),
            source_path: local_path_text(source_path)?,
            reason,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Directory,
    File,
    Unsupported,
}

struct PendingEntry {
    name: String,
    path: PathBuf,
    kind: PendingKind,
    is_symlink: bool,
}

fn local_path_text(path: &Path) -> Result<String, LocalTreeError> {
    let text = path
        .to_str()
        .ok_or_else(|| LocalTreeError::NonUnicodePath(path.to_path_buf()))?;
    #[cfg(windows)]
    {
        Ok(text.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        Ok(text.to_owned())
    }
}

fn normalize_target_root(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() && normalized.starts_with('/') {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn join_relative_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn join_target_path(root: &str, relative_path: &str) -> String {
    if relative_path.is_empty() {
        return root.to_owned();
    }
    match root {
        "" => relative_path.to_owned(),
        "/" => format!("/{relative_path}"),
        _ => format!("{root}/{relative_path}"),
    }
}

fn modified_millis(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_TEMP_TREE: AtomicU64 = AtomicU64::new(0);

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let sequence = NEXT_TEMP_TREE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "netcatty-local-tree-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn discovery_is_deterministic_directory_first_and_serializable() {
        let tree = TempTree::new();
        fs::create_dir_all(tree.0.join("alpha").join("inner")).unwrap();
        fs::create_dir_all(tree.0.join("beta")).unwrap();
        fs::write(tree.0.join("z.txt"), b"z").unwrap();
        fs::write(tree.0.join("a.txt"), b"aa").unwrap();
        fs::write(tree.0.join("alpha").join("root.txt"), b"aaaa").unwrap();
        fs::write(
            tree.0.join("alpha").join("inner").join("deep.txt"),
            b"aaaaa",
        )
        .unwrap();
        fs::write(tree.0.join("beta").join("child.txt"), b"bbb").unwrap();

        let first =
            discover_local_tree(&tree.0, "/uploads/root/", LocalTreeOptions::default()).unwrap();
        let repeated =
            discover_local_tree(&tree.0, "/uploads/root", LocalTreeOptions::default()).unwrap();
        assert_eq!(first, repeated);
        assert_eq!(
            first
                .directories
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["", "alpha", "alpha/inner", "beta"]
        );
        assert_eq!(
            first
                .files
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            [
                "alpha/inner/deep.txt",
                "alpha/root.txt",
                "beta/child.txt",
                "a.txt",
                "z.txt"
            ]
        );
        assert_eq!(first.total_files, 5);
        assert_eq!(first.total_bytes, 15);
        assert_eq!(first.manifest_checkpoint.covered_entries, 5);
        assert_eq!(first.manifest_checkpoint.completed_entries, 0);
        assert!(
            first
                .matches_checkpoint(&first.manifest_checkpoint)
                .unwrap()
        );

        let legacy = first.checkpoint_for_prefix(1, 3, 2).unwrap();
        assert!(first.matches_checkpoint(&legacy).unwrap());
        let different_target =
            discover_local_tree(&tree.0, "/uploads/elsewhere", LocalTreeOptions::default())
                .unwrap();
        assert!(!different_target.matches_checkpoint(&legacy).unwrap());
        let encoded = serde_json::to_vec(&first).unwrap();
        let decoded: LocalTreeManifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, first);
    }

    #[test]
    fn discovery_enforces_entry_and_directory_limits() {
        let tree = TempTree::new();
        fs::write(tree.0.join("a"), b"a").unwrap();
        fs::write(tree.0.join("b"), b"b").unwrap();
        let entry_error = discover_local_tree(
            &tree.0,
            "/target",
            LocalTreeOptions {
                max_entries: 1,
                ..LocalTreeOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            entry_error,
            LocalTreeError::Traversal(DirectoryTraversalError::EntryLimitExceeded)
        ));

        fs::remove_file(tree.0.join("a")).unwrap();
        fs::remove_file(tree.0.join("b")).unwrap();
        fs::create_dir(tree.0.join("child")).unwrap();
        let directory_error = discover_local_tree(
            &tree.0,
            "/target",
            LocalTreeOptions {
                max_directories: 1,
                ..LocalTreeOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            directory_error,
            LocalTreeError::Traversal(DirectoryTraversalError::DirectoryLimitExceeded)
        ));
    }

    #[test]
    fn directory_symlinks_are_opt_in_and_cycles_are_branch_local() {
        let tree = TempTree::new();
        let real = tree.0.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("file.txt"), b"content").unwrap();
        if create_directory_symlink(&real, &tree.0.join("alias")).is_err() {
            // Windows can require Developer Mode or elevated symlink rights.
            return;
        }
        if create_directory_symlink(&tree.0, &real.join("loop")).is_err() {
            return;
        }

        let default_manifest =
            discover_local_tree(&tree.0, "/target", LocalTreeOptions::default()).unwrap();
        assert_eq!(
            default_manifest
                .files
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["real/file.txt"]
        );
        assert!(default_manifest.skipped_entries.iter().any(|entry| {
            entry.relative_path == "alias"
                && entry.reason == LocalTreeSkipReason::DirectorySymlinkNotFollowed
        }));

        let followed = discover_local_tree(
            &tree.0,
            "/target",
            LocalTreeOptions {
                follow_directory_symlinks: true,
                ..LocalTreeOptions::default()
            },
        )
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
                .filter(|entry| entry.reason == LocalTreeSkipReason::CycleDetected)
                .count(),
            2
        );
    }

    #[test]
    fn followed_directory_symlinks_stop_at_the_shared_depth_limit() {
        let tree = TempTree::new();
        let source = tree.0.join("source");
        let targets = tree.0.join("targets");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&targets).unwrap();
        for index in 0..=32 {
            fs::create_dir(targets.join(index.to_string())).unwrap();
        }
        if create_directory_symlink(&targets.join("0"), &source.join("start")).is_err() {
            return;
        }
        for index in 0..32 {
            if create_directory_symlink(
                &targets.join((index + 1).to_string()),
                &targets.join(index.to_string()).join("next"),
            )
            .is_err()
            {
                return;
            }
        }
        fs::write(targets.join("31").join("visible.txt"), b"visible").unwrap();
        fs::write(targets.join("32").join("hidden.txt"), b"hidden").unwrap();

        let manifest = discover_local_tree(
            &source,
            "/target",
            LocalTreeOptions {
                follow_directory_symlinks: true,
                ..LocalTreeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(manifest.total_files, 1);
        assert!(manifest.files[0].relative_path.ends_with("visible.txt"));
        assert_eq!(
            manifest
                .skipped_entries
                .iter()
                .filter(|entry| entry.reason == LocalTreeSkipReason::SymlinkDepthExceeded)
                .count(),
            1
        );
    }

    #[cfg(unix)]
    fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }
}
