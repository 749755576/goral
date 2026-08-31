use std::fmt;
use std::path::{Path, PathBuf};

/// A lexical safety failure while turning a discovered tree entry into a
/// transfer destination.
///
/// The error intentionally does not retain the rejected path. Directory names
/// can contain sensitive information and should not accidentally cross an IPC
/// or logging boundary through an error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPathError {
    EmptyRoot,
    EmptyRelativePath,
    ContainsNul,
    AbsoluteRelativePath,
    DrivePrefixedRelativePath,
    EmptySegment,
    CurrentDirectorySegment,
    ParentDirectorySegment,
    InvalidWindowsSegment,
    OutsideRoot,
}

impl fmt::Display for TransferPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyRoot => "transfer destination root is empty",
            Self::EmptyRelativePath => "transfer relative path is empty",
            Self::ContainsNul => "transfer path contains a NUL byte",
            Self::AbsoluteRelativePath => "transfer relative path is absolute",
            Self::DrivePrefixedRelativePath => {
                "transfer relative path contains a Windows drive prefix"
            }
            Self::EmptySegment => "transfer relative path contains an empty segment",
            Self::CurrentDirectorySegment => {
                "transfer relative path contains a current-directory segment"
            }
            Self::ParentDirectorySegment => {
                "transfer relative path contains a parent-directory segment"
            }
            Self::InvalidWindowsSegment => {
                "transfer relative path contains a Windows-unsafe segment"
            }
            Self::OutsideRoot => "transfer destination escapes its root",
        })
    }
}

impl std::error::Error for TransferPathError {}

/// Safely joins a slash-delimited recursive-transfer path below a remote
/// (POSIX/SFTP) destination root.
///
/// Backslashes are ordinary remote filename characters. Only `/` separates
/// entries, so a remote file literally named `a\\b` remains representable.
pub fn join_remote_transfer_target(
    root: &str,
    relative_path: &str,
) -> Result<String, TransferPathError> {
    validate_text_root(root)?;
    let segments = validate_relative_segments(relative_path, false)?;

    let trimmed_root = root.trim_end_matches('/');
    let normalized_root = if trimmed_root.is_empty() && root.starts_with('/') {
        "/"
    } else {
        trimmed_root
    };
    let relative = segments.join("/");
    let target = if normalized_root == "/" {
        format!("/{relative}")
    } else {
        format!("{normalized_root}/{relative}")
    };

    if remote_target_is_below_root(normalized_root, &target) {
        Ok(target)
    } else {
        Err(TransferPathError::OutsideRoot)
    }
}

/// Safely joins a slash-delimited recursive-transfer path below a local
/// destination root.
///
/// On Windows, and for a Windows drive/UNC root inspected on another host,
/// backslashes, colons, and segments ending in a dot or space are rejected.
/// This validation happens before `PathBuf::push`, preventing inputs such as
/// `..\\outside.txt` from being reinterpreted as multiple Windows components.
pub fn join_local_transfer_target(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, TransferPathError> {
    validate_local_root(root)?;
    let windows_target = is_windows_local_target(root);
    let segments = validate_relative_segments(relative_path, windows_target)?;

    let mut target = root.to_path_buf();
    for segment in segments {
        target.push(segment);
    }

    // The segment validator rejects every component capable of replacing or
    // walking above the base. Keep this independent check as a final invariant
    // in case platform path parsing grows new prefix behavior.
    if target.starts_with(root) {
        Ok(target)
    } else {
        Err(TransferPathError::OutsideRoot)
    }
}

fn validate_text_root(root: &str) -> Result<(), TransferPathError> {
    if root.is_empty() {
        return Err(TransferPathError::EmptyRoot);
    }
    if root.contains('\0') {
        return Err(TransferPathError::ContainsNul);
    }
    Ok(())
}

fn validate_local_root(root: &Path) -> Result<(), TransferPathError> {
    if root.as_os_str().is_empty() {
        return Err(TransferPathError::EmptyRoot);
    }
    if root.as_os_str().to_string_lossy().contains('\0') {
        return Err(TransferPathError::ContainsNul);
    }
    Ok(())
}

fn validate_relative_segments(
    relative_path: &str,
    windows_target: bool,
) -> Result<Vec<&str>, TransferPathError> {
    if relative_path.is_empty() {
        return Err(TransferPathError::EmptyRelativePath);
    }
    if relative_path.contains('\0') {
        return Err(TransferPathError::ContainsNul);
    }
    if relative_path.starts_with('/') || (windows_target && relative_path.starts_with('\\')) {
        return Err(TransferPathError::AbsoluteRelativePath);
    }
    if has_windows_drive_prefix(relative_path) {
        return Err(TransferPathError::DrivePrefixedRelativePath);
    }

    let mut segments = Vec::new();
    for segment in relative_path.split('/') {
        if segment.is_empty() {
            return Err(TransferPathError::EmptySegment);
        }
        if segment == "." {
            return Err(TransferPathError::CurrentDirectorySegment);
        }
        if segment == ".." {
            return Err(TransferPathError::ParentDirectorySegment);
        }
        if windows_target && is_invalid_windows_segment(segment) {
            return Err(TransferPathError::InvalidWindowsSegment);
        }
        segments.push(segment);
    }
    Ok(segments)
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_invalid_windows_segment(segment: &str) -> bool {
    segment.contains(['\\', ':']) || segment.ends_with(['.', ' '])
}

fn is_windows_local_target(root: &Path) -> bool {
    if cfg!(windows) {
        return true;
    }

    // Retain Windows semantics when a drive/UNC root is validated on a Unix
    // build host (for example, while importing a persisted cross-platform job).
    let root = root.as_os_str().to_string_lossy();
    has_windows_drive_prefix(&root) || root.starts_with("\\\\") || root.starts_with("//")
}

fn remote_target_is_below_root(root: &str, target: &str) -> bool {
    if root == "/" {
        return target.starts_with('/') && target.len() > 1;
    }

    target
        .strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_valid_remote_targets_without_treating_backslash_as_a_separator() {
        assert_eq!(
            join_remote_transfer_target("/srv/files/", "dir/report.txt").unwrap(),
            "/srv/files/dir/report.txt"
        );
        assert_eq!(
            join_remote_transfer_target("/srv/files", r"dir/name\with\slashes.txt").unwrap(),
            r"/srv/files/dir/name\with\slashes.txt"
        );
        assert_eq!(
            join_remote_transfer_target("/", "folder/file.txt").unwrap(),
            "/folder/file.txt"
        );
    }

    #[test]
    fn remote_join_rejects_empty_absolute_drive_and_escaping_paths() {
        let rejected = [
            ("", TransferPathError::EmptyRelativePath),
            ("/absolute", TransferPathError::AbsoluteRelativePath),
            ("C:/outside", TransferPathError::DrivePrefixedRelativePath),
            (".", TransferPathError::CurrentDirectorySegment),
            ("..", TransferPathError::ParentDirectorySegment),
            ("dir/../outside", TransferPathError::ParentDirectorySegment),
            ("dir//file", TransferPathError::EmptySegment),
            ("dir/", TransferPathError::EmptySegment),
            ("dir/\0file", TransferPathError::ContainsNul),
        ];

        for (relative, expected) in rejected {
            assert_eq!(
                join_remote_transfer_target("/safe/root", relative),
                Err(expected),
                "relative path {relative:?}"
            );
        }
    }

    #[test]
    fn remote_join_allows_backslash_dot_text_as_an_ordinary_filename() {
        assert_eq!(
            join_remote_transfer_target("/safe", r"..\outside.txt").unwrap(),
            r"/safe/..\outside.txt"
        );
        assert_eq!(
            join_remote_transfer_target("/safe", r"folder\.\file").unwrap(),
            r"/safe/folder\.\file"
        );
    }

    #[test]
    fn local_join_stays_lexically_below_its_root() {
        let root = Path::new(r"C:\transfer-root");
        let target = join_local_transfer_target(root, "folder/file.txt").unwrap();

        assert!(target.starts_with(root));
        assert_eq!(target, root.join("folder").join("file.txt"));
    }

    #[test]
    fn windows_local_join_rejects_separator_injection_and_unsafe_names() {
        let root = Path::new(r"C:\transfer-root");
        let rejected = [
            (r"..\outside.txt", TransferPathError::InvalidWindowsSegment),
            (
                r"folder\outside.txt",
                TransferPathError::InvalidWindowsSegment,
            ),
            ("name:stream", TransferPathError::InvalidWindowsSegment),
            ("folder/name. ", TransferPathError::InvalidWindowsSegment),
            ("folder/name.", TransferPathError::InvalidWindowsSegment),
            ("folder/name ", TransferPathError::InvalidWindowsSegment),
            (r"\rooted", TransferPathError::AbsoluteRelativePath),
            (r"\\server\share", TransferPathError::AbsoluteRelativePath),
        ];

        for (relative, expected) in rejected {
            assert_eq!(
                join_local_transfer_target(root, relative),
                Err(expected),
                "relative path {relative:?}"
            );
        }
    }

    #[test]
    fn local_join_rejects_slash_based_escape_on_every_platform() {
        let root = Path::new("transfer-root");
        for relative in ["../outside.txt", "folder/../../outside.txt"] {
            assert_eq!(
                join_local_transfer_target(root, relative),
                Err(TransferPathError::ParentDirectorySegment)
            );
        }
    }

    #[test]
    fn rejects_empty_or_nul_roots() {
        assert_eq!(
            join_remote_transfer_target("", "file.txt"),
            Err(TransferPathError::EmptyRoot)
        );
        assert_eq!(
            join_remote_transfer_target("/safe\0root", "file.txt"),
            Err(TransferPathError::ContainsNul)
        );
        assert_eq!(
            join_local_transfer_target(Path::new(""), "file.txt"),
            Err(TransferPathError::EmptyRoot)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn posix_local_join_preserves_backslashes_and_colons() {
        let root = Path::new("/tmp/transfer-root");
        assert_eq!(
            join_local_transfer_target(root, r"folder/name\part:one").unwrap(),
            root.join(r"folder/name\part:one")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unc_root_keeps_windows_validation_on_a_posix_build_host() {
        let root = Path::new(r"\\server\share\transfer-root");
        assert_eq!(
            join_local_transfer_target(root, r"..\outside.txt"),
            Err(TransferPathError::InvalidWindowsSegment)
        );
    }
}
