use std::path::{Path, PathBuf};

pub(crate) const CURRENT_APP_IDENTIFIER: &str = "io.github.749755576.goral";
const LEGACY_APP_IDENTIFIER: &str = "io.github.749755576.lumendock";

#[derive(Clone)]
pub(crate) struct CompatibleWebviewDataRoot(PathBuf);

impl CompatibleWebviewDataRoot {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

pub(crate) struct CompatibleDataRoots {
    app_data: PathBuf,
    webview_data: PathBuf,
}

impl CompatibleDataRoots {
    pub(crate) fn app_data(&self) -> &Path {
        &self.app_data
    }

    pub(crate) fn webview_data(&self) -> &Path {
        &self.webview_data
    }
}

#[derive(Clone, Copy)]
enum RootKind {
    Native,
    Webview,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootState {
    MissingOrEmpty,
    Valid,
}

/// Selects the durable root used by the previous product identity when it is
/// present. Reusing the directory in place keeps Vault snapshots, encrypted
/// replay objects, settings, and their OS-kept master keys bound to the exact
/// store files that created them; no secret-bearing artifact is copied or
/// exposed to the renderer.
#[cfg(test)]
pub(crate) fn compatible_data_root(current_root: &Path) -> Result<PathBuf, &'static str> {
    compatible_root(current_root, RootKind::Native)
}

/// Makes the native durable root authoritative for the product identity and
/// applies that same identity to the WebView profile. This prevents Vault and
/// localStorage from splitting between current and legacy identities when one
/// side already contains data and the other is empty.
pub(crate) fn compatible_data_roots(
    current_app_data: &Path,
    current_webview_data: &Path,
) -> Result<CompatibleDataRoots, &'static str> {
    if current_app_data.file_name().and_then(|name| name.to_str()) != Some(CURRENT_APP_IDENTIFIER)
        || current_webview_data
            .file_name()
            .and_then(|name| name.to_str())
            != Some(CURRENT_APP_IDENTIFIER)
    {
        return Ok(CompatibleDataRoots {
            app_data: current_app_data.to_owned(),
            webview_data: current_webview_data.to_owned(),
        });
    }

    let current_native_state =
        inspect_root(current_app_data, CURRENT_APP_IDENTIFIER, RootKind::Native)?;
    let current_webview_state = inspect_root(
        current_webview_data,
        CURRENT_APP_IDENTIFIER,
        RootKind::Webview,
    )?;
    let legacy_app_data = current_app_data
        .parent()
        .ok_or_else(compatibility_error)?
        .join(LEGACY_APP_IDENTIFIER);
    let selected_identifier =
        if current_native_state == RootState::Valid || current_webview_state == RootState::Valid {
            CURRENT_APP_IDENTIFIER
        } else if inspect_root(&legacy_app_data, LEGACY_APP_IDENTIFIER, RootKind::Native)?
            == RootState::Valid
        {
            LEGACY_APP_IDENTIFIER
        } else {
            CURRENT_APP_IDENTIFIER
        };
    let app_data = if selected_identifier == LEGACY_APP_IDENTIFIER {
        legacy_app_data
    } else {
        current_app_data.to_owned()
    };
    let webview_parent = current_webview_data
        .parent()
        .ok_or_else(compatibility_error)?;
    let webview_data = webview_parent.join(selected_identifier);
    let _ = inspect_root(&webview_data, selected_identifier, RootKind::Webview)?;
    Ok(CompatibleDataRoots {
        app_data,
        webview_data,
    })
}

#[cfg(test)]
fn compatible_root(current_root: &Path, kind: RootKind) -> Result<PathBuf, &'static str> {
    if current_root.file_name().and_then(|name| name.to_str()) != Some(CURRENT_APP_IDENTIFIER) {
        return Ok(current_root.to_owned());
    }

    let Some(parent) = current_root.parent() else {
        return Ok(current_root.to_owned());
    };
    if inspect_root(current_root, CURRENT_APP_IDENTIFIER, kind)? == RootState::Valid {
        return Ok(current_root.to_owned());
    }

    let legacy_root = parent.join(LEGACY_APP_IDENTIFIER);
    if inspect_root(&legacy_root, LEGACY_APP_IDENTIFIER, kind)? == RootState::Valid {
        Ok(legacy_root)
    } else {
        Ok(current_root.to_owned())
    }
}

fn inspect_root(
    root: &Path,
    expected_name: &str,
    kind: RootKind,
) -> Result<RootState, &'static str> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RootState::MissingOrEmpty);
        }
        Err(_) => return Err(compatibility_error()),
    };
    if !metadata.is_dir() || is_link_or_reparse_point(&metadata) {
        return Err(compatibility_error());
    }

    let parent = root.parent().ok_or_else(compatibility_error)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|_| compatibility_error())?;
    let canonical_root = std::fs::canonicalize(root).map_err(|_| compatibility_error())?;
    if canonical_root.parent() != Some(canonical_parent.as_path())
        || canonical_root.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        return Err(compatibility_error());
    }

    match kind {
        RootKind::Native => {
            let vault = inspect_known_directory(&canonical_root.join("vault"))?;
            let replays = inspect_known_directory(&canonical_root.join("connection-log-replays"))?;
            Ok(if vault || replays {
                RootState::Valid
            } else {
                RootState::MissingOrEmpty
            })
        }
        RootKind::Webview => {
            let mut entries =
                std::fs::read_dir(&canonical_root).map_err(|_| compatibility_error())?;
            Ok(
                if entries
                    .next()
                    .transpose()
                    .map_err(|_| compatibility_error())?
                    .is_some()
                {
                    RootState::Valid
                } else {
                    RootState::MissingOrEmpty
                },
            )
        }
    }
}

fn inspect_known_directory(path: &Path) -> Result<bool, &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !is_link_or_reparse_point(&metadata) => Ok(true),
        Ok(_) => Err(compatibility_error()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(compatibility_error()),
    }
}

#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn compatibility_error() -> &'static str {
    "Application data compatibility root is unavailable"
}

#[cfg(test)]
mod tests {
    use super::{CURRENT_APP_IDENTIFIER, compatible_data_root, compatible_data_roots};

    #[test]
    fn existing_legacy_root_is_reused_without_copying_or_creating_the_new_root() {
        let base = tempfile::tempdir().expect("temporary data parent");
        let legacy = base.path().join("io.github.749755576.lumendock");
        std::fs::create_dir(&legacy).expect("legacy root");
        std::fs::create_dir(legacy.join("vault")).expect("legacy Vault root");
        std::fs::write(
            legacy.join("vault").join("opaque-store-marker"),
            b"preserve-in-place",
        )
        .expect("legacy marker");
        let current = base.path().join(CURRENT_APP_IDENTIFIER);

        assert_eq!(compatible_data_root(&current).unwrap(), legacy);
        assert!(!current.exists());
        assert_eq!(
            std::fs::read(legacy.join("vault").join("opaque-store-marker")).unwrap(),
            b"preserve-in-place"
        );
    }

    #[test]
    fn fresh_install_uses_the_current_root() {
        let base = tempfile::tempdir().expect("temporary data parent");
        let current = base.path().join(CURRENT_APP_IDENTIFIER);

        assert_eq!(compatible_data_root(&current).unwrap(), current);
    }

    #[test]
    fn a_non_directory_legacy_path_fails_closed_instead_of_starting_empty() {
        let base = tempfile::tempdir().expect("temporary data parent");
        std::fs::write(
            base.path().join("io.github.749755576.lumendock"),
            b"not-a-directory",
        )
        .expect("legacy collision");
        let current = base.path().join(CURRENT_APP_IDENTIFIER);

        assert_eq!(
            compatible_data_root(&current),
            Err("Application data compatibility root is unavailable")
        );
        assert!(!current.exists());
    }

    #[test]
    fn a_valid_current_native_root_wins_over_the_legacy_root() {
        let base = tempfile::tempdir().expect("temporary data parent");
        let legacy = base.path().join("io.github.749755576.lumendock");
        let current = base.path().join(CURRENT_APP_IDENTIFIER);
        std::fs::create_dir_all(legacy.join("vault")).expect("legacy Vault");
        std::fs::create_dir_all(current.join("vault")).expect("current Vault");

        assert_eq!(compatible_data_root(&current).unwrap(), current);
    }

    #[test]
    fn valid_current_webview_profile_keeps_both_roots_on_current_identity() {
        let native = tempfile::tempdir().expect("native parent");
        let profiles = tempfile::tempdir().expect("profile parent");
        let legacy_native = native.path().join("io.github.749755576.lumendock");
        let current_native = native.path().join(CURRENT_APP_IDENTIFIER);
        let legacy_profile = profiles.path().join("io.github.749755576.lumendock");
        let current_profile = profiles.path().join(CURRENT_APP_IDENTIFIER);
        std::fs::create_dir_all(legacy_native.join("vault")).expect("legacy Vault");
        std::fs::create_dir(&legacy_profile).expect("legacy profile");
        std::fs::write(legacy_profile.join("profile-state"), b"legacy").unwrap();
        std::fs::create_dir(&current_profile).expect("current profile");
        std::fs::write(current_profile.join("profile-state"), b"current").unwrap();

        let selected = compatible_data_roots(&current_native, &current_profile).unwrap();
        assert_eq!(selected.app_data(), current_native);
        assert_eq!(selected.webview_data(), current_profile);
    }

    #[test]
    fn valid_current_native_root_keeps_webview_on_current_when_both_sides_exist() {
        let native = tempfile::tempdir().expect("native parent");
        let profiles = tempfile::tempdir().expect("profile parent");
        let legacy_native = native.path().join("io.github.749755576.lumendock");
        let current_native = native.path().join(CURRENT_APP_IDENTIFIER);
        let legacy_profile = profiles.path().join("io.github.749755576.lumendock");
        let current_profile = profiles.path().join(CURRENT_APP_IDENTIFIER);
        std::fs::create_dir_all(legacy_native.join("vault")).expect("legacy Vault");
        std::fs::create_dir_all(current_native.join("vault")).expect("current Vault");
        std::fs::create_dir(&legacy_profile).expect("legacy profile");
        std::fs::write(legacy_profile.join("profile-state"), b"legacy").unwrap();
        std::fs::create_dir(&current_profile).expect("current profile");

        let selected = compatible_data_roots(&current_native, &current_profile).unwrap();
        assert_eq!(selected.app_data(), current_native);
        assert_eq!(selected.webview_data(), current_profile);
    }

    #[test]
    fn auto_created_empty_current_profile_does_not_steal_the_legacy_identity() {
        let native = tempfile::tempdir().expect("native parent");
        let profiles = tempfile::tempdir().expect("profile parent");
        let legacy_native = native.path().join("io.github.749755576.lumendock");
        let current_native = native.path().join(CURRENT_APP_IDENTIFIER);
        let legacy_profile = profiles.path().join("io.github.749755576.lumendock");
        let current_profile = profiles.path().join(CURRENT_APP_IDENTIFIER);
        std::fs::create_dir_all(legacy_native.join("vault")).expect("legacy Vault");
        std::fs::create_dir(&legacy_profile).expect("legacy profile");
        std::fs::write(legacy_profile.join("profile-state"), b"legacy").unwrap();
        std::fs::create_dir(&current_profile).expect("empty current profile");

        let selected = compatible_data_roots(&current_native, &current_profile).unwrap();
        assert_eq!(selected.app_data(), legacy_native);
        assert_eq!(selected.webview_data(), legacy_profile);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_legacy_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().expect("temporary data parent");
        let outside = tempfile::tempdir().expect("outside directory");
        symlink(
            outside.path(),
            base.path().join("io.github.749755576.lumendock"),
        )
        .expect("legacy symlink");
        let current = base.path().join(CURRENT_APP_IDENTIFIER);

        assert_eq!(
            compatible_data_root(&current),
            Err("Application data compatibility root is unavailable")
        );
    }

    #[test]
    fn unrelated_custom_roots_are_not_rewritten() {
        let base = tempfile::tempdir().expect("temporary data parent");
        std::fs::create_dir(base.path().join("io.github.749755576.lumendock"))
            .expect("legacy sibling");
        let custom = base.path().join("isolated-test-profile");

        assert_eq!(compatible_data_root(&custom).unwrap(), custom);
    }
}
