use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtPlatform {
    Windows,
    Macos,
    Linux,
}

impl EtPlatform {
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtArchitecture {
    X86_64,
    Aarch64,
}

impl EtArchitecture {
    pub const fn current() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum EtClientError {
    ResourceRootUnavailable,
    UnsupportedTarget,
    BundledClientMissing,
    BundledClientInvalid,
    BundledClientNotExecutable,
}

impl fmt::Display for EtClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceRootUnavailable => {
                formatter.write_str("The native application resource directory is unavailable")
            }
            Self::UnsupportedTarget => formatter
                .write_str("The bundled Eternal Terminal client is unavailable for this platform"),
            Self::BundledClientMissing => {
                formatter.write_str("The bundled Eternal Terminal client is missing")
            }
            Self::BundledClientInvalid => {
                formatter.write_str("The bundled Eternal Terminal client is invalid")
            }
            Self::BundledClientNotExecutable => {
                formatter.write_str("The bundled Eternal Terminal client is not executable")
            }
        }
    }
}

impl fmt::Debug for EtClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for EtClientError {}

/// Renderer-safe metadata for diagnostics. The native executable path is
/// intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtClientDescriptor {
    bundled: bool,
    platform: EtPlatform,
    architecture: EtArchitecture,
}

impl EtClientDescriptor {
    pub const fn bundled(&self) -> bool {
        self.bundled
    }

    pub const fn platform(&self) -> EtPlatform {
        self.platform
    }

    pub const fn architecture(&self) -> EtArchitecture {
        self.architecture
    }
}

/// Capability proving that an ET executable was resolved beneath the native
/// application resource root. It cannot be deserialized or constructed from
/// renderer data.
#[derive(Clone)]
pub struct TrustedEtClient {
    path: PathBuf,
    descriptor: EtClientDescriptor,
}

impl TrustedEtClient {
    pub fn descriptor(&self) -> &EtClientDescriptor {
        &self.descriptor
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for TrustedEtClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedEtClient")
            .field("path", &"[redacted bundled resource path]")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

/// Resolves only `resource_dir/et/et[.exe]`; there is deliberately no PATH or
/// system-install fallback.
#[derive(Clone)]
pub struct EtClientResolver {
    resource_root: PathBuf,
}

impl EtClientResolver {
    pub fn new(resource_root: PathBuf) -> Self {
        Self { resource_root }
    }

    pub fn resolve_current(&self) -> Result<TrustedEtClient, EtClientError> {
        let platform = EtPlatform::current().ok_or(EtClientError::UnsupportedTarget)?;
        let architecture = EtArchitecture::current().ok_or(EtClientError::UnsupportedTarget)?;
        self.resolve_for(platform, architecture)
    }

    pub fn resolve_for(
        &self,
        platform: EtPlatform,
        architecture: EtArchitecture,
    ) -> Result<TrustedEtClient, EtClientError> {
        if platform == EtPlatform::Windows && architecture == EtArchitecture::Aarch64 {
            return Err(EtClientError::UnsupportedTarget);
        }

        let root = fs::canonicalize(&self.resource_root)
            .map_err(|_| EtClientError::ResourceRootUnavailable)?;
        let file_name = if platform == EtPlatform::Windows {
            "et.exe"
        } else {
            "et"
        };
        let expected = root.join("et").join(file_name);
        let resolved = fs::canonicalize(&expected).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                EtClientError::BundledClientMissing
            } else {
                EtClientError::BundledClientInvalid
            }
        })?;
        if !resolved.starts_with(&root) {
            return Err(EtClientError::BundledClientInvalid);
        }
        let metadata = fs::metadata(&resolved).map_err(|_| EtClientError::BundledClientInvalid)?;
        if !metadata.is_file() {
            return Err(EtClientError::BundledClientInvalid);
        }

        #[cfg(unix)]
        if platform != EtPlatform::Windows {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(EtClientError::BundledClientNotExecutable);
            }
        }

        Ok(TrustedEtClient {
            path: resolved,
            descriptor: EtClientDescriptor {
                bundled: true,
                platform,
                architecture,
            },
        })
    }
}

impl fmt::Debug for EtClientResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtClientResolver")
            .field("resource_root", &"[redacted native resource path]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("netcatty-et-resource-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("et")).unwrap();
        root
    }

    fn write_client(root: &Path, platform: EtPlatform) -> PathBuf {
        let path = root.join("et").join(if platform == EtPlatform::Windows {
            "et.exe"
        } else {
            "et"
        });
        fs::write(&path, b"test client").unwrap();
        #[cfg(unix)]
        if platform != EtPlatform::Windows {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    #[test]
    fn resolver_uses_only_the_exact_bundled_resource() {
        let root = test_root();
        let platform = EtPlatform::current().unwrap();
        let expected = write_client(&root, platform);
        let resolver = EtClientResolver::new(root.clone());
        let client = resolver
            .resolve_for(platform, EtArchitecture::X86_64)
            .unwrap();
        assert_eq!(client.path(), fs::canonicalize(expected).unwrap());
        assert!(client.descriptor().bundled());
        let debug = format!("{client:?} {resolver:?}");
        assert!(!debug.contains(root.to_string_lossy().as_ref()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_bundle_fails_without_a_system_fallback() {
        let root = test_root();
        let resolver = EtClientResolver::new(root.clone());
        assert!(matches!(
            resolver.resolve_for(EtPlatform::Linux, EtArchitecture::X86_64),
            Err(EtClientError::BundledClientMissing)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_arm64_remains_an_explicit_unsupported_target() {
        let root = test_root();
        let resolver = EtClientResolver::new(root.clone());
        assert!(matches!(
            resolver.resolve_for(EtPlatform::Windows, EtArchitecture::Aarch64),
            Err(EtClientError::UnsupportedTarget)
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
