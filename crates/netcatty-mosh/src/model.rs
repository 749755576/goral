use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::{MoshConnect, MoshKey};

pub const MAX_NATIVE_PATH_BYTES: usize = 32 * 1_024;
pub const MAX_HOST_BYTES: usize = 1_024;
pub const MAX_WINDOW_DIMENSION: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoshWindowSize {
    columns: u16,
    rows: u16,
}

impl MoshWindowSize {
    pub fn new(columns: u32, rows: u32) -> Result<Self, MoshConfigError> {
        if columns == 0
            || rows == 0
            || columns > MAX_WINDOW_DIMENSION
            || rows > MAX_WINDOW_DIMENSION
        {
            return Err(MoshConfigError::InvalidWindowSize {
                maximum: MAX_WINDOW_DIMENSION,
            });
        }
        Ok(Self {
            columns: columns as u16,
            rows: rows as u16,
        })
    }

    pub const fn columns(self) -> u16 {
        self.columns
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MoshConfigError {
    InvalidNativeClientPath,
    InvalidHost,
    InvalidWindowSize { maximum: u32 },
}

impl fmt::Display for MoshConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNativeClientPath => {
                formatter.write_str("The bundled Mosh client is unavailable")
            }
            Self::InvalidHost => formatter.write_str("The Mosh host is invalid"),
            Self::InvalidWindowSize { maximum } => write!(
                formatter,
                "Mosh terminal dimensions must be between 1 and {maximum}"
            ),
        }
    }
}

impl fmt::Debug for MoshConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for MoshConfigError {}

/// Native launch authority for the bundled MoshCatty executable.
///
/// This type intentionally has no `Deserialize` implementation. Construct it
/// only after the desktop runtime resolves its own packaged resource path.
#[derive(Clone)]
pub struct TrustedMoshClient {
    executable: PathBuf,
}

impl TrustedMoshClient {
    pub fn from_native_path(executable: PathBuf) -> Result<Self, MoshConfigError> {
        if !executable.is_absolute() || path_bytes(&executable) > MAX_NATIVE_PATH_BYTES {
            return Err(MoshConfigError::InvalidNativeClientPath);
        }
        let Some(file_name) = executable.file_name().and_then(|value| value.to_str()) else {
            return Err(MoshConfigError::InvalidNativeClientPath);
        };
        if !matches!(
            file_name.to_ascii_lowercase().as_str(),
            "mosh-client" | "mosh-client.exe"
        ) {
            return Err(MoshConfigError::InvalidNativeClientPath);
        }
        Ok(Self { executable })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl fmt::Debug for TrustedMoshClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedMoshClient")
            .field("executable", &"[redacted native path]")
            .finish()
    }
}

/// The complete renderer-deserializable portion of a Mosh start request.
///
/// `deny_unknown_fields` is a security boundary: executable paths, commands,
/// inherited environments, and `MOSH_KEY` cannot be smuggled into this shape.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoshStartRequest {
    host: String,
    columns: u32,
    rows: u32,
}

impl MoshStartRequest {
    pub fn new(host: String, columns: u32, rows: u32) -> Self {
        Self {
            host,
            columns,
            rows,
        }
    }
}

impl fmt::Debug for MoshStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshStartRequest")
            .field("host", &"[redacted endpoint]")
            .field("columns", &self.columns)
            .field("rows", &self.rows)
            .finish()
    }
}

#[derive(Clone)]
pub struct MoshSessionConfig {
    client: TrustedMoshClient,
    host: String,
    window_size: MoshWindowSize,
}

impl MoshSessionConfig {
    pub fn resolve(
        client: TrustedMoshClient,
        request: MoshStartRequest,
    ) -> Result<Self, MoshConfigError> {
        validate_host(&request.host)?;
        let window_size = MoshWindowSize::new(request.columns, request.rows)?;
        Ok(Self {
            client,
            host: request.host,
            window_size,
        })
    }

    pub fn window_size(&self) -> MoshWindowSize {
        self.window_size
    }

    pub(crate) fn launch(self, connect: MoshConnect) -> MoshClientLaunch {
        let (port, key, announced_host) = connect.into_parts();
        let client_host = announced_host.unwrap_or_else(|| self.host.clone());
        let fallback_host = (client_host != self.host).then_some(self.host);
        MoshClientLaunch {
            executable: self.client.executable,
            host: client_host,
            port,
            key,
            fallback_host,
            window_size: self.window_size,
        }
    }
}

impl fmt::Debug for MoshSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshSessionConfig")
            .field("client", &self.client)
            .field("host", &"[redacted endpoint]")
            .field("window_size", &self.window_size)
            .finish()
    }
}

/// One native-only MoshCatty launch plan produced from a parsed handshake.
/// It is neither serializable nor clonable because it owns `MOSH_KEY`.
pub struct MoshClientLaunch {
    executable: PathBuf,
    host: String,
    port: u16,
    key: MoshKey,
    fallback_host: Option<String>,
    window_size: MoshWindowSize,
}

impl MoshClientLaunch {
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn fallback_host(&self) -> Option<&str> {
        self.fallback_host.as_deref()
    }

    pub fn window_size(&self) -> MoshWindowSize {
        self.window_size
    }

    pub fn into_parts(self) -> MoshClientLaunchParts {
        MoshClientLaunchParts {
            executable: self.executable,
            host: self.host,
            port: self.port,
            key: self.key,
            fallback_host: self.fallback_host,
            window_size: self.window_size,
        }
    }
}

impl fmt::Debug for MoshClientLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshClientLaunch")
            .field("executable", &"[redacted native path]")
            .field("host", &"[redacted endpoint]")
            .field("port", &self.port)
            .field("key", &"[redacted MOSH_KEY]")
            .field(
                "fallback_host",
                &self.fallback_host.as_ref().map(|_| "[redacted endpoint]"),
            )
            .field("window_size", &self.window_size)
            .finish()
    }
}

/// Consumed by the native process adapter. Environment policy is fixed:
/// `TERM=xterm-256color` and `MOSH_NO_TERM_INIT=1`; only the parsed key and
/// optional original-host fallback vary.
pub struct MoshClientLaunchParts {
    pub executable: PathBuf,
    pub host: String,
    pub port: u16,
    pub key: MoshKey,
    pub fallback_host: Option<String>,
    pub window_size: MoshWindowSize,
}

impl MoshClientLaunchParts {
    pub const TERM: &'static str = "xterm-256color";
    pub const MOSH_NO_TERM_INIT: &'static str = "1";
}

impl fmt::Debug for MoshClientLaunchParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshClientLaunchParts")
            .field("executable", &"[redacted native path]")
            .field("host", &"[redacted endpoint]")
            .field("port", &self.port)
            .field("key", &"[redacted MOSH_KEY]")
            .field(
                "fallback_host",
                &self.fallback_host.as_ref().map(|_| "[redacted endpoint]"),
            )
            .field("window_size", &self.window_size)
            .finish()
    }
}

fn validate_host(host: &str) -> Result<(), MoshConfigError> {
    let bytes = host.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_HOST_BYTES
        || bytes[0] == b'-'
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(MoshConfigError::InvalidHost);
    }
    Ok(())
}

fn path_bytes(path: &Path) -> usize {
    path.as_os_str().to_string_lossy().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_client_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"D:\Netcatty\resources\mosh-client.exe")
        } else {
            PathBuf::from("/opt/netcatty/resources/mosh-client")
        }
    }

    #[test]
    fn renderer_request_rejects_native_launch_authority() {
        for forbidden in ["moshClientPath", "command", "moshKey", "env"] {
            let payload = format!(
                r#"{{"host":"example.test","columns":80,"rows":24,"{forbidden}":"secret"}}"#
            );
            assert!(serde_json::from_str::<MoshStartRequest>(&payload).is_err());
        }
    }

    #[test]
    fn trusted_client_requires_an_absolute_expected_binary_name() {
        assert_eq!(
            TrustedMoshClient::from_native_path(PathBuf::from("mosh-client")).unwrap_err(),
            MoshConfigError::InvalidNativeClientPath
        );
        let wrong = if cfg!(windows) {
            PathBuf::from(r"D:\Netcatty\resources\cmd.exe")
        } else {
            PathBuf::from("/opt/netcatty/resources/sh")
        };
        assert_eq!(
            TrustedMoshClient::from_native_path(wrong).unwrap_err(),
            MoshConfigError::InvalidNativeClientPath
        );
        assert!(TrustedMoshClient::from_native_path(native_client_path()).is_ok());
    }

    #[test]
    fn request_validation_rejects_option_like_and_control_hosts() {
        let client = TrustedMoshClient::from_native_path(native_client_path()).unwrap();
        for host in ["", "--help", "host name", "host\nname"] {
            assert_eq!(
                MoshSessionConfig::resolve(
                    client.clone(),
                    MoshStartRequest::new(host.to_owned(), 80, 24)
                )
                .unwrap_err(),
                MoshConfigError::InvalidHost
            );
        }
    }

    #[test]
    fn debug_output_redacts_paths_hosts_and_keys() {
        let client = TrustedMoshClient::from_native_path(native_client_path()).unwrap();
        let request = MoshStartRequest::new("secret-host.example".to_owned(), 80, 24);
        let config = MoshSessionConfig::resolve(client, request).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret-host"));
        assert!(!debug.contains("Netcatty"));
    }
}
