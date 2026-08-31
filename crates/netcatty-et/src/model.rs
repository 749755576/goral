use std::{error::Error, fmt};

use serde::Deserialize;

pub const MAX_RENDERER_TARGET_ID_BYTES: usize = 128;
pub const MAX_HOST_BYTES: usize = 1_024;
pub const MAX_USERNAME_BYTES: usize = 256;
pub const MAX_NATIVE_PATH_BYTES: usize = 32 * 1_024;
pub const MAX_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1_024;
pub const MAX_SSH_OPTIONS: usize = 64;
pub const MAX_SSH_OPTION_BYTES: usize = 32 * 1_024;
pub const MAX_SSH_OPTION_TOTAL_BYTES: usize = 128 * 1_024;
pub const MAX_WINDOW_DIMENSION: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtConfigField {
    TargetId,
    Hostname,
    Username,
    NativePath,
    Environment,
    SshOption,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum EtConfigError {
    InvalidField {
        field: EtConfigField,
        maximum_bytes: usize,
    },
    InvalidPort,
    InvalidWindowSize {
        maximum: u32,
    },
    TargetMismatch,
    TooManyJumpHosts {
        maximum: usize,
    },
    TooManySshOptions {
        maximum: usize,
    },
    SshOptionsTooLarge {
        maximum_bytes: usize,
    },
    NativePathMustBeAbsolute,
    NativePathUnavailable,
}

impl fmt::Display for EtConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField {
                field,
                maximum_bytes,
            } => write!(
                formatter,
                "Eternal Terminal {field:?} is invalid or exceeds {maximum_bytes} bytes"
            ),
            Self::InvalidPort => formatter.write_str("Eternal Terminal port is invalid"),
            Self::InvalidWindowSize { maximum } => write!(
                formatter,
                "Eternal Terminal dimensions must be between 1 and {maximum}"
            ),
            Self::TargetMismatch => {
                formatter.write_str("The selected Eternal Terminal target is unavailable")
            }
            Self::TooManyJumpHosts { maximum } => write!(
                formatter,
                "Eternal Terminal supports at most {maximum} jump host"
            ),
            Self::TooManySshOptions { maximum } => write!(
                formatter,
                "Eternal Terminal SSH options exceed {maximum} entries"
            ),
            Self::SshOptionsTooLarge { maximum_bytes } => write!(
                formatter,
                "Eternal Terminal SSH options exceed {maximum_bytes} bytes"
            ),
            Self::NativePathMustBeAbsolute => {
                formatter.write_str("An Eternal Terminal native path is invalid")
            }
            Self::NativePathUnavailable => {
                formatter.write_str("An Eternal Terminal native path is unavailable")
            }
        }
    }
}

impl fmt::Debug for EtConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for EtConfigError {}

/// The complete renderer-authorized ET start payload.
///
/// There is intentionally no executable path, hostname, username, argv,
/// environment map, command or secret field here. `hostId` must be resolved
/// against native Vault state before an [`EtTarget`] can be constructed.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EtStartRequest {
    host_id: String,
    columns: u32,
    rows: u32,
}

impl EtStartRequest {
    pub fn new(host_id: String, columns: u32, rows: u32) -> Self {
        Self {
            host_id,
            columns,
            rows,
        }
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub const fn columns(&self) -> u32 {
        self.columns
    }

    pub const fn rows(&self) -> u32 {
        self.rows
    }

    pub fn validate(&self) -> Result<EtWindowSize, EtConfigError> {
        validate_token(
            EtConfigField::TargetId,
            &self.host_id,
            MAX_RENDERER_TARGET_ID_BYTES,
            false,
        )?;
        EtWindowSize::new(self.columns, self.rows)
    }
}

impl fmt::Debug for EtStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtStartRequest")
            .field("host_id", &self.host_id)
            .field("columns", &self.columns)
            .field("rows", &self.rows)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EtWindowSize {
    columns: u16,
    rows: u16,
}

impl EtWindowSize {
    pub fn new(columns: u32, rows: u32) -> Result<Self, EtConfigError> {
        if columns == 0
            || rows == 0
            || columns > MAX_WINDOW_DIMENSION
            || rows > MAX_WINDOW_DIMENSION
        {
            return Err(EtConfigError::InvalidWindowSize {
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

/// Native-owned destination metadata. This type is intentionally not
/// deserializable; construct it only after Vault/Quick Connect resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct EtEndpoint {
    hostname: String,
    username: String,
    ssh_port: u16,
    et_port: u16,
}

impl EtEndpoint {
    pub fn new(
        hostname: String,
        username: String,
        ssh_port: u16,
        et_port: u16,
    ) -> Result<Self, EtConfigError> {
        validate_endpoint_token(EtConfigField::Hostname, &hostname, MAX_HOST_BYTES)?;
        validate_endpoint_token(EtConfigField::Username, &username, MAX_USERNAME_BYTES)?;
        if ssh_port == 0 || et_port == 0 {
            return Err(EtConfigError::InvalidPort);
        }
        Ok(Self {
            hostname,
            username,
            ssh_port,
            et_port,
        })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub const fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    pub const fn et_port(&self) -> u16 {
        self.et_port
    }

    pub(crate) fn user_host(&self) -> String {
        format!("{}@{}", self.username, self.hostname)
    }
}

impl fmt::Debug for EtEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtEndpoint")
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("ssh_port", &self.ssh_port)
            .field("et_port", &self.et_port)
            .finish()
    }
}

/// One native-resolved jump host. Legacy Netcatty supports exactly zero or
/// one ET jump and routes it with `et --jumphost/--jport`.
#[derive(Clone, Eq, PartialEq)]
pub struct EtJumpHost {
    endpoint: EtEndpoint,
}

impl EtJumpHost {
    pub fn new(endpoint: EtEndpoint) -> Self {
        Self { endpoint }
    }

    pub fn endpoint(&self) -> &EtEndpoint {
        &self.endpoint
    }
}

impl fmt::Debug for EtJumpHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtJumpHost")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// A target resolved from native state. It is bound back to the renderer's
/// opaque host ID by [`crate::EtSessionConfig::resolve`].
#[derive(Clone, Eq, PartialEq)]
pub struct EtTarget {
    id: String,
    endpoint: EtEndpoint,
    jump_host: Option<EtJumpHost>,
}

impl EtTarget {
    pub fn new(
        id: String,
        endpoint: EtEndpoint,
        jump_hosts: Vec<EtJumpHost>,
    ) -> Result<Self, EtConfigError> {
        validate_token(
            EtConfigField::TargetId,
            &id,
            MAX_RENDERER_TARGET_ID_BYTES,
            false,
        )?;
        if jump_hosts.len() > 1 {
            return Err(EtConfigError::TooManyJumpHosts { maximum: 1 });
        }
        Ok(Self {
            id,
            endpoint,
            jump_host: jump_hosts.into_iter().next(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn endpoint(&self) -> &EtEndpoint {
        &self.endpoint
    }

    pub fn jump_host(&self) -> Option<&EtJumpHost> {
        self.jump_host.as_ref()
    }
}

impl fmt::Debug for EtTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtTarget")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("jump_host", &self.jump_host)
            .finish()
    }
}

pub(crate) fn validate_token(
    field: EtConfigField,
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> Result<(), EtConfigError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        return Err(EtConfigError::InvalidField {
            field,
            maximum_bytes,
        });
    }
    Ok(())
}

fn validate_endpoint_token(
    field: EtConfigField,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), EtConfigError> {
    validate_token(field, value, maximum_bytes, false)?;
    if value.starts_with('-') || value.contains('@') || value.chars().any(char::is_whitespace) {
        return Err(EtConfigError::InvalidField {
            field,
            maximum_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_request_rejects_launch_authority_and_secrets() {
        let valid: EtStartRequest = serde_json::from_value(serde_json::json!({
            "hostId": "host-1",
            "columns": 120,
            "rows": 32
        }))
        .unwrap();
        assert_eq!(
            valid.validate().unwrap(),
            EtWindowSize::new(120, 32).unwrap()
        );

        for forbidden in ["executable", "command", "args", "environment", "password"] {
            let mut value = serde_json::json!({
                "hostId": "host-1",
                "columns": 120,
                "rows": 32
            });
            value[forbidden] = serde_json::json!("secret-or-command");
            assert!(serde_json::from_value::<EtStartRequest>(value).is_err());
        }
    }

    #[test]
    fn endpoint_tokens_cannot_be_reinterpreted_as_options() {
        assert!(EtEndpoint::new("--help".into(), "alice".into(), 22, 2022).is_err());
        assert!(EtEndpoint::new("host".into(), "bad@user".into(), 22, 2022).is_err());
        assert!(EtEndpoint::new("host name".into(), "alice".into(), 22, 2022).is_err());
    }

    #[test]
    fn target_rejects_more_than_one_jump() {
        let endpoint = EtEndpoint::new("target".into(), "alice".into(), 22, 2022).unwrap();
        let jump = EtJumpHost::new(EtEndpoint::new("jump".into(), "ops".into(), 22, 2022).unwrap());
        assert_eq!(
            EtTarget::new("host-1".into(), endpoint, vec![jump.clone(), jump]),
            Err(EtConfigError::TooManyJumpHosts { maximum: 1 })
        );
    }
}
