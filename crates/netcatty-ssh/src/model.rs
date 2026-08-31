use serde::{Deserialize, Serialize};

pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_TCP_CONNECT_TIMEOUT_SECONDS: u32 = 20;
pub const DEFAULT_AUTH_READY_TIMEOUT_SECONDS: u32 = 120;
pub const MAX_CONNECTION_TIMEOUT_SECONDS: f64 = 3_600.0;
pub const MAX_JUMP_HOSTS: usize = 16;
pub const MAX_KEEPALIVE_INTERVAL_SECONDS: i64 = 86_400;
pub const MAX_KEEPALIVE_COUNT: i64 = 1_000;

/// Secret-safe input contract used for validation before a real connection is started.
/// It carries credential presence and stable references, never credential values.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConnectionConfig {
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u32>,
    pub username: String,
    #[serde(default)]
    pub auth: SshAuthConfig,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub jump_hosts: Vec<SshJumpHost>,
    #[serde(default)]
    pub legacy_algorithms: Option<bool>,
    #[serde(default)]
    pub skip_ecdsa_host_key: bool,
    #[serde(default)]
    pub algorithms: AlgorithmOverrides,
    #[serde(default)]
    pub keepalive: KeepaliveConfig,
    #[serde(default)]
    pub timeouts: SshTimeouts,
}

impl SshConnectionConfig {
    /// Creates the secret-free configuration used by a saved SSH/password host.
    /// The password value is resolved separately and never enters this model.
    #[must_use]
    pub fn saved_password_host(
        hostname: impl Into<String>,
        port: u16,
        username: impl Into<String>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            port: Some(u32::from(port)),
            username: username.into(),
            auth: SshAuthConfig {
                method: Some(SshAuthMethod::Password),
                auth_policy_version: Some(1),
                has_password: true,
                ..SshAuthConfig::default()
            },
            proxy: None,
            jump_hosts: Vec::new(),
            legacy_algorithms: None,
            skip_ecdsa_host_key: false,
            algorithms: AlgorithmOverrides::default(),
            keepalive: KeepaliveConfig::default(),
            timeouts: SshTimeouts::default(),
        }
    }

    /// Creates the secret-free configuration used after the user explicitly
    /// selects local private-key files for a saved SSH/key host.
    ///
    /// Callers must supply paths from the current user interaction. Legacy
    /// import metadata is deliberately not resolved by this constructor.
    #[must_use]
    pub fn saved_key_file_host(
        hostname: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        identity_file_paths: Vec<String>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            port: Some(u32::from(port)),
            username: username.into(),
            auth: SshAuthConfig {
                method: Some(SshAuthMethod::Key),
                auth_policy_version: Some(1),
                identity_file_paths,
                use_ssh_agent: Some(false),
                identities_only: Some(true),
                ..SshAuthConfig::default()
            },
            proxy: None,
            jump_hosts: Vec::new(),
            legacy_algorithms: None,
            skip_ecdsa_host_key: false,
            algorithms: AlgorithmOverrides::default(),
            keepalive: KeepaliveConfig::default(),
            timeouts: SshTimeouts::default(),
        }
    }

    /// Creates the secret-free configuration used by a saved host whose
    /// private key is resolved from trusted managed storage at connection
    /// time. No key material or backend locator enters this model.
    #[must_use]
    pub fn saved_managed_key_host(
        hostname: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        has_certificate: bool,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            port: Some(u32::from(port)),
            username: username.into(),
            auth: SshAuthConfig {
                method: Some(if has_certificate {
                    SshAuthMethod::Certificate
                } else {
                    SshAuthMethod::Key
                }),
                auth_policy_version: Some(1),
                has_private_key: true,
                has_certificate,
                use_ssh_agent: Some(false),
                identities_only: Some(true),
                ..SshAuthConfig::default()
            },
            proxy: None,
            jump_hosts: Vec::new(),
            legacy_algorithms: None,
            skip_ecdsa_host_key: false,
            algorithms: AlgorithmOverrides::default(),
            keepalive: KeepaliveConfig::default(),
            timeouts: SshTimeouts::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SshAuthMethod {
    #[default]
    Auto,
    Password,
    Key,
    Certificate,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshAuthConfig {
    pub method: Option<SshAuthMethod>,
    pub auth_policy_version: Option<u8>,
    pub identity_id: Option<String>,
    pub identity_available: bool,
    pub has_password: bool,
    pub key_id: Option<String>,
    pub key_available: bool,
    pub has_private_key: bool,
    pub has_public_key: bool,
    pub has_certificate: bool,
    pub identity_file_paths: Vec<String>,
    pub use_ssh_agent: Option<bool>,
    pub identity_agent: Option<String>,
    pub identities_only: Option<bool>,
    pub add_keys_to_agent: Option<String>,
    pub use_keychain: Option<bool>,
    pub agent_forwarding: bool,
    pub requires_mfa: bool,
}

impl SshAuthConfig {
    #[must_use]
    pub fn selected_method(&self) -> SshAuthMethod {
        if let Some(method) = self.method {
            return method;
        }
        if self.use_ssh_agent == Some(true) {
            return SshAuthMethod::Auto;
        }
        if self.key_id.as_deref().is_some_and(is_non_empty)
            || self
                .identity_file_paths
                .iter()
                .any(|path| is_non_empty(path))
        {
            return SshAuthMethod::Key;
        }
        if self.has_password && self.auth_policy_version != Some(1) {
            return SshAuthMethod::Password;
        }
        SshAuthMethod::Auto
    }

    #[must_use]
    pub(crate) fn has_key_selector(&self) -> bool {
        self.has_private_key
            || self.has_public_key
            || (self.key_available && self.key_id.as_deref().is_some_and(is_non_empty))
            || self
                .identity_file_paths
                .iter()
                .any(|path| is_non_empty(path))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyType {
    Http,
    Socks5,
    Command,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub has_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshJumpHost {
    pub host_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AlgorithmOverrides {
    pub kex: Vec<String>,
    pub cipher: Vec<String>,
    pub hmac: Vec<String>,
    pub server_host_key: Vec<String>,
    pub compress: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeepaliveConfig {
    pub override_global: bool,
    pub interval_seconds: Option<i64>,
    pub count_max: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshTimeouts {
    pub tcp_connect_seconds: Option<f64>,
    pub auth_ready_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedSshConnectionConfig {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub proxy: Option<NormalizedProxyConfig>,
    pub jump_hosts: Vec<SshJumpHost>,
    pub legacy_algorithms: bool,
    #[serde(skip)]
    pub legacy_algorithms_explicit: bool,
    pub skip_ecdsa_host_key: bool,
    pub algorithms: AlgorithmOverrides,
    pub keepalive: NormalizedKeepaliveConfig,
    pub timeouts: NormalizedSshTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedProxyConfig {
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub has_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedKeepaliveConfig {
    pub override_global: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedSshTimeouts {
    pub tcp_connect_seconds: u32,
    pub auth_ready_seconds: u32,
}

pub(crate) fn is_non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::{SshAuthMethod, SshConnectionConfig};

    #[test]
    fn saved_key_file_host_uses_only_explicit_paths_and_disables_ambient_agent() {
        let config = SshConnectionConfig::saved_key_file_host(
            "key.example.test",
            22,
            "alice",
            vec!["C:\\selected\\id_ed25519".to_owned()],
        );

        assert_eq!(config.auth.method, Some(SshAuthMethod::Key));
        assert_eq!(
            config.auth.identity_file_paths,
            vec!["C:\\selected\\id_ed25519"]
        );
        assert_eq!(config.auth.use_ssh_agent, Some(false));
        assert_eq!(config.auth.identities_only, Some(true));
        assert!(!config.auth.has_private_key);
        assert!(!config.auth.has_password);
    }

    #[test]
    fn saved_managed_key_host_selects_managed_private_key_without_paths_or_agent() {
        let config = SshConnectionConfig::saved_managed_key_host(
            "managed-key.example.test",
            2222,
            "alice",
            false,
        );

        assert_eq!(config.hostname, "managed-key.example.test");
        assert_eq!(config.port, Some(2222));
        assert_eq!(config.username, "alice");
        assert_eq!(config.auth.method, Some(SshAuthMethod::Key));
        assert_eq!(config.auth.auth_policy_version, Some(1));
        assert!(config.auth.has_private_key);
        assert!(!config.auth.has_certificate);
        assert!(config.auth.identity_file_paths.is_empty());
        assert_eq!(config.auth.use_ssh_agent, Some(false));
        assert_eq!(config.auth.identities_only, Some(true));
        assert!(!config.auth.has_password);
        assert!(config.proxy.is_none());
        assert!(config.jump_hosts.is_empty());
    }

    #[test]
    fn saved_managed_certificate_host_selects_certificate_without_paths_or_agent() {
        let config = SshConnectionConfig::saved_managed_key_host(
            "managed-certificate.example.test",
            22,
            "bob",
            true,
        );

        assert_eq!(config.auth.method, Some(SshAuthMethod::Certificate));
        assert_eq!(config.auth.auth_policy_version, Some(1));
        assert!(config.auth.has_private_key);
        assert!(config.auth.has_certificate);
        assert!(config.auth.identity_file_paths.is_empty());
        assert_eq!(config.auth.use_ssh_agent, Some(false));
        assert_eq!(config.auth.identities_only, Some(true));
        assert!(!config.auth.has_password);
    }
}
