use std::collections::HashSet;

use serde::Serialize;

use crate::model::{
    DEFAULT_AUTH_READY_TIMEOUT_SECONDS, DEFAULT_SSH_PORT, DEFAULT_TCP_CONNECT_TIMEOUT_SECONDS,
    MAX_CONNECTION_TIMEOUT_SECONDS, MAX_JUMP_HOSTS, MAX_KEEPALIVE_COUNT,
    MAX_KEEPALIVE_INTERVAL_SECONDS, is_non_empty,
};
use crate::{
    AlgorithmOverrides, AuthPlan, KeepaliveConfig, NormalizedKeepaliveConfig,
    NormalizedProxyConfig, NormalizedSshConnectionConfig, NormalizedSshTimeouts, ProxyConfig,
    ProxyType, SshAuthMethod, SshConnectionConfig, SshJumpHost, SshTimeouts, plan_authentication,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationIssue {
    pub field: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<NormalizedSshConnectionConfig>,
    pub errors: Vec<ValidationIssue>,
    pub auth_plan: AuthPlan,
}

#[must_use]
pub fn validate_connection(config: SshConnectionConfig) -> ValidationResult {
    let auth_plan = plan_authentication(&config.auth);
    let mut errors = Vec::new();

    let hostname = normalize_hostname(&config.hostname);
    if hostname.is_empty() {
        error(&mut errors, "hostname", "required", "SSH 主机地址不能为空");
    }

    let username = config.username.trim().to_owned();
    if username.is_empty() {
        error(&mut errors, "username", "required", "SSH 用户名不能为空");
    }

    let port = validate_port(
        config.port.unwrap_or(u32::from(DEFAULT_SSH_PORT)),
        "port",
        &mut errors,
    );
    validate_auth(&config, &mut errors);
    let proxy = normalize_proxy(config.proxy.as_ref(), &mut errors);
    let jump_hosts = normalize_jump_hosts(&config.jump_hosts, &mut errors);
    let algorithms = normalize_algorithms(&config.algorithms, &mut errors);
    let keepalive = normalize_keepalive(&config.keepalive, &mut errors);
    let timeouts = normalize_timeouts(&config.timeouts, &mut errors);

    let normalized = if errors.is_empty() {
        port.map(|port| NormalizedSshConnectionConfig {
            hostname,
            port,
            username,
            auth_method: config.auth.selected_method(),
            proxy,
            jump_hosts,
            legacy_algorithms: config.legacy_algorithms.unwrap_or(false),
            legacy_algorithms_explicit: config.legacy_algorithms.is_some(),
            skip_ecdsa_host_key: config.skip_ecdsa_host_key,
            algorithms,
            keepalive,
            timeouts,
        })
    } else {
        None
    };
    let valid = normalized.is_some();

    ValidationResult {
        valid,
        normalized,
        errors,
        auth_plan,
    }
}

fn normalize_hostname(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn validate_auth(config: &SshConnectionConfig, errors: &mut Vec<ValidationIssue>) {
    let auth = &config.auth;
    if auth.identity_id.as_deref().is_some_and(is_non_empty) && !auth.identity_available {
        error(
            errors,
            "auth.identityId",
            "missingReference",
            "引用的身份不存在或不可用",
        );
    }
    if auth.key_id.as_deref().is_some_and(is_non_empty) && !auth.key_available {
        error(
            errors,
            "auth.keyId",
            "missingReference",
            "引用的密钥不存在或不可用",
        );
    }
    for (index, path) in auth.identity_file_paths.iter().enumerate() {
        if path.trim().is_empty() {
            error(
                errors,
                format!("auth.identityFilePaths.{index}"),
                "empty",
                "密钥文件路径不能为空",
            );
        }
    }

    match auth.selected_method() {
        SshAuthMethod::Key if !auth.has_key_selector() => error(
            errors,
            "auth",
            "missingKey",
            "密钥认证需要可用密钥、密钥文件或 SSH Agent 密钥选择器",
        ),
        SshAuthMethod::Certificate if !auth.has_certificate => error(
            errors,
            "auth",
            "missingCertificate",
            "证书认证需要可用的 SSH 证书",
        ),
        _ => {}
    }
}

fn normalize_proxy(
    proxy: Option<&ProxyConfig>,
    errors: &mut Vec<ValidationIssue>,
) -> Option<NormalizedProxyConfig> {
    let proxy = proxy?;
    let identity_id = trim_option(proxy.identity_id.as_deref());

    match proxy.proxy_type {
        ProxyType::Command => {
            let command = trim_option(proxy.command.as_deref());
            if command.is_none() {
                error(errors, "proxy.command", "required", "命令代理需要代理命令");
            }
            Some(NormalizedProxyConfig {
                proxy_type: proxy.proxy_type,
                host: None,
                port: None,
                command,
                identity_id: None,
                username: None,
                has_password: false,
            })
        }
        ProxyType::Http | ProxyType::Socks5 => {
            let host = proxy.host.trim().to_owned();
            if host.is_empty() {
                error(errors, "proxy.host", "required", "网络代理地址不能为空");
            }
            let port = match proxy.port {
                Some(port) => validate_port(port, "proxy.port", errors),
                None => {
                    error(errors, "proxy.port", "required", "网络代理端口不能为空");
                    None
                }
            };
            // A proxy identity and inline credentials are mutually exclusive
            // in the legacy product. The trusted Vault adapter resolves the
            // identity into connection-time username/password material before
            // transport validation; this generic contract must never merge a
            // selected identity with stale manual authentication hints.
            let (username, has_password) = if identity_id.is_some() {
                (None, false)
            } else {
                (trim_option(proxy.username.as_deref()), proxy.has_password)
            };
            Some(NormalizedProxyConfig {
                proxy_type: proxy.proxy_type,
                host: (!host.is_empty()).then_some(host),
                port,
                command: None,
                identity_id,
                username,
                has_password,
            })
        }
    }
}

fn normalize_jump_hosts(
    jump_hosts: &[SshJumpHost],
    errors: &mut Vec<ValidationIssue>,
) -> Vec<SshJumpHost> {
    if jump_hosts.len() > MAX_JUMP_HOSTS {
        error(
            errors,
            "jumpHosts",
            "tooMany",
            format!("跳板机链最多允许 {MAX_JUMP_HOSTS} 台主机"),
        );
    }

    let mut seen = HashSet::new();
    jump_hosts
        .iter()
        .enumerate()
        .filter_map(|(index, jump)| {
            let host_id = jump.host_id.trim().to_owned();
            if host_id.is_empty() {
                error(
                    errors,
                    format!("jumpHosts.{index}.hostId"),
                    "required",
                    "跳板机引用不能为空",
                );
                return None;
            }
            if !seen.insert(host_id.clone()) {
                error(
                    errors,
                    format!("jumpHosts.{index}.hostId"),
                    "duplicate",
                    "跳板机链不能重复引用同一主机",
                );
                return None;
            }
            Some(SshJumpHost { host_id })
        })
        .collect()
}

fn normalize_algorithms(
    algorithms: &AlgorithmOverrides,
    errors: &mut Vec<ValidationIssue>,
) -> AlgorithmOverrides {
    AlgorithmOverrides {
        kex: normalize_algorithm_list("algorithms.kex", &algorithms.kex, errors),
        cipher: normalize_algorithm_list("algorithms.cipher", &algorithms.cipher, errors),
        hmac: normalize_algorithm_list("algorithms.hmac", &algorithms.hmac, errors),
        server_host_key: normalize_algorithm_list(
            "algorithms.serverHostKey",
            &algorithms.server_host_key,
            errors,
        ),
        compress: normalize_algorithm_list("algorithms.compress", &algorithms.compress, errors),
    }
}

fn normalize_algorithm_list(
    field: &str,
    values: &[String],
    errors: &mut Vec<ValidationIssue>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let value = value.trim();
        if value.is_empty() {
            error(
                errors,
                format!("{field}.{index}"),
                "empty",
                "SSH 算法名称不能为空",
            );
        } else if seen.insert(value.to_owned()) {
            normalized.push(value.to_owned());
        }
    }
    normalized
}

fn normalize_keepalive(
    keepalive: &KeepaliveConfig,
    errors: &mut Vec<ValidationIssue>,
) -> NormalizedKeepaliveConfig {
    let interval_seconds = keepalive.interval_seconds.and_then(|value| {
        if (0..=MAX_KEEPALIVE_INTERVAL_SECONDS).contains(&value) {
            Some(value as u32)
        } else {
            error(
                errors,
                "keepalive.intervalSeconds",
                "outOfRange",
                "SSH 保活间隔必须在 0 到 86400 秒之间",
            );
            None
        }
    });
    let count_max = keepalive.count_max.and_then(|value| {
        if (0..=MAX_KEEPALIVE_COUNT).contains(&value) {
            Some(value as u32)
        } else {
            error(
                errors,
                "keepalive.countMax",
                "outOfRange",
                "SSH 保活失败次数必须在 0 到 1000 之间",
            );
            None
        }
    });

    NormalizedKeepaliveConfig {
        override_global: keepalive.override_global,
        interval_seconds,
        count_max,
    }
}

fn normalize_timeouts(
    timeouts: &SshTimeouts,
    errors: &mut Vec<ValidationIssue>,
) -> NormalizedSshTimeouts {
    NormalizedSshTimeouts {
        tcp_connect_seconds: normalize_timeout(
            timeouts.tcp_connect_seconds,
            DEFAULT_TCP_CONNECT_TIMEOUT_SECONDS,
            "timeouts.tcpConnectSeconds",
            errors,
        ),
        auth_ready_seconds: normalize_timeout(
            timeouts.auth_ready_seconds,
            DEFAULT_AUTH_READY_TIMEOUT_SECONDS,
            "timeouts.authReadySeconds",
            errors,
        ),
    }
}

fn normalize_timeout(
    value: Option<f64>,
    default: u32,
    field: &str,
    errors: &mut Vec<ValidationIssue>,
) -> u32 {
    match value {
        None => default,
        Some(value)
            if value.is_finite() && (1.0..=MAX_CONNECTION_TIMEOUT_SECONDS).contains(&value) =>
        {
            value.round() as u32
        }
        Some(_) => {
            error(
                errors,
                field,
                "outOfRange",
                "SSH 连接超时必须在 1 到 3600 秒之间",
            );
            default
        }
    }
}

fn validate_port(value: u32, field: &str, errors: &mut Vec<ValidationIssue>) -> Option<u16> {
    match u16::try_from(value) {
        Ok(port) if port > 0 => Some(port),
        _ => {
            error(errors, field, "outOfRange", "端口必须在 1 到 65535 之间");
            None
        }
    }
}

fn trim_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn error(
    errors: &mut Vec<ValidationIssue>,
    field: impl Into<String>,
    code: impl Into<String>,
    message: impl Into<String>,
) {
    errors.push(ValidationIssue {
        field: field.into(),
        code: code.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use crate::{
        AlgorithmOverrides, KeepaliveConfig, ProxyConfig, ProxyType, SshAuthConfig, SshAuthMethod,
        SshConnectionConfig, SshJumpHost, SshTimeouts, validate_connection,
    };

    fn valid_config() -> SshConnectionConfig {
        SshConnectionConfig {
            hostname: " server.example.test trailing-value".to_owned(),
            port: None,
            username: " deploy ".to_owned(),
            auth: SshAuthConfig::default(),
            proxy: None,
            jump_hosts: Vec::new(),
            legacy_algorithms: None,
            skip_ecdsa_host_key: false,
            algorithms: AlgorithmOverrides::default(),
            keepalive: KeepaliveConfig::default(),
            timeouts: SshTimeouts::default(),
        }
    }

    #[test]
    fn valid_config_uses_legacy_hostname_cleanup_and_defaults() {
        let result = validate_connection(valid_config());
        let normalized = result.normalized.expect("valid config");

        assert!(result.valid);
        assert_eq!(normalized.hostname, "server.example.test");
        assert_eq!(normalized.username, "deploy");
        assert_eq!(normalized.port, 22);
        assert_eq!(normalized.timeouts.tcp_connect_seconds, 20);
        assert_eq!(normalized.timeouts.auth_ready_seconds, 120);
        assert_eq!(normalized.auth_method, SshAuthMethod::Auto);
    }

    #[test]
    fn rejects_empty_host_username_and_invalid_port_without_echoing_values() {
        let mut config = valid_config();
        config.hostname = "  ".to_owned();
        config.username = "".to_owned();
        config.port = Some(70_000);

        let result = validate_connection(config);
        let fields: Vec<_> = result
            .errors
            .iter()
            .map(|error| error.field.as_str())
            .collect();

        assert!(!result.valid);
        assert!(result.normalized.is_none());
        assert_eq!(fields, vec!["hostname", "username", "port"]);
        assert!(
            result
                .errors
                .iter()
                .all(|error| !error.message.contains("70000"))
        );
    }

    #[test]
    fn explicit_key_and_certificate_modes_fail_closed() {
        for method in [SshAuthMethod::Key, SshAuthMethod::Certificate] {
            let mut config = valid_config();
            config.auth.method = Some(method);
            let result = validate_connection(config);
            assert!(!result.valid);
            assert_eq!(result.errors[0].field, "auth");
        }
    }

    #[test]
    fn a_key_file_satisfies_explicit_key_mode() {
        let mut config = valid_config();
        config.auth.method = Some(SshAuthMethod::Key);
        config.auth.identity_file_paths = vec![" ~/.ssh/id_work ".to_owned()];

        assert!(validate_connection(config).valid);
    }

    #[test]
    fn missing_identity_and_key_references_are_rejected() {
        let mut config = valid_config();
        config.auth.identity_id = Some("identity-deleted".to_owned());
        config.auth.key_id = Some("key-deleted".to_owned());

        let result = validate_connection(config);
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|error| error.code == "missingReference")
                .count(),
            2
        );
    }

    #[test]
    fn proxy_types_validate_only_the_fields_they_use() {
        let mut command_config = valid_config();
        command_config.proxy = Some(ProxyConfig {
            proxy_type: ProxyType::Command,
            host: "stale.proxy.example".to_owned(),
            port: Some(8080),
            command: Some("  ssh -W %h:%p bastion  ".to_owned()),
            identity_id: Some("stale-identity".to_owned()),
            username: Some("stale-user".to_owned()),
            has_password: true,
        });
        let command_result = validate_connection(command_config);
        assert!(command_result.valid);
        let command_proxy = command_result
            .normalized
            .expect("valid command proxy")
            .proxy
            .expect("normalized command proxy");
        assert_eq!(
            command_proxy.command.as_deref(),
            Some("ssh -W %h:%p bastion")
        );
        assert!(command_proxy.host.is_none());
        assert!(command_proxy.port.is_none());
        assert!(command_proxy.identity_id.is_none());
        assert!(command_proxy.username.is_none());
        assert!(!command_proxy.has_password);

        let mut socks_config = valid_config();
        socks_config.proxy = Some(ProxyConfig {
            proxy_type: ProxyType::Socks5,
            host: String::new(),
            port: Some(0),
            command: None,
            identity_id: None,
            username: None,
            has_password: false,
        });
        assert_eq!(validate_connection(socks_config).errors.len(), 2);
    }

    #[test]
    fn proxy_identity_excludes_stale_manual_authentication_hints() {
        let mut config = valid_config();
        config.proxy = Some(ProxyConfig {
            proxy_type: ProxyType::Http,
            host: " proxy.example.test ".to_owned(),
            port: Some(8080),
            command: Some("stale command".to_owned()),
            identity_id: Some(" shared-proxy-identity ".to_owned()),
            username: Some("stale-manual-user".to_owned()),
            has_password: true,
        });

        let normalized = validate_connection(config)
            .normalized
            .expect("valid identity-backed proxy")
            .proxy
            .expect("normalized proxy");
        assert_eq!(normalized.host.as_deref(), Some("proxy.example.test"));
        assert_eq!(normalized.port, Some(8080));
        assert_eq!(
            normalized.identity_id.as_deref(),
            Some("shared-proxy-identity")
        );
        assert!(normalized.command.is_none());
        assert!(normalized.username.is_none());
        assert!(!normalized.has_password);
    }

    #[test]
    fn jump_hosts_must_be_non_empty_unique_and_bounded() {
        let mut config = valid_config();
        config.jump_hosts = vec![
            SshJumpHost {
                host_id: "jump-1".to_owned(),
            },
            SshJumpHost {
                host_id: " jump-1 ".to_owned(),
            },
            SshJumpHost {
                host_id: " ".to_owned(),
            },
        ];

        let result = validate_connection(config);
        assert_eq!(result.errors.len(), 2);
    }

    #[test]
    fn algorithms_are_trimmed_and_deduplicated_but_empty_entries_are_errors() {
        let mut config = valid_config();
        config.algorithms.kex = vec![
            " curve25519-sha256 ".to_owned(),
            "curve25519-sha256".to_owned(),
        ];
        let result = validate_connection(config);
        assert_eq!(result.normalized.expect("valid").algorithms.kex.len(), 1);

        let mut invalid = valid_config();
        invalid.algorithms.cipher = vec![" ".to_owned()];
        assert!(!validate_connection(invalid).valid);
    }

    #[test]
    fn timeouts_match_legacy_rounding_and_limits() {
        let mut config = valid_config();
        config.timeouts.tcp_connect_seconds = Some(45.4);
        config.timeouts.auth_ready_seconds = Some(3_601.0);

        let result = validate_connection(config);
        assert!(!result.valid);
        assert_eq!(result.errors[0].field, "timeouts.authReadySeconds");

        let mut rounded = valid_config();
        rounded.timeouts.tcp_connect_seconds = Some(45.5);
        assert_eq!(
            validate_connection(rounded)
                .normalized
                .expect("valid")
                .timeouts
                .tcp_connect_seconds,
            46
        );
    }

    #[test]
    fn keepalive_accepts_zero_as_disabled_and_rejects_unbounded_values() {
        let mut config = valid_config();
        config.keepalive.interval_seconds = Some(0);
        config.keepalive.count_max = Some(1_001);

        let result = validate_connection(config);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].field, "keepalive.countMax");
    }

    #[test]
    fn legacy_auth_inference_is_preserved() {
        let mut legacy_password = valid_config();
        legacy_password.auth.has_password = true;
        assert_eq!(
            validate_connection(legacy_password).auth_plan.method,
            SshAuthMethod::Password
        );

        let mut versioned = valid_config();
        versioned.auth.has_password = true;
        versioned.auth.auth_policy_version = Some(1);
        assert_eq!(
            validate_connection(versioned).auth_plan.method,
            SshAuthMethod::Auto
        );
    }
}
