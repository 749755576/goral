use serde::Serialize;

use crate::model::{SshAuthConfig, SshAuthMethod};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthAttemptKind {
    None,
    KeyboardInteractive,
    SshAgent,
    SelectedKey,
    Certificate,
    DefaultKeys,
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthAttempt {
    pub kind: AuthAttemptKind,
    pub can_prompt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPlan {
    pub method: SshAuthMethod,
    pub attempts: Vec<AuthAttempt>,
    pub agent_forwarding: bool,
}

/// Builds the secret-free authentication order. Transport code will later bind each
/// entry to actual credentials without changing the policy order defined here.
#[must_use]
pub fn plan_authentication(auth: &SshAuthConfig) -> AuthPlan {
    let method = auth.selected_method();
    let mut attempts = vec![attempt(AuthAttemptKind::None, false)];

    match method {
        SshAuthMethod::Password => {
            append_password_attempts(&mut attempts, auth);
        }
        SshAuthMethod::Key => {
            if auth.use_ssh_agent == Some(true) && auth.has_key_selector() {
                attempts.push(attempt(AuthAttemptKind::SshAgent, false));
            }
            if auth.has_key_selector() {
                attempts.push(attempt(AuthAttemptKind::SelectedKey, false));
            }
            if auth.has_password {
                append_password_attempts(&mut attempts, auth);
            } else {
                attempts.push(attempt(AuthAttemptKind::KeyboardInteractive, true));
            }
        }
        SshAuthMethod::Certificate => {
            if auth.has_certificate {
                attempts.push(attempt(AuthAttemptKind::Certificate, false));
            }
            if auth.has_password {
                append_password_attempts(&mut attempts, auth);
            } else {
                attempts.push(attempt(AuthAttemptKind::KeyboardInteractive, true));
            }
        }
        SshAuthMethod::Auto => {
            if auth.requires_mfa && !auth.has_password {
                attempts.push(attempt(AuthAttemptKind::KeyboardInteractive, true));
            }
            if auth.use_ssh_agent != Some(false) {
                attempts.push(attempt(AuthAttemptKind::SshAgent, false));
            }
            if auth.has_key_selector() {
                attempts.push(attempt(AuthAttemptKind::SelectedKey, false));
            }
            attempts.push(attempt(AuthAttemptKind::DefaultKeys, false));
            if auth.has_password {
                append_password_attempts(&mut attempts, auth);
            }
            ensure_keyboard_interactive(&mut attempts);
        }
    }

    AuthPlan {
        method,
        attempts,
        agent_forwarding: auth.agent_forwarding,
    }
}

fn append_password_attempts(attempts: &mut Vec<AuthAttempt>, auth: &SshAuthConfig) {
    if auth.requires_mfa {
        ensure_keyboard_interactive(attempts);
    }
    if auth.has_password {
        attempts.push(attempt(AuthAttemptKind::Password, false));
    }
    ensure_keyboard_interactive(attempts);
}

fn ensure_keyboard_interactive(attempts: &mut Vec<AuthAttempt>) {
    if !attempts
        .iter()
        .any(|entry| entry.kind == AuthAttemptKind::KeyboardInteractive)
    {
        attempts.push(attempt(AuthAttemptKind::KeyboardInteractive, true));
    }
}

const fn attempt(kind: AuthAttemptKind, can_prompt: bool) -> AuthAttempt {
    AuthAttempt { kind, can_prompt }
}

#[cfg(test)]
mod tests {
    use super::{AuthAttemptKind, plan_authentication};
    use crate::model::{SshAuthConfig, SshAuthMethod};

    fn kinds(auth: &SshAuthConfig) -> Vec<AuthAttemptKind> {
        plan_authentication(auth)
            .attempts
            .into_iter()
            .map(|attempt| attempt.kind)
            .collect()
    }

    #[test]
    fn password_mode_never_attempts_keys_or_agent() {
        let auth = SshAuthConfig {
            method: Some(SshAuthMethod::Password),
            has_password: true,
            has_private_key: true,
            use_ssh_agent: Some(true),
            ..SshAuthConfig::default()
        };

        assert_eq!(
            kinds(&auth),
            vec![
                AuthAttemptKind::None,
                AuthAttemptKind::Password,
                AuthAttemptKind::KeyboardInteractive,
            ]
        );
    }

    #[test]
    fn mfa_moves_keyboard_interactive_before_password() {
        let auth = SshAuthConfig {
            method: Some(SshAuthMethod::Password),
            has_password: true,
            requires_mfa: true,
            ..SshAuthConfig::default()
        };

        assert_eq!(
            kinds(&auth),
            vec![
                AuthAttemptKind::None,
                AuthAttemptKind::KeyboardInteractive,
                AuthAttemptKind::Password,
            ]
        );
    }

    #[test]
    fn automatic_mode_preserves_ambient_agent_and_open_ssh_fallbacks() {
        let auth = SshAuthConfig::default();

        assert_eq!(
            kinds(&auth),
            vec![
                AuthAttemptKind::None,
                AuthAttemptKind::SshAgent,
                AuthAttemptKind::DefaultKeys,
                AuthAttemptKind::KeyboardInteractive,
            ]
        );
    }

    #[test]
    fn explicit_agent_opt_out_is_respected_in_automatic_mode() {
        let auth = SshAuthConfig {
            method: Some(SshAuthMethod::Auto),
            use_ssh_agent: Some(false),
            ..SshAuthConfig::default()
        };

        assert!(!kinds(&auth).contains(&AuthAttemptKind::SshAgent));
    }

    #[test]
    fn certificate_mode_never_uses_login_agent() {
        let auth = SshAuthConfig {
            method: Some(SshAuthMethod::Certificate),
            has_certificate: true,
            use_ssh_agent: Some(true),
            ..SshAuthConfig::default()
        };

        assert_eq!(
            kinds(&auth),
            vec![
                AuthAttemptKind::None,
                AuthAttemptKind::Certificate,
                AuthAttemptKind::KeyboardInteractive,
            ]
        );
    }
}
