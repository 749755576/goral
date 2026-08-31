use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use netcatty_et::{
    EtAskpassMap, EtClientError, EtClientResolver, EtEndpoint, EtHostKeyChecking, EtJumpHost,
    EtNativeEnvironment, EtRuntimeError, EtRuntimeEvent, EtSessionConfig, EtSessionId, EtSshOption,
    EtStartRequest, EtTarget, MAX_INPUT_BYTES, NativePath, TrustedEtClient,
};
use netcatty_ssh::{ConnectionCredentials, KnownHost, SshAuthMethod, SshConnectionConfig};
use netcatty_vault::{SavedHost, SavedHostId};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeBody, Request, Response};
use tauri::{State, WebviewWindow};

use super::connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_started_connection_log,
};
use super::{
    ClientAttemptId, DesktopState, PreparedSavedHostSession, StartSavedHostSessionRequest,
    confirm_current_saved_host_snapshot, connection_log_replay_manager_for_session,
    current_unix_millis, finalize_connection_log_replay, frame_data, plan_saved_host_chain,
    prepare_saved_host_session_operation, saved_host_invalid, saved_host_not_found,
    saved_host_repair_required,
};

const ET_SESSION_ID_BYTES: usize = 36;
const DEFAULT_ET_PORT: u16 = 2022;
const MAX_KNOWN_HOSTS_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_ET_KEY_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_ET_CERTIFICATE_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_ET_ASKPASS_SECRET_BYTES: usize = 64 * 1_024;
const ET_NOT_ENABLED: &str =
    "ET_NOT_ENABLED: Eternal Terminal is not enabled for this saved SSH host";
const ET_CHAIN_UNSUPPORTED: &str =
    "ET_JUMP_CHAIN_UNSUPPORTED: Eternal Terminal supports at most one saved jump host";
const ET_PROXY_UNSUPPORTED: &str =
    "ET_PROXY_UNSUPPORTED: Eternal Terminal does not support this saved proxy configuration";
const ET_AUTH_UNSUPPORTED: &str = "ET_AUTH_UNSUPPORTED: This saved authentication mode cannot be passed safely to Eternal Terminal";
const ET_AUTH_INVALID: &str = "ET_AUTH_INVALID: The saved Eternal Terminal credential does not match its authentication policy";
const ET_AUTH_STORAGE_UNAVAILABLE: &str =
    "ET_AUTH_STORAGE_UNAVAILABLE: Private Eternal Terminal authentication storage is unavailable";
const ET_ALGORITHM_UNSUPPORTED: &str = "ET_ALGORITHM_UNSUPPORTED: This saved SSH algorithm policy cannot yet be applied safely to Eternal Terminal";
const ET_RESOURCE_UNAVAILABLE: &str =
    "ET_CLIENT_UNAVAILABLE: The bundled Eternal Terminal client is unavailable";
const EXIT_MODE_RESET: &[u8] =
    b"\x1b[0m\x1b[?1l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartedEtSession {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum EtControlEvent {
    Connecting,
    Connected,
    Error { code: String, message: String },
    ExitStatus { status: u32 },
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EtTerminalSize {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

struct EtStartPlan {
    revision: u64,
    target_et_port: u16,
    jump_ports: Vec<(String, u16)>,
}

struct EtAuthArtifacts {
    directory: PathBuf,
    files: Vec<PathBuf>,
}

impl EtAuthArtifacts {
    fn track(&mut self, path: PathBuf) {
        self.files.push(path);
    }
}

impl Drop for EtAuthArtifacts {
    fn drop(&mut self) {
        // Never recurse through a directory an external native process could
        // have replaced while ET ran. Remove only exact files created here.
        for path in self.files.iter().rev() {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(&self.directory);
    }
}

pub(crate) fn resolve_trusted_et_client(
    resource_dir: &Path,
) -> Result<TrustedEtClient, EtClientError> {
    EtClientResolver::new(resource_dir.to_path_buf()).resolve_current()
}

fn available_client(state: &DesktopState) -> Result<TrustedEtClient, String> {
    state
        .et_client
        .as_ref()
        .as_ref()
        .cloned()
        .map_err(|_| ET_RESOURCE_UNAVAILABLE.to_owned())
}

#[tauri::command]
pub(crate) async fn start_et_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: EtStartRequest,
    on_control: Channel<EtControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedEtSession, String> {
    request.validate().map_err(et_config_error)?;
    let client = available_client(state.inner())?;
    let plan = prepare_et_start_plan(state.inner(), request.host_id()).await?;
    let ssh_request = StartSavedHostSessionRequest {
        client_attempt_id: ClientAttemptId::internal("et-saved"),
        host_id: request.host_id().to_owned(),
        expected_revision: plan.revision,
        credential_reference: None,
        proxy_credential_reference: None,
        key_passphrase_reference: None,
        selected_identity_file_paths: Vec::new(),
        known_hosts: Vec::new(),
        verify_host_keys: true,
        shell: None,
    };
    let prepared = prepare_saved_host_session_operation(
        state.inner().clone(),
        window.label().to_owned(),
        ssh_request,
    )
    .await?;
    begin_et_session(
        state.inner(),
        request,
        client,
        plan,
        prepared,
        on_control,
        on_data,
    )
    .await
}

async fn prepare_et_start_plan(state: &DesktopState, host_id: &str) -> Result<EtStartPlan, String> {
    let id = SavedHostId::from_opaque(host_id.to_owned()).map_err(|_| saved_host_invalid())?;
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let mut matches = snapshot.graph().hosts().iter().filter(|host| host.id == id);
    let host = matches.next().ok_or_else(saved_host_not_found)?;
    if matches.next().is_some() {
        return Err(saved_host_repair_required());
    }
    let chain = plan_saved_host_chain(snapshot.graph(), host)?;
    let effective = chain.target.effective_host();
    if !effective.protocol.is_ssh() {
        return Err(ET_NOT_ENABLED.to_owned());
    }
    if !effective_et_enabled(effective)? {
        return Err(ET_NOT_ENABLED.to_owned());
    }
    if chain.jumps.len() > 1 {
        return Err(ET_CHAIN_UNSUPPORTED.to_owned());
    }
    let target_et_port = effective_et_port(effective)?;
    let mut jump_ports = Vec::with_capacity(chain.jumps.len());
    for (jump_id, projection) in chain.jumps {
        jump_ports.push((jump_id, effective_et_port(projection.effective_host())?));
    }
    Ok(EtStartPlan {
        revision: host.revision,
        target_et_port,
        jump_ports,
    })
}

pub(crate) fn effective_et_enabled(host: &SavedHost) -> Result<bool, String> {
    if !host.protocol.is_ssh() {
        return Ok(false);
    }
    match host.compatibility_fields().get("etEnabled") {
        Some(serde_json::Value::Bool(true)) => {
            // Legacy Netcatty treats Mosh and ET as mutually exclusive. Keep
            // the renderer projection and native start authority aligned even
            // for an old/imported record that contains both switches.
            Ok(!crate::mosh_session::effective_mosh_enabled(host))
        }
        Some(serde_json::Value::Bool(false)) => Ok(false),
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(_) => Err(saved_host_repair_required()),
    }
}

fn effective_et_port(host: &SavedHost) -> Result<u16, String> {
    match host.compatibility_fields().get("etPort") {
        None | Some(serde_json::Value::Null) => Ok(DEFAULT_ET_PORT),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or_else(saved_host_repair_required),
        Some(_) => Err(saved_host_repair_required()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn begin_et_session(
    state: &DesktopState,
    request: EtStartRequest,
    client: TrustedEtClient,
    plan: EtStartPlan,
    prepared: PreparedSavedHostSession,
    on_control: Channel<EtControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedEtSession, String> {
    let PreparedSavedHostSession {
        client_attempt_id: _,
        config,
        credentials,
        jump_hosts,
        known_hosts,
        verify_host_keys,
        shell: _,
        connection_log,
        effective_mosh_enabled,
    } = prepared;
    if effective_mosh_enabled {
        return Err(ET_NOT_ENABLED.to_owned());
    }
    if config.proxy.is_some() || jump_hosts.iter().any(|jump| jump.config.proxy.is_some()) {
        return Err(ET_PROXY_UNSUPPORTED.to_owned());
    }
    if jump_hosts.len() != plan.jump_ports.len()
        || jump_hosts
            .iter()
            .zip(&plan.jump_ports)
            .any(|(prepared, (id, _))| prepared.host_id != *id)
    {
        return Err(ET_CHAIN_UNSUPPORTED.to_owned());
    }
    ensure_supported_auth(&config, false)?;
    for jump in &jump_hosts {
        ensure_supported_auth(&jump.config, true)?;
    }

    let target = EtEndpoint::new(
        config.hostname.clone(),
        config.username.clone(),
        config
            .port
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(22),
        plan.target_et_port,
    )
    .map_err(et_config_error)?;
    let jumps = jump_hosts
        .iter()
        .zip(&plan.jump_ports)
        .map(|(jump, (_, et_port))| {
            EtEndpoint::new(
                jump.config.hostname.clone(),
                jump.config.username.clone(),
                jump.config
                    .port
                    .and_then(|port| u16::try_from(port).ok())
                    .unwrap_or(22),
                *et_port,
            )
            .map(EtJumpHost::new)
            .map_err(et_config_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let target =
        EtTarget::new(request.host_id().to_owned(), target, jumps).map_err(et_config_error)?;
    let (artifacts, cwd, environment, ssh_options) = prepare_auth_artifacts(
        state.et_auth_root.as_ref(),
        &config,
        &credentials,
        &jump_hosts,
        &known_hosts,
        verify_host_keys,
    )?;
    // Authentication artifacts now own the only external copies. Drop the
    // resolved zeroizing credentials before any ET process is started.
    drop(credentials);
    drop(jump_hosts);
    let session_config =
        EtSessionConfig::resolve(request, target, client, cwd, ssh_options, environment, None)
            .map_err(et_config_error)?;
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let started = state
        .et_sessions
        .start(session_config)
        .map_err(et_runtime_error)?;
    let (session_id, events) = started.into_parts();
    let response = StartedEtSession {
        session_id: session_id.as_str().to_owned(),
    };
    forward_et_events(
        state.clone(),
        session_id,
        events,
        artifacts,
        connection_log.into_et(),
        replay_manager,
        on_control,
        on_data,
    );
    Ok(response)
}

fn ensure_supported_auth(config: &SshConnectionConfig, is_jump: bool) -> Result<(), String> {
    if config.legacy_algorithms == Some(true)
        || config.skip_ecdsa_host_key
        || !config.algorithms.kex.is_empty()
        || !config.algorithms.cipher.is_empty()
        || !config.algorithms.hmac.is_empty()
        || !config.algorithms.server_host_key.is_empty()
        || !config.algorithms.compress.is_empty()
    {
        return Err(ET_ALGORITHM_UNSUPPORTED.to_owned());
    }
    let auth = &config.auth;
    if auth.requires_mfa
        || auth.has_public_key
        || auth.key_available
        || auth.identity_available
        || auth.identity_id.is_some()
        || auth.key_id.is_some()
        || auth.use_ssh_agent == Some(true)
        || auth.identity_agent.is_some()
        || !auth.identity_file_paths.is_empty()
        || auth.agent_forwarding
    {
        return Err(ET_AUTH_UNSUPPORTED.to_owned());
    }
    match auth.selected_method() {
        SshAuthMethod::Auto
            if !auth.has_password && !auth.has_private_key && !auth.has_certificate =>
        {
            Ok(())
        }
        SshAuthMethod::Password
            if auth.has_password && !auth.has_private_key && !auth.has_certificate =>
        {
            Ok(())
        }
        SshAuthMethod::Key
            if !is_jump && auth.has_private_key && !auth.has_password && !auth.has_certificate =>
        {
            Ok(())
        }
        SshAuthMethod::Certificate
            if !is_jump && auth.has_private_key && auth.has_certificate && !auth.has_password =>
        {
            Ok(())
        }
        _ => Err(ET_AUTH_UNSUPPORTED.to_owned()),
    }
}

fn prepare_auth_artifacts(
    root: &Path,
    target: &SshConnectionConfig,
    target_credentials: &ConnectionCredentials,
    jumps: &[super::PreparedSavedHostJump],
    known_hosts: &[KnownHost],
    verify_host_keys: bool,
) -> Result<
    (
        EtAuthArtifacts,
        NativePath,
        EtNativeEnvironment,
        Vec<EtSshOption>,
    ),
    String,
> {
    if !root.is_absolute() {
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    fs::create_dir_all(root).map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
    if path_is_reparse_point(root)? {
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    harden_private_directory(root)?;
    let root = fs::canonicalize(root).map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
    let raw_directory = root.join(format!("session-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&raw_directory).map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
    if path_is_reparse_point(&raw_directory).unwrap_or(true)
        || harden_private_directory(&raw_directory).is_err()
    {
        let _ = fs::remove_dir(&raw_directory);
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    let directory = match fs::canonicalize(&raw_directory) {
        Ok(directory) => directory,
        Err(_) => {
            let _ = fs::remove_dir(&raw_directory);
            return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
        }
    };
    if !directory.starts_with(&root) || directory.parent() != Some(root.as_path()) {
        let _ = fs::remove_dir(&raw_directory);
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    let mut artifacts = EtAuthArtifacts {
        directory: directory.clone(),
        files: Vec::new(),
    };
    let known_hosts_path = directory.join("known_hosts");
    let jump_configs = jumps.iter().map(|jump| &jump.config).collect::<Vec<_>>();
    let content = render_known_hosts(target, &jump_configs, known_hosts)?;
    write_tracked_private_file(&mut artifacts, &known_hosts_path, content.as_bytes())?;
    let cwd = NativePath::existing_directory(directory.clone()).map_err(et_config_error)?;
    let known_hosts_path = NativePath::existing_file(known_hosts_path).map_err(et_config_error)?;
    let mut environment = EtNativeEnvironment::new();
    environment.set_home(cwd.clone());
    environment.set_user_profile(cwd.clone());
    let mut ssh_options = vec![
        EtSshOption::UserKnownHostsFile(known_hosts_path.clone()),
        EtSshOption::GlobalKnownHostsFile(known_hosts_path),
        EtSshOption::DisableKnownHostsCommand,
        EtSshOption::StrictHostKeyChecking(if verify_host_keys {
            EtHostKeyChecking::AcceptNew
        } else {
            EtHostKeyChecking::No
        }),
        EtSshOption::LogLevelError,
        EtSshOption::DisableIdentityAgent,
        EtSshOption::OnePasswordPrompt,
    ];
    let mut askpass_map = EtAskpassMap::new();
    prepare_target_auth_artifacts(
        &directory,
        target,
        target_credentials,
        &mut artifacts,
        &mut askpass_map,
        &mut ssh_options,
    )?;
    for jump in jumps {
        prepare_jump_auth_artifacts(
            &directory,
            &jump.config,
            &jump.credentials,
            &mut artifacts,
            &mut askpass_map,
        )?;
    }
    if !askpass_map.is_empty() {
        let map_bytes = askpass_map
            .encode()
            .map_err(|_| ET_AUTH_INVALID.to_owned())?;
        let map_path = directory.join(random_artifact_name("askpass", ".map"));
        write_tracked_private_file(&mut artifacts, &map_path, &map_bytes)?;
        let map_path = NativePath::existing_file(map_path).map_err(et_config_error)?;
        let helper_path =
            std::env::current_exe().map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
        let helper_path = NativePath::existing_file(helper_path)
            .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
        environment.set_ssh_askpass(helper_path);
        environment.set_askpass_map(map_path);
        environment.enable_askpass_helper();
        environment
            .set_display("netcatty-et:0".to_owned())
            .map_err(et_config_error)?;
    }
    Ok((artifacts, cwd, environment, ssh_options))
}

fn prepare_target_auth_artifacts(
    directory: &Path,
    config: &SshConnectionConfig,
    credentials: &ConnectionCredentials,
    artifacts: &mut EtAuthArtifacts,
    askpass_map: &mut EtAskpassMap,
    ssh_options: &mut Vec<EtSshOption>,
) -> Result<(), String> {
    credentials.expose_to_native_client(|view| match config.auth.selected_method() {
        SshAuthMethod::Auto => {
            if credential_view_has_material(&view) {
                Err(ET_AUTH_INVALID.to_owned())
            } else {
                Ok(())
            }
        }
        SshAuthMethod::Password => {
            if view.private_key_bytes().is_some()
                || view.private_key_passphrase_bytes().is_some()
                || view.certificate_bytes().is_some()
                || !view.agent_public_keys().is_empty()
            {
                return Err(ET_AUTH_INVALID.to_owned());
            }
            let password = view
                .password_bytes()
                .ok_or_else(|| ET_AUTH_INVALID.to_owned())?;
            validate_askpass_secret(password)?;
            let secret_name = random_artifact_name("secret", ".bin");
            let secret_path = directory.join(&secret_name);
            write_tracked_private_file(artifacts, &secret_path, password)?;
            askpass_map
                .add_password(
                    &format!("{}@{}", config.username, config.hostname),
                    &secret_name,
                )
                .map_err(|_| ET_AUTH_INVALID.to_owned())?;
            ssh_options.push(EtSshOption::DisablePublicKeyAuthentication);
            ssh_options.push(EtSshOption::EnableKeyboardInteractive);
            Ok(())
        }
        SshAuthMethod::Key | SshAuthMethod::Certificate => {
            if view.password_bytes().is_some() || !view.agent_public_keys().is_empty() {
                return Err(ET_AUTH_INVALID.to_owned());
            }
            let private_key = view
                .private_key_bytes()
                .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_ET_KEY_BYTES)
                .ok_or_else(|| ET_AUTH_INVALID.to_owned())?;
            let key_name = random_artifact_name("identity", "");
            let key_path = directory.join(&key_name);
            write_tracked_private_file(artifacts, &key_path, private_key)?;
            let native_key = NativePath::existing_file(key_path)
                .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
            ssh_options.push(EtSshOption::IdentityFile(native_key));
            ssh_options.push(EtSshOption::IdentitiesOnly);
            ssh_options.push(EtSshOption::PublicKeyAuthenticationOnly);

            if let Some(passphrase) = view.private_key_passphrase_bytes() {
                validate_askpass_secret(passphrase)?;
                let secret_name = random_artifact_name("secret", ".bin");
                let secret_path = directory.join(&secret_name);
                write_tracked_private_file(artifacts, &secret_path, passphrase)?;
                askpass_map
                    .add_passphrase(&key_name, &secret_name)
                    .map_err(|_| ET_AUTH_INVALID.to_owned())?;
            }

            match (config.auth.selected_method(), view.certificate_bytes()) {
                (SshAuthMethod::Certificate, Some(certificate))
                    if !certificate.is_empty() && certificate.len() <= MAX_ET_CERTIFICATE_BYTES =>
                {
                    let certificate_path =
                        directory.join(random_artifact_name("certificate", ".pub"));
                    write_tracked_private_file(artifacts, &certificate_path, certificate)?;
                    let certificate_path = NativePath::existing_file(certificate_path)
                        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
                    ssh_options.push(EtSshOption::CertificateFile(certificate_path));
                    Ok(())
                }
                (SshAuthMethod::Key, None) => Ok(()),
                _ => Err(ET_AUTH_INVALID.to_owned()),
            }
        }
    })
}

fn prepare_jump_auth_artifacts(
    directory: &Path,
    config: &SshConnectionConfig,
    credentials: &ConnectionCredentials,
    artifacts: &mut EtAuthArtifacts,
    askpass_map: &mut EtAskpassMap,
) -> Result<(), String> {
    credentials.expose_to_native_client(|view| match config.auth.selected_method() {
        SshAuthMethod::Auto => {
            if credential_view_has_material(&view) {
                Err(ET_AUTH_INVALID.to_owned())
            } else {
                Ok(())
            }
        }
        SshAuthMethod::Password => {
            if view.private_key_bytes().is_some()
                || view.private_key_passphrase_bytes().is_some()
                || view.certificate_bytes().is_some()
                || !view.agent_public_keys().is_empty()
            {
                return Err(ET_AUTH_INVALID.to_owned());
            }
            let password = view
                .password_bytes()
                .ok_or_else(|| ET_AUTH_INVALID.to_owned())?;
            validate_askpass_secret(password)?;
            let secret_name = random_artifact_name("secret", ".bin");
            let secret_path = directory.join(&secret_name);
            write_tracked_private_file(artifacts, &secret_path, password)?;
            askpass_map
                .add_password(
                    &format!("{}@{}", config.username, config.hostname),
                    &secret_name,
                )
                .map_err(|_| ET_AUTH_INVALID.to_owned())
        }
        SshAuthMethod::Key | SshAuthMethod::Certificate => Err(ET_AUTH_UNSUPPORTED.to_owned()),
    })
}

fn credential_view_has_material(view: &netcatty_ssh::NativeClientCredentialView<'_>) -> bool {
    view.password_bytes().is_some()
        || view.private_key_bytes().is_some()
        || view.private_key_passphrase_bytes().is_some()
        || view.certificate_bytes().is_some()
        || !view.agent_public_keys().is_empty()
}

fn validate_askpass_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty()
        || secret.len() > MAX_ET_ASKPASS_SECRET_BYTES
        || secret.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(ET_AUTH_INVALID.to_owned());
    }
    Ok(())
}

fn random_artifact_name(prefix: &str, suffix: &str) -> String {
    format!("{prefix}-{}{suffix}", uuid::Uuid::new_v4())
}

fn render_known_hosts(
    target: &SshConnectionConfig,
    jumps: &[&SshConnectionConfig],
    known_hosts: &[KnownHost],
) -> Result<String, String> {
    let mut output = String::new();
    for endpoint in std::iter::once(target).chain(jumps.iter().copied()) {
        let port = endpoint
            .port
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(22);
        for known in known_hosts
            .iter()
            .filter(|known| known_host_matches(known, &endpoint.hostname, port))
        {
            let Some(public_key) = known.public_key.as_deref() else {
                continue;
            };
            let mut fields = public_key.split_whitespace();
            let Some(key_type) = fields.next() else {
                continue;
            };
            let Some(key_body) = fields.next() else {
                continue;
            };
            if key_type.is_empty()
                || key_body.is_empty()
                || key_type.chars().any(char::is_control)
                || key_body
                    .chars()
                    .any(|value| value.is_control() || value.is_whitespace())
            {
                continue;
            }
            let host = if port == 22 {
                endpoint.hostname.clone()
            } else {
                format!("[{}]:{port}", endpoint.hostname)
            };
            output.push_str(&host);
            output.push(' ');
            output.push_str(key_type);
            output.push(' ');
            output.push_str(key_body);
            output.push('\n');
            if output.len() > MAX_KNOWN_HOSTS_BYTES {
                return Err("ET_KNOWN_HOSTS_INVALID: Known Hosts data is too large".to_owned());
            }
        }
    }
    Ok(output)
}

fn known_host_matches(known: &KnownHost, hostname: &str, port: u16) -> bool {
    let first = known.hostname.trim().split(',').next().unwrap_or_default();
    let (known_hostname, embedded_port) = if let Some(rest) = first.strip_prefix('[') {
        rest.split_once("]:")
            .map(|(host, port)| (host, port.parse::<u16>().ok()))
            .unwrap_or((first, None))
    } else {
        (first, None)
    };
    !known_hostname.is_empty()
        && known_hostname.eq_ignore_ascii_case(hostname.trim())
        && known.port.or(embedded_port).unwrap_or(22) == port
}

fn write_tracked_private_file(
    artifacts: &mut EtAuthArtifacts,
    path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    if path.parent() != Some(artifacts.directory.as_path()) {
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    artifacts.track(path.to_path_buf());
    write_private_file(path, bytes)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())?;
    harden_private_file(path)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(unix)]
fn path_is_reparse_point(path: &Path) -> Result<bool, String> {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(windows)]
fn path_is_reparse_point(path: &Path) -> Result<bool, String> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(not(any(unix, windows)))]
fn path_is_reparse_point(_: &Path) -> Result<bool, String> {
    Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(unix)]
fn harden_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(unix)]
fn harden_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(windows)]
fn harden_private_directory(path: &Path) -> Result<(), String> {
    apply_private_windows_acl(path)
}

#[cfg(windows)]
fn harden_private_file(path: &Path) -> Result<(), String> {
    apply_private_windows_acl(path)
}

#[cfg(windows)]
fn apply_private_windows_acl(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };

    // Protected DACL: the file owner and LocalSystem only. No inherited ACE is
    // retained, so another local account cannot read transient credentials.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)\0".encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let applied = unsafe {
        SetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if applied == 0 {
        return Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn harden_private_directory(_: &Path) -> Result<(), String> {
    Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[cfg(not(any(unix, windows)))]
fn harden_private_file(_: &Path) -> Result<(), String> {
    Err(ET_AUTH_STORAGE_UNAVAILABLE.to_owned())
}

#[tauri::command]
pub(crate) fn et_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("Eternal Terminal input must use raw IPC".to_owned()),
    };
    let (session_id, input) = parse_input_envelope(bytes)?;
    state
        .et_sessions
        .input(&session_id, input)
        .map_err(et_runtime_error)
}

#[tauri::command]
pub(crate) fn resize_et_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: EtTerminalSize,
) -> Result<(), String> {
    let _ = (size.pixel_width, size.pixel_height);
    state
        .et_sessions
        .resize(&parse_session_id(&session_id)?, size.columns, size.rows)
        .map_err(et_runtime_error)
}

#[tauri::command]
pub(crate) fn close_et_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state
        .et_sessions
        .close(&parse_session_id(&session_id)?)
        .map_err(et_runtime_error)
}

#[tauri::command]
pub(crate) fn cancel_et_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state
        .et_sessions
        .cancel(&parse_session_id(&session_id)?)
        .map_err(et_runtime_error)
}

fn parse_session_id(value: &str) -> Result<EtSessionId, String> {
    if value.len() != ET_SESSION_ID_BYTES {
        return Err("Invalid Eternal Terminal session ID".to_owned());
    }
    EtSessionId::parse(value).map_err(|_| "Invalid Eternal Terminal session ID".to_owned())
}

fn parse_input_envelope(bytes: &[u8]) -> Result<(EtSessionId, &[u8]), String> {
    const HEADER_BYTES: usize = 2;
    if bytes.len() > HEADER_BYTES + ET_SESSION_ID_BYTES + MAX_INPUT_BYTES {
        return Err("Eternal Terminal input exceeds the session limit".to_owned());
    }
    let length = bytes
        .get(..HEADER_BYTES)
        .and_then(|header| <[u8; HEADER_BYTES]>::try_from(header).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| "Invalid Eternal Terminal input envelope".to_owned())?;
    if length != ET_SESSION_ID_BYTES {
        return Err("Invalid Eternal Terminal session ID".to_owned());
    }
    let id_end = HEADER_BYTES + length;
    let session_id = bytes
        .get(HEADER_BYTES..id_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "Invalid Eternal Terminal session ID".to_owned())?;
    let input = bytes
        .get(id_end..)
        .ok_or_else(|| "Invalid Eternal Terminal input envelope".to_owned())?;
    Ok((parse_session_id(session_id)?, input))
}

#[allow(clippy::too_many_arguments)]
fn forward_et_events(
    state: DesktopState,
    session_id: EtSessionId,
    mut events: tokio::sync::mpsc::Receiver<EtRuntimeEvent>,
    artifacts: EtAuthArtifacts,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<super::connection_log_replay::ConnectionLogReplayManager>,
    on_control: Channel<EtControlEvent>,
    on_data: Channel<Response>,
) {
    let captured_session_id = session_id.as_str().to_owned();
    let started_log = current_unix_millis().ok().and_then(|start_time| {
        connection_log
            .into_started_log(&captured_session_id, start_time)
            .ok()
    });
    let captured_log_id = started_log.as_ref().map(|log| log.id.clone());
    let replay_capture = replay_manager.and_then(|replays| {
        let log = started_log.as_ref()?.clone();
        replays
            .begin_session(captured_session_id.clone(), log)
            .ok()?;
        Some(replays)
    });
    let manager = state.et_sessions.clone();
    tauri::async_runtime::spawn(async move {
        let _artifacts = artifacts;
        let start_state = state.clone();
        let start_capture = tauri::async_runtime::spawn(async move {
            if let Some(log) = started_log {
                persist_started_connection_log(start_state, log)
                    .await
                    .is_ok()
            } else {
                false
            }
        });
        let mut renderer_open = true;
        while let Some(event) = events.recv().await {
            let result = match event {
                EtRuntimeEvent::Starting => on_control.send(EtControlEvent::Connecting),
                EtRuntimeEvent::Started { .. } => on_control.send(EtControlEvent::Connected),
                EtRuntimeEvent::Data(data) => {
                    let data = data.into_vec();
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, &data);
                    }
                    on_data.send(Response::new(frame_data(0, None, data)))
                }
                EtRuntimeEvent::Error(error) => on_control.send(EtControlEvent::Error {
                    code: et_runtime_code(&error).to_owned(),
                    message: error.to_string(),
                }),
                EtRuntimeEvent::Exited(exit) => {
                    if let Some(status) = exit.exit_code() {
                        let _ = on_control.send(EtControlEvent::ExitStatus { status });
                    }
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, EXIT_MODE_RESET);
                    }
                    let _ =
                        on_data.send(Response::new(frame_data(0, None, EXIT_MODE_RESET.to_vec())));
                    let _ = on_control.send(EtControlEvent::Closed);
                    break;
                }
            };
            if renderer_open && result.is_err() {
                renderer_open = false;
                let _ = manager.cancel(&session_id);
            }
        }

        let started_persisted = start_capture.await.unwrap_or(false);
        if !started_persisted {
            if let Some(replays) = replay_capture {
                let _ = replays.discard_session(&captured_session_id);
            }
            return;
        }
        let (Some(log_id), Ok(end_time)) = (captured_log_id, current_unix_millis()) else {
            if let Some(replays) = replay_capture {
                let _ = replays.discard_session(&captured_session_id);
            }
            return;
        };
        if let Some(replays) = replay_capture {
            finalize_connection_log_replay(state, replays, log_id, captured_session_id, end_time)
                .await;
        } else {
            let _ =
                persist_finished_connection_log(state, log_id, captured_session_id, end_time).await;
        }
    });
}

fn et_config_error(error: impl std::fmt::Display) -> String {
    format!("ET_CONFIG_INVALID: {error}")
}

fn et_runtime_error(error: EtRuntimeError) -> String {
    format!("{}: {error}", et_runtime_code(&error))
}

fn et_runtime_code(error: &EtRuntimeError) -> &'static str {
    match error {
        EtRuntimeError::InvalidSessionId => "ET_SESSION_ID_INVALID",
        EtRuntimeError::InputTooLarge { .. } => "ET_INPUT_TOO_LARGE",
        EtRuntimeError::InputQueueFull { .. } | EtRuntimeError::CommandQueueFull { .. } => {
            "ET_INPUT_BACKPRESSURE"
        }
        EtRuntimeError::SessionNotFound => "ET_SESSION_NOT_FOUND",
        EtRuntimeError::SessionClosing => "ET_SESSION_CLOSING",
        EtRuntimeError::Config(_) => "ET_CONFIG_INVALID",
        EtRuntimeError::RuntimeThreadUnavailable
        | EtRuntimeError::BackendFailed { .. }
        | EtRuntimeError::IoFailed { .. }
        | EtRuntimeError::FinalOutputDrainTimedOut { .. } => "ET_RUNTIME_FAILED",
        _ => "ET_RUNTIME_FAILED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_ssh::SecretText;
    use serde_json::json;

    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    #[test]
    fn raw_input_envelope_is_exact_and_bounded() {
        let mut envelope = Vec::from((SESSION_ID.len() as u16).to_be_bytes());
        envelope.extend_from_slice(SESSION_ID.as_bytes());
        envelope.extend_from_slice(b"abc");
        let (id, input) = parse_input_envelope(&envelope).unwrap();
        assert_eq!(id.as_str(), SESSION_ID);
        assert_eq!(input, b"abc");
        envelope[1] = 35;
        assert!(parse_input_envelope(&envelope).is_err());
    }

    #[test]
    fn effective_et_switch_is_ssh_only_and_mutually_exclusive_with_mosh() {
        let host = |protocol: &str, et_enabled: serde_json::Value, mosh_enabled: bool| {
            serde_json::from_value::<SavedHost>(json!({
                "recordVersion": 1,
                "id": format!("et-switch-{protocol}-{mosh_enabled}"),
                "revision": 1,
                "label": "ET switch host",
                "hostname": "et-switch.example.test",
                "port": 22,
                "username": "alice",
                "protocol": protocol,
                "authMethod": "auto",
                "authPolicyVersion": 1,
                "createdAt": 10,
                "updatedAt": 10,
                "etEnabled": et_enabled,
                "moshEnabled": mosh_enabled
            }))
            .expect("saved host")
        };

        assert_eq!(
            effective_et_enabled(&host("ssh", json!(true), false)),
            Ok(true)
        );
        assert_eq!(
            effective_et_enabled(&host("ssh", json!(true), true)),
            Ok(false)
        );
        assert_eq!(
            effective_et_enabled(&host("telnet", json!(true), false)),
            Ok(false)
        );
        assert!(effective_et_enabled(&host("ssh", json!("invalid"), false)).is_err());
    }

    #[test]
    fn saved_password_and_managed_target_auth_are_admitted_without_mfa() {
        let config = SshConnectionConfig::saved_password_host("target.test", 22, "alice");
        assert_eq!(ensure_supported_auth(&config, false), Ok(()));

        let key = SshConnectionConfig::saved_managed_key_host("target.test", 22, "alice", false);
        assert_eq!(ensure_supported_auth(&key, false), Ok(()));
        assert_eq!(
            ensure_supported_auth(&key, true),
            Err(ET_AUTH_UNSUPPORTED.to_owned())
        );

        let mut mfa = config;
        mfa.auth.requires_mfa = true;
        assert_eq!(
            ensure_supported_auth(&mfa, false),
            Err(ET_AUTH_UNSUPPORTED.to_owned())
        );
    }

    #[test]
    fn known_hosts_output_uses_only_endpoint_bound_public_keys() {
        let config = SshConnectionConfig::saved_password_host("target.test", 2222, "alice");
        let known = KnownHost {
            id: "kh".into(),
            hostname: "target.test".into(),
            port: Some(2222),
            key_type: "ssh-ed25519".into(),
            fingerprint: None,
            public_key: Some("ssh-ed25519 AAAATEST ignored-comment".into()),
        };
        assert_eq!(
            render_known_hosts(&config, &[], &[known]).unwrap(),
            "[target.test]:2222 ssh-ed25519 AAAATEST\n"
        );
    }

    #[test]
    fn password_artifacts_are_scoped_redacted_and_removed_exactly() {
        const SENTINEL: &str = "et-password-sentinel-never-in-map-or-debug";
        let root = std::env::temp_dir().join(format!("netcatty-et-auth-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let config = SshConnectionConfig::saved_password_host("target.test", 22, "alice");
        let credentials = ConnectionCredentials::empty().with_password(SecretText::new(SENTINEL));
        let (artifacts, _, environment, options) =
            prepare_auth_artifacts(&root, &config, &credentials, &[], &[], true).unwrap();

        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::DisablePublicKeyAuthentication))
        );
        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::EnableKeyboardInteractive))
        );
        let environment_debug = format!("{environment:?}");
        assert!(environment_debug.contains("SSH_ASKPASS"));
        assert!(environment_debug.contains("NETCATTY_ET_ASKPASS_HELPER"));
        assert!(!environment_debug.contains(SENTINEL));

        let map_path = artifacts
            .files
            .iter()
            .find(|path| path.extension().is_some_and(|value| value == "map"))
            .unwrap();
        let map = fs::read(map_path).unwrap();
        assert!(
            !map.windows(SENTINEL.len())
                .any(|window| window == SENTINEL.as_bytes())
        );
        let directory = artifacts.directory.clone();
        let files = artifacts.files.clone();
        drop(artifacts);
        assert!(!directory.exists());
        assert!(files.iter().all(|path| !path.exists()));
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn delimiter_bearing_password_fails_before_launch_and_cleans_session_directory() {
        let root = std::env::temp_dir().join(format!("netcatty-et-auth-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let config = SshConnectionConfig::saved_password_host("target.test", 22, "alice");
        let credentials =
            ConnectionCredentials::empty().with_password(SecretText::new("unsafe\npassword"));
        let result = prepare_auth_artifacts(&root, &config, &credentials, &[], &[], true);
        assert_eq!(result.err().unwrap(), ET_AUTH_INVALID);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn managed_certificate_artifacts_bind_key_certificate_and_passphrase() {
        let key = [
            "-----BEGIN OPENSSH PRIVATE",
            " KEY-----\nTEST\n-----END OPENSSH PRIVATE",
            " KEY-----\n",
        ]
        .concat();
        const PASSPHRASE: &str = "managed-passphrase-sentinel";
        const CERTIFICATE: &str = "ssh-ed25519-cert-v01@openssh.com AAAATEST";
        let root = std::env::temp_dir().join(format!("netcatty-et-auth-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let config = SshConnectionConfig::saved_managed_key_host("target.test", 22, "alice", true);
        let credentials = ConnectionCredentials::empty()
            .with_private_key(
                SecretText::new(key.as_str()),
                Some(SecretText::new(PASSPHRASE)),
            )
            .with_certificate(CERTIFICATE);
        let (artifacts, _, environment, options) =
            prepare_auth_artifacts(&root, &config, &credentials, &[], &[], true).unwrap();

        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::IdentityFile(_)))
        );
        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::CertificateFile(_)))
        );
        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::IdentitiesOnly))
        );
        assert!(
            options
                .iter()
                .any(|option| matches!(option, EtSshOption::PublicKeyAuthenticationOnly))
        );
        let debug = format!("{environment:?}");
        assert!(debug.contains("SSH_ASKPASS"));
        assert!(!debug.contains(PASSPHRASE));
        let map_path = artifacts
            .files
            .iter()
            .find(|path| path.extension().is_some_and(|value| value == "map"))
            .unwrap();
        let map = fs::read(map_path).unwrap();
        assert!(
            !map.windows(PASSPHRASE.len())
                .any(|window| window == PASSPHRASE.as_bytes())
        );
        let directory = artifacts.directory.clone();
        drop(artifacts);
        assert!(!directory.exists());
        fs::remove_dir(root).unwrap();
    }
}
