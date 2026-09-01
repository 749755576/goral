mod ai_agent_discovery;
mod ai_agent_runtime;
mod ai_claude_runtime;
mod ai_commands;
// OpenCode isolation remains a test-only prototype until executable identity
// and whole-process-tree cancellation are proven fail-closed on Windows.
#[cfg(test)]
mod ai_opencode_runtime;
mod app_data_compat;
mod connection_log_capture;
mod connection_log_catalog;
mod connection_log_export;
mod connection_log_replay;
mod et_session;
mod group_config_catalog;
mod group_config_transaction;
mod known_hosts_catalog;
mod known_hosts_commands;
mod legacy_graph;
mod legacy_import_transaction;
mod local_pty_session;
mod managed_key_catalog;
mod managed_key_staging;
#[cfg(test)]
mod managed_key_transaction_tests;
mod mosh_session;
mod notes_snippets_catalog;
mod password_identity_catalog;
mod password_identity_transaction;
mod port_forward_catalog;
mod proxy_profile_catalog;
mod proxy_profile_transaction;
mod saved_host_auth_guard;
mod saved_host_proxy_catalog;
mod saved_host_visual;
mod saved_proxy_auth_guard;
mod saved_telnet_resolver;
mod serial_session;
mod serial_ymodem;
mod serial_zmodem;
mod settings_catalog;
mod settings_commands;
mod settings_window;
mod system_manager_commands;
mod telnet_session;
#[cfg(desktop)]
mod window_lifecycle;

use ai_agent_runtime::{cancel_local_ai_agent, run_local_ai_agent};
use ai_commands::{
    authorize_ai_agent_tool, cancel_ai_agent_turn, cancel_ai_chat, complete_ai_chat,
    continue_ai_agent_turn, delete_ai_api_key, has_saved_ai_api_key, list_ai_models,
    save_ai_api_key, start_ai_agent_turn, stream_ai_chat,
};
use connection_log_capture::{
    ConnectionLogCapture, persist_finished_connection_log, persist_finished_connection_log_locked,
    persist_started_connection_log,
};
use connection_log_catalog::{
    CONNECTION_LOGS_INVENTORY_CHANGED, CONNECTION_LOGS_PUBLICATION_FAILED,
    CONNECTION_LOGS_REPAIR_REQUIRED, ClearUnsavedConnectionLogsRequest, ConnectionLogsCatalog,
    ReplaceConnectionLogsRequest, connection_logs_error, connection_logs_invalid,
};
use connection_log_export::{
    ConnectionLogExportDialogLocale, ConnectionLogExportError, ConnectionLogExportTarget,
    ExportConnectionLogRequest, ExportConnectionLogResponse, authoritative_export_metadata,
    connection_log_export_command_error, connection_log_export_dialog_text,
    render_and_write_export_with_locale, selected_export_target,
};
use connection_log_replay::{
    ConnectionLogReplayManager, ConnectionLogReplayRuntime, ReadConnectionLogReplayRequest,
    ReadConnectionLogReplayResponse, connection_log_replay_command_error,
};
use et_session::{
    cancel_et_session, close_et_session, et_session_input_raw, resize_et_session,
    resolve_trusted_et_client, start_et_session,
};
use group_config_catalog::{
    CreateGroupConfigRequest, DeleteGroupConfigRequest, GroupConfigCatalog,
    UpdateGroupConfigRequest, group_config_invalid, group_config_repair_required,
    prepare_group_config_creation, prepare_group_config_deletion, prepare_group_config_update,
};
use group_config_transaction::{
    commit_group_config_deletion, commit_group_config_mutation, load_group_config_catalog,
};
use hmac::{Hmac, Mac};
use known_hosts_commands::{list_known_hosts, replace_known_hosts, scan_system_known_hosts};
use legacy_import_transaction::{
    LegacyImportCredentialOwner, LegacyImportCredentialOwnerKind, LegacyImportTransaction,
    LegacyImportTransactionPhase, LegacyPreviousCredentialState,
};
use local_pty_session::{
    cancel_local_pty_session, close_local_pty_session, list_local_shells,
    local_pty_session_input_raw, resize_local_pty_session, start_local_pty_session,
};
use managed_key_catalog::{
    CreateManagedSshKeyRequest, DeleteManagedSshKeyRequest, MANAGED_KEY_IN_USE,
    MANAGED_KEY_INVENTORY_CHANGED, MANAGED_KEY_PUBLICATION_FAILED, MANAGED_KEY_REPAIR_REQUIRED,
    ManagedSshKeyCatalog, ManagedSshKeyMetadataRequest, PreparedManagedKeyMutation,
    UpdateManagedSshKeyRequest, managed_key_error, preflight_managed_key_creation,
    prepare_managed_key_creation, prepare_managed_key_deletion, prepare_managed_key_update,
};
use managed_key_staging::{
    ManagedKeyStagingReference, ManagedKeyStagingStore, parse_managed_key_staging_envelope,
};
use mosh_session::{
    MoshClientAvailabilityError, MoshSessionManager, cancel_mosh_session, close_mosh_session,
    mosh_session_input_raw, resize_mosh_session, resolve_trusted_mosh_client, start_mosh_session,
    start_saved_mosh_session,
};
use netcatty_core::BackendStatus;
use netcatty_credentials::{
    CredentialErrorCode, CredentialKind, EphemeralCredentialReference, EphemeralCredentialStore,
    MasterKey, OsCredentialStore, OsMasterKeyStore, SecretValue, StoredCredentialReference,
};
use netcatty_migration::{
    LegacyCredentialDisposition, LegacyGroupConfigCandidate, LegacyHostCandidate,
    LegacyNotesSnippetsAssessment, LegacyNotesSnippetsCandidates, LegacyNotesSnippetsDisposition,
    LegacyPasswordIdentityCandidate, LegacyPasswordIdentityCredentialDisposition,
    LegacyProxyCredentialDisposition, LegacyProxyProfileCandidate, LegacyVaultDocument,
    LegacyVaultPreview, MAX_LEGACY_BACKUP_BYTES, parse_legacy_vault,
    plan_legacy_notes_snippets_import,
};
use netcatty_secret_store::{
    MasterKeyRotationRecovery, SecretFileMutation, SecretFileStore, SecretFileStoreErrorCode,
    SecretFileStoreExclusiveGuard, SecretFileStoreState, SecretObjectRetention, SshSecretBundle,
};
use netcatty_ssh::{
    ConnectionCredentials, DirectoryResumeCheckpoint, HostChainResolver, HostKeyBroker,
    HostKeyPrompt, InteractiveAuthBroker, InteractivePrompt, KnownHost, LocalTreeOptions,
    MAX_JUMP_HOSTS, NormalizedPortForwardRule, PortForwardError, PortForwardStart,
    PromptingHostKeyVerifier, PromptingInteractiveAuthResponder, ProxyConfig, ProxyType,
    RemoteTreeOptions, ResolvedPortForwardManager, ResolvedSshEndpoint, SecretText, SessionEvent,
    SessionManager, SessionManagerError, SessionSftpError, SessionStart, SftpDownloadPlan,
    SftpEntry, SftpError, SftpMetadata, SftpTransferCheckpoint, SftpTransferEvent, SftpUploadPlan,
    ShellOptions, SshConnectionConfig, SshJumpHost, TerminalSize, TransportError,
    TransportErrorCode, ValidationResult, validate_connection,
};
#[cfg(test)]
use netcatty_vault::SavedHostImportAssessment;
use netcatty_vault::{
    SavedGroupCatalog, SavedGroupConfig, SavedGroupConfigUpdate, SavedGroupCredentialOverride,
    SavedGroupId, SavedGroupPath, SavedGroupProxyOverride, SavedHost, SavedHostAuthMethod,
    SavedHostAuthentication, SavedHostConnectionCredentialOwner, SavedHostConnectionProjection,
    SavedHostDraft, SavedHostId, SavedHostImportDisposition, SavedHostInventoryRevision,
    SavedHostProtocol, SavedHostStore, SavedHostUpdate, SavedKnownHost, SavedManagedSshKey,
    SavedPasswordIdentity, SavedPasswordIdentityId, SavedPasswordIdentityUpdate, SavedProxyConfig,
    SavedProxyProfile, SavedProxyProfileId, SavedProxyProfileUpdate, SavedSecretObjectLocator,
    SavedSerialConfig, SavedSnippetId, SavedSshKeyCustodyReference, SavedSshKeyReferenceId,
    SavedVaultCommitDurability, SavedVaultDurableSnapshot, SavedVaultGraph,
    SavedVaultGraphCommitment, SavedVaultGraphImportAssessment, SavedVaultGraphReplacementPlan,
    SavedVaultImportDisposition, SavedVaultInventoryRevision, SavedVaultNoteId, StoreError,
    project_saved_host_connection,
};
use notes_snippets_catalog::{
    CreateSavedSnippetRequest, CreateVaultNoteRequest, DeleteSavedSnippetRequest,
    DeleteVaultNoteRequest, NOTES_SNIPPETS_INVENTORY_CHANGED, NOTES_SNIPPETS_PUBLICATION_FAILED,
    NotesSnippetsCatalog, PreparedNotesSnippetsMutation, UpdateSavedSnippetRequest,
    UpdateVaultNoteRequest, notes_snippets_error, notes_snippets_invalid, prepare_note_creation,
    prepare_note_deletion, prepare_note_update, prepare_snippet_creation, prepare_snippet_deletion,
    prepare_snippet_update,
};
use password_identity_catalog::{
    CreatePasswordIdentityRequest, DeletePasswordIdentityRequest, PasswordIdentityCatalog,
    UpdatePasswordIdentityRequest, password_identity_invalid, password_identity_repair_required,
    prepare_password_identity_creation, prepare_password_identity_deletion,
    prepare_password_identity_update,
};
use password_identity_transaction::{
    commit_password_identity_deletion, commit_password_identity_mutation,
    load_password_identity_catalog,
};
use port_forward_catalog::{
    CreatePortForwardRuleRequest, DeletePortForwardRuleRequest, PORT_FORWARD_ALREADY_RUNNING,
    PORT_FORWARD_CONNECTION_FAILED, PORT_FORWARD_INVENTORY_CHANGED, PORT_FORWARD_NOT_RUNNING,
    PORT_FORWARD_PUBLICATION_FAILED, PortForwardCatalog, PreparedPortForwardMutation,
    UpdatePortForwardRuleRequest, normalized_transport_rule, port_forward_error,
    prepare_creation as prepare_port_forward_creation,
    prepare_deletion as prepare_port_forward_deletion,
    prepare_update as prepare_port_forward_update,
};
use proxy_profile_catalog::{
    CreateProxyProfileRequest, DeleteProxyProfileRequest, ProxyProfileCatalog,
    UpdateProxyProfileRequest, prepare_proxy_profile_creation, prepare_proxy_profile_deletion,
    prepare_proxy_profile_update, proxy_profile_invalid, proxy_profile_repair_required,
};
use proxy_profile_transaction::{
    commit_proxy_profile_deletion, commit_proxy_profile_mutation, load_proxy_profile_catalog,
};
use saved_host_auth_guard::{
    SavedHostAuthResolution, SavedPasswordCredentialAction, SavedPasswordCredentialLookup,
    resolve_projected_saved_password_authentication, resolve_saved_host_authentication,
    resolve_saved_password_authentication, validate_saved_password_identity_selection,
};
use saved_host_proxy_catalog::{
    HostInlineProxyMutationRequest, HostProxyProfileMutationRequest,
    PreparedHostInlineProxyCredentialMutation, SavedHostProxyMutationRequest, SavedHostProxyView,
    prepare_saved_host_proxy_creation, prepare_saved_host_proxy_update, saved_host_proxy_view,
};
use saved_host_visual::SavedHostVisualView;
use saved_proxy_auth_guard::{
    SavedProxyAuthGuardError, SavedProxyConnectionPlan, SavedProxyCredentialAction,
    SavedProxyCredentialLookup, SavedProxyTransportPlan,
    resolve_projected_saved_proxy_authentication,
};
use saved_telnet_resolver::{
    ResolvedSavedTelnetSession, SavedTelnetHintRepair, SavedTelnetTerminalOptions,
    resolve_saved_telnet_session,
};
use serde::{Deserialize, Serialize};
use serial_session::{
    SerialControlEvent, SerialTerminalSize, StartedSerialSession, begin_serial_session,
    cancel_serial_session, close_serial_session, list_serial_ports, resize_serial_session,
    serial_session_input_raw, start_serial_session,
};
use serial_ymodem::{cancel_serial_ymodem, receive_serial_ymodem, send_serial_ymodem};
use serial_zmodem::{cancel_serial_zmodem, start_serial_zmodem};
use settings_catalog::RendererSafeSettingsStore;
use settings_commands::{list_settings, replace_settings};
use settings_window::{hide_settings_window, open_settings_window};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use system_manager_commands::{
    create_tmux_session, get_docker_stats, get_system_overview, inspect_docker_container,
    kill_tmux_session, list_docker_containers, list_docker_images, list_listening_ports,
    list_nvidia_gpus, list_remote_processes, list_system_services, list_tmux_sessions,
    rename_tmux_session, run_docker_container_action, run_system_service_action,
    signal_remote_process,
};
use tauri::ipc::{Channel, InvokeBody, Request, Response};
use tauri::{Manager, State, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use telnet_session::{
    StartedTelnetSession, TelnetControlEvent, begin_telnet_session, cancel_telnet_session,
    close_telnet_session, resize_telnet_session, start_telnet_session, telnet_session_input_raw,
};

const SAVED_CREDENTIAL_NOT_FOUND: &str = "SAVED_CREDENTIAL_NOT_FOUND";
const SAVED_HOST_REVISION_CONFLICT: &str = "SAVED_HOST_REVISION_CONFLICT";
const SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED: &str = "SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED";
const SAVED_HOST_KEY_FILE_SELECTION_INVALID: &str = "SAVED_HOST_KEY_FILE_SELECTION_INVALID";
const SAVED_HOST_MANAGED_KEY_UNAVAILABLE: &str = "SAVED_HOST_MANAGED_KEY_UNAVAILABLE";
const SAVED_HOST_CREDENTIAL_MUTATION_INVALID: &str = "SAVED_HOST_CREDENTIAL_MUTATION_INVALID";
const SAVED_HOST_NOT_FOUND: &str = "SAVED_HOST_NOT_FOUND";
const SAVED_HOST_PUBLICATION_FAILED: &str = "SAVED_HOST_PUBLICATION_FAILED";
const SAVED_HOST_REPAIR_REQUIRED: &str = "SAVED_HOST_REPAIR_REQUIRED";
const SAVED_PASSWORD_IDENTITY_HINT_REPAIR_FAILED: &str =
    "SAVED_PASSWORD_IDENTITY_HINT_REPAIR_FAILED";
const SAVED_PROXY_HINT_REPAIR_FAILED: &str = "SAVED_PROXY_HINT_REPAIR_FAILED";
const SAVED_GROUP_HINT_REPAIR_FAILED: &str = "SAVED_GROUP_HINT_REPAIR_FAILED";
const SAVED_HOST_COORDINATOR_FAILED: &str = "Saved-host coordinator failed";
const LEGACY_VAULT_SOURCE_UNAVAILABLE: &str = "LEGACY_VAULT_SOURCE_UNAVAILABLE";
const LEGACY_VAULT_SOURCE_NOT_REGULAR: &str = "LEGACY_VAULT_SOURCE_NOT_REGULAR";
const LEGACY_VAULT_SOURCE_TOO_LARGE: &str = "LEGACY_VAULT_SOURCE_TOO_LARGE";
const LEGACY_VAULT_SOURCE_INVALID: &str = "LEGACY_VAULT_SOURCE_INVALID";
const LEGACY_VAULT_SOURCE_CHANGED: &str = "LEGACY_VAULT_SOURCE_CHANGED";
const LEGACY_VAULT_RECOVERY_REQUIRED: &str = "LEGACY_VAULT_RECOVERY_REQUIRED";
const LEGACY_VAULT_INVENTORY_CHANGED: &str = "LEGACY_VAULT_INVENTORY_CHANGED";
const LEGACY_VAULT_ASSESSMENT_FAILED: &str = "LEGACY_VAULT_ASSESSMENT_FAILED";
const LEGACY_VAULT_IMPORT_FAILED: &str = "LEGACY_VAULT_IMPORT_FAILED";
const LEGACY_VAULT_IMPORT_REPAIR_REQUIRED: &str = "LEGACY_VAULT_IMPORT_REPAIR_REQUIRED";
const LEGACY_VAULT_CREDENTIAL_FAILED: &str = "LEGACY_VAULT_CREDENTIAL_FAILED";
const LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED: &str = "LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED";
const LEGACY_VAULT_SECRET_STORE_FAILED: &str = "LEGACY_VAULT_SECRET_STORE_FAILED";
const LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED: &str = "LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED";
static LEGACY_SOURCE_FINGERPRINT_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
const MAX_SELECTED_IDENTITY_FILES: usize = 8;
const MAX_SELECTED_IDENTITY_FILE_PATH_BYTES: usize = 32 * 1_024;
const MAX_SSH_CLIENT_ATTEMPT_ID_BYTES: usize = 128;
const SSH_CLIENT_ATTEMPT_ID_INVALID: &str =
    "SSH_CLIENT_ATTEMPT_ID_INVALID: The SSH client attempt identifier is invalid";
const SAVED_HOST_CHAIN_INVALID: &str = "SAVED_HOST_CHAIN_INVALID";
const SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED: &str = "SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED";

#[derive(Clone)]
struct DesktopState {
    sessions: SessionManager,
    ssh_session_logs:
        std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, ConnectionLogCapture>>>,
    telnet_sessions: netcatty_telnet::TelnetRuntimeManager,
    serial_sessions: netcatty_serial::SerialRuntimeManager,
    local_shells: std::sync::Arc<
        Result<netcatty_local_pty::ShellCatalog, netcatty_local_pty::ShellDiscoveryError>,
    >,
    local_pty_sessions: netcatty_local_pty::LocalPtyManager,
    mosh_client:
        std::sync::Arc<Result<netcatty_mosh::TrustedMoshClient, MoshClientAvailabilityError>>,
    mosh_sessions: MoshSessionManager,
    et_client: std::sync::Arc<Result<netcatty_et::TrustedEtClient, netcatty_et::EtClientError>>,
    et_sessions: netcatty_et::EtSessionManager,
    et_auth_root: std::sync::Arc<std::path::PathBuf>,
    port_forwards: ResolvedPortForwardManager,
    host_keys: HostKeyBroker,
    interactive_auth: InteractiveAuthBroker,
    ephemeral_credentials: EphemeralCredentialStore,
    managed_key_staging: ManagedKeyStagingStore,
    persistent_credentials: OsCredentialStore,
    master_keys: OsMasterKeyStore,
    secret_files: SecretFileStore,
    saved_hosts: SavedHostStore,
    connection_log_replays: Option<ConnectionLogReplayRuntime>,
    settings: RendererSafeSettingsStore,
    saved_host_mutations: std::sync::Arc<tokio::sync::Mutex<()>>,
    saved_host_lock_path: std::sync::Arc<std::path::PathBuf>,
    legacy_import_transaction_root: std::sync::Arc<std::path::PathBuf>,
}

impl DesktopState {
    fn open(vault_path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        std::fs::create_dir_all(vault_path.as_ref())
            .map_err(|_| "Application vault directory is unavailable".to_owned())?;
        let lock_path = vault_path.as_ref().join("saved-hosts.transaction.lock");
        let startup_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| "Saved-host transaction lock is unavailable".to_owned())?;
        fs2::FileExt::lock_exclusive(&startup_lock)
            .map_err(|_| "Saved-host transaction lock is unavailable".to_owned())?;
        let saved_hosts = SavedHostStore::open(vault_path.as_ref().join("saved-hosts"))
            .map_err(|error| error.to_string())?;
        let secret_files = SecretFileStore::open(vault_path.as_ref().join("secret-blobs"))
            .map_err(|error| error.to_string())?;
        let settings = RendererSafeSettingsStore::open(vault_path.as_ref().join("settings"))
            .map_err(|error| error.to_string())?;
        fs2::FileExt::unlock(&startup_lock)
            .map_err(|_| "Saved-host transaction lock is unavailable".to_owned())?;
        Ok(Self {
            sessions: SessionManager::default(),
            ssh_session_logs: std::sync::Arc::default(),
            telnet_sessions: netcatty_telnet::TelnetRuntimeManager::default(),
            serial_sessions: netcatty_serial::SerialRuntimeManager::default(),
            local_shells: std::sync::Arc::new(netcatty_local_pty::discover_shells()),
            local_pty_sessions: netcatty_local_pty::LocalPtyManager::default(),
            mosh_client: std::sync::Arc::new(Err(MoshClientAvailabilityError::ResourceUnavailable)),
            mosh_sessions: MoshSessionManager::default(),
            et_client: std::sync::Arc::new(Err(
                netcatty_et::EtClientError::ResourceRootUnavailable,
            )),
            et_sessions: netcatty_et::EtSessionManager::default(),
            et_auth_root: std::sync::Arc::new(vault_path.as_ref().join("et-session-auth")),
            port_forwards: ResolvedPortForwardManager::default(),
            host_keys: HostKeyBroker::default(),
            interactive_auth: InteractiveAuthBroker::default(),
            ephemeral_credentials: EphemeralCredentialStore::default(),
            managed_key_staging: ManagedKeyStagingStore::default(),
            persistent_credentials: OsCredentialStore::default(),
            master_keys: OsMasterKeyStore::default(),
            secret_files,
            saved_hosts,
            connection_log_replays: None,
            settings,
            saved_host_mutations: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            saved_host_lock_path: std::sync::Arc::new(lock_path),
            legacy_import_transaction_root: std::sync::Arc::new(
                vault_path.as_ref().join("legacy-import-transactions"),
            ),
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ClientAttemptId(String);

impl ClientAttemptId {
    fn parse(value: String) -> Result<Self, &'static str> {
        let bytes = value.as_bytes();
        let starts_safely = bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        let has_only_safe_bytes = bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b':'));
        if bytes.len() > MAX_SSH_CLIENT_ATTEMPT_ID_BYTES || !starts_safely || !has_only_safe_bytes {
            return Err(SSH_CLIENT_ATTEMPT_ID_INVALID);
        }
        Ok(Self(value))
    }

    fn internal(purpose: &'static str) -> Self {
        Self::parse(format!("internal-{purpose}-{}", uuid::Uuid::new_v4()))
            .expect("internal SSH client attempt IDs are valid")
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientAttemptId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientAttemptId([validated route id])")
    }
}

impl<'de> Deserialize<'de> for ClientAttemptId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartSshSessionRequest {
    client_attempt_id: ClientAttemptId,
    config: SshConnectionConfig,
    credential_reference: EphemeralCredentialReference,
    #[serde(default)]
    known_hosts: Vec<KnownHost>,
    #[serde(default = "default_true")]
    verify_host_keys: bool,
    #[serde(default)]
    shell: Option<ShellOptions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloneSshSessionRequest {
    source_session_id: String,
    #[serde(default)]
    shell: Option<ShellOptions>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct SavedHostTransportOverridesRequest {
    mosh_enabled: Option<bool>,
    et_enabled: Option<bool>,
    et_port: Option<u32>,
}

struct SavedHostDraftRequest {
    label: Option<String>,
    hostname: String,
    port: u32,
    username: String,
    protocol: SavedHostProtocolRequest,
    serial_config: Option<SavedSerialConfig>,
    charset: Option<String>,
    group: Option<String>,
    auth_method: SavedHostAuthenticationMethodRequest,
    managed_ssh_key_id: Option<String>,
    tags: Vec<String>,
    host_chain: Option<SavedHostChainRequest>,
    password_identity_id: Option<String>,
    transport: SavedHostTransportOverridesRequest,
    proxy: Option<SavedHostProxyMutationRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedHostDraftRequestWire {
    #[serde(default)]
    label: Option<String>,
    hostname: String,
    port: u32,
    username: String,
    #[serde(default)]
    protocol: SavedHostProtocolRequest,
    #[serde(default)]
    serial_config: Option<SavedSerialConfig>,
    #[serde(default)]
    charset: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    auth_method: SavedHostAuthenticationMethodRequest,
    #[serde(default)]
    managed_ssh_key_id: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    host_chain: Option<SavedHostChainRequest>,
    #[serde(default)]
    password_identity_id: Option<String>,
    #[serde(default)]
    mosh_enabled: Option<bool>,
    #[serde(default)]
    et_enabled: Option<bool>,
    #[serde(default)]
    et_port: Option<u32>,
    #[serde(default)]
    proxy: Option<SavedHostProxyMutationRequest>,
}

impl<'de> Deserialize<'de> for SavedHostDraftRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SavedHostDraftRequestWire::deserialize(deserializer)?;
        Ok(Self {
            label: wire.label,
            hostname: wire.hostname,
            port: wire.port,
            username: wire.username,
            protocol: wire.protocol,
            serial_config: wire.serial_config,
            charset: wire.charset,
            group: wire.group,
            auth_method: wire.auth_method,
            managed_ssh_key_id: wire.managed_ssh_key_id,
            tags: wire.tags,
            host_chain: wire.host_chain,
            password_identity_id: wire.password_identity_id,
            transport: SavedHostTransportOverridesRequest {
                mosh_enabled: wire.mosh_enabled,
                et_enabled: wire.et_enabled,
                et_port: wire.et_port,
            },
            proxy: wire.proxy,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SavedHostProtocolRequest {
    #[default]
    Ssh,
    Telnet,
    Serial,
}

impl SavedHostTransportOverridesRequest {
    fn normalize_for_protocol(
        mut self,
        protocol: SavedHostProtocolRequest,
    ) -> Result<Self, String> {
        if protocol != SavedHostProtocolRequest::Ssh {
            if self.mosh_enabled.is_some() || self.et_enabled.is_some() || self.et_port.is_some() {
                return Err(saved_host_invalid());
            }
            return Ok(Self::default());
        }
        if self
            .et_port
            .is_some_and(|port| port == 0 || port > u16::MAX.into())
        {
            return Err(saved_host_invalid());
        }
        if self.mosh_enabled == Some(true) && self.et_enabled == Some(true) {
            return Err(saved_host_invalid());
        }
        // Match the legacy full-host editor: selecting one external transport
        // writes an explicit false for the other, so a GroupConfig default
        // cannot reactivate both transports underneath the host.
        if self.mosh_enabled == Some(true) {
            self.et_enabled = Some(false);
        } else if self.et_enabled == Some(true) {
            self.mosh_enabled = Some(false);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SavedHostAuthenticationMethodRequest {
    #[default]
    Password,
    Key,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedHostChainRequest {
    #[serde(default)]
    host_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateSavedHostRequest {
    draft: SavedHostDraftRequest,
    #[serde(default)]
    staged_credential_reference: Option<EphemeralCredentialReference>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum SavedHostCredentialMutation {
    Keep,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
    Remove,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateSavedHostRequest {
    id: String,
    expected_revision: u64,
    draft: SavedHostDraftRequest,
    credential_mutation: SavedHostCredentialMutation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteSavedHostRequest {
    id: String,
    expected_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartSavedHostSessionRequest {
    client_attempt_id: ClientAttemptId,
    host_id: String,
    expected_revision: u64,
    #[serde(default)]
    credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    proxy_credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    key_passphrase_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    selected_identity_file_paths: Vec<String>,
    #[serde(default)]
    known_hosts: Vec<KnownHost>,
    #[serde(default = "default_true")]
    verify_host_keys: bool,
    #[serde(default)]
    shell: Option<ShellOptions>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartSavedTelnetSessionRequest {
    host_id: String,
    expected_revision: u64,
    #[serde(default)]
    credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default = "default_saved_telnet_terminal_type")]
    terminal: String,
    size: SavedHostTelnetTerminalSizeRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartSavedSerialSessionRequest {
    host_id: String,
    expected_revision: u64,
    size: SerialTerminalSize,
}

impl std::fmt::Debug for StartSavedTelnetSessionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StartSavedTelnetSessionRequest")
            .field("host_id", &"[redacted]")
            .field("expected_revision", &self.expected_revision)
            .field(
                "has_credential_reference",
                &self.credential_reference.is_some(),
            )
            .field("terminal", &"[redacted validated terminal]")
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedHostTelnetTerminalSizeRequest {
    columns: u32,
    rows: u32,
    #[serde(default)]
    pixel_width: u32,
    #[serde(default)]
    pixel_height: u32,
}

fn default_saved_telnet_terminal_type() -> String {
    "xterm-256color".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartPortForwardRequest {
    id: String,
    expected_inventory_revision: SavedVaultInventoryRevision,
    #[serde(default)]
    credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    proxy_credential_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    key_passphrase_reference: Option<EphemeralCredentialReference>,
    #[serde(default)]
    selected_identity_file_paths: Vec<String>,
    #[serde(default)]
    known_hosts: Vec<KnownHost>,
    #[serde(default = "default_true")]
    verify_host_keys: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopPortForwardRequest {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedPortForward {
    rule_id: String,
    tunnel_id: String,
    address: String,
    port: u16,
    catalog: PortForwardCatalog,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InspectLegacyVaultRequest {
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitLegacyVaultImportRequest {
    path: String,
    source_fingerprint: String,
    inventory_revision: SavedHostInventoryRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyVaultInspection {
    #[serde(flatten)]
    preview: LegacyVaultPreview,
    source_fingerprint: String,
    inventory_revision: SavedHostInventoryRevision,
    source_ssh_key_count: u32,
    importable_ssh_key_reference_count: u32,
    duplicate_ssh_key_reference_count: u32,
    conflict_ssh_key_reference_count: u32,
    unsupported_ssh_key_count: u32,
    source_managed_ssh_key_count: u32,
    importable_managed_ssh_key_count: u32,
    duplicate_managed_ssh_key_count: u32,
    conflict_managed_ssh_key_count: u32,
    managed_ssh_key_recovery_required_count: u32,
    managed_passphrases_discarded_by_policy_count: u32,
    source_identity_count: u32,
    importable_identity_reference_count: u32,
    duplicate_identity_reference_count: u32,
    conflict_identity_reference_count: u32,
    source_password_identity_count: u32,
    importable_password_identity_count: u32,
    duplicate_password_identity_count: u32,
    conflict_password_identity_count: u32,
    recoverable_password_identity_credential_count: u32,
    password_identity_credential_reentry_required_count: u32,
    recoverable_telnet_credential_count: u32,
    telnet_credential_reentry_required_count: u32,
    source_proxy_profile_count: u32,
    source_inline_proxy_host_count: u32,
    importable_proxy_profile_count: u32,
    duplicate_proxy_profile_count: u32,
    conflict_proxy_profile_count: u32,
    recoverable_proxy_profile_credential_count: u32,
    recoverable_inline_proxy_credential_count: u32,
    proxy_profile_credential_reentry_required_count: u32,
    inline_proxy_credential_reentry_required_count: u32,
    unsupported_proxy_profile_count: u32,
    unsupported_identity_count: u32,
    source_custom_group_count: u32,
    importable_custom_group_count: u32,
    duplicate_custom_group_count: u32,
    conflict_custom_group_count: u32,
    source_group_config_count: u32,
    importable_group_config_count: u32,
    duplicate_group_config_count: u32,
    conflict_group_config_count: u32,
    source_snippet_count: u32,
    importable_snippet_count: u32,
    duplicate_snippet_count: u32,
    conflict_snippet_count: u32,
    source_snippet_package_count: u32,
    importable_snippet_package_count: u32,
    duplicate_snippet_package_count: u32,
    source_note_count: u32,
    importable_note_count: u32,
    duplicate_note_count: u32,
    conflict_note_count: u32,
    source_note_group_count: u32,
    importable_note_group_count: u32,
    duplicate_note_group_count: u32,
    catalog_scope_change_count: u32,
    remapped_snippet_id_count: u32,
    remapped_note_id_count: u32,
    remapped_host_script_edge_count: u32,
    remapped_group_script_edge_count: u32,
    remapped_entity_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyVaultImportResult {
    imported_count: u32,
    ssh_key_references_imported_count: u32,
    identity_references_imported_count: u32,
    password_identities_imported_count: u32,
    managed_ssh_keys_imported_count: u32,
    managed_secret_blobs_published_count: u32,
    remapped_entity_count: u32,
    duplicate_count: u32,
    conflict_count: u32,
    credentials_stored_count: u32,
    telnet_credentials_stored_count: u32,
    telnet_credential_reentry_required_count: u32,
    password_identity_credentials_stored_count: u32,
    password_identity_credential_reentry_required_count: u32,
    proxy_profiles_imported_count: u32,
    proxy_profile_credentials_stored_count: u32,
    inline_proxy_credentials_stored_count: u32,
    proxy_credential_reentry_required_count: u32,
    custom_groups_imported_count: u32,
    group_configs_imported_count: u32,
    snippets_imported_count: u32,
    snippet_packages_imported_count: u32,
    notes_imported_count: u32,
    note_groups_imported_count: u32,
    requires_credential_reentry_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedSecretGarbageCollectionResult {
    removed_blob_revisions: u32,
    removed_objects: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ManagedSshMasterKeyRotationStatus {
    NotInitialized,
    Completed,
    CompletedCleanupPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedSshMasterKeyRotationResult {
    status: ManagedSshMasterKeyRotationStatus,
    retained_secret_revision_count: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ManagedMasterKeyRotationRecoveryOutcome {
    retained_secret_revision_count: u32,
    cleanup_pending: bool,
    recovered_work: bool,
}

impl ManagedMasterKeyRotationRecoveryOutcome {
    const fn renderer_result(self) -> ManagedSshMasterKeyRotationResult {
        ManagedSshMasterKeyRotationResult {
            status: if self.cleanup_pending {
                ManagedSshMasterKeyRotationStatus::CompletedCleanupPending
            } else {
                ManagedSshMasterKeyRotationStatus::Completed
            },
            retained_secret_revision_count: self.retained_secret_revision_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SavedHostView {
    id: String,
    revision: u64,
    label: String,
    hostname: String,
    port: u32,
    username: String,
    group: Option<String>,
    tags: Vec<String>,
    host_chain: Option<SavedHostChainRequest>,
    protocol: String,
    visual: SavedHostVisualView,
    serial_config: Option<SavedSerialConfig>,
    effective_serial_config: Option<SavedSerialConfig>,
    has_explicit_serial_backspace_behavior: bool,
    has_explicit_charset: bool,
    charset: Option<String>,
    auth_method: String,
    managed_ssh_key_id: Option<String>,
    has_saved_credential: bool,
    has_saved_host_credential: bool,
    password_identity: Option<SavedHostPasswordIdentityView>,
    key_source: SavedHostKeySource,
    has_saved_key_passphrase: bool,
    proxy: Option<SavedHostProxyView>,
    effective_appearance: SavedHostEffectiveAppearanceView,
    mosh_enabled: Option<bool>,
    et_enabled: Option<bool>,
    et_port: Option<u32>,
    effective_mosh_enabled: bool,
    effective_et_enabled: bool,
    created_at: u64,
    updated_at: u64,
}

/// The only SavedHost/GroupConfig appearance values exposed to the renderer.
///
/// Presence already includes the legacy override rule: an explicit `true`
/// enables a value, an explicit `false` disables it, and an omitted flag keeps
/// old Vault records with a value working. This is a connection-time view and
/// is never written back into the durable host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SavedHostEffectiveAppearanceView {
    theme_id: Option<String>,
    font_family: Option<String>,
    font_size: Option<serde_json::Number>,
    font_weight: Option<serde_json::Number>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SavedHostPasswordIdentityView {
    id: String,
    label: String,
    username: String,
    has_saved_credential: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum SavedHostKeySource {
    None,
    Reference,
    Managed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum SshControlEvent {
    Connecting,
    Connected,
    Eof,
    ExitStatus { status: u32 },
    Error { code: String, message: String },
    Closed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedSshSession {
    session_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedSftpTransfer {
    transfer_id: String,
    plan: SftpUploadPlan,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedSftpDownload {
    transfer_id: String,
    plan: SftpDownloadPlan,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedSftpDirectoryTransfer {
    transfer_id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum LocalTransferSourceKind {
    File,
    Directory,
}

fn default_true() -> bool {
    true
}

#[tauri::command]
fn get_backend_status() -> BackendStatus {
    BackendStatus::current(env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
fn validate_ssh_connection(config: SshConnectionConfig) -> ValidationResult {
    validate_connection(config)
}

#[tauri::command]
async fn stage_ssh_password(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "SSH password").await
}

#[tauri::command]
async fn stage_telnet_password(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "Telnet password").await
}

#[tauri::command]
async fn stage_ssh_key_passphrase(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "SSH key passphrase").await
}

#[tauri::command]
async fn stage_group_ssh_password(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "Group SSH password").await
}

#[tauri::command]
async fn stage_group_telnet_password(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "Group Telnet password").await
}

#[tauri::command]
async fn stage_group_proxy_password(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<EphemeralCredentialReference, String> {
    stage_raw_ssh_secret(window, state, request, "Group proxy password").await
}

#[tauri::command]
async fn stage_managed_ssh_key_bundle(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<ManagedKeyStagingReference, String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => {
            return Err(
                "MANAGED_SSH_KEY_INVALID: Managed SSH key material must use the raw IPC body"
                    .to_owned(),
            );
        }
    };
    let bundle = parse_managed_key_staging_envelope(bytes).map_err(|error| {
        managed_key_error(managed_key_catalog::MANAGED_KEY_INVALID, &error.to_string())
    })?;
    state
        .managed_key_staging
        .insert(window.label(), bundle)
        .await
        .map_err(|error| {
            managed_key_error(managed_key_catalog::MANAGED_KEY_INVALID, &error.to_string())
        })
}

async fn stage_raw_ssh_secret(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
    kind: &str,
) -> Result<EphemeralCredentialReference, String> {
    const MAX_PASSWORD_BYTES: usize = 64 * 1024;
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err(format!("{kind} must use the raw IPC body")),
    };
    if bytes.is_empty() || bytes.len() > MAX_PASSWORD_BYTES {
        return Err(format!("{kind} length is invalid"));
    }
    std::str::from_utf8(bytes).map_err(|_| format!("{kind} must be valid UTF-8"))?;
    let secret = SecretValue::new(bytes.to_vec()).map_err(|error| error.to_string())?;
    state
        .ephemeral_credentials
        .insert(window.label(), secret)
        .await
        .map_err(|error| error.to_string())
}

async fn run_blocking_result<T, E, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| "Background storage operation failed".to_owned())?
        .map_err(|error| error.to_string())
}

struct CrossProcessSavedHostLock(std::fs::File);

impl Drop for CrossProcessSavedHostLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

async fn acquire_saved_host_lock(
    path: std::sync::Arc<std::path::PathBuf>,
) -> Result<CrossProcessSavedHostLock, String> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.as_ref())
            .map_err(|_| "Saved-host transaction lock is unavailable".to_owned())?;
        fs2::FileExt::lock_exclusive(&file)
            .map_err(|_| "Saved-host transaction lock is unavailable".to_owned())?;
        Ok(CrossProcessSavedHostLock(file))
    })
    .await
    .map_err(|_| SAVED_HOST_COORDINATOR_FAILED.to_owned())?
}

/// Runs an entire saved-host operation in a detached coordinator task. Dropping
/// a Tauri invoke future (for example when a window closes) only drops the join
/// handle; the transaction retains both locks and finishes or compensates.
async fn run_saved_host_operation_with_rotation<T, F, Fut>(
    state: DesktopState,
    operation: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(DesktopState, Option<ManagedMasterKeyRotationRecoveryOutcome>) -> Fut
        + Send
        + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + Send + 'static,
{
    tauri::async_runtime::spawn(async move {
        let process_gate = state.saved_host_mutations.clone();
        let _process_guard = process_gate.lock_owned().await;
        let _cross_process_guard =
            acquire_saved_host_lock(state.saved_host_lock_path.clone()).await?;
        // Rotation recovery is the first secret/Vault coordinator action under
        // the shared locks. A pending rotation must be resolved before legacy
        // journal recovery or any ordinary Vault mutation can proceed.
        let rotation = recover_managed_master_key_rotation(&state).await?;
        recover_pending_legacy_import(&state).await?;
        operation(state, rotation).await
    })
    .await
    .map_err(|_| SAVED_HOST_COORDINATOR_FAILED.to_owned())?
}

async fn run_saved_host_operation<T, F, Fut>(state: DesktopState, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(DesktopState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + Send + 'static,
{
    run_saved_host_operation_with_rotation(state, move |state, _rotation| operation(state)).await
}

fn managed_vault_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => managed_key_error(
            MANAGED_KEY_INVENTORY_CHANGED,
            "The managed SSH key catalog changed; refresh and retry",
        ),
        StoreError::MissingGraphReference { .. } => {
            managed_key_error(MANAGED_KEY_IN_USE, "The managed SSH key is still in use")
        }
        StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::IncompatibleGraphReference { .. } => managed_key_error(
            managed_key_catalog::MANAGED_KEY_INVALID,
            "The managed SSH key has incompatible relationships",
        ),
        StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::ArtifactConflict => managed_key_error(
            MANAGED_KEY_REPAIR_REQUIRED,
            "The managed SSH key catalog requires recovery before it can be changed",
        ),
        _ => managed_key_error(
            MANAGED_KEY_PUBLICATION_FAILED,
            "The managed SSH key catalog could not be updated",
        ),
    }
}

async fn run_managed_vault<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "The managed SSH key storage worker failed",
            )
        })?
        .map_err(managed_vault_error)
}

async fn load_managed_key_graph(
    state: &DesktopState,
    expected_revision: Option<&SavedVaultInventoryRevision>,
) -> Result<(SavedVaultInventoryRevision, SavedVaultGraph), String> {
    let store = state.saved_hosts.clone();
    let snapshot = run_managed_vault(move || store.confirm_current_snapshot_durability()).await?;
    if expected_revision.is_some_and(|expected| expected != snapshot.revision()) {
        return Err(managed_key_error(
            MANAGED_KEY_INVENTORY_CHANGED,
            "The managed SSH key catalog changed; refresh and retry",
        ));
    }
    Ok((snapshot.revision().clone(), snapshot.graph().clone()))
}

async fn plan_managed_key_graph(
    store: SavedHostStore,
    expected_revision: SavedVaultInventoryRevision,
    target: SavedVaultGraph,
) -> Result<SavedVaultGraphReplacementPlan, String> {
    run_managed_vault(move || store.plan_graph_replacement(expected_revision, &target)).await
}

async fn commit_managed_key_graph(
    store: SavedHostStore,
    plan: SavedVaultGraphReplacementPlan,
    target: SavedVaultGraph,
) -> Result<(SavedVaultInventoryRevision, SavedVaultGraph), String> {
    run_managed_vault(move || {
        let committed = store.commit_planned_graph_replacement(plan, target)?;
        if committed.durability() == SavedVaultCommitDurability::Durable {
            return Ok((committed.revision().clone(), committed.into_graph()));
        }
        let confirmed = store.confirm_current_snapshot_durability()?;
        if confirmed.revision() != committed.revision() || confirmed.graph() != committed.graph() {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        Ok((confirmed.revision().clone(), confirmed.graph().clone()))
    })
    .await
}

fn managed_key_publication(
    key: &SavedManagedSshKey,
    bundle: SshSecretBundle,
) -> ManagedSecretPublication {
    ManagedSecretPublication {
        entity_id: key.id.as_str().to_owned(),
        backend_locator: key.custody().backend_locator().as_str().to_owned(),
        custody_revision: key.custody().custody_revision(),
        bundle,
    }
}

fn current_unix_millis() -> Result<u64, String> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| managed_key_catalog::managed_key_invalid())?
        .as_millis();
    u64::try_from(millis).map_err(|_| managed_key_catalog::managed_key_invalid())
}

#[tauri::command]
async fn list_managed_ssh_keys(
    state: State<'_, DesktopState>,
) -> Result<ManagedSshKeyCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        let (revision, graph) = load_managed_key_graph(&state, None).await?;
        Ok(ManagedSshKeyCatalog::from_graph(revision, &graph))
    })
    .await
}

#[tauri::command]
async fn create_managed_ssh_key(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: CreateManagedSshKeyRequest,
) -> Result<ManagedSshKeyCatalog, String> {
    let CreateManagedSshKeyRequest {
        expected_inventory_revision,
        metadata,
        staged_bundle_reference,
    } = request;
    let bundle = state
        .managed_key_staging
        .take(window.label(), &staged_bundle_reference)
        .await
        .map_err(|error| {
            managed_key_error(managed_key_catalog::MANAGED_KEY_INVALID, &error.to_string())
        })?;
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        create_managed_ssh_key_inner(&state, expected_inventory_revision, metadata, bundle).await
    })
    .await
}

async fn create_managed_ssh_key_inner(
    state: &DesktopState,
    expected_inventory_revision: SavedVaultInventoryRevision,
    metadata: ManagedSshKeyMetadataRequest,
    bundle: SshSecretBundle,
) -> Result<ManagedSshKeyCatalog, String> {
    // Reject a stale complete-Vault CAS token before touching the encrypted
    // object store. Cleanup is a real filesystem side effect even when it
    // removes only objects that are no longer retained.
    let (_, graph) = load_managed_key_graph(state, Some(&expected_inventory_revision)).await?;
    let id = SavedSshKeyReferenceId::new();
    let now = current_unix_millis()?;
    let mut bundle = bundle;
    preflight_managed_key_creation(&graph, &metadata, &mut bundle, &id, now)?;
    if garbage_collect_managed_secret_blobs(state).await.is_err() {
        return Err(managed_key_error(
            MANAGED_KEY_REPAIR_REQUIRED,
            "Managed SSH key storage must be repaired before adding a key",
        ));
    }
    let allow_initialization = managed_secret_store_initialization_allowed(state)
        .await
        .map_err(|_| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key storage must be repaired before adding a key",
            )
        })?;
    let secret_lease = SecretStoreTransactionLease::start(state, allow_initialization)
        .await
        .map_err(|_| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key storage must be repaired before adding a key",
            )
        })?;
    let locator = secret_lease
        .derive_locators(vec![id.as_str().to_owned()])
        .await
        .map_err(|_| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key storage could not derive a secure object locator",
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key storage could not derive a secure object locator",
            )
        })?;
    let prepared = prepare_managed_key_creation(graph, metadata, bundle, id, locator, now)?;
    publish_and_commit_managed_key(
        state,
        expected_inventory_revision,
        prepared,
        Some(secret_lease),
    )
    .await
}

#[tauri::command]
async fn update_managed_ssh_key(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: UpdateManagedSshKeyRequest,
) -> Result<ManagedSshKeyCatalog, String> {
    let UpdateManagedSshKeyRequest {
        id,
        expected_inventory_revision,
        metadata,
        staged_bundle_reference,
    } = request;
    let staged_bundle = match staged_bundle_reference {
        Some(reference) => Some(
            state
                .managed_key_staging
                .take(window.label(), &reference)
                .await
                .map_err(|error| {
                    managed_key_error(managed_key_catalog::MANAGED_KEY_INVALID, &error.to_string())
                })?,
        ),
        None => None,
    };
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            id,
            expected_inventory_revision,
            metadata,
            staged_bundle,
        )
        .await
    })
    .await
}

async fn update_managed_ssh_key_inner(
    state: &DesktopState,
    id: String,
    expected_inventory_revision: SavedVaultInventoryRevision,
    metadata: ManagedSshKeyMetadataRequest,
    staged_bundle: Option<SshSecretBundle>,
) -> Result<ManagedSshKeyCatalog, String> {
    // As with create, stale and otherwise invalid input must be rejected
    // before optional GC can mutate the secret-object tree.
    let (_, graph) = load_managed_key_graph(state, Some(&expected_inventory_revision)).await?;
    let id = SavedSshKeyReferenceId::from_opaque(id)
        .map_err(|_| managed_key_catalog::managed_key_invalid())?;
    let prepared =
        prepare_managed_key_update(graph, &id, metadata, staged_bundle, current_unix_millis()?)?;
    if prepared.publication().is_some()
        && garbage_collect_managed_secret_blobs(state).await.is_err()
    {
        return Err(managed_key_error(
            MANAGED_KEY_REPAIR_REQUIRED,
            "Managed SSH key storage must be repaired before replacing key material",
        ));
    }
    let secret_lease = if prepared.publication().is_some() {
        Some(
            SecretStoreTransactionLease::start(state, false)
                .await
                .map_err(|_| {
                    managed_key_error(
                        MANAGED_KEY_REPAIR_REQUIRED,
                        "Managed SSH key storage must be repaired before replacing key material",
                    )
                })?,
        )
    } else {
        None
    };
    publish_and_commit_managed_key(state, expected_inventory_revision, prepared, secret_lease).await
}

async fn publish_and_commit_managed_key(
    state: &DesktopState,
    expected_inventory_revision: SavedVaultInventoryRevision,
    prepared: PreparedManagedKeyMutation,
    secret_lease: Option<SecretStoreTransactionLease>,
) -> Result<ManagedSshKeyCatalog, String> {
    let plan = plan_managed_key_graph(
        state.saved_hosts.clone(),
        expected_inventory_revision,
        prepared.target_graph().clone(),
    )
    .await?;
    let had_secret_publication = prepared.publication().is_some();
    let (target, key, bundle) = prepared.into_parts();
    if let Some(bundle) = bundle {
        let lease = secret_lease.as_ref().ok_or_else(|| {
            managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key storage lease is unavailable",
            )
        })?;
        let published = lease
            .publish(vec![managed_key_publication(&key, bundle)])
            .await
            .map_err(|failure| match failure {
                ManagedSecretPublicationFailure::BeforePublication => managed_key_error(
                    MANAGED_KEY_PUBLICATION_FAILED,
                    "Managed SSH key material could not be published",
                ),
                ManagedSecretPublicationFailure::RepairRequired => managed_key_error(
                    MANAGED_KEY_REPAIR_REQUIRED,
                    "Managed SSH key publication requires recovery",
                ),
            })?;
        if published != 1 {
            return Err(managed_key_error(
                MANAGED_KEY_REPAIR_REQUIRED,
                "Managed SSH key publication returned an invalid result",
            ));
        }
    }
    let (revision, graph) =
        commit_managed_key_graph(state.saved_hosts.clone(), plan, target).await?;
    drop(secret_lease);
    if had_secret_publication {
        let _ = garbage_collect_managed_secret_blobs(state).await;
    }
    Ok(ManagedSshKeyCatalog::from_graph(revision, &graph))
}

#[tauri::command]
async fn delete_managed_ssh_key(
    state: State<'_, DesktopState>,
    request: DeleteManagedSshKeyRequest,
) -> Result<ManagedSshKeyCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        delete_managed_ssh_key_inner(&state, request.id, request.expected_inventory_revision).await
    })
    .await
}

async fn delete_managed_ssh_key_inner(
    state: &DesktopState,
    id: String,
    expected_inventory_revision: SavedVaultInventoryRevision,
) -> Result<ManagedSshKeyCatalog, String> {
    let (_, graph) = load_managed_key_graph(state, Some(&expected_inventory_revision)).await?;
    let id = SavedSshKeyReferenceId::from_opaque(id)
        .map_err(|_| managed_key_catalog::managed_key_invalid())?;
    let target = prepare_managed_key_deletion(graph, &id)?;
    let plan = plan_managed_key_graph(
        state.saved_hosts.clone(),
        expected_inventory_revision,
        target.clone(),
    )
    .await?;
    let (revision, graph) =
        commit_managed_key_graph(state.saved_hosts.clone(), plan, target).await?;
    // The Vault pointer is confirmed durable before any blob cleanup.
    // Fallback snapshots remain part of the retention union, so ciphertext
    // is retained automatically while it can still become authoritative.
    let _ = garbage_collect_managed_secret_blobs(state).await;
    Ok(ManagedSshKeyCatalog::from_graph(revision, &graph))
}

#[tauri::command]
async fn rotate_managed_ssh_master_key(
    state: State<'_, DesktopState>,
) -> Result<ManagedSshMasterKeyRotationResult, String> {
    run_saved_host_operation_with_rotation(
        state.inner().clone(),
        |state, recovered_rotation| async move {
            // A retry that actually resumed work reports that completion
            // instead of immediately starting another epoch. A historical
            // completed marker whose source key was already retired is first
            // revalidated by the coordinator and then permits a new rotation.
            if let Some(recovered) = recovered_rotation.filter(|result| result.recovered_work) {
                return Ok(recovered.renderer_result());
            }
            begin_managed_master_key_rotation(&state).await
        },
    )
    .await
}

async fn load_password_identity_graph_for_command(
    state: &DesktopState,
) -> Result<SavedVaultGraph, String> {
    confirm_current_legacy_vault_snapshot(state)
        .await
        .map(|snapshot| snapshot.graph().clone())
        .map_err(|_| password_identity_repair_required())
}

#[tauri::command]
async fn list_password_identities(
    state: State<'_, DesktopState>,
) -> Result<PasswordIdentityCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_password_identity_catalog(&state).await
    })
    .await
}

#[tauri::command]
async fn create_password_identity(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: CreatePasswordIdentityRequest,
) -> Result<PasswordIdentityCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_password_identity_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| password_identity_invalid())?;
        let prepared = prepare_password_identity_creation(
            graph,
            request,
            SavedPasswordIdentityId::new(),
            now,
        )?;
        commit_password_identity_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn update_password_identity(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: UpdatePasswordIdentityRequest,
) -> Result<PasswordIdentityCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_password_identity_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| password_identity_invalid())?;
        let prepared = prepare_password_identity_update(graph, request, now)?;
        commit_password_identity_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn delete_password_identity(
    state: State<'_, DesktopState>,
    request: DeletePasswordIdentityRequest,
) -> Result<PasswordIdentityCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_password_identity_graph_for_command(&state).await?;
        let prepared = prepare_password_identity_deletion(graph, request)?;
        commit_password_identity_deletion(&state, prepared).await
    })
    .await
}

async fn load_proxy_profile_graph_for_command(
    state: &DesktopState,
) -> Result<SavedVaultGraph, String> {
    confirm_current_legacy_vault_snapshot(state)
        .await
        .map(|snapshot| snapshot.graph().clone())
        .map_err(|_| proxy_profile_repair_required())
}

#[tauri::command]
async fn list_proxy_profiles(
    state: State<'_, DesktopState>,
) -> Result<ProxyProfileCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_proxy_profile_catalog(&state).await
    })
    .await
}

#[tauri::command]
async fn create_proxy_profile(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: CreateProxyProfileRequest,
) -> Result<ProxyProfileCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_proxy_profile_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| proxy_profile_invalid())?;
        let prepared =
            prepare_proxy_profile_creation(graph, request, SavedProxyProfileId::new(), now)?;
        commit_proxy_profile_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn update_proxy_profile(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: UpdateProxyProfileRequest,
) -> Result<ProxyProfileCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_proxy_profile_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| proxy_profile_invalid())?;
        let prepared = prepare_proxy_profile_update(graph, request, now)?;
        commit_proxy_profile_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn delete_proxy_profile(
    state: State<'_, DesktopState>,
    request: DeleteProxyProfileRequest,
) -> Result<ProxyProfileCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_proxy_profile_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| proxy_profile_invalid())?;
        let prepared = prepare_proxy_profile_deletion(graph, request, now)?;
        commit_proxy_profile_deletion(&state, prepared).await
    })
    .await
}

async fn load_group_config_graph_for_command(
    state: &DesktopState,
) -> Result<SavedVaultGraph, String> {
    confirm_current_legacy_vault_snapshot(state)
        .await
        .map(|snapshot| snapshot.graph().clone())
        .map_err(|_| group_config_repair_required())
}

#[tauri::command]
async fn list_group_configs(state: State<'_, DesktopState>) -> Result<GroupConfigCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_group_config_catalog(&state).await
    })
    .await
}

#[tauri::command]
async fn create_group_config(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: CreateGroupConfigRequest,
) -> Result<GroupConfigCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_group_config_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| group_config_invalid())?;
        let prepared = prepare_group_config_creation(graph, request, SavedGroupId::new(), now)?;
        commit_group_config_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn update_group_config(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: UpdateGroupConfigRequest,
) -> Result<GroupConfigCatalog, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_group_config_graph_for_command(&state).await?;
        let now = current_unix_millis().map_err(|_| group_config_invalid())?;
        let prepared = prepare_group_config_update(graph, request, now)?;
        commit_group_config_mutation(&state, &owner, prepared).await
    })
    .await
}

#[tauri::command]
async fn delete_group_config(
    state: State<'_, DesktopState>,
    request: DeleteGroupConfigRequest,
) -> Result<GroupConfigCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let graph = load_group_config_graph_for_command(&state).await?;
        let prepared = prepare_group_config_deletion(graph, request)?;
        commit_group_config_deletion(&state, prepared).await
    })
    .await
}

fn map_port_forward_store_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => port_forward_error(
            PORT_FORWARD_INVENTORY_CHANGED,
            "The port-forward catalog changed; refresh and retry",
        ),
        StoreError::Serialization
        | StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => {
            port_forward_catalog::port_forward_invalid()
        }
        _ => port_forward_error(
            PORT_FORWARD_PUBLICATION_FAILED,
            "The port-forward catalog could not be updated",
        ),
    }
}

async fn run_port_forward_vault<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            port_forward_error(
                PORT_FORWARD_PUBLICATION_FAILED,
                "The port-forward storage worker failed",
            )
        })?
        .map_err(map_port_forward_store_error)
}

async fn confirm_port_forward_snapshot(
    state: &DesktopState,
    expected_revision: Option<&SavedVaultInventoryRevision>,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    let snapshot =
        run_port_forward_vault(move || store.confirm_current_snapshot_durability()).await?;
    if expected_revision.is_some_and(|expected| expected != snapshot.revision()) {
        return Err(port_forward_error(
            PORT_FORWARD_INVENTORY_CHANGED,
            "The port-forward catalog changed; refresh and retry",
        ));
    }
    Ok(snapshot)
}

async fn port_forward_catalog_from_graph(
    state: &DesktopState,
    inventory_revision: SavedVaultInventoryRevision,
    graph: &SavedVaultGraph,
) -> PortForwardCatalog {
    PortForwardCatalog {
        inventory_revision,
        rules: graph.port_forward_rules().to_vec(),
        runtime: state.port_forwards.runtime_snapshot().await,
    }
}

async fn load_port_forward_catalog_inner(
    state: &DesktopState,
) -> Result<PortForwardCatalog, String> {
    let snapshot = confirm_port_forward_snapshot(state, None).await?;
    Ok(port_forward_catalog_from_graph(state, snapshot.revision().clone(), snapshot.graph()).await)
}

async fn commit_port_forward_graph(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
) -> Result<(SavedVaultInventoryRevision, SavedVaultGraph), String> {
    let store = state.saved_hosts.clone();
    run_port_forward_vault(move || {
        let plan = store.plan_graph_replacement(expected_revision, &target_graph)?;
        let committed = store.commit_planned_graph_replacement(plan, target_graph)?;
        if committed.durability() == SavedVaultCommitDurability::Durable {
            return Ok((committed.revision().clone(), committed.into_graph()));
        }
        let confirmed = store.confirm_current_snapshot_durability()?;
        if confirmed.revision() != committed.revision() || confirmed.graph() != committed.graph() {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        Ok((confirmed.revision().clone(), confirmed.graph().clone()))
    })
    .await
}

async fn commit_port_forward_mutation(
    state: &DesktopState,
    prepared: PreparedPortForwardMutation,
) -> Result<PortForwardCatalog, String> {
    let (revision, graph) = commit_port_forward_graph(
        state,
        prepared.expected_inventory_revision,
        prepared.target_graph,
    )
    .await?;
    Ok(port_forward_catalog_from_graph(state, revision, &graph).await)
}

fn port_forward_connection_changed(
    current: &netcatty_vault::SavedPortForwardRule,
    updated: &netcatty_vault::SavedPortForwardRule,
) -> bool {
    current.kind != updated.kind
        || current.local_port != updated.local_port
        || current.bind_address != updated.bind_address
        || current.remote_host != updated.remote_host
        || current.remote_port != updated.remote_port
        || current.host_id != updated.host_id
}

fn port_forward_connection_error() -> String {
    port_forward_error(
        PORT_FORWARD_CONNECTION_FAILED,
        "The SSH port-forward connection could not be established",
    )
}

fn normalize_port_forward_catalog_error(error: String) -> String {
    if error.starts_with("PORT_FORWARD_") {
        error
    } else {
        port_forward_error(
            PORT_FORWARD_PUBLICATION_FAILED,
            "The port-forward catalog operation could not be completed",
        )
    }
}

fn map_port_forward_runtime_error(error: PortForwardError) -> String {
    match error {
        PortForwardError::DuplicateRule => port_forward_error(
            PORT_FORWARD_ALREADY_RUNNING,
            "The port-forward rule is already running",
        ),
        PortForwardError::NotFound => port_forward_error(
            PORT_FORWARD_NOT_RUNNING,
            "The port-forward rule is not running",
        ),
        PortForwardError::InvalidRule => port_forward_catalog::port_forward_invalid(),
        _ => port_forward_connection_error(),
    }
}

#[tauri::command]
async fn list_port_forward_rules(
    state: State<'_, DesktopState>,
) -> Result<PortForwardCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_port_forward_catalog_inner(&state).await
    })
    .await
    .map_err(normalize_port_forward_catalog_error)
}

#[tauri::command]
async fn create_port_forward_rule(
    state: State<'_, DesktopState>,
    request: CreatePortForwardRuleRequest,
) -> Result<PortForwardCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_port_forward_snapshot(&state, Some(&expected)).await?;
        let now =
            current_unix_millis().map_err(|_| port_forward_catalog::port_forward_invalid())?;
        let prepared = prepare_port_forward_creation(
            snapshot.graph().clone(),
            request,
            uuid::Uuid::new_v4().to_string(),
            now,
        )?;
        commit_port_forward_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_port_forward_catalog_error)
}

#[tauri::command]
async fn update_port_forward_rule(
    state: State<'_, DesktopState>,
    request: UpdatePortForwardRuleRequest,
) -> Result<PortForwardCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let id = request.id.clone();
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_port_forward_snapshot(&state, Some(&expected)).await?;
        let current = snapshot
            .graph()
            .port_forward_rules()
            .iter()
            .find(|rule| rule.id == id)
            .cloned()
            .ok_or_else(port_forward_catalog::port_forward_not_found)?;
        let prepared = prepare_port_forward_update(snapshot.graph().clone(), request)?;
        let updated = prepared
            .rule
            .as_ref()
            .ok_or_else(port_forward_catalog::port_forward_invalid)?;
        if port_forward_connection_changed(&current, updated) {
            match state.port_forwards.stop(&id).await {
                Ok(()) | Err(PortForwardError::NotFound) => {}
                Err(error) => return Err(map_port_forward_runtime_error(error)),
            }
        }
        commit_port_forward_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_port_forward_catalog_error)
}

#[tauri::command]
async fn delete_port_forward_rule(
    state: State<'_, DesktopState>,
    request: DeletePortForwardRuleRequest,
) -> Result<PortForwardCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let id = request.id.clone();
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_port_forward_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_port_forward_deletion(snapshot.graph().clone(), request)?;
        match state.port_forwards.stop(&id).await {
            Ok(()) | Err(PortForwardError::NotFound) => {}
            Err(error) => return Err(map_port_forward_runtime_error(error)),
        }
        commit_port_forward_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_port_forward_catalog_error)
}

struct PreparedPortForwardStart {
    expected_inventory_revision: SavedVaultInventoryRevision,
    graph: SavedVaultGraph,
    rule_id: String,
    transport_rule: NormalizedPortForwardRule,
    session: PreparedSavedHostSession,
}

async fn drain_port_forward_secrets(
    state: &DesktopState,
    owner: &str,
    request: &StartPortForwardRequest,
) -> Result<StagedSavedHostSessionSecrets, String> {
    let (credential, proxy_credential, key_passphrase) = tokio::join!(
        take_optional_ephemeral_secret(state, owner, request.credential_reference.as_ref()),
        take_optional_ephemeral_secret(state, owner, request.proxy_credential_reference.as_ref()),
        take_optional_ephemeral_secret(state, owner, request.key_passphrase_reference.as_ref()),
    );
    match (credential, proxy_credential, key_passphrase) {
        (Err(_), _, _) | (Ok(_), Err(_), _) | (Ok(_), Ok(_), Err(_)) => {
            Err(port_forward_connection_error())
        }
        (Ok(credential), Ok(proxy_credential), Ok(key_passphrase)) => {
            Ok(StagedSavedHostSessionSecrets {
                credential,
                proxy_credential,
                key_passphrase,
            })
        }
    }
}

async fn prepare_port_forward_start(
    state: &DesktopState,
    request: StartPortForwardRequest,
    staged: StagedSavedHostSessionSecrets,
) -> Result<PreparedPortForwardStart, String> {
    let expected_inventory_revision = request.expected_inventory_revision.clone();
    let snapshot = confirm_port_forward_snapshot(state, Some(&expected_inventory_revision)).await?;
    let rule = snapshot
        .graph()
        .port_forward_rules()
        .iter()
        .find(|rule| rule.id == request.id)
        .cloned()
        .ok_or_else(port_forward_catalog::port_forward_not_found)?;
    let transport_rule = normalized_transport_rule(&rule)?;
    let host = snapshot
        .graph()
        .hosts()
        .iter()
        .find(|host| host.id == rule.host_id)
        .ok_or_else(port_forward_catalog::port_forward_invalid)?;
    let session_request = StartSavedHostSessionRequest {
        client_attempt_id: ClientAttemptId::internal("port-forward"),
        host_id: host.id.as_str().to_owned(),
        expected_revision: host.revision,
        credential_reference: None,
        proxy_credential_reference: None,
        key_passphrase_reference: None,
        selected_identity_file_paths: request.selected_identity_file_paths,
        known_hosts: request.known_hosts,
        verify_host_keys: request.verify_host_keys,
        shell: None,
    };
    let session = prepare_saved_host_session(state, session_request, staged)
        .await
        .map_err(|_| port_forward_connection_error())?;
    // Credential-hint repair is allowed during preparation. If it changed the
    // graph, fail before opening a tunnel rather than publishing lastUsedAt
    // against a different durable catalog.
    confirm_port_forward_snapshot(state, Some(&expected_inventory_revision)).await?;
    Ok(PreparedPortForwardStart {
        expected_inventory_revision,
        graph: snapshot.graph().clone(),
        rule_id: rule.id,
        transport_rule,
        session,
    })
}

async fn begin_prepared_port_forward(
    window: &WebviewWindow,
    state: &DesktopState,
    rule: NormalizedPortForwardRule,
    prepared: PreparedSavedHostSession,
) -> Result<PortForwardStart, String> {
    let PreparedSavedHostSession {
        client_attempt_id,
        config,
        credentials,
        jump_hosts,
        known_hosts,
        verify_host_keys,
        shell: _,
        connection_log: _,
        effective_mosh_enabled: _,
    } = prepared;
    let expected_jump_ids = config
        .jump_hosts
        .iter()
        .map(|jump| jump.host_id.as_str())
        .collect::<Vec<_>>();
    if expected_jump_ids.len() != jump_hosts.len()
        || expected_jump_ids
            .iter()
            .zip(&jump_hosts)
            .any(|(expected, prepared)| **expected != prepared.host_id)
    {
        return Err(port_forward_connection_error());
    }

    let target = build_resolved_ssh_endpoint(
        window,
        state,
        &client_attempt_id,
        config,
        credentials,
        known_hosts.clone(),
        verify_host_keys,
    )
    .map_err(|_| port_forward_connection_error())?;
    if jump_hosts.is_empty() {
        return state
            .port_forwards
            .start(rule, target)
            .await
            .map_err(map_port_forward_runtime_error);
    }

    let mut endpoints = std::collections::HashMap::with_capacity(jump_hosts.len());
    for jump in jump_hosts {
        let endpoint = build_resolved_ssh_endpoint(
            window,
            state,
            &client_attempt_id,
            jump.config,
            jump.credentials,
            known_hosts.clone(),
            verify_host_keys,
        )
        .map_err(|_| port_forward_connection_error())?;
        if endpoints.insert(jump.host_id, endpoint).is_some() {
            return Err(port_forward_connection_error());
        }
    }
    state
        .port_forwards
        .start_chain(
            rule,
            target,
            std::sync::Arc::new(PreparedSavedHostChainResolver {
                endpoints: tokio::sync::Mutex::new(endpoints),
            }),
        )
        .await
        .map_err(map_port_forward_runtime_error)
}

#[tauri::command]
async fn start_port_forward(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartPortForwardRequest,
) -> Result<StartedPortForward, String> {
    // One-shot references are drained before either saved-host lock, matching
    // the saved-session cancellation and secret-ownership boundary.
    let staged = drain_port_forward_secrets(&state, window.label(), &request).await?;
    let state = state.inner().clone();
    // Once secrets have been drained, the connection and its lastUsedAt CAS
    // finish in an owned task. Cancelling the invoke waiter cannot strand a
    // connecting manager entry or drop the publication half of a live tunnel.
    tauri::async_runtime::spawn(async move {
        finish_port_forward_start(window, state, request, staged).await
    })
    .await
    .map_err(|_| port_forward_connection_error())?
}

async fn finish_port_forward_start(
    window: WebviewWindow,
    state: DesktopState,
    request: StartPortForwardRequest,
    staged: StagedSavedHostSessionSecrets,
) -> Result<StartedPortForward, String> {
    let prepared = run_saved_host_operation(state.clone(), move |state| async move {
        prepare_port_forward_start(&state, request, staged).await
    })
    .await
    .map_err(|error| {
        if error.starts_with("PORT_FORWARD_") {
            error
        } else {
            port_forward_connection_error()
        }
    })?;
    let PreparedPortForwardStart {
        expected_inventory_revision,
        graph,
        rule_id,
        transport_rule,
        session,
    } = prepared;
    let started = begin_prepared_port_forward(&window, &state, transport_rule, session).await?;

    let now = match current_unix_millis() {
        Ok(now) => now,
        Err(_) => {
            let _ = state.port_forwards.stop(&rule_id).await;
            return Err(port_forward_error(
                PORT_FORWARD_PUBLICATION_FAILED,
                "The port-forward usage timestamp could not be published",
            ));
        }
    };
    let mut rules = graph.port_forward_rules().to_vec();
    let Some(index) = rules.iter().position(|rule| rule.id == rule_id) else {
        let _ = state.port_forwards.stop(&rule_id).await;
        return Err(port_forward_error(
            PORT_FORWARD_PUBLICATION_FAILED,
            "The running port-forward could not be published",
        ));
    };
    rules[index] = rules[index].clone().with_last_used_at(now);
    let target_graph = graph.with_port_forward_rules(rules);
    let publication = run_saved_host_operation(state.clone(), move |state| async move {
        commit_port_forward_graph(&state, expected_inventory_revision, target_graph).await
    })
    .await;
    let (inventory_revision, committed_graph) = match publication {
        Ok(committed) => committed,
        Err(error) => {
            let _ = state.port_forwards.stop(&rule_id).await;
            return Err(if error.starts_with("PORT_FORWARD_") {
                error
            } else {
                port_forward_error(
                    PORT_FORWARD_PUBLICATION_FAILED,
                    "The running port-forward could not be published",
                )
            });
        }
    };
    let catalog =
        port_forward_catalog_from_graph(&state, inventory_revision, &committed_graph).await;
    Ok(StartedPortForward {
        rule_id,
        tunnel_id: started.tunnel_id,
        address: started.address,
        port: started.port,
        catalog,
    })
}

#[tauri::command]
async fn stop_port_forward(
    state: State<'_, DesktopState>,
    request: StopPortForwardRequest,
) -> Result<PortForwardCatalog, String> {
    state
        .port_forwards
        .stop(&request.id)
        .await
        .map_err(map_port_forward_runtime_error)?;
    list_port_forward_rules(state).await
}

fn map_connection_logs_store_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => connection_logs_error(
            CONNECTION_LOGS_INVENTORY_CHANGED,
            "The Connection Logs catalog changed; refresh and retry",
        ),
        StoreError::Serialization | StoreError::DuplicateGraphEntityId(_) => {
            connection_logs_invalid()
        }
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => connection_logs_error(
            CONNECTION_LOGS_REPAIR_REQUIRED,
            "Connection Logs storage requires reconciliation",
        ),
        _ => connection_logs_error(
            CONNECTION_LOGS_PUBLICATION_FAILED,
            "The Connection Logs catalog could not be updated",
        ),
    }
}

fn normalize_connection_logs_command_error(error: String) -> String {
    if error.starts_with("CONNECTION_LOGS_") {
        error
    } else {
        connection_logs_error(
            CONNECTION_LOGS_REPAIR_REQUIRED,
            "Connection Logs storage requires reconciliation",
        )
    }
}

async fn run_connection_logs_vault<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            connection_logs_error(
                CONNECTION_LOGS_PUBLICATION_FAILED,
                "The Connection Logs storage worker failed",
            )
        })?
        .map_err(map_connection_logs_store_error)
}

async fn load_connection_logs_catalog_inner(
    state: &DesktopState,
) -> Result<ConnectionLogsCatalog, String> {
    let store = state.saved_hosts.clone();
    run_connection_logs_vault(move || {
        let snapshot = store.confirm_current_snapshot_durability()?;
        Ok(ConnectionLogsCatalog {
            inventory_revision: snapshot.revision().clone(),
            logs: snapshot.connection_logs().to_vec(),
        })
    })
    .await
}

#[tauri::command]
async fn list_connection_logs(
    state: State<'_, DesktopState>,
) -> Result<ConnectionLogsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_connection_logs_catalog_inner(&state).await
    })
    .await
    .map_err(normalize_connection_logs_command_error)
}

#[tauri::command]
async fn read_connection_log_replay(
    state: State<'_, DesktopState>,
    request: ReadConnectionLogReplayRequest,
) -> Result<ReadConnectionLogReplayResponse, String> {
    // Validate renderer input before opening either the Vault catalog or the
    // encrypted replay store.
    let requested_log_id = request
        .into_log_id()
        .map_err(connection_log_replay_command_error)?;
    let desktop = state.inner().clone();
    let replay_runtime = desktop.connection_log_replays.clone().ok_or_else(|| {
        "CONNECTION_LOG_REPLAY_STORAGE_FAILED: Connection-log replay storage failed".to_owned()
    })?;
    let replays = replay_runtime
        .manager()
        .await
        .map_err(connection_log_replay_command_error)?;
    run_saved_host_operation(desktop, move |state| async move {
        let catalog = load_connection_logs_catalog_inner(&state).await?;
        if !catalog.logs.iter().any(|log| log.id == requested_log_id) {
            return Err(
                "CONNECTION_LOG_REPLAY_UNAVAILABLE: No replay is available for this log".to_owned(),
            );
        }
        replays
            .read_one(ReadConnectionLogReplayRequest::new(requested_log_id))
            .await
            .map_err(connection_log_replay_command_error)
    })
    .await
}

fn normalize_connection_log_export_command_error(error: String) -> String {
    if error.starts_with("CONNECTION_LOG_EXPORT_") {
        error
    } else {
        connection_log_export_command_error(ConnectionLogExportError::storage_failed())
    }
}

async fn choose_connection_log_export_path(
    window: &WebviewWindow,
    default_file_name: String,
    locale: ConnectionLogExportDialogLocale,
) -> Result<Option<ConnectionLogExportTarget>, ConnectionLogExportError> {
    let text = connection_log_export_dialog_text(locale);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let dialog = window
        .app_handle()
        .dialog()
        .file()
        .set_title(text.title)
        .set_file_name(default_file_name)
        .add_filter(text.text_files_filter, &["txt"])
        .add_filter(text.log_files_filter, &["log"])
        .add_filter(text.html_files_filter, &["html"])
        .add_filter(text.all_files_filter, &["*"])
        .set_parent(window);
    dialog.save_file(move |selected| {
        let selected = selected
            .map(|path| path.into_path())
            .transpose()
            .map_err(|_| ConnectionLogExportError::dialog_failed())
            .and_then(selected_export_target);
        let _ = sender.send(selected);
    });
    receiver
        .await
        .map_err(|_| ConnectionLogExportError::dialog_failed())?
}

#[tauri::command]
async fn export_connection_log(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: ExportConnectionLogRequest,
) -> Result<ExportConnectionLogResponse, String> {
    let (requested_log_id, locale) = request
        .into_parts()
        .map_err(connection_log_export_command_error)?;
    let desktop = state.inner().clone();
    let replay_runtime = desktop.connection_log_replays.clone().ok_or_else(|| {
        connection_log_export_command_error(ConnectionLogExportError::storage_failed())
    })?;
    let replays = replay_runtime.manager().await.map_err(|_| {
        connection_log_export_command_error(ConnectionLogExportError::storage_failed())
    })?;

    // The first coordinator pass authorizes only safe metadata and constructs
    // the suggested leaf name. It is deliberately released before showing a
    // native modal dialog.
    let first_log_id = requested_log_id.clone();
    let default_file_name = run_saved_host_operation(desktop.clone(), move |state| async move {
        let catalog = load_connection_logs_catalog_inner(&state).await?;
        authoritative_export_metadata(&catalog.logs, &first_log_id)
            .and_then(|metadata| metadata.default_file_name())
            .map_err(connection_log_export_command_error)
    })
    .await
    .map_err(normalize_connection_log_export_command_error)?;

    let Some(target) = choose_connection_log_export_path(&window, default_file_name, locale)
        .await
        .map_err(connection_log_export_command_error)?
    else {
        return Ok(ExportConnectionLogResponse::canceled());
    };

    // The dialog can remain open arbitrarily long. Re-enter the coordinator
    // and re-authorize exact membership before reading the encrypted replay,
    // so deletion while the dialog is open cannot export stale data.
    let second_log_id = requested_log_id;
    let (metadata, terminal_data) = run_saved_host_operation(desktop, move |state| async move {
        let catalog = load_connection_logs_catalog_inner(&state).await?;
        let metadata = authoritative_export_metadata(&catalog.logs, &second_log_id)
            .map_err(connection_log_export_command_error)?;
        let replay = replays
            .read_one(ReadConnectionLogReplayRequest::new(second_log_id))
            .await
            .map_err(|_| {
                connection_log_export_command_error(ConnectionLogExportError::storage_failed())
            })?;
        if replay.terminal_data().is_empty() {
            return Err(connection_log_export_command_error(
                ConnectionLogExportError::unavailable(),
            ));
        }
        Ok((metadata, replay.terminal_data().to_owned()))
    })
    .await
    .map_err(normalize_connection_log_export_command_error)?;

    tokio::task::spawn_blocking(move || {
        render_and_write_export_with_locale(&target, &metadata, &terminal_data, locale)
    })
    .await
    .map_err(|_| connection_log_export_command_error(ConnectionLogExportError::storage_failed()))?
    .map_err(connection_log_export_command_error)?;
    Ok(ExportConnectionLogResponse::success())
}

#[tauri::command]
async fn replace_connection_logs(
    state: State<'_, DesktopState>,
    request: ReplaceConnectionLogsRequest,
) -> Result<ConnectionLogsCatalog, String> {
    let (expected_inventory_revision, logs) = request.into_parts();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let store = state.saved_hosts.clone();
        let catalog = run_connection_logs_vault(move || {
            let committed = store.replace_connection_logs(expected_inventory_revision, logs)?;
            if committed.durability() == SavedVaultCommitDurability::Durable {
                return Ok(ConnectionLogsCatalog::from_commit(&committed));
            }
            let confirmed = store.confirm_current_snapshot_durability()?;
            if confirmed.revision() != committed.revision()
                || confirmed.connection_logs() != committed.logs()
            {
                return Err(StoreError::SnapshotDurabilityUnconfirmed);
            }
            Ok(ConnectionLogsCatalog {
                inventory_revision: confirmed.revision().clone(),
                logs: confirmed.connection_logs().to_vec(),
            })
        })
        .await?;
        if let Some(replays) = state
            .connection_log_replays
            .as_ref()
            .and_then(ConnectionLogReplayRuntime::ready_manager)
        {
            // The coordinator remains held across metadata publication and
            // replay retention, making delete/bookmark/read linearizable.
            let _ = replays.reconcile_catalog(catalog.logs.clone()).await;
        }
        Ok(catalog)
    })
    .await
    .map_err(normalize_connection_logs_command_error)
}

#[tauri::command]
async fn clear_unsaved_connection_logs(
    state: State<'_, DesktopState>,
    request: ClearUnsavedConnectionLogsRequest,
) -> Result<ConnectionLogsCatalog, String> {
    let expected_inventory_revision = request.into_expected_revision();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let store = state.saved_hosts.clone();
        let catalog = run_connection_logs_vault(move || {
            let committed = store.clear_unsaved_connection_logs(expected_inventory_revision)?;
            if committed.durability() == SavedVaultCommitDurability::Durable {
                return Ok(ConnectionLogsCatalog::from_commit(&committed));
            }
            let confirmed = store.confirm_current_snapshot_durability()?;
            if confirmed.revision() != committed.revision()
                || confirmed.connection_logs() != committed.logs()
            {
                return Err(StoreError::SnapshotDurabilityUnconfirmed);
            }
            Ok(ConnectionLogsCatalog {
                inventory_revision: confirmed.revision().clone(),
                logs: confirmed.connection_logs().to_vec(),
            })
        })
        .await?;
        if let Some(replays) = state
            .connection_log_replays
            .as_ref()
            .and_then(ConnectionLogReplayRuntime::ready_manager)
        {
            // Keep metadata and encrypted replay retention in one ordered
            // transaction. A replay cleanup fault is retried by startup
            // reconciliation without restoring deleted metadata.
            let _ = replays.reconcile_catalog(catalog.logs.clone()).await;
        }
        Ok(catalog)
    })
    .await
    .map_err(normalize_connection_logs_command_error)
}

fn map_notes_snippets_store_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => notes_snippets_error(
            NOTES_SNIPPETS_INVENTORY_CHANGED,
            "The notes/snippets catalog changed; refresh and retry",
        ),
        StoreError::Serialization
        | StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => notes_snippets_invalid(),
        _ => notes_snippets_error(
            NOTES_SNIPPETS_PUBLICATION_FAILED,
            "The notes/snippets catalog could not be updated",
        ),
    }
}

fn normalize_notes_snippets_command_error(error: String) -> String {
    if error.starts_with("NOTES_SNIPPETS_") {
        error
    } else {
        notes_snippets_error(
            NOTES_SNIPPETS_PUBLICATION_FAILED,
            "The notes/snippets operation could not be completed",
        )
    }
}

async fn run_notes_snippets_vault<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            notes_snippets_error(
                NOTES_SNIPPETS_PUBLICATION_FAILED,
                "The notes/snippets storage worker failed",
            )
        })?
        .map_err(map_notes_snippets_store_error)
}

async fn confirm_notes_snippets_snapshot(
    state: &DesktopState,
    expected_revision: Option<&SavedVaultInventoryRevision>,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    let snapshot =
        run_notes_snippets_vault(move || store.confirm_current_snapshot_durability()).await?;
    if expected_revision.is_some_and(|expected| expected != snapshot.revision()) {
        return Err(notes_snippets_error(
            NOTES_SNIPPETS_INVENTORY_CHANGED,
            "The notes/snippets catalog changed; refresh and retry",
        ));
    }
    Ok(snapshot)
}

async fn load_notes_snippets_catalog_inner(
    state: &DesktopState,
) -> Result<NotesSnippetsCatalog, String> {
    let snapshot = confirm_notes_snippets_snapshot(state, None).await?;
    Ok(NotesSnippetsCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

async fn commit_notes_snippets_mutation(
    state: &DesktopState,
    prepared: PreparedNotesSnippetsMutation,
) -> Result<NotesSnippetsCatalog, String> {
    let store = state.saved_hosts.clone();
    let (revision, graph) = run_notes_snippets_vault(move || {
        let plan = store
            .plan_graph_replacement(prepared.expected_inventory_revision, &prepared.target_graph)?;
        let committed = store.commit_planned_graph_replacement(plan, prepared.target_graph)?;
        if committed.durability() == SavedVaultCommitDurability::Durable {
            return Ok((committed.revision().clone(), committed.into_graph()));
        }
        let confirmed = store.confirm_current_snapshot_durability()?;
        if confirmed.revision() != committed.revision() || confirmed.graph() != committed.graph() {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        Ok((confirmed.revision().clone(), confirmed.graph().clone()))
    })
    .await?;
    Ok(NotesSnippetsCatalog::from_graph(revision, &graph))
}

fn current_notes_snippets_time() -> Result<f64, String> {
    current_unix_millis()
        .map(|millis| millis as f64)
        .map_err(|_| notes_snippets_invalid())
}

#[tauri::command]
async fn list_vault_notes(state: State<'_, DesktopState>) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_notes_snippets_catalog_inner(&state).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn create_vault_note(
    state: State<'_, DesktopState>,
    request: CreateVaultNoteRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_note_creation(
            snapshot.graph().clone(),
            request,
            SavedVaultNoteId::new(),
            current_notes_snippets_time()?,
        )?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn update_vault_note(
    state: State<'_, DesktopState>,
    request: UpdateVaultNoteRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_note_update(
            snapshot.graph().clone(),
            request,
            current_notes_snippets_time()?,
        )?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn delete_vault_note(
    state: State<'_, DesktopState>,
    request: DeleteVaultNoteRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_note_deletion(snapshot.graph().clone(), request)?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn list_saved_snippets(
    state: State<'_, DesktopState>,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_notes_snippets_catalog_inner(&state).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn create_saved_snippet(
    state: State<'_, DesktopState>,
    request: CreateSavedSnippetRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared =
            prepare_snippet_creation(snapshot.graph().clone(), request, SavedSnippetId::new())?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn update_saved_snippet(
    state: State<'_, DesktopState>,
    request: UpdateSavedSnippetRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_snippet_update(snapshot.graph().clone(), request)?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

#[tauri::command]
async fn delete_saved_snippet(
    state: State<'_, DesktopState>,
    request: DeleteSavedSnippetRequest,
) -> Result<NotesSnippetsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let expected = request.expected_inventory_revision.clone();
        let snapshot = confirm_notes_snippets_snapshot(&state, Some(&expected)).await?;
        let prepared = prepare_snippet_deletion(snapshot.graph().clone(), request)?;
        commit_notes_snippets_mutation(&state, prepared).await
    })
    .await
    .map_err(normalize_notes_snippets_command_error)
}

async fn take_ephemeral_ssh_password(
    state: &DesktopState,
    owner: &str,
    reference: &EphemeralCredentialReference,
) -> Result<ConnectionCredentials, String> {
    let secret = state
        .ephemeral_credentials
        .take(owner, reference)
        .await
        .map_err(|error| error.to_string())?;
    credentials_from_secret(secret)
}

fn credentials_from_secret(secret: SecretValue) -> Result<ConnectionCredentials, String> {
    let password = secret
        .as_utf8()
        .map_err(|error| error.to_string())?
        .to_owned();
    Ok(ConnectionCredentials::empty().with_password(SecretText::new(password)))
}

fn has_saved_credential(host: &SavedHost) -> bool {
    host.compatibility_fields()
        .get("hasSavedCredential")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn validate_selected_identity_file_paths(paths: Vec<String>) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Err(format!(
            "{SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED}: Select the private key file for this connection"
        ));
    }
    if paths.len() > MAX_SELECTED_IDENTITY_FILES {
        return Err(format!(
            "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: Too many private key files were selected"
        ));
    }

    let mut seen = std::collections::HashSet::with_capacity(paths.len());
    for path in &paths {
        if path.trim().is_empty()
            || path.len() > MAX_SELECTED_IDENTITY_FILE_PATH_BYTES
            || path.chars().any(char::is_control)
            || !seen.insert(path.as_str())
        {
            return Err(format!(
                "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: The private key file selection is invalid"
            ));
        }
    }
    Ok(paths)
}

fn saved_host_tags(host: &SavedHost) -> Vec<String> {
    host.compatibility_fields()
        .get("tags")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default()
}

fn saved_host_chain(host: &SavedHost) -> Option<SavedHostChainRequest> {
    host.compatibility_fields()
        .get("hostChain")
        .cloned()
        .and_then(|value| serde_json::from_value::<SavedHostChainRequest>(value).ok())
        .filter(|chain| !chain.host_ids.is_empty())
}

const MAX_RENDERER_APPEARANCE_TEXT_BYTES: usize = 512;

fn legacy_style_override_enabled(
    fields: &std::collections::BTreeMap<String, serde_json::Value>,
    flag_key: &str,
    legacy_value_present: bool,
) -> bool {
    match fields.get(flag_key) {
        Some(serde_json::Value::Bool(value)) => *value,
        None => legacy_value_present,
        // Legacy JavaScript treated null and non-boolean flag values as an
        // explicit non-override, rather than as an omitted flag.
        Some(_) => false,
    }
}

fn effective_appearance_text(host: &SavedHost, value_key: &str, flag_key: &str) -> Option<String> {
    let fields = host.compatibility_fields();
    let value = fields.get(value_key)?.as_str()?;
    let legacy_value_present = !value.trim().is_empty();
    if !legacy_style_override_enabled(fields, flag_key, legacy_value_present)
        || !legacy_value_present
        || value.len() > MAX_RENDERER_APPEARANCE_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn effective_appearance_number(
    host: &SavedHost,
    value_key: &str,
    flag_key: &str,
) -> Option<serde_json::Number> {
    let fields = host.compatibility_fields();
    let value = fields.get(value_key)?.as_number()?;
    legacy_style_override_enabled(fields, flag_key, true).then(|| value.clone())
}

fn saved_host_effective_appearance(host: &SavedHost) -> SavedHostEffectiveAppearanceView {
    SavedHostEffectiveAppearanceView {
        theme_id: effective_appearance_text(host, "theme", "themeOverride"),
        font_family: effective_appearance_text(host, "fontFamily", "fontFamilyOverride"),
        font_size: effective_appearance_number(host, "fontSize", "fontSizeOverride"),
        font_weight: effective_appearance_number(host, "fontWeight", "fontWeightOverride"),
    }
}

fn saved_host_effective_charset(host: &SavedHost) -> Option<String> {
    host.compatibility_fields()
        .get("charset")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
}

fn saved_host_view(host: &SavedHost) -> SavedHostView {
    let has_saved_host_credential = !host.protocol.is_serial() && has_saved_credential(host);
    let serial_config = host.serial_config().ok().flatten();
    let effective_serial_config = host.effective_serial_config().ok();
    let has_explicit_serial_backspace_behavior = host.protocol.is_serial()
        && (serial_config
            .as_ref()
            .is_some_and(|config| config.backspace_behavior.is_some())
            || matches!(
                host.compatibility_fields().get("backspaceBehavior"),
                Some(serde_json::Value::String(value))
                    if value == "default" || value == "ctrl-h"
            ));
    let has_explicit_charset = matches!(
        host.compatibility_fields().get("charset"),
        Some(serde_json::Value::String(value)) if !value.trim().is_empty()
    );
    SavedHostView {
        id: host.id.as_str().to_owned(),
        revision: host.revision,
        label: host.label.clone(),
        hostname: host.hostname.clone(),
        port: host.port,
        username: host.username.clone(),
        group: host
            .group_path()
            .ok()
            .flatten()
            .map(|path| path.as_str().to_owned()),
        tags: saved_host_tags(host),
        host_chain: saved_host_chain(host),
        protocol: host.protocol.as_str().to_owned(),
        visual: SavedHostVisualView::from_host(host),
        serial_config,
        effective_serial_config,
        has_explicit_serial_backspace_behavior,
        has_explicit_charset,
        charset: saved_host_effective_charset(host),
        auth_method: host.auth_method.as_str().to_owned(),
        managed_ssh_key_id: None,
        has_saved_credential: has_saved_host_credential,
        has_saved_host_credential,
        password_identity: None,
        key_source: if host.protocol.is_ssh()
            && (host.auth_method.as_str().eq_ignore_ascii_case("key")
                || host
                    .auth_method
                    .as_str()
                    .eq_ignore_ascii_case("certificate"))
        {
            SavedHostKeySource::Reference
        } else {
            SavedHostKeySource::None
        },
        has_saved_key_passphrase: false,
        proxy: None,
        effective_appearance: saved_host_effective_appearance(host),
        mosh_enabled: saved_host_boolean_override(host, "moshEnabled"),
        et_enabled: saved_host_boolean_override(host, "etEnabled"),
        et_port: saved_host_port_override(host, "etPort"),
        effective_mosh_enabled: mosh_session::effective_mosh_enabled(host),
        effective_et_enabled: et_session::effective_et_enabled(host).unwrap_or(false),
        created_at: host.created_at,
        updated_at: host.updated_at,
    }
}

fn saved_host_boolean_override(host: &SavedHost, field: &str) -> Option<bool> {
    host.compatibility_fields()
        .get(field)
        .and_then(|value| match value {
            serde_json::Value::Bool(value) => Some(*value),
            _ => None,
        })
}

fn saved_host_port_override(host: &SavedHost, field: &str) -> Option<u32> {
    host.compatibility_fields()
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (1..=u16::MAX.into()).contains(value))
}

fn saved_host_view_from_graph(
    host: &SavedHost,
    graph: &SavedVaultGraph,
) -> Result<SavedHostView, String> {
    let mut view = saved_host_view(host);
    let proxy = if host.protocol.is_ssh() {
        Some(saved_host_proxy_view(host, graph)?)
    } else {
        None
    };
    let projection = project_saved_host_connection(host, graph.groups()).map_err(|_| {
        "SAVED_HOST_APPEARANCE_REPAIR_REQUIRED: Saved-host appearance metadata must be repaired"
            .to_owned()
    })?;
    view.effective_appearance = saved_host_effective_appearance(projection.effective_host());
    view.effective_mosh_enabled = mosh_session::effective_mosh_enabled(projection.effective_host());
    view.effective_et_enabled =
        et_session::effective_et_enabled(projection.effective_host()).unwrap_or(false);
    view.charset = saved_host_effective_charset(projection.effective_host());
    view.effective_serial_config = projection.effective_host().effective_serial_config().ok();
    view.proxy = proxy.and_then(|proxy| {
        (proxy.proxy_profile_id.is_some() || proxy.inline_proxy.is_some()).then_some(proxy)
    });
    view.key_source = SavedHostKeySource::None;
    view.has_saved_key_passphrase = false;
    if host.protocol.is_serial() {
        view.has_saved_credential = false;
        view.has_saved_host_credential = false;
        view.password_identity = None;
        view.proxy = None;
        view.host_chain = None;
        view.managed_ssh_key_id = None;
        return Ok(view);
    }
    if host.protocol.is_telnet() {
        // Telnet keeps its reusable identity binding in the legacy-compatible
        // `telnetIdentityId` field.  Never run the SSH authentication resolver
        // for this record: doing so would interpret an inactive SSH identity
        // or key binding as the active Telnet credential.
        let identity = match projection
            .effective_host()
            .compatibility_fields()
            .get("telnetIdentityId")
        {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(id)) if id.is_empty() => None,
            Some(serde_json::Value::String(id)) => Some(
                validate_saved_password_identity_selection(id, graph)
                    .map_err(|_| saved_host_repair_required())?,
            ),
            Some(_) => return Err(saved_host_repair_required()),
        };
        view.has_saved_host_credential = has_saved_credential(host);
        view.has_saved_credential = identity.is_some_and(|identity| identity.has_saved_credential)
            || projection.telnet_credential_owner().is_some();
        view.password_identity = identity.map(|identity| SavedHostPasswordIdentityView {
            id: identity.id.as_str().to_owned(),
            label: identity.label.clone(),
            username: identity.username.clone(),
            has_saved_credential: identity.has_saved_credential,
        });
        // Primary Telnet deliberately has no active SSH proxy, key, or jump
        // relationship in the renderer-facing view.
        view.proxy = None;
        view.host_chain = None;
        view.managed_ssh_key_id = None;
        view.key_source = SavedHostKeySource::None;
        return Ok(view);
    }
    match resolve_saved_host_authentication(host, graph) {
        Ok(SavedHostAuthResolution::Password) => {
            if let Ok(plan) = resolve_saved_password_authentication(host, graph) {
                view.has_saved_credential = plan.effective_has_saved_credential();
                view.has_saved_host_credential = plan.host_has_saved_credential();
                view.password_identity = match (
                    plan.password_identity_id(),
                    plan.password_identity_label(),
                    plan.password_identity_username(),
                ) {
                    (Some(id), Some(label), Some(username)) => {
                        Some(SavedHostPasswordIdentityView {
                            id: id.as_str().to_owned(),
                            label: label.to_owned(),
                            username: username.to_owned(),
                            has_saved_credential: plan.identity_has_saved_credential(),
                        })
                    }
                    _ => None,
                };
            }
        }
        Ok(SavedHostAuthResolution::ManagedPrivateKey {
            key_id,
            has_saved_passphrase,
        })
        | Ok(SavedHostAuthResolution::ManagedCertificate {
            key_id,
            has_saved_passphrase,
        }) => {
            view.key_source = SavedHostKeySource::Managed;
            view.managed_ssh_key_id = Some(key_id.as_str().to_owned());
            view.has_saved_key_passphrase = has_saved_passphrase;
        }
        Ok(SavedHostAuthResolution::ReferencePrivateKey { .. }) => {
            view.key_source = SavedHostKeySource::Reference;
        }
        Err(_) => {}
    }
    Ok(view)
}

fn saved_host_views_from_graph(graph: &SavedVaultGraph) -> Result<Vec<SavedHostView>, String> {
    graph
        .hosts()
        .iter()
        .map(|host| saved_host_view_from_graph(host, graph))
        .collect()
}

fn requested_saved_host_authentication(
    auth_method: SavedHostAuthenticationMethodRequest,
    password_identity_id: Option<&str>,
    managed_ssh_key_id: Option<&str>,
    has_saved_host_credential: bool,
) -> Result<SavedHostAuthentication, String> {
    match auth_method {
        SavedHostAuthenticationMethodRequest::Password => {
            if managed_ssh_key_id.is_some() {
                return Err(saved_host_invalid());
            }
            match password_identity_id {
                Some(identity_id) => Ok(SavedHostAuthentication::PasswordIdentity {
                    identity_id: SavedPasswordIdentityId::from_opaque(identity_id.to_owned())
                        .map_err(|_| saved_host_invalid())?,
                    has_saved_host_credential,
                }),
                None => Ok(SavedHostAuthentication::DirectPassword {
                    has_saved_credential: has_saved_host_credential,
                }),
            }
        }
        SavedHostAuthenticationMethodRequest::Key
        | SavedHostAuthenticationMethodRequest::Certificate => {
            if password_identity_id.is_some() {
                return Err(saved_host_invalid());
            }
            if has_saved_host_credential {
                return Err(format!(
                    "{SAVED_HOST_CREDENTIAL_MUTATION_INVALID}: Password credentials cannot be stored for this host"
                ));
            }
            let key_id = managed_ssh_key_id.ok_or_else(saved_host_invalid)?;
            let key_id = SavedSshKeyReferenceId::from_opaque(key_id.to_owned())
                .map_err(|_| saved_host_invalid())?;
            Ok(match auth_method {
                SavedHostAuthenticationMethodRequest::Key => {
                    SavedHostAuthentication::ManagedPrivateKey { key_id }
                }
                SavedHostAuthenticationMethodRequest::Certificate => {
                    SavedHostAuthentication::ManagedCertificate { key_id }
                }
                SavedHostAuthenticationMethodRequest::Password => {
                    return Err(saved_host_invalid());
                }
            })
        }
    }
}

fn validate_saved_host_authentication_selection(
    request: &SavedHostDraftRequest,
    graph: &SavedVaultGraph,
    has_saved_host_credential: bool,
) -> Result<(), String> {
    if request.protocol == SavedHostProtocolRequest::Serial {
        if request.auth_method != SavedHostAuthenticationMethodRequest::Password
            || request.managed_ssh_key_id.is_some()
            || request.password_identity_id.is_some()
            || request.serial_config.is_none()
            || has_saved_host_credential
            || request
                .host_chain
                .as_ref()
                .is_some_and(|chain| !chain.host_ids.is_empty())
            || request.proxy.is_some()
            || !request.username.trim().is_empty()
        {
            return Err(saved_host_invalid());
        }
        return Ok(());
    }
    if request.protocol == SavedHostProtocolRequest::Telnet {
        if request.serial_config.is_some()
            || request.auth_method != SavedHostAuthenticationMethodRequest::Password
            || request.managed_ssh_key_id.is_some()
            || request
                .host_chain
                .as_ref()
                .is_some_and(|chain| !chain.host_ids.is_empty())
            || request.proxy.is_some()
        {
            return Err(saved_host_invalid());
        }
        if let Some(identity_id) = request.password_identity_id.as_deref() {
            validate_saved_password_identity_selection(identity_id, graph)
                .map_err(|_| saved_host_invalid())?;
        }
        return Ok(());
    }
    if request.serial_config.is_some() {
        return Err(saved_host_invalid());
    }
    let authentication = requested_saved_host_authentication(
        request.auth_method,
        request.password_identity_id.as_deref(),
        request.managed_ssh_key_id.as_deref(),
        has_saved_host_credential,
    )?;
    match authentication {
        SavedHostAuthentication::DirectPassword { .. } => Ok(()),
        SavedHostAuthentication::PasswordIdentity { identity_id, .. } => {
            validate_saved_password_identity_selection(identity_id.as_str(), graph)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        SavedHostAuthentication::ManagedPrivateKey { key_id }
        | SavedHostAuthentication::ManagedCertificate { key_id } => {
            let key = graph
                .managed_ssh_keys()
                .iter()
                .find(|key| key.id == key_id)
                .ok_or_else(saved_host_invalid)?;
            let category_matches = match request.auth_method {
                SavedHostAuthenticationMethodRequest::Key => {
                    key.category.as_str().eq_ignore_ascii_case("key")
                        || key.category.as_str().eq_ignore_ascii_case("identity")
                }
                SavedHostAuthenticationMethodRequest::Certificate => {
                    key.category.as_str().eq_ignore_ascii_case("certificate")
                }
                SavedHostAuthenticationMethodRequest::Password => false,
            };
            category_matches
                .then_some(())
                .ok_or_else(saved_host_invalid)
        }
    }
}

fn create_vault_draft(
    request: SavedHostDraftRequest,
    has_credential: bool,
) -> Result<SavedHostDraft, String> {
    let transport = request.transport.normalize_for_protocol(request.protocol)?;
    let SavedHostDraftRequest {
        label,
        hostname,
        port,
        username,
        protocol,
        serial_config,
        charset,
        group,
        auth_method,
        managed_ssh_key_id,
        tags,
        host_chain,
        password_identity_id,
        transport: _,
        proxy: _,
    } = request;
    let mut draft = match protocol {
        SavedHostProtocolRequest::Ssh => {
            if serial_config.is_some() {
                return Err(saved_host_invalid());
            }
            let authentication = requested_saved_host_authentication(
                auth_method,
                password_identity_id.as_deref(),
                managed_ssh_key_id.as_deref(),
                has_credential,
            )?;
            SavedHostDraft::ssh_password(hostname, username).with_authentication(authentication)
        }
        SavedHostProtocolRequest::Telnet => {
            if serial_config.is_some()
                || auth_method != SavedHostAuthenticationMethodRequest::Password
                || managed_ssh_key_id.is_some()
            {
                return Err(saved_host_invalid());
            }
            let mut draft = SavedHostDraft::telnet(hostname, username);
            if has_credential {
                draft = draft
                    .with_compatibility_field("hasSavedCredential", serde_json::Value::Bool(true))
                    .map_err(|_| saved_host_invalid())?;
            }
            if let Some(identity_id) = password_identity_id {
                let identity_id = SavedPasswordIdentityId::from_opaque(identity_id)
                    .map_err(|_| saved_host_invalid())?;
                draft = draft
                    .with_compatibility_field(
                        "telnetIdentityId",
                        serde_json::Value::String(identity_id.as_str().to_owned()),
                    )
                    .map_err(|_| saved_host_invalid())?;
            }
            draft
        }
        SavedHostProtocolRequest::Serial => {
            let config = serial_config.ok_or_else(saved_host_invalid)?;
            if has_credential
                || auth_method != SavedHostAuthenticationMethodRequest::Password
                || managed_ssh_key_id.is_some()
                || password_identity_id.is_some()
                || hostname.trim() != config.path
                || port != config.baud_rate
                || !username.trim().is_empty()
            {
                return Err(saved_host_invalid());
            }
            SavedHostDraft::serial(config).map_err(|_| saved_host_invalid())?
        }
    };
    draft.label = label;
    if protocol != SavedHostProtocolRequest::Serial {
        draft.port = Some(port);
    }
    if let Some(charset) = normalize_saved_host_charset(charset)? {
        draft = draft
            .with_compatibility_field("charset", serde_json::Value::String(charset))
            .map_err(|_| saved_host_invalid())?;
    }
    if let Some(group) = group {
        draft =
            draft.with_group_path(SavedGroupPath::new(group).map_err(|error| error.to_string())?);
    }
    if !tags.is_empty() {
        draft = draft
            .with_compatibility_field(
                "tags",
                serde_json::to_value(tags).map_err(|_| saved_host_invalid())?,
            )
            .map_err(|_| saved_host_invalid())?;
    }
    if let Some(host_chain) = host_chain.filter(|chain| !chain.host_ids.is_empty()) {
        draft = draft
            .with_compatibility_field(
                "hostChain",
                serde_json::to_value(host_chain).map_err(|_| saved_host_invalid())?,
            )
            .map_err(|_| saved_host_invalid())?;
    }
    if let Some(mosh_enabled) = transport.mosh_enabled {
        draft = draft
            .with_compatibility_field("moshEnabled", serde_json::Value::Bool(mosh_enabled))
            .map_err(|_| saved_host_invalid())?;
    }
    if let Some(et_enabled) = transport.et_enabled {
        draft = draft
            .with_compatibility_field("etEnabled", serde_json::Value::Bool(et_enabled))
            .map_err(|_| saved_host_invalid())?;
    }
    if let Some(et_port) = transport.et_port {
        draft = draft
            .with_compatibility_field("etPort", serde_json::Value::from(et_port))
            .map_err(|_| saved_host_invalid())?;
    }
    Ok(draft)
}

fn create_vault_update(
    request: SavedHostDraftRequest,
    has_credential: bool,
) -> Result<SavedHostUpdate, String> {
    let transport = request.transport.normalize_for_protocol(request.protocol)?;
    let SavedHostDraftRequest {
        label,
        hostname,
        port,
        username,
        protocol,
        serial_config,
        charset,
        group,
        auth_method,
        managed_ssh_key_id,
        tags,
        host_chain,
        password_identity_id,
        transport: _,
        proxy: _,
    } = request;
    let fallback_label = hostname.clone();
    let mut update = SavedHostUpdate::default();
    update.label = Some(label.unwrap_or(fallback_label));
    update.hostname = Some(hostname.clone());
    update.port = Some(port);
    update.username = Some(username.clone());
    match protocol {
        SavedHostProtocolRequest::Ssh => {
            if serial_config.is_some() {
                return Err(saved_host_invalid());
            }
            update.protocol = Some(SavedHostProtocol::ssh());
            update = update.with_authentication(requested_saved_host_authentication(
                auth_method,
                password_identity_id.as_deref(),
                managed_ssh_key_id.as_deref(),
                has_credential,
            )?);
        }
        SavedHostProtocolRequest::Telnet => {
            if serial_config.is_some()
                || auth_method != SavedHostAuthenticationMethodRequest::Password
                || managed_ssh_key_id.is_some()
            {
                return Err(saved_host_invalid());
            }
            update.protocol = Some(SavedHostProtocol::telnet());
            update.auth_method = Some(SavedHostAuthMethod::password());
            update = update
                .with_compatibility_field(
                    "hasSavedCredential",
                    if has_credential {
                        serde_json::Value::Bool(true)
                    } else {
                        serde_json::Value::Null
                    },
                )
                .map_err(|_| saved_host_invalid())?
                .with_compatibility_field(
                    "telnetIdentityId",
                    match password_identity_id {
                        Some(identity_id) => serde_json::Value::String(
                            SavedPasswordIdentityId::from_opaque(identity_id)
                                .map_err(|_| saved_host_invalid())?
                                .as_str()
                                .to_owned(),
                        ),
                        None => serde_json::Value::Null,
                    },
                )
                .map_err(|_| saved_host_invalid())?
                // Primary Telnet CRUD stores its current endpoint in the
                // canonical host fields. Remove older override fields so an
                // edited port or username cannot be shadowed at connection
                // time by stale legacy metadata.
                .with_compatibility_field("telnetPort", serde_json::Value::Null)
                .map_err(|_| saved_host_invalid())?
                .with_compatibility_field("telnetUsername", serde_json::Value::Null)
                .map_err(|_| saved_host_invalid())?;
        }
        SavedHostProtocolRequest::Serial => {
            let config = serial_config.ok_or_else(saved_host_invalid)?;
            if has_credential
                || auth_method != SavedHostAuthenticationMethodRequest::Password
                || managed_ssh_key_id.is_some()
                || password_identity_id.is_some()
                || hostname.trim() != config.path
                || port != config.baud_rate
                || !username.trim().is_empty()
            {
                return Err(saved_host_invalid());
            }
            update.auth_method = Some(SavedHostAuthMethod::password());
            update = update
                .with_serial_config(config)
                .map_err(|_| saved_host_invalid())?;
        }
    }
    if let Some(charset) = normalize_saved_host_charset(charset)? {
        update = update
            .with_compatibility_field("charset", serde_json::Value::String(charset))
            .map_err(|_| saved_host_invalid())?;
    }
    update = match group {
        Some(group) => {
            update.with_group_path(SavedGroupPath::new(group).map_err(|error| error.to_string())?)
        }
        None => update.clear_group_path(),
    };
    update = update
        .with_compatibility_field(
            "tags",
            if tags.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::to_value(tags).map_err(|_| saved_host_invalid())?
            },
        )
        .map_err(|_| saved_host_invalid())?;
    update = update
        .with_compatibility_field(
            "hostChain",
            match host_chain.filter(|chain| !chain.host_ids.is_empty()) {
                Some(chain) => serde_json::to_value(chain).map_err(|_| saved_host_invalid())?,
                None => serde_json::Value::Null,
            },
        )
        .map_err(|_| saved_host_invalid())?;
    update = update
        .with_compatibility_field(
            "moshEnabled",
            transport
                .mosh_enabled
                .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        )
        .map_err(|_| saved_host_invalid())?
        .with_compatibility_field(
            "etEnabled",
            transport
                .et_enabled
                .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        )
        .map_err(|_| saved_host_invalid())?
        .with_compatibility_field(
            "etPort",
            transport
                .et_port
                .map_or(serde_json::Value::Null, serde_json::Value::from),
        )
        .map_err(|_| saved_host_invalid())?;
    Ok(update)
}

fn normalize_saved_host_charset(value: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 || value.chars().any(char::is_control) {
        return Err(saved_host_invalid());
    }
    Ok(Some(value.to_owned()))
}

fn stored_reference(host: &SavedHost) -> Result<StoredCredentialReference, String> {
    StoredCredentialReference::for_saved_host(host.id.as_str()).map_err(|error| error.to_string())
}

fn legacy_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

fn validate_legacy_source_fingerprint(fingerprint: &str) -> Result<(), String> {
    if fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(legacy_error(
            LEGACY_VAULT_SOURCE_CHANGED,
            "The legacy Vault inspection fingerprint is invalid",
        ))
    }
}

fn legacy_source_fingerprint_key() -> &'static [u8; 32] {
    // One random key is shared by every window and reparse in this process.
    // It is intentionally not persisted: renderer-held inspection tokens from
    // an earlier app process must be inspected again after a restart.
    LEGACY_SOURCE_FINGERPRINT_KEY.get_or_init(|| {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let mut key = [0_u8; 32];
        key[..16].copy_from_slice(first.as_bytes());
        key[16..].copy_from_slice(second.as_bytes());
        key
    })
}

fn legacy_source_fingerprint_token(raw_sha256: &[u8; 32]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(legacy_source_fingerprint_key())
        .expect("HMAC accepts a 32-byte key");
    mac.update(b"netcatty-legacy-vault-source-v1\0");
    mac.update(raw_sha256);
    let digest = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_legacy_source_fingerprint(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn verify_legacy_source_fingerprint(raw_sha256: &[u8; 32], token: &str) -> bool {
    let Some(token) = decode_legacy_source_fingerprint(token) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(legacy_source_fingerprint_key())
        .expect("HMAC accepts a 32-byte key");
    mac.update(b"netcatty-legacy-vault-source-v1\0");
    mac.update(raw_sha256);
    mac.verify_slice(&token).is_ok()
}

fn ensure_legacy_document_is_committable(document: &LegacyVaultDocument) -> Result<(), String> {
    if document.preview().source_recovery_required() {
        Err(legacy_error(
            LEGACY_VAULT_RECOVERY_REQUIRED,
            "This device-bound backup must be recovered and re-exported by the legacy app",
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn legacy_source_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    legacy_file_attributes_are_reparse_point(metadata.file_attributes())
}

#[cfg(windows)]
const fn legacy_file_attributes_are_reparse_point(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn legacy_source_is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn read_legacy_vault_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use std::io::Read;

    let initial = std::fs::symlink_metadata(path).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_SOURCE_UNAVAILABLE,
            "The legacy Vault file is unavailable",
        )
    })?;
    if initial.file_type().is_symlink()
        || legacy_source_is_reparse_point(&initial)
        || !initial.is_file()
    {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_NOT_REGULAR,
            "The legacy Vault source must be a regular file",
        ));
    }
    if initial.len() > MAX_LEGACY_BACKUP_BYTES as u64 {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_TOO_LARGE,
            "The legacy Vault file exceeds the import limit",
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_SOURCE_UNAVAILABLE,
            "The legacy Vault file is unavailable",
        )
    })?;
    let opened = file.metadata().map_err(|_| {
        legacy_error(
            LEGACY_VAULT_SOURCE_UNAVAILABLE,
            "The legacy Vault file is unavailable",
        )
    })?;
    if opened.file_type().is_symlink()
        || legacy_source_is_reparse_point(&opened)
        || !opened.is_file()
    {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_NOT_REGULAR,
            "The legacy Vault source must be a regular file",
        ));
    }
    if opened.len() > MAX_LEGACY_BACKUP_BYTES as u64 {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_TOO_LARGE,
            "The legacy Vault file exceeds the import limit",
        ));
    }

    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(
        (opened.len() as usize).min(MAX_LEGACY_BACKUP_BYTES),
    ));
    file.take(MAX_LEGACY_BACKUP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_SOURCE_UNAVAILABLE,
                "The legacy Vault file could not be read",
            )
        })?;
    if bytes.len() > MAX_LEGACY_BACKUP_BYTES {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_TOO_LARGE,
            "The legacy Vault file exceeds the import limit",
        ));
    }
    let final_metadata = std::fs::symlink_metadata(path).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_SOURCE_UNAVAILABLE,
            "The legacy Vault file changed while it was being read",
        )
    })?;
    if final_metadata.file_type().is_symlink()
        || legacy_source_is_reparse_point(&final_metadata)
        || !final_metadata.is_file()
    {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_NOT_REGULAR,
            "The legacy Vault source must remain a regular file",
        ));
    }
    Ok(bytes)
}

async fn load_legacy_vault_document(path: String) -> Result<LegacyVaultDocument, String> {
    tokio::task::spawn_blocking(move || {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_SOURCE_INVALID,
                    "The system clock is unavailable",
                )
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_SOURCE_INVALID,
                    "The system clock is unavailable",
                )
            })?;
        let bytes = read_legacy_vault_file(std::path::Path::new(&path))?;
        parse_legacy_vault(&bytes, now_ms).map_err(|error| {
            legacy_error(
                LEGACY_VAULT_SOURCE_INVALID,
                &format!("The legacy Vault file is invalid ({})", error.code.as_str()),
            )
        })
    })
    .await
    .map_err(|_| {
        legacy_error(
            LEGACY_VAULT_SOURCE_INVALID,
            "The legacy Vault parser failed",
        )
    })?
}

#[derive(Clone, Copy)]
struct LegacySourceCatalogCounts {
    source_ssh_keys: u32,
    candidate_managed_ssh_keys: u32,
    managed_ssh_key_recovery_required: u32,
    managed_passphrases_discarded_by_policy: u32,
    duplicate_ssh_keys: u32,
    unsupported_ssh_keys: u32,
    rejected_ssh_keys: u32,
    source_identities: u32,
    candidate_password_identities: u32,
    duplicate_identities: u32,
    unsupported_identities: u32,
    rejected_identities: u32,
    source_proxy_profiles: u32,
    duplicate_proxy_profiles: u32,
    unsupported_proxy_profiles: u32,
    rejected_proxy_profiles: u32,
    candidate_inline_proxy_hosts: u32,
    source_custom_groups: u32,
    source_group_configs: u32,
}

struct AssessableLegacyGraph {
    preview: LegacyVaultPreview,
    host_candidates: Vec<LegacyHostCandidate>,
    password_identity_candidates: Vec<LegacyPasswordIdentityCandidate>,
    proxy_profile_candidates: Vec<LegacyProxyProfileCandidate>,
    group_config_candidates: Vec<LegacyGroupConfigCandidate>,
    notes_snippets_candidates: LegacyNotesSnippetsCandidates,
    graph: SavedVaultGraph,
    managed_secret_bundles: Vec<SshSecretBundle>,
    source_catalog_counts: LegacySourceCatalogCounts,
    relationship_mode: bool,
}

fn into_assessable_legacy_graph(
    document: LegacyVaultDocument,
    managed_locators: Vec<SavedSecretObjectLocator>,
) -> Result<AssessableLegacyGraph, String> {
    let counts = document.preview().counts();
    let source_catalog_counts = LegacySourceCatalogCounts {
        source_ssh_keys: counts.source_ssh_keys,
        candidate_managed_ssh_keys: counts.candidate_managed_ssh_keys,
        managed_ssh_key_recovery_required: counts.managed_ssh_key_recovery_required,
        managed_passphrases_discarded_by_policy: counts.managed_passphrases_discarded_by_policy,
        duplicate_ssh_keys: counts.duplicate_ssh_keys,
        unsupported_ssh_keys: counts.unsupported_ssh_keys,
        rejected_ssh_keys: counts.rejected_ssh_keys,
        source_identities: counts.source_identities,
        candidate_password_identities: counts.candidate_password_identities,
        duplicate_identities: counts.duplicate_identities,
        unsupported_identities: counts.unsupported_identities,
        rejected_identities: counts.rejected_identities,
        source_proxy_profiles: counts.source_proxy_profiles,
        duplicate_proxy_profiles: counts.duplicate_proxy_profiles,
        unsupported_proxy_profiles: counts.unsupported_proxy_profiles,
        rejected_proxy_profiles: counts.rejected_proxy_profiles,
        candidate_inline_proxy_hosts: counts.candidate_inline_proxy_hosts,
        source_custom_groups: counts.source_custom_groups,
        source_group_configs: counts.source_group_configs,
    };
    let (
        preview,
        host_candidates,
        ssh_keys,
        managed_keys,
        identities,
        password_identity_candidates,
        proxy_profile_candidates,
        group_catalog_candidates,
        notes_snippets_candidates,
    ) = document.into_current_graph_parts();
    let (custom_groups, group_config_candidates) = group_catalog_candidates.into_parts();
    let group_config_candidates = group_config_candidates.unwrap_or_default();
    let group_catalog = custom_groups
        .map(SavedGroupCatalog::from_paths)
        .transpose()
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy custom-group catalog could not be assessed",
            )
        })?;
    let hosts = host_candidates
        .iter()
        .map(legacy_candidate_for_assessment)
        .collect::<Result<Vec<_>, _>>()?;
    let ssh_key_references = ssh_keys
        .into_iter()
        .map(|candidate| candidate.into_reference())
        .collect::<Vec<_>>();
    if managed_keys.len() != managed_locators.len() {
        return Err(legacy_error(
            LEGACY_VAULT_ASSESSMENT_FAILED,
            "The managed SSH-key inventory could not be assessed",
        ));
    }
    let mut managed_ssh_keys = Vec::with_capacity(managed_keys.len());
    let mut managed_secret_bundles = Vec::with_capacity(managed_keys.len());
    for (candidate, backend_locator) in managed_keys.into_iter().zip(managed_locators) {
        let (metadata, bundle) = candidate.into_parts();
        let (
            id,
            label,
            category,
            source,
            has_saved_passphrase,
            created_at,
            updated_at,
            compatibility_fields,
        ) = metadata.into_parts();
        let custody = SavedSshKeyCustodyReference::new(backend_locator, 1).map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The managed SSH-key inventory could not be assessed",
            )
        })?;
        let managed = SavedManagedSshKey::from_parts(
            id,
            label,
            category,
            source,
            has_saved_passphrase,
            created_at,
            updated_at,
            custody,
            compatibility_fields,
        )
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The managed SSH-key inventory could not be assessed",
            )
        })?;
        managed_ssh_keys.push(managed);
        managed_secret_bundles.push(bundle);
    }
    let identity_references = identities
        .into_iter()
        .map(|candidate| candidate.into_reference())
        .collect::<Vec<_>>();
    let password_identities = password_identity_candidates
        .iter()
        .map(legacy_password_identity_candidate_for_assessment)
        .collect::<Result<Vec<_>, _>>()?;
    let proxy_profiles = proxy_profile_candidates
        .iter()
        .map(legacy_proxy_profile_candidate_for_assessment)
        .collect::<Result<Vec<_>, _>>()?;
    let groups = group_config_candidates
        .iter()
        .map(|candidate| candidate.config().clone())
        .collect::<Vec<_>>();
    let relationship_mode = !ssh_key_references.is_empty()
        || !managed_ssh_keys.is_empty()
        || !identity_references.is_empty()
        || !password_identities.is_empty()
        || !proxy_profiles.is_empty()
        || !groups.is_empty()
        || hosts.iter().any(|host| {
            host.auth_method.as_str().eq_ignore_ascii_case("key")
                || host.proxy_config().ok().flatten().is_some()
                || host.proxy_profile_id().ok().flatten().is_some()
        });
    Ok(AssessableLegacyGraph {
        preview,
        host_candidates,
        password_identity_candidates,
        proxy_profile_candidates,
        group_config_candidates,
        notes_snippets_candidates,
        graph: SavedVaultGraph::new_with_proxy_profiles(
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
        )
        .with_group_catalog(group_catalog),
        managed_secret_bundles,
        source_catalog_counts,
        relationship_mode,
    })
}

/// Rewrites the legacy Notes/Scripts slice before graph assessment. This order
/// is intentional: a source host or GroupConfig that refers to a snippet
/// whose ID conflicts with the current Vault must be compared after that
/// snippet reference has been deterministically rewritten, otherwise a
/// repeated import could incorrectly look like a host/group conflict.
async fn attach_legacy_notes_snippets_plan(
    state: &DesktopState,
    graph: SavedVaultGraph,
    candidates: &LegacyNotesSnippetsCandidates,
    source_sha256: &[u8; 32],
) -> Result<(SavedVaultGraph, LegacyNotesSnippetsAssessment, u32), String> {
    let store = state.saved_hosts.clone();
    let current = tokio::task::spawn_blocking(move || store.graph())
        .await
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The current Vault graph could not be assessed",
            )
        })?
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The current Vault graph could not be assessed",
            )
        })?;
    let plan = plan_legacy_notes_snippets_import(
        candidates,
        current.notes_snippets(),
        graph.hosts(),
        current.hosts(),
        graph.groups(),
        current.groups(),
        &std::collections::BTreeMap::new(),
        source_sha256,
    )
    .map_err(|_| {
        legacy_error(
            LEGACY_VAULT_ASSESSMENT_FAILED,
            "The legacy Notes/Scripts relationship graph could not be assessed",
        )
    })?;
    let (assessment, notes_snippets, hosts, groups) = plan.into_parts();
    let custom_group_scope_change_count =
        u32::from(graph.group_catalog().is_some() && current.group_catalog().is_none());
    let (
        _,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        _,
        group_catalog,
        _,
    ) = graph.into_latest_parts();
    Ok((
        SavedVaultGraph::new_with_notes_snippets(
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            notes_snippets,
        )
        .with_group_catalog(group_catalog),
        assessment,
        custom_group_scope_change_count,
    ))
}

/// Performs the relationship checks that do not depend on the real managed
/// secret-store locator before that store is opened or initialized. A rejected
/// Notes/Scripts edge must not create a master key or keyset merely because the
/// same legacy document also contains a managed SSH key.
async fn preflight_legacy_document_structure(
    state: &DesktopState,
    document: &LegacyVaultDocument,
) -> Result<(), String> {
    if let Some(paths) = document.custom_groups() {
        SavedGroupCatalog::from_paths(paths.to_vec()).map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy custom-group catalog could not be assessed",
            )
        })?;
    }

    let hosts = document
        .candidates()
        .iter()
        .chain(document.managed_key_host_candidates())
        .chain(document.password_identity_host_candidates())
        .map(legacy_candidate_for_assessment)
        .collect::<Result<Vec<_>, _>>()?;
    let groups = document
        .group_config_candidates()
        .unwrap_or_default()
        .iter()
        .map(|candidate| candidate.config().clone())
        .collect::<Vec<_>>();
    let store = state.saved_hosts.clone();
    let current = tokio::task::spawn_blocking(move || store.graph())
        .await
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The current Vault graph could not be assessed",
            )
        })?
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The current Vault graph could not be assessed",
            )
        })?;
    plan_legacy_notes_snippets_import(
        document.notes_snippets_candidates(),
        current.notes_snippets(),
        &hosts,
        current.hosts(),
        &groups,
        current.groups(),
        &std::collections::BTreeMap::new(),
        document.source_sha256(),
    )
    .map_err(|_| {
        legacy_error(
            LEGACY_VAULT_ASSESSMENT_FAILED,
            "The legacy Notes/Scripts relationship graph could not be assessed",
        )
    })?;
    Ok(())
}

fn legacy_managed_candidate_ids(document: &LegacyVaultDocument) -> Vec<String> {
    document
        .managed_ssh_key_candidates()
        .iter()
        .map(|candidate| candidate.metadata().id().as_str().to_owned())
        .collect()
}

fn placeholder_managed_locator(
    source_sha256: &[u8; 32],
    entity_id: &str,
) -> Result<SavedSecretObjectLocator, String> {
    const DOMAIN: &[u8] = b"netcatty-legacy-managed-inspection-locator-v1\0";
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(source_sha256);
    digest.update((entity_id.len() as u64).to_be_bytes());
    digest.update(entity_id.as_bytes());
    SavedSecretObjectLocator::from_hex(format!("{:x}", digest.finalize())).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_ASSESSMENT_FAILED,
            "The managed SSH-key inventory could not be assessed",
        )
    })
}

async fn inspection_managed_locators(
    state: &DesktopState,
    entity_ids: Vec<String>,
    source_sha256: [u8; 32],
) -> Result<Vec<SavedSecretObjectLocator>, String> {
    if entity_ids.is_empty() {
        return Ok(Vec::new());
    }
    let store = state.saved_hosts.clone();
    let secret_files = state.secret_files.clone();
    tokio::task::spawn_blocking(move || {
        let retained = store
            .managed_secret_retention_set()
            .map_err(|_| legacy_import_repair_error())?;
        let guard = secret_files
            .lock_exclusive()
            .map_err(|_| legacy_secret_store_repair_error())?;
        match guard
            .owner_id()
            .map_err(|_| legacy_secret_store_repair_error())?
        {
            None if retained.is_empty() => entity_ids
                .iter()
                .map(|entity_id| placeholder_managed_locator(&source_sha256, entity_id))
                .collect(),
            None => Err(legacy_secret_store_repair_error()),
            Some(_) => {
                guard
                    .load_state()
                    .map_err(|_| legacy_secret_store_repair_error())?;
                entity_ids
                    .iter()
                    .map(|entity_id| {
                        let locator = guard
                            .derive_object_locator(entity_id)
                            .map_err(|_| legacy_secret_store_repair_error())?;
                        SavedSecretObjectLocator::from_hex(locator.backend_locator_hex())
                            .map_err(|_| legacy_secret_store_repair_error())
                    })
                    .collect()
            }
        }
    })
    .await
    .map_err(|_| legacy_secret_store_repair_error())?
}

fn rebind_managed_graph_locators(
    graph: SavedVaultGraph,
    locators: Vec<SavedSecretObjectLocator>,
) -> Result<SavedVaultGraph, String> {
    if graph.managed_ssh_keys().len() != locators.len() {
        return Err(legacy_secret_store_repair_error());
    }
    let (
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    let managed_keys = managed_keys
        .into_iter()
        .zip(locators)
        .map(|key| {
            let (key, locator) = key;
            let compatibility_fields = key.compatibility_fields().clone();
            let custody =
                SavedSshKeyCustodyReference::new(locator, key.custody().custody_revision())
                    .map_err(|_| legacy_secret_store_repair_error())?;
            SavedManagedSshKey::from_parts(
                key.id,
                key.label,
                key.category,
                key.source,
                key.has_saved_passphrase,
                key.created_at,
                key.updated_at,
                custody,
                compatibility_fields,
            )
            .map_err(|_| legacy_secret_store_repair_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

struct ManagedSecretPublication {
    entity_id: String,
    backend_locator: String,
    custody_revision: u64,
    bundle: SshSecretBundle,
}

struct ManagedSecretReference {
    entity_id: String,
    backend_locator: String,
    custody_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedSecretPublicationFailure {
    /// The immutable hard-link publication point was not reached for the
    /// failing object. Already-published earlier batch objects are safe
    /// unreferenced artifacts for later authenticated GC.
    BeforePublication,
    /// Publication may be visible but exact durability/authentication could
    /// not be confirmed. Callers must retain all recovery material.
    RepairRequired,
}

impl ManagedSecretPublicationFailure {
    fn legacy_error(self) -> String {
        match self {
            Self::BeforePublication => legacy_secret_store_error(),
            Self::RepairRequired => legacy_secret_store_repair_error(),
        }
    }
}

enum SecretStoreWorkerCommand {
    DeriveLocators {
        entity_ids: Vec<String>,
        reply: tokio::sync::oneshot::Sender<Result<Vec<SavedSecretObjectLocator>, String>>,
    },
    Publish {
        publications: Vec<ManagedSecretPublication>,
        reply: tokio::sync::oneshot::Sender<Result<u32, ManagedSecretPublicationFailure>>,
    },
    Confirm {
        references: Vec<ManagedSecretReference>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// A command handle whose blocking worker owns the non-Send secret-file guard.
/// Dropping the final sender releases that guard. The surrounding saved-host
/// coordinator is detached to completion, so invoke cancellation cannot
/// release it halfway through a journal/Vault transaction.
struct SecretStoreTransactionLease {
    sender: std::sync::mpsc::Sender<SecretStoreWorkerCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretStoreInitializationFailureDisposition {
    DeleteUnownedMasterKey,
    RetainForRetry,
    RetainForRepair,
}

fn secret_store_initialization_failure_disposition(
    expected_owner: uuid::Uuid,
    observed_owner: Result<Option<uuid::Uuid>, netcatty_secret_store::SecretFileStoreError>,
) -> SecretStoreInitializationFailureDisposition {
    match observed_owner {
        Ok(None) => SecretStoreInitializationFailureDisposition::DeleteUnownedMasterKey,
        Ok(Some(owner)) if owner == expected_owner => {
            SecretStoreInitializationFailureDisposition::RetainForRetry
        }
        Ok(Some(_)) | Err(_) => SecretStoreInitializationFailureDisposition::RetainForRepair,
    }
}

impl SecretStoreTransactionLease {
    async fn start(state: &DesktopState, allow_initialization: bool) -> Result<Self, String> {
        let secret_files = state.secret_files.clone();
        let master_keys = state.master_keys.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let guard = match secret_files.lock_exclusive() {
                Ok(guard) => guard,
                Err(_) => {
                    let _ = ready_sender.send(Err(legacy_secret_store_repair_error()));
                    return;
                }
            };
            let (store_state, master_key) =
                match load_or_initialize_secret_store(&guard, &master_keys, allow_initialization) {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                        return;
                    }
                };
            if ready_sender.send(Ok(())).is_err() {
                return;
            }
            while let Ok(command) = receiver.recv() {
                match command {
                    SecretStoreWorkerCommand::DeriveLocators { entity_ids, reply } => {
                        let result = entity_ids
                            .iter()
                            .map(|entity_id| {
                                let locator = guard
                                    .derive_object_locator(entity_id)
                                    .map_err(|_| legacy_secret_store_repair_error())?;
                                SavedSecretObjectLocator::from_hex(locator.backend_locator_hex())
                                    .map_err(|_| legacy_secret_store_repair_error())
                            })
                            .collect();
                        let _ = reply.send(result);
                    }
                    SecretStoreWorkerCommand::Publish {
                        publications,
                        reply,
                    } => {
                        let result = publish_managed_secret_objects(
                            &guard,
                            &store_state,
                            &master_key,
                            publications,
                        );
                        let _ = reply.send(result);
                    }
                    SecretStoreWorkerCommand::Confirm { references, reply } => {
                        let result =
                            confirm_managed_secret_references(&guard, &master_key, &references);
                        let _ = reply.send(result);
                    }
                }
            }
        });
        ready_receiver
            .await
            .map_err(|_| legacy_secret_store_repair_error())??;
        Ok(Self { sender })
    }

    async fn derive_locators(
        &self,
        entity_ids: Vec<String>,
    ) -> Result<Vec<SavedSecretObjectLocator>, String> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.sender
            .send(SecretStoreWorkerCommand::DeriveLocators { entity_ids, reply })
            .map_err(|_| legacy_secret_store_repair_error())?;
        receiver
            .await
            .map_err(|_| legacy_secret_store_repair_error())?
    }

    async fn publish(
        &self,
        publications: Vec<ManagedSecretPublication>,
    ) -> Result<u32, ManagedSecretPublicationFailure> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.sender
            .send(SecretStoreWorkerCommand::Publish {
                publications,
                reply,
            })
            .map_err(|_| ManagedSecretPublicationFailure::RepairRequired)?;
        receiver
            .await
            .map_err(|_| ManagedSecretPublicationFailure::RepairRequired)?
    }

    async fn confirm(&self, references: Vec<ManagedSecretReference>) -> Result<(), String> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.sender
            .send(SecretStoreWorkerCommand::Confirm { references, reply })
            .map_err(|_| legacy_secret_store_repair_error())?;
        receiver
            .await
            .map_err(|_| legacy_secret_store_repair_error())?
    }
}

fn load_or_initialize_secret_store(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    master_keys: &OsMasterKeyStore,
    allow_initialization: bool,
) -> Result<(SecretFileStoreState, MasterKey), String> {
    const INITIAL_MASTER_KEY_EPOCH: u32 = 1;
    let owner = guard
        .owner_id()
        .map_err(|_| legacy_secret_store_repair_error())?;
    if let Some(owner) = owner {
        return match guard.load_state() {
            Ok(store_state) => confirm_loaded_secret_store(guard, master_keys, owner, store_state),
            Err(error) if error.code() == SecretFileStoreErrorCode::NotInitialized => {
                if !allow_initialization {
                    return Err(legacy_secret_store_repair_error());
                }
                // Only an owner-only first-initialization crash can resume
                // here. Never create a replacement key for an existing owner.
                let master_key = master_keys
                    .load_blocking(owner, INITIAL_MASTER_KEY_EPOCH)
                    .map_err(|_| legacy_secret_store_repair_error())?;
                let mutation = guard
                    .initialize(owner, INITIAL_MASTER_KEY_EPOCH)
                    .map_err(|_| legacy_secret_store_repair_error())?;
                let store_state = confirm_secret_store_initialization(guard, mutation)?;
                Ok((store_state, master_key))
            }
            Err(_) => Err(legacy_secret_store_repair_error()),
        };
    }

    if !allow_initialization {
        return Err(legacy_secret_store_repair_error());
    }

    let owner = uuid::Uuid::new_v4();
    let master_key = master_keys
        .create_if_absent_blocking(owner, INITIAL_MASTER_KEY_EPOCH)
        .map_err(|_| legacy_secret_store_error())?;
    let mutation = match guard.initialize(owner, INITIAL_MASTER_KEY_EPOCH) {
        Ok(mutation) => mutation,
        Err(_) => {
            // Owner publication precedes keyset publication, so a later I/O
            // error can leave a recoverable owner-only store. Delete the new
            // OS-held key only when the still-held file lock proves that no
            // owner was published. Any visible or uncertain owner state must
            // retain the key for the next idempotent initialization attempt.
            return match secret_store_initialization_failure_disposition(owner, guard.owner_id()) {
                SecretStoreInitializationFailureDisposition::DeleteUnownedMasterKey => {
                    match master_keys.delete_blocking(owner, INITIAL_MASTER_KEY_EPOCH) {
                        Ok(()) => Err(legacy_secret_store_error()),
                        Err(_) => Err(legacy_secret_store_repair_error()),
                    }
                }
                SecretStoreInitializationFailureDisposition::RetainForRetry => {
                    Err(legacy_secret_store_error())
                }
                SecretStoreInitializationFailureDisposition::RetainForRepair => {
                    Err(legacy_secret_store_repair_error())
                }
            };
        }
    };
    let store_state = confirm_secret_store_initialization(guard, mutation)?;
    Ok((store_state, master_key))
}

fn confirm_loaded_secret_store(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    master_keys: &OsMasterKeyStore,
    owner: uuid::Uuid,
    store_state: SecretFileStoreState,
) -> Result<(SecretFileStoreState, MasterKey), String> {
    if owner != store_state.store_id() {
        return Err(legacy_secret_store_repair_error());
    }
    let master_key = master_keys
        .load_blocking(owner, store_state.active_master_key_epoch())
        .map_err(|_| legacy_secret_store_repair_error())?;
    let store_state = match guard.confirm_keyset_durability(&store_state) {
        Ok(confirmed) => confirmed,
        Err(error) if error.code() == SecretFileStoreErrorCode::DurabilityUnconfirmed => {
            // A crash may leave exactly one immutable keyset copy. Re-publish
            // only the missing same-epoch copy while the secret-store lock is
            // still held. Corrupt, ambiguous, or higher-generation artifacts
            // are rejected by the crate and remain repair-required.
            let mutation = guard
                .activate_master_key_epoch(&store_state, store_state.active_master_key_epoch())
                .map_err(|_| legacy_secret_store_repair_error())?;
            confirm_secret_store_initialization(guard, mutation)?
        }
        Err(_) => return Err(legacy_secret_store_repair_error()),
    };
    Ok((store_state, master_key))
}

fn confirm_secret_store_initialization(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    mutation: SecretFileMutation<SecretFileStoreState>,
) -> Result<SecretFileStoreState, String> {
    match mutation {
        SecretFileMutation::Durable(state) => Ok(state),
        SecretFileMutation::PublishedDurabilityUncertain
        | SecretFileMutation::PublicationIndeterminate => {
            let state = guard
                .load_state()
                .map_err(|_| legacy_secret_store_repair_error())?;
            guard
                .confirm_keyset_durability(&state)
                .map_err(|_| legacy_secret_store_repair_error())
        }
    }
}

fn publish_managed_secret_objects(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    store_state: &SecretFileStoreState,
    master_key: &MasterKey,
    publications: Vec<ManagedSecretPublication>,
) -> Result<u32, ManagedSecretPublicationFailure> {
    let mut published = 0_u32;
    for publication in publications {
        let locator = guard
            .restore_object_locator(&publication.entity_id, &publication.backend_locator)
            .map_err(|_| ManagedSecretPublicationFailure::RepairRequired)?;
        let prepared = guard
            .prepare_object(
                store_state,
                master_key,
                &locator,
                publication.custody_revision,
                publication.bundle,
            )
            .map_err(|_| ManagedSecretPublicationFailure::BeforePublication)?;
        match guard
            .publish_object(master_key, &prepared)
            .map_err(|_| ManagedSecretPublicationFailure::BeforePublication)?
        {
            SecretFileMutation::Durable(()) => {}
            SecretFileMutation::PublishedDurabilityUncertain
            | SecretFileMutation::PublicationIndeterminate => guard
                .confirm_object_durability(master_key, &locator, publication.custody_revision)
                .map_err(|_| ManagedSecretPublicationFailure::RepairRequired)?,
        }
        published = published.saturating_add(1);
    }
    Ok(published)
}

fn confirm_managed_secret_references(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    master_key: &MasterKey,
    references: &[ManagedSecretReference],
) -> Result<(), String> {
    for reference in references {
        let locator = guard
            .restore_object_locator(&reference.entity_id, &reference.backend_locator)
            .map_err(|_| legacy_secret_store_repair_error())?;
        guard
            .confirm_object_durability(master_key, &locator, reference.custody_revision)
            .map_err(|_| legacy_secret_store_repair_error())?;
    }
    Ok(())
}

fn managed_secret_references_from_graph(graph: &SavedVaultGraph) -> Vec<ManagedSecretReference> {
    graph
        .managed_ssh_keys()
        .iter()
        .map(|key| ManagedSecretReference {
            entity_id: key.id.as_str().to_owned(),
            backend_locator: key.custody().backend_locator().as_str().to_owned(),
            custody_revision: key.custody().custody_revision(),
        })
        .collect()
}

async fn confirm_managed_graph_blobs(
    state: &DesktopState,
    graph: SavedVaultGraph,
) -> Result<(), String> {
    let references = managed_secret_references_from_graph(&graph);
    if references.is_empty() {
        return Err(legacy_secret_store_repair_error());
    }
    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    tokio::task::spawn_blocking(move || {
        let guard = secret_files
            .lock_exclusive()
            .map_err(|_| legacy_secret_store_repair_error())?;
        let owner = guard
            .owner_id()
            .map_err(|_| legacy_secret_store_repair_error())?
            .ok_or_else(legacy_secret_store_repair_error)?;
        let store_state = guard
            .load_state()
            .map_err(|_| legacy_secret_store_repair_error())?;
        let (_, master_key) =
            confirm_loaded_secret_store(&guard, &master_keys, owner, store_state)?;
        confirm_managed_secret_references(&guard, &master_key, &references)
    })
    .await
    .map_err(|_| legacy_secret_store_repair_error())?
}

/// Runs only while the caller holds the outer saved-host process and file
/// locks. The Vault retention scan and secret-store cleanup therefore observe
/// one serialized cross-store state. Failures retain encrypted artifacts.
async fn garbage_collect_managed_secret_blobs(
    state: &DesktopState,
) -> Result<ManagedSecretGarbageCollectionResult, String> {
    let saved_hosts = state.saved_hosts.clone();
    let retained = tokio::task::spawn_blocking(move || saved_hosts.managed_secret_retention_set())
        .await
        .map_err(|_| legacy_secret_store_repair_error())?
        .map_err(|_| legacy_secret_store_repair_error())?;

    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    tokio::task::spawn_blocking(move || {
        let guard = secret_files
            .lock_exclusive()
            .map_err(|_| legacy_secret_store_repair_error())?;
        let Some(owner) = guard
            .owner_id()
            .map_err(|_| legacy_secret_store_repair_error())?
        else {
            return if retained.is_empty() {
                Ok(ManagedSecretGarbageCollectionResult {
                    removed_blob_revisions: 0,
                    removed_objects: 0,
                })
            } else {
                Err(legacy_secret_store_repair_error())
            };
        };
        let store_state = guard
            .load_state()
            .map_err(|_| legacy_secret_store_repair_error())?;
        let (store_state, master_key) =
            confirm_loaded_secret_store(&guard, &master_keys, owner, store_state)?;
        let retained = retained
            .into_iter()
            .map(|item| {
                SecretObjectRetention::new(
                    item.entity_id().as_str(),
                    item.backend_locator().as_str(),
                    item.custody_revision(),
                )
                .map_err(|_| legacy_secret_store_repair_error())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let report = guard
            .garbage_collect_objects(&store_state, &master_key, &retained)
            .map_err(|_| legacy_secret_store_repair_error())?;
        let removed_blob_revisions = u32::try_from(report.removed_blob_revisions())
            .map_err(|_| legacy_secret_store_repair_error())?;
        let removed_objects = u32::try_from(report.removed_objects())
            .map_err(|_| legacy_secret_store_repair_error())?;
        Ok(ManagedSecretGarbageCollectionResult {
            removed_blob_revisions,
            removed_objects,
        })
    })
    .await
    .map_err(|_| legacy_secret_store_repair_error())?
}

fn master_key_rotation_repair_error() -> String {
    managed_key_error(
        MANAGED_KEY_REPAIR_REQUIRED,
        "Managed SSH key master-key rotation requires recovery",
    )
}

fn load_master_key_rotation_retention(
    saved_hosts: &SavedHostStore,
) -> Result<Vec<SecretObjectRetention>, String> {
    saved_hosts
        .managed_secret_retention_set()
        .map_err(|_| master_key_rotation_repair_error())?
        .into_iter()
        .map(|item| {
            SecretObjectRetention::new(
                item.entity_id().as_str(),
                item.backend_locator().as_str(),
                item.custody_revision(),
            )
            .map_err(|_| master_key_rotation_repair_error())
        })
        .collect()
}

fn completed_rotation_outcome(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    master_keys: &OsMasterKeyStore,
    owner: uuid::Uuid,
    target_key: &MasterKey,
    completion: netcatty_secret_store::CompletedMasterKeyRotation,
    recovered_work: bool,
) -> Result<ManagedMasterKeyRotationRecoveryOutcome, String> {
    if !completion.old_master_key_deletion_authorized()
        || completion.state().store_id() != owner
        || completion.state().active_master_key_epoch() != completion.target_epoch()
    {
        return Err(master_key_rotation_repair_error());
    }
    let retained_secret_revision_count = u32::try_from(completion.retained_objects())
        .map_err(|_| master_key_rotation_repair_error())?;

    // Re-read the active target key immediately before retiring the source.
    // A keyring record that disappeared or changed after file-store
    // confirmation must never authorize deletion of the only usable key.
    let persisted_target = master_keys
        .load_blocking(owner, completion.target_epoch())
        .map_err(|_| master_key_rotation_repair_error())?;
    if !bool::from(persisted_target.as_bytes().ct_eq(target_key.as_bytes())) {
        return Err(master_key_rotation_repair_error());
    }
    drop(persisted_target);

    // Delete is deliberately followed by an authoritative read. Keyring
    // backends may report an error after applying the side effect, while an
    // apparent successful delete could still be ambiguous across processes.
    let _delete_result = master_keys.delete_blocking(owner, completion.source_epoch());
    let source_absent = match master_keys.load_blocking(owner, completion.source_epoch()) {
        Err(error) if error.code() == CredentialErrorCode::NotFound => true,
        Ok(source_key) => {
            drop(source_key);
            false
        }
        Err(_) => false,
    };
    if !source_absent {
        return Ok(ManagedMasterKeyRotationRecoveryOutcome {
            retained_secret_revision_count,
            cleanup_pending: true,
            recovered_work,
        });
    }

    // The durable marker is the file-store's proof that the source OS key is
    // gone. Only then may future operations stop scanning this lineage and a
    // later explicit rotation advance to another epoch.
    let cleanup_pending = match guard.acknowledge_source_key_retired(&completion) {
        Ok(SecretFileMutation::Durable(())) => false,
        Ok(
            SecretFileMutation::PublishedDurabilityUncertain
            | SecretFileMutation::PublicationIndeterminate,
        ) => true,
        Err(_) => return Err(master_key_rotation_repair_error()),
    };
    Ok(ManagedMasterKeyRotationRecoveryOutcome {
        retained_secret_revision_count,
        cleanup_pending,
        recovered_work,
    })
}

fn recover_master_key_rotation_locked(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    master_keys: &OsMasterKeyStore,
    saved_hosts: &SavedHostStore,
    owner: uuid::Uuid,
    recovery: MasterKeyRotationRecovery,
) -> Result<ManagedMasterKeyRotationRecoveryOutcome, String> {
    let retained = load_master_key_rotation_retention(saved_hosts)?;
    let target_key = master_keys
        .load_blocking(owner, recovery.target_epoch())
        .map_err(|_| master_key_rotation_repair_error())?;

    if recovery.completed() {
        let completion = guard
            .confirm_completed_master_key_rotation(&recovery, &target_key, &retained)
            .map_err(|_| master_key_rotation_repair_error())?;
        return completed_rotation_outcome(
            guard,
            master_keys,
            owner,
            &target_key,
            completion,
            true,
        );
    }

    // Once a target epoch has any durable file-store artifact, its OS key must
    // already exist. Recovery therefore loads it and never generates a silent
    // replacement for missing or corrupt custody state.
    let source_key = master_keys
        .load_blocking(owner, recovery.source_epoch())
        .map_err(|_| master_key_rotation_repair_error())?;
    let completion = match guard
        .rotate_master_key_epoch(
            &recovery.source_state(),
            &source_key,
            recovery.target_epoch(),
            &target_key,
            &retained,
        )
        .map_err(|_| master_key_rotation_repair_error())?
    {
        SecretFileMutation::Durable(completion) => completion,
        SecretFileMutation::PublishedDurabilityUncertain
        | SecretFileMutation::PublicationIndeterminate => {
            return Err(master_key_rotation_repair_error());
        }
    };
    completed_rotation_outcome(guard, master_keys, owner, &target_key, completion, true)
}

/// Inspects and resumes rotation before legacy-journal recovery or ordinary
/// Vault work. It runs only while the outer process/file locks are held.
async fn recover_managed_master_key_rotation(
    state: &DesktopState,
) -> Result<Option<ManagedMasterKeyRotationRecoveryOutcome>, String> {
    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    let saved_hosts = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || {
        let guard = secret_files
            .lock_exclusive()
            .map_err(|_| master_key_rotation_repair_error())?;
        let owner = guard
            .owner_id()
            .map_err(|_| master_key_rotation_repair_error())?;
        let Some(owner) = owner else {
            return if load_master_key_rotation_retention(&saved_hosts)?.is_empty() {
                Ok(None)
            } else {
                Err(master_key_rotation_repair_error())
            };
        };
        match guard.load_state() {
            Ok(_) => {}
            Err(error) if error.code() == SecretFileStoreErrorCode::NotInitialized => {
                // Preserve the existing owner-only first-initialization
                // recovery path; it has no keyset and therefore cannot
                // contain a rotation.
                return if load_master_key_rotation_retention(&saved_hosts)?.is_empty() {
                    Ok(None)
                } else {
                    Err(master_key_rotation_repair_error())
                };
            }
            Err(_) => return Err(master_key_rotation_repair_error()),
        }
        let Some(recovery) = guard
            .inspect_master_key_rotation()
            .map_err(|_| master_key_rotation_repair_error())?
        else {
            return Ok(None);
        };
        recover_master_key_rotation_locked(&guard, &master_keys, &saved_hosts, owner, recovery)
            .map(Some)
    })
    .await
    .map_err(|_| master_key_rotation_repair_error())?
}

async fn begin_managed_master_key_rotation(
    state: &DesktopState,
) -> Result<ManagedSshMasterKeyRotationResult, String> {
    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    let saved_hosts = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || {
        let guard = secret_files
            .lock_exclusive()
            .map_err(|_| master_key_rotation_repair_error())?;
        let owner = guard
            .owner_id()
            .map_err(|_| master_key_rotation_repair_error())?;
        let retained = load_master_key_rotation_retention(&saved_hosts)?;
        let Some(owner) = owner else {
            return if retained.is_empty() {
                Ok(ManagedSshMasterKeyRotationResult {
                    status: ManagedSshMasterKeyRotationStatus::NotInitialized,
                    retained_secret_revision_count: 0,
                })
            } else {
                Err(master_key_rotation_repair_error())
            };
        };

        let (source_state, source_key) = match guard.load_state() {
            Ok(state) => confirm_loaded_secret_store(&guard, &master_keys, owner, state)
                .map_err(|_| master_key_rotation_repair_error())?,
            Err(error) if error.code() == SecretFileStoreErrorCode::NotInitialized => {
                if !retained.is_empty() {
                    return Err(master_key_rotation_repair_error());
                }
                // An owner-only root is an interrupted first initialization,
                // not an empty store. Resume only with the already persisted
                // epoch-one key; the helper never regenerates it for an
                // existing owner.
                load_or_initialize_secret_store(&guard, &master_keys, true)
                    .map_err(|_| master_key_rotation_repair_error())?
            }
            Err(_) => return Err(master_key_rotation_repair_error()),
        };
        if guard
            .inspect_master_key_rotation()
            .map_err(|_| master_key_rotation_repair_error())?
            .is_some()
        {
            return Err(master_key_rotation_repair_error());
        }
        let target_epoch = source_state
            .active_master_key_epoch()
            .checked_add(1)
            .ok_or_else(master_key_rotation_repair_error)?;

        // Inspection above proves there is no pending target artifact. Only
        // in that state may a missing target key be created. An orphan key
        // from a crash before the first file publication is reused exactly.
        let target_key = master_keys
            .create_if_absent_blocking(owner, target_epoch)
            .map_err(|_| master_key_rotation_repair_error())?;
        let completion = match guard
            .rotate_master_key_epoch(
                &source_state,
                &source_key,
                target_epoch,
                &target_key,
                &retained,
            )
            .map_err(|_| master_key_rotation_repair_error())?
        {
            SecretFileMutation::Durable(completion) => completion,
            SecretFileMutation::PublishedDurabilityUncertain
            | SecretFileMutation::PublicationIndeterminate => {
                return Err(master_key_rotation_repair_error());
            }
        };
        completed_rotation_outcome(&guard, &master_keys, owner, &target_key, completion, true)
            .map(ManagedMasterKeyRotationRecoveryOutcome::renderer_result)
    })
    .await
    .map_err(|_| master_key_rotation_repair_error())?
}

/// Keeps the Vault's public key category and the authenticated secret bundle
/// symmetric. A certificate must be present exactly for certificate records;
/// otherwise metadata tampering could silently downgrade authentication.
fn checked_managed_certificate<'a>(
    category: &str,
    certificate: Option<&'a [u8]>,
) -> Result<Option<&'a [u8]>, ()> {
    match (category.eq_ignore_ascii_case("certificate"), certificate) {
        (true, Some(certificate)) => Ok(Some(certificate)),
        (false, None) => Ok(None),
        (true, None) | (false, Some(_)) => Err(()),
    }
}

async fn resolve_saved_managed_key_credentials(
    state: &DesktopState,
    key: SavedManagedSshKey,
    supplied_passphrase: Option<SecretValue>,
) -> Result<ConnectionCredentials, String> {
    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    tokio::task::spawn_blocking(move || {
        let unavailable = || {
            format!("{SAVED_HOST_MANAGED_KEY_UNAVAILABLE}: The saved private key is unavailable")
        };
        let guard = secret_files.lock_exclusive().map_err(|_| unavailable())?;
        let owner = guard
            .owner_id()
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let store_state = guard.load_state().map_err(|_| unavailable())?;
        if owner != store_state.store_id() {
            return Err(unavailable());
        }
        let master_key = master_keys
            .load_blocking(owner, store_state.active_master_key_epoch())
            .map_err(|_| unavailable())?;
        let locator = guard
            .restore_object_locator(key.id.as_str(), key.custody().backend_locator().as_str())
            .map_err(|_| unavailable())?;
        let bundle = guard
            .resolve_object(&master_key, &locator, key.custody().custody_revision())
            .map_err(|_| unavailable())?;
        // Wrap the private key immediately after UTF-8 validation. Any later
        // passphrase/certificate failure then drops a zeroizing SecretText,
        // rather than releasing an ordinary String containing key material.
        let private_key = SecretText::new(
            std::str::from_utf8(bundle.private_key())
                .map_err(|_| unavailable())?
                .to_owned(),
        );
        let passphrase = match supplied_passphrase {
            Some(value) => Some(SecretText::new(
                value.as_utf8().map_err(|_| unavailable())?.to_owned(),
            )),
            None => bundle
                .passphrase()
                .map(|value| {
                    std::str::from_utf8(value).map(|value| SecretText::new(value.to_owned()))
                })
                .transpose()
                .map_err(|_| unavailable())?,
        };
        let certificate = checked_managed_certificate(key.category.as_str(), bundle.certificate())
            .map_err(|()| unavailable())?;
        let mut credentials =
            ConnectionCredentials::empty().with_private_key(private_key, passphrase);
        if let Some(certificate) = certificate {
            let certificate = std::str::from_utf8(certificate)
                .map(str::to_owned)
                .map_err(|_| unavailable())?;
            credentials = credentials.with_certificate(certificate);
        }
        Ok(credentials)
    })
    .await
    .map_err(|_| {
        format!("{SAVED_HOST_MANAGED_KEY_UNAVAILABLE}: The saved private key is unavailable")
    })?
}

#[cfg(test)]
async fn assess_legacy_hosts(
    store: SavedHostStore,
    hosts: Vec<SavedHost>,
) -> Result<SavedHostImportAssessment, String> {
    tokio::task::spawn_blocking(move || store.assess_import(&hosts))
        .await
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The saved-host inventory could not be inspected",
            )
        })?
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy import candidates could not be assessed",
            )
        })
}

async fn assess_legacy_graph(
    store: SavedHostStore,
    graph: SavedVaultGraph,
) -> Result<SavedVaultGraphImportAssessment, String> {
    tokio::task::spawn_blocking(move || store.assess_graph_import(&graph))
        .await
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The Vault relationship inventory could not be inspected",
            )
        })?
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy relationship graph could not be assessed",
            )
        })
}

fn import_disposition_counts(dispositions: &[SavedHostImportDisposition]) -> (u32, u32, u32) {
    let mut importable = 0_u32;
    let mut duplicate = 0_u32;
    let mut conflict = 0_u32;
    for disposition in dispositions {
        match disposition {
            SavedHostImportDisposition::Importable => importable = importable.saturating_add(1),
            SavedHostImportDisposition::Duplicate => duplicate = duplicate.saturating_add(1),
            SavedHostImportDisposition::Conflict => conflict = conflict.saturating_add(1),
        }
    }
    (importable, duplicate, conflict)
}

fn graph_disposition_counts(dispositions: &[SavedVaultImportDisposition]) -> (u32, u32, u32) {
    import_disposition_counts(dispositions)
}

fn notes_snippets_disposition_counts(
    dispositions: &[LegacyNotesSnippetsDisposition],
) -> (u32, u32, u32) {
    dispositions.iter().fold(
        (0_u32, 0_u32, 0_u32),
        |counts, disposition| match disposition {
            LegacyNotesSnippetsDisposition::Importable
            | LegacyNotesSnippetsDisposition::RemappedImportable => {
                (counts.0.saturating_add(1), counts.1, counts.2)
            }
            LegacyNotesSnippetsDisposition::Duplicate
            | LegacyNotesSnippetsDisposition::RemappedDuplicate => {
                (counts.0, counts.1.saturating_add(1), counts.2)
            }
        },
    )
}

struct AssessedLegacyGraph {
    graph: SavedVaultGraph,
    assessment: SavedVaultGraphImportAssessment,
    remapped_entity_count: u32,
}

enum ManagedLocatorResolver<'a> {
    Inspection {
        state: &'a DesktopState,
        source_sha256: [u8; 32],
    },
    Transaction(&'a SecretStoreTransactionLease),
}

impl ManagedLocatorResolver<'_> {
    async fn resolve(
        &self,
        entity_ids: Vec<String>,
    ) -> Result<Vec<SavedSecretObjectLocator>, String> {
        match self {
            Self::Inspection {
                state,
                source_sha256,
            } => inspection_managed_locators(state, entity_ids, *source_sha256).await,
            Self::Transaction(lease) => lease.derive_locators(entity_ids).await,
        }
    }
}

fn graph_conflict_count(assessment: &SavedVaultGraphImportAssessment) -> usize {
    assessment
        .host_dispositions()
        .iter()
        .chain(assessment.ssh_key_reference_dispositions())
        .chain(assessment.managed_ssh_key_dispositions())
        .chain(assessment.identity_reference_dispositions())
        .chain(assessment.password_identity_dispositions())
        .chain(assessment.proxy_profile_dispositions())
        .chain(assessment.group_dispositions())
        .filter(|disposition| **disposition == SavedVaultImportDisposition::Conflict)
        .count()
}

fn graph_catalog_conflict_count(assessment: &SavedVaultGraphImportAssessment) -> usize {
    assessment
        .ssh_key_reference_dispositions()
        .iter()
        .chain(assessment.managed_ssh_key_dispositions())
        .chain(assessment.identity_reference_dispositions())
        .chain(assessment.password_identity_dispositions())
        .chain(assessment.proxy_profile_dispositions())
        .chain(assessment.group_dispositions())
        .filter(|disposition| **disposition == SavedVaultImportDisposition::Conflict)
        .count()
}

fn graph_id_change_count(before: &SavedVaultGraph, after: &SavedVaultGraph) -> u32 {
    before
        .hosts()
        .iter()
        .map(|host| host.id.as_str())
        .zip(after.hosts().iter().map(|host| host.id.as_str()))
        .chain(
            before
                .ssh_key_references()
                .iter()
                .map(|key| key.id.as_str())
                .zip(after.ssh_key_references().iter().map(|key| key.id.as_str())),
        )
        .chain(
            before
                .managed_ssh_keys()
                .iter()
                .map(|key| key.id.as_str())
                .zip(after.managed_ssh_keys().iter().map(|key| key.id.as_str())),
        )
        .chain(
            before
                .identity_references()
                .iter()
                .map(|identity| identity.id.as_str())
                .zip(
                    after
                        .identity_references()
                        .iter()
                        .map(|identity| identity.id.as_str()),
                ),
        )
        .chain(
            before
                .password_identities()
                .iter()
                .map(|identity| identity.id.as_str())
                .zip(
                    after
                        .password_identities()
                        .iter()
                        .map(|identity| identity.id.as_str()),
                ),
        )
        .chain(
            before
                .proxy_profiles()
                .iter()
                .map(|profile| profile.id.as_str())
                .zip(
                    after
                        .proxy_profiles()
                        .iter()
                        .map(|profile| profile.id.as_str()),
                ),
        )
        .chain(
            before
                .groups()
                .iter()
                .map(|group| group.id.as_str())
                .zip(after.groups().iter().map(|group| group.id.as_str())),
        )
        .filter(|(before, after)| before != after)
        .count() as u32
}

async fn assess_and_remap_legacy_graph(
    store: SavedHostStore,
    mut graph: SavedVaultGraph,
    source_sha256: &[u8; 32],
    remap_conflicts: bool,
    locator_resolver: &ManagedLocatorResolver<'_>,
) -> Result<AssessedLegacyGraph, String> {
    const MAX_REMAP_ROUNDS: usize = 8;
    let mut remapped_entity_count = 0_u32;
    for _ in 0..MAX_REMAP_ROUNDS {
        let assessment = assess_legacy_graph(store.clone(), graph.clone()).await?;
        let conflicts = graph_conflict_count(&assessment);
        if conflicts == 0 || !remap_conflicts {
            return Ok(AssessedLegacyGraph {
                graph,
                assessment,
                remapped_entity_count,
            });
        }
        let defer_host_ids = graph_catalog_conflict_count(&assessment) > 0;
        let before_remap = graph.clone();
        let next = if defer_host_ids {
            // Dependency IDs are rewritten first. A host that differs only by
            // that still-unrewritten edge can otherwise be spuriously remapped
            // on a repeated import. Genuine host conflicts remain visible and
            // are handled on the next assessment round.
            legacy_graph::remap_conflicting_graph_without_host_ids(
                graph,
                &assessment,
                source_sha256,
            )
        } else {
            legacy_graph::remap_conflicting_graph(graph, &assessment, source_sha256)
        }
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy relationship graph could not be remapped",
            )
        })?
        .ok_or_else(|| {
            legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy relationship graph remap made no progress",
            )
        })?;
        let changed_entity_count = graph_id_change_count(&before_remap, &next);
        if changed_entity_count == 0 {
            return Err(legacy_error(
                LEGACY_VAULT_ASSESSMENT_FAILED,
                "The legacy relationship graph remap made no progress",
            ));
        }
        graph = if next.managed_ssh_keys().is_empty() {
            next
        } else {
            let entity_ids = next
                .managed_ssh_keys()
                .iter()
                .map(|key| key.id.as_str().to_owned())
                .collect();
            let locators = locator_resolver.resolve(entity_ids).await?;
            rebind_managed_graph_locators(next, locators)?
        };
        remapped_entity_count = remapped_entity_count.saturating_add(changed_entity_count);
    }
    Err(legacy_error(
        LEGACY_VAULT_ASSESSMENT_FAILED,
        "The legacy relationship graph could not be made conflict-free",
    ))
}

#[tauri::command]
async fn inspect_legacy_vault(
    state: State<'_, DesktopState>,
    request: InspectLegacyVaultRequest,
) -> Result<LegacyVaultInspection, String> {
    let document = load_legacy_vault_document(request.path).await?;
    inspect_legacy_vault_document(state.inner().clone(), document).await
}

async fn inspect_legacy_vault_document(
    state: DesktopState,
    document: LegacyVaultDocument,
) -> Result<LegacyVaultInspection, String> {
    let source_fingerprint = legacy_source_fingerprint_token(document.source_sha256());
    let source_sha256 = *document.source_sha256();
    run_saved_host_operation(state, move |state| async move {
        let managed_ids = legacy_managed_candidate_ids(&document);
        let managed_locators =
            inspection_managed_locators(&state, managed_ids, source_sha256).await?;
        let parts = into_assessable_legacy_graph(document, managed_locators)?;
        let AssessableLegacyGraph {
            mut preview,
            host_candidates,
            password_identity_candidates,
            proxy_profile_candidates,
            group_config_candidates,
            notes_snippets_candidates,
            graph,
            managed_secret_bundles,
            source_catalog_counts,
            relationship_mode,
        } = parts;
        // Inspection never needs or stores the secret bundles. Drop them
        // before any renderer-safe result is assembled.
        drop(managed_secret_bundles);
        let source_host_duplicates = preview.duplicate_count;
        let credentials = host_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.has_ssh_password_candidate()
                        && candidate.credential_disposition()
                            == LegacyCredentialDisposition::PlaintextCandidate,
                    candidate.has_telnet_password_candidate()
                        && candidate.telnet_credential_disposition()
                            == LegacyCredentialDisposition::PlaintextCandidate,
                    candidate.requires_credential_reentry(),
                    disposition_requires_credential_reentry(
                        candidate.telnet_credential_disposition(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let inline_proxy_credentials = host_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.has_inline_proxy_password_candidate()
                        && candidate.inline_proxy_credential_disposition()
                            == LegacyProxyCredentialDisposition::PlaintextCandidate,
                    candidate
                        .inline_proxy_credential_disposition()
                        .requires_reentry(),
                )
            })
            .collect::<Vec<_>>();
        drop(host_candidates);
        let password_identity_credentials = password_identity_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.has_password_candidate()
                        && candidate.credential_disposition()
                            == LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate,
                    candidate.credential_disposition().requires_reentry(),
                )
            })
            .collect::<Vec<_>>();
        drop(password_identity_candidates);
        let proxy_profile_credentials = proxy_profile_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.has_password_candidate()
                        && candidate.credential_disposition()
                            == LegacyProxyCredentialDisposition::PlaintextCandidate,
                    candidate.credential_disposition().requires_reentry(),
                )
            })
            .collect::<Vec<_>>();
        drop(proxy_profile_candidates);
        let (graph, notes_snippets_assessment, custom_group_scope_change_count) =
            attach_legacy_notes_snippets_plan(
                &state,
                graph,
                &notes_snippets_candidates,
                &source_sha256,
            )
            .await?;
        drop(notes_snippets_candidates);
        // Group candidates remain Rust-only. Inspection uses their final graph
        // dispositions below; no group password is ever materialized here.
        drop(group_config_candidates);
        let locator_resolver = ManagedLocatorResolver::Inspection {
            state: &state,
            source_sha256,
        };
        let finalized = assess_and_remap_legacy_graph(
            state.saved_hosts.clone(),
            graph,
            &source_sha256,
            relationship_mode
                || notes_snippets_assessment.snippets_present
                || notes_snippets_assessment.snippet_packages_present
                || notes_snippets_assessment.notes_present
                || notes_snippets_assessment.note_groups_present,
            &locator_resolver,
        )
        .await?;
        let AssessedLegacyGraph {
            assessment,
            remapped_entity_count,
            ..
        } = finalized;
        let (importable_hosts, duplicate_hosts, conflict_hosts) =
            graph_disposition_counts(assessment.host_dispositions());
        let (importable_keys, duplicate_keys, conflict_keys) =
            graph_disposition_counts(assessment.ssh_key_reference_dispositions());
        let (importable_managed_keys, duplicate_managed_keys, conflict_managed_keys) =
            graph_disposition_counts(assessment.managed_ssh_key_dispositions());
        let (importable_identities, duplicate_identities, conflict_identities) =
            graph_disposition_counts(assessment.identity_reference_dispositions());
        let (
            importable_password_identities,
            duplicate_password_identities,
            conflict_password_identities,
        ) = graph_disposition_counts(assessment.password_identity_dispositions());
        let (importable_proxy_profiles, duplicate_proxy_profiles, conflict_proxy_profiles) =
            graph_disposition_counts(assessment.proxy_profile_dispositions());
        let (importable_custom_groups, duplicate_custom_groups, conflict_custom_groups) =
            graph_disposition_counts(assessment.custom_group_dispositions());
        let (importable_group_configs, duplicate_group_configs, conflict_group_configs) =
            graph_disposition_counts(assessment.group_dispositions());
        let (importable_snippets, duplicate_snippets, conflict_snippets) =
            notes_snippets_disposition_counts(&notes_snippets_assessment.snippet_dispositions);
        let (importable_notes, duplicate_notes, conflict_notes) =
            notes_snippets_disposition_counts(&notes_snippets_assessment.note_dispositions);
        preview.importable_count = importable_hosts;
        preview.duplicate_count = source_host_duplicates.saturating_add(duplicate_hosts);
        preview.conflict_count = conflict_hosts;
        preview.recoverable_credential_count = assessment
            .host_dispositions()
            .iter()
            .zip(&credentials)
            .filter(|(disposition, credential)| {
                **disposition == SavedVaultImportDisposition::Importable
                    && (credential.0 || credential.1)
            })
            .count() as u32;
        preview.requires_credential_reentry_count = assessment
            .host_dispositions()
            .iter()
            .zip(&credentials)
            .filter(|(disposition, credential)| {
                **disposition == SavedVaultImportDisposition::Importable && credential.2
            })
            .count() as u32;
        Ok(LegacyVaultInspection {
            preview,
            source_fingerprint,
            inventory_revision: assessment.revision().clone(),
            source_ssh_key_count: source_catalog_counts.source_ssh_keys,
            importable_ssh_key_reference_count: importable_keys,
            duplicate_ssh_key_reference_count: source_catalog_counts
                .duplicate_ssh_keys
                .saturating_add(duplicate_keys),
            conflict_ssh_key_reference_count: conflict_keys,
            unsupported_ssh_key_count: source_catalog_counts
                .unsupported_ssh_keys
                .saturating_add(source_catalog_counts.rejected_ssh_keys),
            source_managed_ssh_key_count: source_catalog_counts
                .candidate_managed_ssh_keys
                .saturating_add(source_catalog_counts.managed_ssh_key_recovery_required),
            importable_managed_ssh_key_count: importable_managed_keys,
            duplicate_managed_ssh_key_count: duplicate_managed_keys,
            conflict_managed_ssh_key_count: conflict_managed_keys,
            managed_ssh_key_recovery_required_count: source_catalog_counts
                .managed_ssh_key_recovery_required,
            managed_passphrases_discarded_by_policy_count: source_catalog_counts
                .managed_passphrases_discarded_by_policy,
            source_identity_count: source_catalog_counts.source_identities,
            importable_identity_reference_count: importable_identities,
            duplicate_identity_reference_count: source_catalog_counts
                .duplicate_identities
                .saturating_add(duplicate_identities),
            conflict_identity_reference_count: conflict_identities,
            source_password_identity_count: source_catalog_counts.candidate_password_identities,
            importable_password_identity_count: importable_password_identities,
            duplicate_password_identity_count: duplicate_password_identities,
            conflict_password_identity_count: conflict_password_identities,
            recoverable_password_identity_credential_count: assessment
                .password_identity_dispositions()
                .iter()
                .zip(&password_identity_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.0
                })
                .count() as u32,
            password_identity_credential_reentry_required_count: assessment
                .password_identity_dispositions()
                .iter()
                .zip(&password_identity_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.1
                })
                .count() as u32,
            recoverable_telnet_credential_count: assessment
                .host_dispositions()
                .iter()
                .zip(&credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.1
                })
                .count() as u32,
            telnet_credential_reentry_required_count: assessment
                .host_dispositions()
                .iter()
                .zip(&credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.3
                })
                .count() as u32,
            source_proxy_profile_count: source_catalog_counts.source_proxy_profiles,
            source_inline_proxy_host_count: source_catalog_counts.candidate_inline_proxy_hosts,
            importable_proxy_profile_count: importable_proxy_profiles,
            duplicate_proxy_profile_count: source_catalog_counts
                .duplicate_proxy_profiles
                .saturating_add(duplicate_proxy_profiles),
            conflict_proxy_profile_count: conflict_proxy_profiles,
            recoverable_proxy_profile_credential_count: assessment
                .proxy_profile_dispositions()
                .iter()
                .zip(&proxy_profile_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.0
                })
                .count() as u32,
            recoverable_inline_proxy_credential_count: assessment
                .host_dispositions()
                .iter()
                .zip(&inline_proxy_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.0
                })
                .count() as u32,
            proxy_profile_credential_reentry_required_count: assessment
                .proxy_profile_dispositions()
                .iter()
                .zip(&proxy_profile_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.1
                })
                .count() as u32,
            inline_proxy_credential_reentry_required_count: assessment
                .host_dispositions()
                .iter()
                .zip(&inline_proxy_credentials)
                .filter(|(disposition, credential)| {
                    **disposition == SavedVaultImportDisposition::Importable && credential.1
                })
                .count() as u32,
            unsupported_proxy_profile_count: source_catalog_counts
                .unsupported_proxy_profiles
                .saturating_add(source_catalog_counts.rejected_proxy_profiles),
            unsupported_identity_count: source_catalog_counts
                .unsupported_identities
                .saturating_add(source_catalog_counts.rejected_identities),
            source_custom_group_count: source_catalog_counts.source_custom_groups,
            importable_custom_group_count: importable_custom_groups,
            duplicate_custom_group_count: duplicate_custom_groups,
            conflict_custom_group_count: conflict_custom_groups,
            source_group_config_count: source_catalog_counts.source_group_configs,
            importable_group_config_count: importable_group_configs,
            duplicate_group_config_count: duplicate_group_configs,
            conflict_group_config_count: conflict_group_configs,
            source_snippet_count: notes_snippets_assessment.source_snippet_count,
            importable_snippet_count: importable_snippets,
            duplicate_snippet_count: duplicate_snippets,
            conflict_snippet_count: conflict_snippets,
            source_snippet_package_count: notes_snippets_assessment.source_snippet_package_count,
            importable_snippet_package_count: notes_snippets_assessment
                .importable_snippet_package_count,
            duplicate_snippet_package_count: notes_snippets_assessment
                .duplicate_snippet_package_count,
            source_note_count: notes_snippets_assessment.source_note_count,
            importable_note_count: importable_notes,
            duplicate_note_count: duplicate_notes,
            conflict_note_count: conflict_notes,
            source_note_group_count: notes_snippets_assessment.source_note_group_count,
            importable_note_group_count: notes_snippets_assessment.importable_note_group_count,
            duplicate_note_group_count: notes_snippets_assessment.duplicate_note_group_count,
            catalog_scope_change_count: notes_snippets_assessment
                .catalog_scope_change_count
                .saturating_add(custom_group_scope_change_count),
            remapped_snippet_id_count: notes_snippets_assessment.remapped_snippet_id_count,
            remapped_note_id_count: notes_snippets_assessment.remapped_note_id_count,
            remapped_host_script_edge_count: notes_snippets_assessment
                .remapped_host_script_edge_count,
            remapped_group_script_edge_count: notes_snippets_assessment
                .remapped_group_script_edge_count,
            remapped_entity_count,
        })
    })
    .await
}

#[tauri::command]
async fn commit_legacy_vault_import(
    state: State<'_, DesktopState>,
    request: CommitLegacyVaultImportRequest,
) -> Result<LegacyVaultImportResult, String> {
    validate_legacy_source_fingerprint(&request.source_fingerprint)?;
    // The source is reopened and parsed before either saved-host lock is held.
    let document = load_legacy_vault_document(request.path).await?;
    if !verify_legacy_source_fingerprint(document.source_sha256(), &request.source_fingerprint) {
        return Err(legacy_error(
            LEGACY_VAULT_SOURCE_CHANGED,
            "The legacy Vault file changed after inspection",
        ));
    }
    ensure_legacy_document_is_committable(&document)?;
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        commit_legacy_vault_document(&state, request.inventory_revision, document).await
    })
    .await
}

struct PreparedLegacyImport {
    host: SavedHost,
    credential: Option<SecretValue>,
    telnet_credential: Option<SecretValue>,
    inline_proxy_credential: Option<SecretValue>,
}

struct PreparedLegacyPasswordIdentityImport {
    identity: SavedPasswordIdentity,
    credential: Option<SecretValue>,
}

struct PreparedLegacyProxyProfileImport {
    profile: SavedProxyProfile,
    credential: Option<SecretValue>,
}

struct PreparedLegacyGroupConfigImport {
    group: SavedGroupConfig,
    ssh_credential: Option<SecretValue>,
    telnet_credential: Option<SecretValue>,
    proxy_credential: Option<SecretValue>,
}

struct PreparedLegacyCredential {
    owner: LegacyImportCredentialOwner,
    secret: SecretValue,
}

fn disposition_requires_credential_reentry(disposition: LegacyCredentialDisposition) -> bool {
    matches!(
        disposition,
        LegacyCredentialDisposition::ReentryRequiredEncrypted
            | LegacyCredentialDisposition::ReentryRequiredOversized
            | LegacyCredentialDisposition::ReentryRequiredInvalid
            | LegacyCredentialDisposition::ReentryRequiredMissing
            | LegacyCredentialDisposition::ReentryRequiredAdditionalSecret
            | LegacyCredentialDisposition::ReentryRequiredNonSsh
            | LegacyCredentialDisposition::NotSavedByPolicy
    )
}

fn saved_host_with_credential_hint(
    host: SavedHost,
    has_saved_credential: bool,
) -> Result<SavedHost, String> {
    let mut value = serde_json::to_value(host).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported host could not be normalized",
        )
    })?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "An imported host could not be normalized",
            )
        })?
        .insert(
            "hasSavedCredential".to_owned(),
            serde_json::Value::Bool(has_saved_credential),
        );
    serde_json::from_value(value).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported host could not be normalized",
        )
    })
}

fn saved_host_with_inline_proxy_credential_hint(
    host: SavedHost,
    has_saved_credential: bool,
) -> Result<SavedHost, String> {
    let Some(config) = host.proxy_config().map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported host proxy could not be normalized",
        )
    })?
    else {
        return if has_saved_credential {
            Err(legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "An imported host proxy could not be normalized",
            ))
        } else {
            Ok(host)
        };
    };
    let is_manual_network = matches!(
        &config,
        SavedProxyConfig::Http {
            identity_id: None,
            ..
        } | SavedProxyConfig::Socks5 {
            identity_id: None,
            ..
        }
    );
    if !is_manual_network {
        return if has_saved_credential {
            Err(legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "An imported host proxy could not be normalized",
            ))
        } else {
            Ok(host)
        };
    }
    let config = config
        .with_saved_credential_hint(has_saved_credential)
        .map_err(|_| {
            legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "An imported host proxy could not be normalized",
            )
        })?;
    let mut value = serde_json::to_value(host).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported host proxy could not be normalized",
        )
    })?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "An imported host proxy could not be normalized",
            )
        })?
        .insert(
            "proxyConfig".to_owned(),
            serde_json::to_value(config).map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "An imported host proxy could not be normalized",
                )
            })?,
        );
    serde_json::from_value(value).map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported host proxy could not be normalized",
        )
    })
}

fn legacy_candidate_for_assessment(candidate: &LegacyHostCandidate) -> Result<SavedHost, String> {
    // Assessment must compare exactly the metadata that a successful commit
    // would publish. Otherwise a host imported with a recovered plaintext
    // password (`true`) would be seen as conflicting with the parser's
    // deliberately fail-closed initial hint (`false`) on every later import.
    let will_store_credential = if candidate.host().protocol.is_telnet() {
        candidate.has_telnet_password_candidate()
            && candidate.telnet_credential_disposition()
                == LegacyCredentialDisposition::PlaintextCandidate
    } else {
        candidate.has_ssh_password_candidate()
            && candidate.credential_disposition() == LegacyCredentialDisposition::PlaintextCandidate
    };
    let host = saved_host_with_credential_hint(candidate.host().clone(), will_store_credential)?;
    let will_store_proxy_credential = candidate.has_inline_proxy_password_candidate()
        && candidate.inline_proxy_credential_disposition()
            == LegacyProxyCredentialDisposition::PlaintextCandidate;
    saved_host_with_inline_proxy_credential_hint(host, will_store_proxy_credential)
}

fn saved_password_identity_with_credential_hint(
    identity: SavedPasswordIdentity,
    has_saved_credential: bool,
) -> Result<SavedPasswordIdentity, String> {
    let compatibility_fields = identity.compatibility_fields().clone();
    SavedPasswordIdentity::from_parts(
        identity.id,
        identity.revision,
        identity.label,
        identity.username,
        has_saved_credential,
        identity.created_at,
        identity.updated_at,
        compatibility_fields,
    )
    .map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported password identity could not be normalized",
        )
    })
}

fn legacy_password_identity_candidate_for_assessment(
    candidate: &LegacyPasswordIdentityCandidate,
) -> Result<SavedPasswordIdentity, String> {
    // As with host credentials, assessment must compare the exact secret-free
    // metadata that the transaction will publish. This keeps a repeated
    // plaintext import idempotent instead of remapping the identity because
    // the parser deliberately initializes its custody hint to false.
    let will_store_credential = candidate.has_password_candidate()
        && candidate.credential_disposition()
            == LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate;
    saved_password_identity_with_credential_hint(
        candidate.identity().clone(),
        will_store_credential,
    )
}

fn saved_proxy_profile_with_credential_hint(
    profile: SavedProxyProfile,
    has_saved_credential: bool,
) -> Result<SavedProxyProfile, String> {
    let compatibility_fields = profile.compatibility_fields().clone();
    let is_manual_network = matches!(
        &profile.config,
        SavedProxyConfig::Http {
            identity_id: None,
            ..
        } | SavedProxyConfig::Socks5 {
            identity_id: None,
            ..
        }
    );
    let config = if is_manual_network {
        profile
            .config
            .with_saved_credential_hint(has_saved_credential)
            .map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "An imported proxy profile could not be normalized",
                )
            })?
    } else if has_saved_credential {
        return Err(legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported proxy profile could not be normalized",
        ));
    } else {
        profile.config
    };
    SavedProxyProfile::from_parts(
        profile.id,
        profile.revision,
        profile.label,
        config,
        profile.created_at,
        profile.updated_at,
        compatibility_fields,
    )
    .map_err(|_| {
        legacy_error(
            LEGACY_VAULT_IMPORT_FAILED,
            "An imported proxy profile could not be normalized",
        )
    })
}

fn legacy_proxy_profile_candidate_for_assessment(
    candidate: &LegacyProxyProfileCandidate,
) -> Result<SavedProxyProfile, String> {
    let will_store_credential = candidate.has_password_candidate()
        && candidate.credential_disposition()
            == LegacyProxyCredentialDisposition::PlaintextCandidate;
    saved_proxy_profile_with_credential_hint(candidate.profile().clone(), will_store_credential)
}

fn legacy_import_repair_error() -> String {
    legacy_error(
        LEGACY_VAULT_IMPORT_REPAIR_REQUIRED,
        "A pending legacy Vault import requires credential or managed-key reconciliation",
    )
}

fn legacy_secret_store_error() -> String {
    legacy_error(
        LEGACY_VAULT_SECRET_STORE_FAILED,
        "A managed SSH-key secret could not be stored",
    )
}

fn legacy_secret_store_repair_error() -> String {
    legacy_error(
        LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED,
        "Managed SSH-key storage requires reconciliation",
    )
}

fn legacy_credential_repair_error() -> String {
    legacy_error(
        LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED,
        "One or more credential entries could not be restored",
    )
}

async fn load_legacy_import_transaction(
    state: &DesktopState,
) -> Result<Option<LegacyImportTransaction>, String> {
    let root = state.legacy_import_transaction_root.clone();
    tokio::task::spawn_blocking(move || LegacyImportTransaction::load(root.as_ref()))
        .await
        .map_err(|_| legacy_import_repair_error())?
        .map_err(|_| legacy_import_repair_error())
}

async fn begin_legacy_import_transaction(
    state: &DesktopState,
    saved_host_ids: Vec<SavedHostId>,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
) -> Result<LegacyImportTransaction, String> {
    let owners = saved_host_ids
        .iter()
        .map(LegacyImportCredentialOwner::for_saved_host)
        .collect();
    begin_legacy_import_transaction_for_owners(
        state,
        owners,
        before_graph_commitment,
        after_graph_commitment,
    )
    .await
}

async fn begin_legacy_import_transaction_for_owners(
    state: &DesktopState,
    owners: Vec<LegacyImportCredentialOwner>,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
) -> Result<LegacyImportTransaction, String> {
    let root = state.legacy_import_transaction_root.clone();
    tokio::task::spawn_blocking(move || {
        LegacyImportTransaction::begin_for_owners(
            root.as_ref(),
            &owners,
            before_graph_commitment,
            after_graph_commitment,
        )
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn begin_legacy_import_transaction_with_blobs(
    state: &DesktopState,
    saved_host_ids: Vec<SavedHostId>,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
) -> Result<LegacyImportTransaction, String> {
    let owners = saved_host_ids
        .iter()
        .map(LegacyImportCredentialOwner::for_saved_host)
        .collect();
    begin_legacy_import_transaction_with_blobs_for_owners(
        state,
        owners,
        before_graph_commitment,
        after_graph_commitment,
    )
    .await
}

async fn begin_legacy_import_transaction_with_blobs_for_owners(
    state: &DesktopState,
    owners: Vec<LegacyImportCredentialOwner>,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
) -> Result<LegacyImportTransaction, String> {
    let root = state.legacy_import_transaction_root.clone();
    tokio::task::spawn_blocking(move || {
        LegacyImportTransaction::begin_for_owners_with_blob_publication(
            root.as_ref(),
            &owners,
            before_graph_commitment,
            after_graph_commitment,
        )
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn mark_legacy_blobs_durable(
    mut transaction: LegacyImportTransaction,
) -> Result<LegacyImportTransaction, String> {
    tokio::task::spawn_blocking(move || {
        transaction.mark_blobs_durable()?;
        Ok::<_, legacy_import_transaction::LegacyImportTransactionError>(transaction)
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn activate_legacy_import_transaction(
    transaction: LegacyImportTransaction,
    previous_states: Vec<(SavedHostId, LegacyPreviousCredentialState)>,
) -> Result<LegacyImportTransaction, String> {
    let previous_states = previous_states
        .iter()
        .map(|(id, previous)| (LegacyImportCredentialOwner::for_saved_host(id), *previous))
        .collect();
    activate_legacy_import_transaction_for_owners(transaction, previous_states).await
}

async fn activate_legacy_import_transaction_for_owners(
    mut transaction: LegacyImportTransaction,
    previous_states: Vec<(LegacyImportCredentialOwner, LegacyPreviousCredentialState)>,
) -> Result<LegacyImportTransaction, String> {
    tokio::task::spawn_blocking(move || {
        transaction.activate_for_owners(&previous_states)?;
        Ok::<_, legacy_import_transaction::LegacyImportTransactionError>(transaction)
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn finish_legacy_import_transaction(
    transaction: LegacyImportTransaction,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || transaction.finish())
        .await
        .map_err(|_| legacy_import_repair_error())?
        .map_err(|_| legacy_import_repair_error())
}

async fn mark_legacy_rollback_targets_restored(
    mut transaction: LegacyImportTransaction,
) -> Result<LegacyImportTransaction, String> {
    tokio::task::spawn_blocking(move || {
        transaction.mark_rollback_targets_restored()?;
        Ok::<_, legacy_import_transaction::LegacyImportTransactionError>(transaction)
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn mark_legacy_vault_durable(
    mut transaction: LegacyImportTransaction,
) -> Result<LegacyImportTransaction, String> {
    tokio::task::spawn_blocking(move || {
        transaction.mark_vault_durable()?;
        Ok::<_, legacy_import_transaction::LegacyImportTransactionError>(transaction)
    })
    .await
    .map_err(|_| legacy_import_repair_error())?
    .map_err(|_| legacy_import_repair_error())
}

async fn confirm_current_legacy_vault_snapshot(
    state: &DesktopState,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.confirm_current_snapshot_durability())
        .await
        .map_err(|_| legacy_import_repair_error())?
        .map_err(|_| legacy_import_repair_error())
}

fn legacy_import_credential_references(
    transaction: &LegacyImportTransaction,
    saved_host_id: &SavedHostId,
) -> Result<(StoredCredentialReference, StoredCredentialReference), String> {
    let owner = LegacyImportCredentialOwner::for_saved_host(saved_host_id);
    legacy_import_credential_references_for_owner(transaction, &owner)
}

fn legacy_import_credential_references_for_owner(
    transaction: &LegacyImportTransaction,
    owner: &LegacyImportCredentialOwner,
) -> Result<(StoredCredentialReference, StoredCredentialReference), String> {
    let transaction_id = transaction.transaction_id().hyphenated().to_string();
    let (target, backup) = match owner.kind() {
        LegacyImportCredentialOwnerKind::Host => (
            StoredCredentialReference::for_saved_host(owner.id()),
            StoredCredentialReference::for_legacy_import_backup(&transaction_id, owner.id()),
        ),
        LegacyImportCredentialOwnerKind::HostTelnet => (
            StoredCredentialReference::for_saved_host_telnet(owner.id()),
            StoredCredentialReference::for_legacy_import_host_telnet_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::PasswordIdentity => (
            StoredCredentialReference::for_saved_identity(owner.id()),
            StoredCredentialReference::for_legacy_import_identity_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::HostInlineProxy => (
            StoredCredentialReference::for_saved_host_proxy(owner.id()),
            StoredCredentialReference::for_legacy_import_host_proxy_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::ProxyProfile => (
            StoredCredentialReference::for_saved_proxy_profile(owner.id()),
            StoredCredentialReference::for_legacy_import_proxy_profile_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::GroupSsh => (
            StoredCredentialReference::for_saved_group_ssh(owner.id()),
            StoredCredentialReference::for_legacy_import_group_ssh_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::GroupTelnet => (
            StoredCredentialReference::for_saved_group_telnet(owner.id()),
            StoredCredentialReference::for_legacy_import_group_telnet_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
        LegacyImportCredentialOwnerKind::GroupProxy => (
            StoredCredentialReference::for_saved_group_proxy(owner.id()),
            StoredCredentialReference::for_legacy_import_group_proxy_backup(
                &transaction_id,
                owner.id(),
            ),
        ),
    };
    let target = target.map_err(|_| legacy_import_repair_error())?;
    let backup = backup.map_err(|_| legacy_import_repair_error())?;
    Ok((target, backup))
}

const fn legacy_import_credential_kind_for_owner(
    owner: &LegacyImportCredentialOwner,
) -> CredentialKind {
    match owner.kind() {
        LegacyImportCredentialOwnerKind::Host
        | LegacyImportCredentialOwnerKind::PasswordIdentity
        | LegacyImportCredentialOwnerKind::GroupSsh => CredentialKind::SshPassword,
        LegacyImportCredentialOwnerKind::HostTelnet
        | LegacyImportCredentialOwnerKind::GroupTelnet => CredentialKind::TelnetPassword,
        LegacyImportCredentialOwnerKind::HostInlineProxy
        | LegacyImportCredentialOwnerKind::ProxyProfile
        | LegacyImportCredentialOwnerKind::GroupProxy => CredentialKind::ProxyPassword,
    }
}

async fn cleanup_legacy_import_backups(
    state: &DesktopState,
    transaction: &LegacyImportTransaction,
) -> Result<(), String> {
    for entry in transaction.entries() {
        let (_, backup) =
            legacy_import_credential_references_for_owner(transaction, &entry.owner())?;
        state
            .persistent_credentials
            .delete(&backup)
            .await
            .map_err(|_| legacy_credential_repair_error())?;
    }
    Ok(())
}

async fn rollback_active_legacy_import(
    state: &DesktopState,
    transaction: LegacyImportTransaction,
) -> Result<(), String> {
    if transaction
        .entries()
        .iter()
        .any(|entry| entry.previous() == LegacyPreviousCredentialState::Unknown)
    {
        // Unknown is safe only while Preparing. Seeing it in Active means the
        // journal cannot prove whether a target account was changed, so retain
        // both the journal and every backup for explicit repair.
        return Err(legacy_import_repair_error());
    }

    for entry in transaction.entries().iter().rev() {
        let owner = entry.owner();
        let kind = legacy_import_credential_kind_for_owner(&owner);
        let (target, backup) = legacy_import_credential_references_for_owner(&transaction, &owner)?;
        match entry.previous() {
            LegacyPreviousCredentialState::BackedUp => {
                let previous = state
                    .persistent_credentials
                    .resolve(&backup, kind)
                    .await
                    .map_err(|_| legacy_credential_repair_error())?;
                state
                    .persistent_credentials
                    .upsert(&target, kind, previous)
                    .await
                    .map_err(|_| legacy_credential_repair_error())?;
            }
            LegacyPreviousCredentialState::Absent => {
                state
                    .persistent_credentials
                    .delete(&target)
                    .await
                    .map_err(|_| legacy_credential_repair_error())?;
            }
            LegacyPreviousCredentialState::Unknown => {
                return Err(legacy_import_repair_error());
            }
        }
    }

    let transaction = mark_legacy_rollback_targets_restored(transaction).await?;
    cleanup_legacy_import_backups(state, &transaction).await?;
    finish_legacy_import_transaction(transaction).await
}

async fn recover_pending_legacy_import(state: &DesktopState) -> Result<(), String> {
    let Some(transaction) = load_legacy_import_transaction(state).await? else {
        return Ok(());
    };

    match transaction.phase() {
        LegacyImportTransactionPhase::Preparing => {
            // Preparing never mutates a final credential account. It may have
            // created some isolated backups, which are safe to discard.
            cleanup_legacy_import_backups(state, &transaction).await?;
            finish_legacy_import_transaction(transaction).await
        }
        LegacyImportTransactionPhase::BlobsDurable => {
            // Target credentials were not yet authorized for mutation and
            // Vault must still be the exact planned before graph. The already
            // durable new blobs may remain as unreachable orphans for a later
            // reference-aware GC pass.
            let snapshot = confirm_current_legacy_vault_snapshot(state).await?;
            if snapshot.commitment() != transaction.before_graph_commitment() {
                return Err(legacy_import_repair_error());
            }
            cleanup_legacy_import_backups(state, &transaction).await?;
            finish_legacy_import_transaction(transaction).await
        }
        LegacyImportTransactionPhase::RollbackTargetsRestored => {
            // A crash can leave only the first durable publication of this
            // terminal phase. Republish it to both slots before deleting the
            // last copies of any old credentials.
            let transaction = mark_legacy_rollback_targets_restored(transaction).await?;
            cleanup_legacy_import_backups(state, &transaction).await?;
            finish_legacy_import_transaction(transaction).await
        }
        LegacyImportTransactionPhase::VaultDurable => {
            // Once the exact Vault snapshot was synced and this decision was
            // durably recorded, final target credentials must never be rolled
            // back. Complete a possibly interrupted dual-slot publication,
            // then retry only backup/journal cleanup.
            let transaction = mark_legacy_vault_durable(transaction).await?;
            cleanup_legacy_import_backups(state, &transaction).await?;
            finish_legacy_import_transaction(transaction).await
        }
        LegacyImportTransactionPhase::Active => {
            // Current visibility or matching entity IDs are insufficient
            // after a hard-link publication whose directory sync failed.
            // Sync both Vault slots, re-read the exact full graph, and compare
            // its stable commitment with the journal's before/after states.
            let snapshot = confirm_current_legacy_vault_snapshot(state).await?;
            if snapshot.commitment() == transaction.after_graph_commitment() {
                if transaction.requires_blob_publication() {
                    confirm_managed_graph_blobs(state, snapshot.graph().clone()).await?;
                }
                // The exact expected graph is durable. Record the keep-target
                // decision in both journal slots before removing backups.
                let transaction = mark_legacy_vault_durable(transaction).await?;
                cleanup_legacy_import_backups(state, &transaction).await?;
                finish_legacy_import_transaction(transaction).await
            } else if snapshot.commitment() == transaction.before_graph_commitment() {
                rollback_active_legacy_import(state, transaction).await
            } else {
                // A third graph may be mixed, externally changed, or from an
                // unrelated publication. Never infer which credential state
                // it needs from matching IDs alone.
                Err(legacy_import_repair_error())
            }
        }
    }
}

async fn legacy_import_failure_with_recovery(state: &DesktopState, primary: String) -> String {
    match recover_pending_legacy_import(state).await {
        Ok(()) => primary,
        Err(repair) => format!("{primary}; {repair}"),
    }
}

async fn managed_secret_store_initialization_allowed(state: &DesktopState) -> Result<bool, String> {
    // A pending journal is itself cross-store authority. The outer saved-host
    // coordinator normally recovers it first; this second check protects
    // direct/internal callers from initializing a replacement secret store.
    if load_legacy_import_transaction(state).await?.is_some() {
        return Err(legacy_import_repair_error());
    }
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.managed_secret_retention_set())
        .await
        .map_err(|_| legacy_import_repair_error())?
        .map(|retained| retained.is_empty())
        .map_err(|_| legacy_import_repair_error())
}

async fn commit_legacy_vault_document(
    state: &DesktopState,
    expected_revision: SavedHostInventoryRevision,
    document: LegacyVaultDocument,
) -> Result<LegacyVaultImportResult, String> {
    ensure_legacy_document_is_committable(&document)?;
    let current_revision =
        assess_legacy_graph(state.saved_hosts.clone(), SavedVaultGraph::default())
            .await?
            .into_revision();
    if current_revision != expected_revision {
        return Err(legacy_error(
            LEGACY_VAULT_INVENTORY_CHANGED,
            "The Vault inventory changed after inspection; inspect the file again",
        ));
    }
    // Keep all locator-independent graph validation ahead of managed secret
    // store initialization. The formal transaction below still re-assesses
    // the graph with the real locators before touching credential targets.
    preflight_legacy_document_structure(state, &document).await?;
    let source_sha256 = *document.source_sha256();
    let managed_ids = legacy_managed_candidate_ids(&document);
    let secret_lease = if managed_ids.is_empty() {
        None
    } else {
        let allow_initialization = managed_secret_store_initialization_allowed(state).await?;
        Some(SecretStoreTransactionLease::start(state, allow_initialization).await?)
    };
    let managed_locators = match secret_lease.as_ref() {
        Some(lease) => lease.derive_locators(managed_ids).await?,
        None => Vec::new(),
    };
    let AssessableLegacyGraph {
        preview,
        host_candidates,
        password_identity_candidates,
        proxy_profile_candidates,
        group_config_candidates,
        notes_snippets_candidates,
        graph,
        managed_secret_bundles,
        relationship_mode,
        ..
    } = into_assessable_legacy_graph(document, managed_locators)?;
    let source_duplicates = preview.duplicate_count;
    let (graph, notes_snippets_assessment, _custom_group_scope_change_count) =
        attach_legacy_notes_snippets_plan(state, graph, &notes_snippets_candidates, &source_sha256)
            .await?;
    drop(notes_snippets_candidates);
    let locator_resolver = match secret_lease.as_ref() {
        Some(lease) => ManagedLocatorResolver::Transaction(lease),
        None => ManagedLocatorResolver::Inspection {
            state,
            source_sha256,
        },
    };
    let finalized = assess_and_remap_legacy_graph(
        state.saved_hosts.clone(),
        graph,
        &source_sha256,
        relationship_mode
            || notes_snippets_assessment.snippets_present
            || notes_snippets_assessment.snippet_packages_present
            || notes_snippets_assessment.notes_present
            || notes_snippets_assessment.note_groups_present,
        &locator_resolver,
    )
    .await?;
    let AssessedLegacyGraph {
        graph,
        assessment,
        remapped_entity_count,
    } = finalized;
    if assessment.revision() != &expected_revision {
        return Err(legacy_error(
            LEGACY_VAULT_INVENTORY_CHANGED,
            "The Vault inventory changed after inspection; inspect the file again",
        ));
    }
    let (_, store_duplicates, conflicts) = graph_disposition_counts(assessment.host_dispositions());
    let host_dispositions = assessment.host_dispositions().to_vec();
    let key_dispositions = assessment.ssh_key_reference_dispositions().to_vec();
    let managed_key_dispositions = assessment.managed_ssh_key_dispositions().to_vec();
    let identity_dispositions = assessment.identity_reference_dispositions().to_vec();
    let password_identity_dispositions = assessment.password_identity_dispositions().to_vec();
    let proxy_profile_dispositions = assessment.proxy_profile_dispositions().to_vec();
    let group_config_dispositions = assessment.group_dispositions().to_vec();
    let final_hosts = graph.hosts().to_vec();
    let final_managed_keys = graph.managed_ssh_keys().to_vec();
    let final_password_identities = graph.password_identities().to_vec();
    let final_proxy_profiles = graph.proxy_profiles().to_vec();
    let final_group_configs = graph.groups().to_vec();
    if final_managed_keys.len() != managed_secret_bundles.len() {
        return Err(legacy_secret_store_repair_error());
    }

    let mut prepared = Vec::new();
    let mut requires_reentry = 0_u32;
    let mut telnet_requires_reentry = 0_u32;
    let mut inline_proxy_requires_reentry = 0_u32;
    for ((candidate, host), disposition) in host_candidates
        .into_iter()
        .zip(final_hosts)
        .zip(&host_dispositions)
    {
        if *disposition != SavedVaultImportDisposition::Importable {
            continue;
        }
        let (
            _source_host,
            credential,
            credential_disposition,
            telnet_credential,
            telnet_credential_disposition,
            inline_proxy_credential,
            inline_proxy_credential_disposition,
        ) = candidate.into_all_credential_parts();
        let telnet_requires_reentry_for_host =
            disposition_requires_credential_reentry(telnet_credential_disposition);
        if disposition_requires_credential_reentry(credential_disposition)
            || telnet_requires_reentry_for_host
        {
            requires_reentry = requires_reentry.saturating_add(1);
        }
        if telnet_requires_reentry_for_host {
            telnet_requires_reentry = telnet_requires_reentry.saturating_add(1);
        }
        // Defense in depth: only the parser's explicit plaintext disposition
        // is eligible for OS storage. enc:v1 and all other dispositions are
        // dropped even if a future parser regression supplied bytes.
        let credential =
            if credential_disposition == LegacyCredentialDisposition::PlaintextCandidate {
                credential
            } else {
                None
            };
        let telnet_credential =
            if telnet_credential_disposition == LegacyCredentialDisposition::PlaintextCandidate {
                telnet_credential
            } else {
                None
            };
        if inline_proxy_credential_disposition.requires_reentry() {
            inline_proxy_requires_reentry = inline_proxy_requires_reentry.saturating_add(1);
        }
        let inline_proxy_credential = if inline_proxy_credential_disposition
            == LegacyProxyCredentialDisposition::PlaintextCandidate
        {
            inline_proxy_credential
        } else {
            None
        };
        let host = saved_host_with_credential_hint(
            host,
            credential.is_some() || telnet_credential.is_some(),
        )?;
        let host =
            saved_host_with_inline_proxy_credential_hint(host, inline_proxy_credential.is_some())?;
        prepared.push(PreparedLegacyImport {
            host,
            credential,
            telnet_credential,
            inline_proxy_credential,
        });
    }

    if proxy_profile_candidates.len() != final_proxy_profiles.len() {
        return Err(legacy_import_repair_error());
    }
    let mut prepared_proxy_profiles = Vec::new();
    let mut proxy_profile_requires_reentry = 0_u32;
    for ((candidate, profile), disposition) in proxy_profile_candidates
        .into_iter()
        .zip(final_proxy_profiles)
        .zip(&proxy_profile_dispositions)
    {
        if *disposition != SavedVaultImportDisposition::Importable {
            continue;
        }
        let (_source_profile, credential, credential_disposition) = candidate.into_parts();
        if credential_disposition.requires_reentry() {
            proxy_profile_requires_reentry = proxy_profile_requires_reentry.saturating_add(1);
        }
        let credential =
            if credential_disposition == LegacyProxyCredentialDisposition::PlaintextCandidate {
                credential
            } else {
                None
            };
        let profile = saved_proxy_profile_with_credential_hint(profile, credential.is_some())?;
        prepared_proxy_profiles.push(PreparedLegacyProxyProfileImport {
            profile,
            credential,
        });
    }

    if password_identity_candidates.len() != final_password_identities.len() {
        return Err(legacy_import_repair_error());
    }
    let mut prepared_password_identities = Vec::new();
    let mut password_identity_requires_reentry = 0_u32;
    for ((candidate, identity), disposition) in password_identity_candidates
        .into_iter()
        .zip(final_password_identities)
        .zip(&password_identity_dispositions)
    {
        if *disposition != SavedVaultImportDisposition::Importable {
            continue;
        }
        let (_source_identity, credential, credential_disposition) = candidate.into_parts();
        if credential_disposition.requires_reentry() {
            password_identity_requires_reentry =
                password_identity_requires_reentry.saturating_add(1);
        }
        // Only explicitly classified plaintext can enter OS custody. All
        // enc:v1, missing, malformed, and oversized forms retain their
        // secret-free identity metadata with a false re-entry hint.
        let credential = if credential_disposition
            == LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate
        {
            credential
        } else {
            None
        };
        let identity =
            saved_password_identity_with_credential_hint(identity, credential.is_some())?;
        prepared_password_identities.push(PreparedLegacyPasswordIdentityImport {
            identity,
            credential,
        });
    }

    if group_config_candidates.len() != final_group_configs.len() {
        return Err(legacy_import_repair_error());
    }
    let mut prepared_group_configs = Vec::new();
    let mut group_credential_reentry_count = 0_u32;
    for ((candidate, group), disposition) in group_config_candidates
        .into_iter()
        .zip(final_group_configs)
        .zip(&group_config_dispositions)
    {
        if *disposition != SavedVaultImportDisposition::Importable {
            continue;
        }
        let (
            _source_group,
            ssh_credential,
            ssh_disposition,
            telnet_credential,
            telnet_disposition,
            proxy_credential,
            proxy_disposition,
        ) = candidate.into_parts();
        if disposition_requires_credential_reentry(ssh_disposition) {
            group_credential_reentry_count = group_credential_reentry_count.saturating_add(1);
        }
        if disposition_requires_credential_reentry(telnet_disposition) {
            group_credential_reentry_count = group_credential_reentry_count.saturating_add(1);
        }
        if proxy_disposition.requires_reentry() {
            group_credential_reentry_count = group_credential_reentry_count.saturating_add(1);
        }
        prepared_group_configs.push(PreparedLegacyGroupConfigImport {
            group,
            ssh_credential: (ssh_disposition == LegacyCredentialDisposition::PlaintextCandidate)
                .then_some(ssh_credential)
                .flatten(),
            telnet_credential: (telnet_disposition
                == LegacyCredentialDisposition::PlaintextCandidate)
                .then_some(telnet_credential)
                .flatten(),
            proxy_credential: (proxy_disposition
                == LegacyProxyCredentialDisposition::PlaintextCandidate)
                .then_some(proxy_credential)
                .flatten(),
        });
    }

    let host_credentials_stored_count = prepared
        .iter()
        .filter(|candidate| candidate.credential.is_some())
        .count() as u32;
    let host_telnet_credentials_stored_count = prepared
        .iter()
        .filter(|candidate| candidate.telnet_credential.is_some())
        .count() as u32;
    let password_identity_credentials_stored_count = prepared_password_identities
        .iter()
        .filter(|candidate| candidate.credential.is_some())
        .count() as u32;
    let inline_proxy_credentials_stored_count = prepared
        .iter()
        .filter(|candidate| candidate.inline_proxy_credential.is_some())
        .count() as u32;
    let proxy_profile_credentials_stored_count = prepared_proxy_profiles
        .iter()
        .filter(|candidate| candidate.credential.is_some())
        .count() as u32;
    let group_ssh_credentials_stored_count = prepared_group_configs
        .iter()
        .filter(|candidate| candidate.ssh_credential.is_some())
        .count() as u32;
    let group_telnet_credentials_stored_count = prepared_group_configs
        .iter()
        .filter(|candidate| candidate.telnet_credential.is_some())
        .count() as u32;
    let group_proxy_credentials_stored_count = prepared_group_configs
        .iter()
        .filter(|candidate| candidate.proxy_credential.is_some())
        .count() as u32;
    let credential_count = host_credentials_stored_count
        .saturating_add(host_telnet_credentials_stored_count)
        .saturating_add(password_identity_credentials_stored_count)
        .saturating_add(inline_proxy_credentials_stored_count)
        .saturating_add(proxy_profile_credentials_stored_count)
        .saturating_add(group_ssh_credentials_stored_count)
        .saturating_add(group_telnet_credentials_stored_count)
        .saturating_add(group_proxy_credentials_stored_count);

    // Build the exact graph before touching keyring targets. The store plans
    // the same normalized merge used by commit_graph_import and returns
    // secret-free commitments for the current and expected final graphs.
    let import_hosts = prepared
        .iter()
        .map(|candidate| candidate.host.clone())
        .collect::<Vec<_>>();
    let import_keys = graph
        .ssh_key_references()
        .iter()
        .zip(&key_dispositions)
        .filter(|(_, disposition)| **disposition == SavedVaultImportDisposition::Importable)
        .map(|(reference, _)| reference.clone())
        .collect::<Vec<_>>();
    let import_managed_keys = final_managed_keys
        .iter()
        .zip(&managed_key_dispositions)
        .filter(|(_, disposition)| **disposition == SavedVaultImportDisposition::Importable)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    let import_identities = graph
        .identity_references()
        .iter()
        .zip(&identity_dispositions)
        .filter(|(_, disposition)| **disposition == SavedVaultImportDisposition::Importable)
        .map(|(reference, _)| reference.clone())
        .collect::<Vec<_>>();
    let import_password_identities = prepared_password_identities
        .iter()
        .map(|candidate| candidate.identity.clone())
        .collect::<Vec<_>>();
    let import_proxy_profiles = prepared_proxy_profiles
        .iter()
        .map(|candidate| candidate.profile.clone())
        .collect::<Vec<_>>();
    let import_group_configs = prepared_group_configs
        .iter()
        .map(|candidate| candidate.group.clone())
        .collect::<Vec<_>>();
    let import_graph = SavedVaultGraph::new_with_notes_snippets(
        import_hosts,
        import_keys,
        import_managed_keys,
        import_identities,
        import_password_identities,
        import_proxy_profiles,
        import_group_configs,
        graph.notes_snippets().clone(),
    )
    .with_group_catalog(graph.group_catalog().cloned());
    let store = state.saved_hosts.clone();
    let plan_revision = expected_revision.clone();
    let plan_graph = import_graph.clone();
    let import_plan =
        tokio::task::spawn_blocking(move || store.plan_graph_import(plan_revision, &plan_graph))
            .await
            .map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "The legacy Vault relationship batch could not be planned",
                )
            })?
            .map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "The legacy Vault relationship batch could not be planned",
                )
            })?;
    let before_graph_commitment = import_plan.before_graph_commitment().clone();
    let after_graph_commitment = import_plan.after_graph_commitment().clone();
    let requires_blob_transaction = !final_managed_keys.is_empty() && import_plan.has_changes();
    if (credential_count > 0 || requires_blob_transaction) && !import_plan.has_changes() {
        return Err(legacy_import_repair_error());
    }
    let mut prepared_credentials = Vec::with_capacity(credential_count as usize);
    for candidate in &mut prepared {
        if let Some(secret) = candidate.credential.take() {
            prepared_credentials.push(PreparedLegacyCredential {
                owner: LegacyImportCredentialOwner::for_saved_host(&candidate.host.id),
                secret,
            });
        }
        if let Some(secret) = candidate.telnet_credential.take() {
            prepared_credentials.push(PreparedLegacyCredential {
                owner: LegacyImportCredentialOwner::for_saved_host_telnet(&candidate.host.id),
                secret,
            });
        }
        if let Some(secret) = candidate.inline_proxy_credential.take() {
            prepared_credentials.push(PreparedLegacyCredential {
                owner: LegacyImportCredentialOwner::for_host_inline_proxy(&candidate.host.id),
                secret,
            });
        }
    }
    for candidate in &mut prepared_password_identities {
        if let Some(secret) = candidate.credential.take() {
            let owner =
                LegacyImportCredentialOwner::for_password_identity(candidate.identity.id.as_str())
                    .map_err(|_| {
                        legacy_error(
                            LEGACY_VAULT_IMPORT_FAILED,
                            "An imported credential account could not be derived",
                        )
                    })?;
            prepared_credentials.push(PreparedLegacyCredential { owner, secret });
        }
    }
    for candidate in &mut prepared_proxy_profiles {
        if let Some(secret) = candidate.credential.take() {
            let owner =
                LegacyImportCredentialOwner::for_proxy_profile(candidate.profile.id.as_str())
                    .map_err(|_| {
                        legacy_error(
                            LEGACY_VAULT_IMPORT_FAILED,
                            "An imported proxy credential account could not be derived",
                        )
                    })?;
            prepared_credentials.push(PreparedLegacyCredential { owner, secret });
        }
    }
    for candidate in &mut prepared_group_configs {
        let group_id = candidate.group.id.as_str();
        if let Some(secret) = candidate.ssh_credential.take() {
            let owner = LegacyImportCredentialOwner::for_group_ssh(group_id).map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "An imported group credential account could not be derived",
                )
            })?;
            prepared_credentials.push(PreparedLegacyCredential { owner, secret });
        }
        if let Some(secret) = candidate.telnet_credential.take() {
            let owner = LegacyImportCredentialOwner::for_group_telnet(group_id).map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "An imported group credential account could not be derived",
                )
            })?;
            prepared_credentials.push(PreparedLegacyCredential { owner, secret });
        }
        if let Some(secret) = candidate.proxy_credential.take() {
            let owner = LegacyImportCredentialOwner::for_group_proxy(group_id).map_err(|_| {
                legacy_error(
                    LEGACY_VAULT_IMPORT_FAILED,
                    "An imported group credential account could not be derived",
                )
            })?;
            prepared_credentials.push(PreparedLegacyCredential { owner, secret });
        }
    }
    let credential_owners = prepared_credentials
        .iter()
        .map(|candidate| candidate.owner.clone())
        .collect::<Vec<_>>();
    let mut transaction = if credential_owners.is_empty() && !requires_blob_transaction {
        None
    } else if requires_blob_transaction {
        Some(
            begin_legacy_import_transaction_with_blobs_for_owners(
                state,
                credential_owners,
                before_graph_commitment,
                after_graph_commitment.clone(),
            )
            .await?,
        )
    } else {
        Some(
            begin_legacy_import_transaction_for_owners(
                state,
                credential_owners,
                before_graph_commitment,
                after_graph_commitment.clone(),
            )
            .await?,
        )
    };

    let mut previous_states = Vec::new();
    if let Some(preparing) = transaction.as_ref() {
        previous_states.reserve(preparing.entries().len());
        for candidate in &prepared_credentials {
            let kind = legacy_import_credential_kind_for_owner(&candidate.owner);
            let (reference, backup) =
                match legacy_import_credential_references_for_owner(preparing, &candidate.owner) {
                    Ok(references) => references,
                    Err(primary) => {
                        return Err(legacy_import_failure_with_recovery(state, primary).await);
                    }
                };
            let previous = match state.persistent_credentials.resolve(&reference, kind).await {
                Ok(previous) => Some(previous),
                Err(error) if error.code() == CredentialErrorCode::NotFound => None,
                Err(_) => {
                    let primary = legacy_error(
                        LEGACY_VAULT_CREDENTIAL_FAILED,
                        "A credential entry could not be backed up",
                    );
                    return Err(legacy_import_failure_with_recovery(state, primary).await);
                }
            };
            let previous_state = if let Some(previous) = previous {
                if state
                    .persistent_credentials
                    .upsert(&backup, kind, previous)
                    .await
                    .is_err()
                {
                    let primary = legacy_error(
                        LEGACY_VAULT_CREDENTIAL_FAILED,
                        "A credential entry could not be backed up",
                    );
                    return Err(legacy_import_failure_with_recovery(state, primary).await);
                }
                LegacyPreviousCredentialState::BackedUp
            } else {
                LegacyPreviousCredentialState::Absent
            };
            previous_states.push((candidate.owner.clone(), previous_state));
        }
    }

    let publications = final_managed_keys
        .iter()
        .zip(managed_secret_bundles)
        .map(|(key, bundle)| ManagedSecretPublication {
            entity_id: key.id.as_str().to_owned(),
            backend_locator: key.custody().backend_locator().as_str().to_owned(),
            custody_revision: key.custody().custody_revision(),
            bundle,
        })
        .collect::<Vec<_>>();
    let managed_secret_blobs_published_count = if publications.is_empty() {
        0
    } else {
        let Some(lease) = secret_lease.as_ref() else {
            return Err(legacy_secret_store_repair_error());
        };
        match lease.publish(publications).await {
            Ok(count) => count,
            Err(failure) => {
                let primary = failure.legacy_error();
                return if transaction.is_some() {
                    Err(legacy_import_failure_with_recovery(state, primary).await)
                } else {
                    Err(primary)
                };
            }
        }
    };

    if transaction
        .as_ref()
        .is_some_and(LegacyImportTransaction::requires_blob_publication)
    {
        let preparing = transaction.take().expect("transaction exists");
        transaction = match mark_legacy_blobs_durable(preparing).await {
            Ok(durable) => Some(durable),
            Err(primary) => {
                return Err(legacy_import_failure_with_recovery(state, primary).await);
            }
        };
    }

    if let Some(preparing) = transaction.take() {
        transaction =
            match activate_legacy_import_transaction_for_owners(preparing, previous_states).await {
                Ok(active) => Some(active),
                Err(primary) => {
                    return Err(legacy_import_failure_with_recovery(state, primary).await);
                }
            };
    }

    for candidate in prepared_credentials {
        let Some(active) = transaction.as_ref() else {
            return Err(legacy_import_repair_error());
        };
        let (reference, _) =
            match legacy_import_credential_references_for_owner(active, &candidate.owner) {
                Ok(references) => references,
                Err(primary) => {
                    return Err(legacy_import_failure_with_recovery(state, primary).await);
                }
            };
        let kind = legacy_import_credential_kind_for_owner(&candidate.owner);
        if state
            .persistent_credentials
            .upsert(&reference, kind, candidate.secret)
            .await
            .is_err()
        {
            let primary = legacy_error(
                LEGACY_VAULT_CREDENTIAL_FAILED,
                "A legacy credential could not be stored",
            );
            return Err(legacy_import_failure_with_recovery(state, primary).await);
        }
    }

    let store = state.saved_hosts.clone();
    // This is the sole Vault write for the whole batch.
    let committed = match tokio::task::spawn_blocking(move || {
        store.commit_planned_graph_import(import_plan, import_graph)
    })
    .await
    {
        Ok(Ok(committed)) => committed,
        Ok(Err(_)) | Err(_) => {
            let primary = legacy_error(
                LEGACY_VAULT_IMPORT_FAILED,
                "The legacy Vault relationship batch could not be committed",
            );
            return Err(legacy_import_failure_with_recovery(state, primary).await);
        }
    };
    let committed_revision = committed.revision().clone();
    if let Some(transaction) = transaction {
        // Confirm both Vault slot directories and the exact after graph while
        // the secret-store lease remains held. Managed transactions also
        // re-authenticate every referenced blob before publishing the durable
        // keep-target decision to both journal slots.
        let snapshot = confirm_current_legacy_vault_snapshot(state).await?;
        if snapshot.revision() != &committed_revision
            || snapshot.commitment() != &after_graph_commitment
        {
            return Err(legacy_import_repair_error());
        }
        if transaction.requires_blob_publication() {
            let Some(lease) = secret_lease.as_ref() else {
                return Err(legacy_secret_store_repair_error());
            };
            lease
                .confirm(managed_secret_references_from_graph(snapshot.graph()))
                .await?;
        }
        let transaction = mark_legacy_vault_durable(transaction).await?;
        cleanup_legacy_import_backups(state, &transaction).await?;
        finish_legacy_import_transaction(transaction).await?;
    } else if committed.durability() != SavedVaultCommitDurability::Durable {
        // A secret-free batch has no credential journal, but it still must not
        // report success for a vanished or superseded uncertain publication.
        let snapshot = confirm_current_legacy_vault_snapshot(state).await?;
        if snapshot.revision() != &committed_revision
            || snapshot.commitment() != &after_graph_commitment
        {
            return Err(legacy_import_repair_error());
        }
    }

    // Release the transaction-wide non-Send secret guard before starting a
    // fresh cleanup lease. Cleanup is best effort: the import is already
    // durable, and a GC failure must retain ciphertext rather than turn a
    // successful import into a misleading rollback error.
    drop(secret_lease);
    if managed_secret_blobs_published_count > 0 {
        let _ = garbage_collect_managed_secret_blobs(state).await;
    }

    Ok(LegacyVaultImportResult {
        imported_count: committed.imported().hosts().len() as u32,
        ssh_key_references_imported_count: committed.imported().ssh_key_references().len() as u32,
        identity_references_imported_count: committed.imported().identity_references().len() as u32,
        password_identities_imported_count: committed.imported().password_identities().len() as u32,
        proxy_profiles_imported_count: committed.imported().proxy_profiles().len() as u32,
        managed_ssh_keys_imported_count: committed.imported().managed_ssh_keys().len() as u32,
        managed_secret_blobs_published_count,
        remapped_entity_count,
        duplicate_count: source_duplicates.saturating_add(store_duplicates),
        conflict_count: conflicts,
        credentials_stored_count: credential_count,
        telnet_credentials_stored_count: host_telnet_credentials_stored_count,
        telnet_credential_reentry_required_count: telnet_requires_reentry,
        password_identity_credentials_stored_count,
        password_identity_credential_reentry_required_count: password_identity_requires_reentry,
        proxy_profile_credentials_stored_count,
        inline_proxy_credentials_stored_count,
        proxy_credential_reentry_required_count: proxy_profile_requires_reentry
            .saturating_add(inline_proxy_requires_reentry),
        custom_groups_imported_count: committed
            .imported()
            .group_catalog()
            .map_or(0, |catalog| catalog.explicit_paths().len() as u32),
        group_configs_imported_count: committed.imported().groups().len() as u32,
        snippets_imported_count: committed
            .imported()
            .notes_snippets()
            .snippets()
            .map_or(0, |values| values.len() as u32),
        snippet_packages_imported_count: committed
            .imported()
            .notes_snippets()
            .snippet_packages()
            .map_or(0, |values| values.len() as u32),
        notes_imported_count: committed
            .imported()
            .notes_snippets()
            .notes()
            .map_or(0, |values| values.len() as u32),
        note_groups_imported_count: committed
            .imported()
            .notes_snippets()
            .note_groups()
            .map_or(0, |values| values.len() as u32),
        requires_credential_reentry_count: requires_reentry
            .saturating_add(password_identity_requires_reentry)
            .saturating_add(proxy_profile_requires_reentry)
            .saturating_add(inline_proxy_requires_reentry)
            .saturating_add(group_credential_reentry_count),
    })
}

#[tauri::command]
async fn list_saved_hosts(state: State<'_, DesktopState>) -> Result<Vec<SavedHostView>, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        let store = state.saved_hosts.clone();
        let graph = run_blocking_result(move || store.graph()).await?;
        saved_host_views_from_graph(&graph)
    })
    .await
}

enum SavedHostCredentialAction {
    Remove {
        target: StoredCredentialReference,
    },
    Replace {
        target: StoredCredentialReference,
        secret: SecretValue,
    },
}

impl SavedHostCredentialAction {
    const fn target(&self) -> &StoredCredentialReference {
        match self {
            Self::Remove { target } | Self::Replace { target, .. } => target,
        }
    }
}

enum PlannedSavedHostPasswordCredentialMutation {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

async fn materialize_saved_host_credential_actions(
    state: &DesktopState,
    window_owner: &str,
    host_id: &SavedHostId,
    protocol: SavedHostProtocolRequest,
    password: PlannedSavedHostPasswordCredentialMutation,
    inline_proxy: Option<PreparedHostInlineProxyCredentialMutation>,
) -> Result<Vec<(LegacyImportCredentialOwner, SavedHostCredentialAction)>, String> {
    let staged_password = match &password {
        PlannedSavedHostPasswordCredentialMutation::Replace {
            staged_credential_reference,
        } => Some(staged_credential_reference),
        PlannedSavedHostPasswordCredentialMutation::Keep
        | PlannedSavedHostPasswordCredentialMutation::Remove => None,
    };
    let staged_proxy = inline_proxy
        .as_ref()
        .and_then(PreparedHostInlineProxyCredentialMutation::staged_credential_reference);
    // Validate and consume the complete owner-bound capability set under one
    // store lock. A stale peer must not consume an otherwise valid secret.
    let staged_references = [staged_password, staged_proxy]
        .into_iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let mut staged_secrets = state
        .ephemeral_credentials
        .take_many(window_owner, &staged_references)
        .await
        .map_err(|_| saved_host_invalid())?
        .into_iter();
    let password_secret = staged_password.map(|_| {
        staged_secrets
            .next()
            .expect("validated password capability yields one secret")
    });
    let proxy_secret = staged_proxy.map(|_| {
        staged_secrets
            .next()
            .expect("validated proxy capability yields one secret")
    });
    debug_assert!(staged_secrets.next().is_none());

    let mut actions = Vec::with_capacity(2);
    match password {
        PlannedSavedHostPasswordCredentialMutation::Keep => {}
        PlannedSavedHostPasswordCredentialMutation::Remove => {
            let target = saved_host_password_reference(host_id, protocol)?;
            actions.push((
                saved_host_password_owner(host_id, protocol)?,
                SavedHostCredentialAction::Remove { target },
            ));
        }
        PlannedSavedHostPasswordCredentialMutation::Replace { .. } => {
            let target = saved_host_password_reference(host_id, protocol)?;
            let secret = password_secret.ok_or_else(saved_host_invalid)?;
            actions.push((
                saved_host_password_owner(host_id, protocol)?,
                SavedHostCredentialAction::Replace { target, secret },
            ));
        }
    }
    match inline_proxy {
        None | Some(PreparedHostInlineProxyCredentialMutation::Keep { .. }) => {}
        Some(PreparedHostInlineProxyCredentialMutation::Remove { target }) => {
            actions.push((
                LegacyImportCredentialOwner::for_host_inline_proxy(host_id),
                SavedHostCredentialAction::Remove { target },
            ));
        }
        Some(PreparedHostInlineProxyCredentialMutation::Replace { target, .. }) => {
            let secret = proxy_secret.ok_or_else(saved_host_invalid)?;
            actions.push((
                LegacyImportCredentialOwner::for_host_inline_proxy(host_id),
                SavedHostCredentialAction::Replace { target, secret },
            ));
        }
    }
    Ok(actions)
}

fn saved_host_password_reference(
    host_id: &SavedHostId,
    protocol: SavedHostProtocolRequest,
) -> Result<StoredCredentialReference, String> {
    match protocol {
        SavedHostProtocolRequest::Ssh => {
            StoredCredentialReference::for_saved_host(host_id.as_str())
        }
        SavedHostProtocolRequest::Telnet => {
            StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
        }
        SavedHostProtocolRequest::Serial => return Err(saved_host_invalid()),
    }
    .map_err(|_| saved_host_repair_required())
}

fn saved_host_password_owner(
    host_id: &SavedHostId,
    protocol: SavedHostProtocolRequest,
) -> Result<LegacyImportCredentialOwner, String> {
    Ok(match protocol {
        SavedHostProtocolRequest::Ssh => LegacyImportCredentialOwner::for_saved_host(host_id),
        SavedHostProtocolRequest::Telnet => {
            LegacyImportCredentialOwner::for_saved_host_telnet(host_id)
        }
        SavedHostProtocolRequest::Serial => return Err(saved_host_invalid()),
    })
}

fn saved_host_password_kind(protocol: SavedHostProtocolRequest) -> Result<CredentialKind, String> {
    Ok(match protocol {
        SavedHostProtocolRequest::Ssh => CredentialKind::SshPassword,
        SavedHostProtocolRequest::Telnet => CredentialKind::TelnetPassword,
        SavedHostProtocolRequest::Serial => return Err(saved_host_invalid()),
    })
}

async fn saved_host_password_exists(
    state: &DesktopState,
    host_id: &SavedHostId,
    protocol: SavedHostProtocolRequest,
) -> Result<bool, String> {
    let reference = saved_host_password_reference(host_id, protocol)?;
    match state
        .persistent_credentials
        .resolve(&reference, saved_host_password_kind(protocol)?)
        .await
    {
        Ok(secret) => {
            drop(secret);
            Ok(true)
        }
        Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(false),
        Err(_) => Err(saved_host_repair_required()),
    }
}

fn saved_host_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

fn saved_host_invalid() -> String {
    saved_host_error(
        SAVED_HOST_CREDENTIAL_MUTATION_INVALID,
        "The saved-host request is invalid",
    )
}

fn saved_host_not_found() -> String {
    saved_host_error(SAVED_HOST_NOT_FOUND, "The saved host was not found")
}

fn saved_host_revision_conflict() -> String {
    saved_host_error(
        SAVED_HOST_REVISION_CONFLICT,
        "The saved host changed; refresh and retry",
    )
}

fn saved_host_publication_failed() -> String {
    saved_host_error(
        SAVED_HOST_PUBLICATION_FAILED,
        "The saved host could not be stored",
    )
}

fn saved_host_repair_required() -> String {
    saved_host_error(
        SAVED_HOST_REPAIR_REQUIRED,
        "Saved-host credential storage requires reconciliation",
    )
}

fn map_saved_host_store_error(error: StoreError) -> String {
    match error {
        StoreError::RevisionConflict { .. } | StoreError::InventoryRevisionConflict { .. } => {
            saved_host_revision_conflict()
        }
        StoreError::NotFound(_) => saved_host_not_found(),
        StoreError::Validation(_)
        | StoreError::DuplicateId(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => saved_host_invalid(),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => saved_host_repair_required(),
        _ => saved_host_publication_failed(),
    }
}

fn saved_host_graph_with_created_host(
    graph: SavedVaultGraph,
    host: SavedHost,
) -> Result<SavedVaultGraph, String> {
    let (
        mut hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    if hosts.iter().any(|candidate| candidate.id == host.id) {
        return Err(saved_host_invalid());
    }
    hosts.push(host);
    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

fn saved_host_graph_with_updated_host(
    graph: SavedVaultGraph,
    host: SavedHost,
) -> Result<SavedVaultGraph, String> {
    let (
        mut hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    let Some(index) = hosts.iter().position(|candidate| candidate.id == host.id) else {
        return Err(saved_host_not_found());
    };
    hosts[index] = host;
    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

fn saved_host_graph_without_host(
    graph: SavedVaultGraph,
    id: &SavedHostId,
) -> Result<SavedVaultGraph, String> {
    let (
        mut hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    let original_len = hosts.len();
    hosts.retain(|candidate| &candidate.id != id);
    if hosts.len() == original_len {
        return Err(saved_host_not_found());
    }
    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

async fn confirm_current_saved_host_snapshot(
    state: &DesktopState,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.confirm_current_snapshot_durability())
        .await
        .map_err(|_| saved_host_repair_required())?
        .map_err(map_saved_host_store_error)
}

async fn plan_saved_host_graph(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    target_graph: &SavedVaultGraph,
) -> Result<SavedVaultGraphReplacementPlan, String> {
    let store = state.saved_hosts.clone();
    let target_graph = target_graph.clone();
    tokio::task::spawn_blocking(move || {
        store.plan_graph_replacement(expected_revision, &target_graph)
    })
    .await
    .map_err(|_| saved_host_repair_required())?
    .map_err(map_saved_host_store_error)
}

async fn commit_planned_saved_host_graph(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<netcatty_vault::SavedVaultGraphReplacementCommit, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.commit_planned_graph_replacement(plan, target_graph))
        .await
        .map_err(|_| saved_host_repair_required())?
        .map_err(map_saved_host_store_error)
}

async fn confirm_exact_saved_host_commit(
    state: &DesktopState,
    expected_revision: &SavedVaultInventoryRevision,
    expected_commitment: &SavedVaultGraphCommitment,
    expected_graph: &SavedVaultGraph,
) -> Result<SavedVaultDurableSnapshot, String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    if snapshot.revision() != expected_revision
        || snapshot.commitment() != expected_commitment
        || snapshot.graph() != expected_graph
    {
        return Err(saved_host_repair_required());
    }
    Ok(snapshot)
}

async fn commit_saved_host_graph_without_credential(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<SavedVaultDurableSnapshot, String> {
    let after = plan.after_graph_commitment().clone();
    let committed = commit_planned_saved_host_graph(state, plan, target_graph).await?;
    confirm_exact_saved_host_commit(state, committed.revision(), &after, committed.graph()).await
}

async fn recover_saved_host_credential_transaction(
    state: &DesktopState,
    before: &SavedVaultGraphCommitment,
    after: &SavedVaultGraphCommitment,
    expected_after: Option<(SavedVaultInventoryRevision, SavedVaultGraph)>,
    primary: String,
) -> Result<SavedVaultDurableSnapshot, String> {
    if recover_pending_legacy_import(state).await.is_err() {
        return Err(saved_host_repair_required());
    }
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    if snapshot.commitment() == after {
        if let Some((expected_revision, expected_graph)) = expected_after
            && (snapshot.revision() != &expected_revision || snapshot.graph() != &expected_graph)
        {
            return Err(saved_host_repair_required());
        }
        return Ok(snapshot);
    }
    if snapshot.commitment() == before {
        return Err(primary);
    }
    Err(saved_host_repair_required())
}

async fn commit_saved_host_graph_with_credentials(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
    actions: Vec<(LegacyImportCredentialOwner, SavedHostCredentialAction)>,
) -> Result<SavedVaultDurableSnapshot, String> {
    if actions.is_empty() {
        return Err(saved_host_repair_required());
    }
    if !plan.has_changes() {
        return Err(saved_host_repair_required());
    }
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let owners = actions
        .iter()
        .map(|(owner, _)| owner.clone())
        .collect::<Vec<_>>();
    let mut transaction = match begin_legacy_import_transaction_for_owners(
        state,
        owners,
        before.clone(),
        after.clone(),
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(_) => {
            if recover_pending_legacy_import(state).await.is_err() {
                return Err(saved_host_repair_required());
            }
            return Err(saved_host_repair_required());
        }
    };

    let mut previous_states = Vec::with_capacity(actions.len());
    for (owner, action) in &actions {
        let (target, backup) =
            match legacy_import_credential_references_for_owner(&transaction, owner) {
                Ok(references) => references,
                Err(_) => {
                    return recover_saved_host_credential_transaction(
                        state,
                        &before,
                        &after,
                        None,
                        saved_host_repair_required(),
                    )
                    .await;
                }
            };
        if &target != action.target() {
            return recover_saved_host_credential_transaction(
                state,
                &before,
                &after,
                None,
                saved_host_repair_required(),
            )
            .await;
        }
        let credential_kind = legacy_import_credential_kind_for_owner(owner);

        // Presence hints are not custody authority. Probe every deterministic
        // account touched by the complete host mutation, including false hints.
        let previous = match state
            .persistent_credentials
            .resolve(&target, credential_kind)
            .await
        {
            Ok(previous) => Some(previous),
            Err(error) if error.code() == CredentialErrorCode::NotFound => None,
            Err(_) => {
                return recover_saved_host_credential_transaction(
                    state,
                    &before,
                    &after,
                    None,
                    saved_host_repair_required(),
                )
                .await;
            }
        };
        let previous_state = if let Some(previous) = previous {
            if state
                .persistent_credentials
                .upsert(&backup, credential_kind, previous)
                .await
                .is_err()
            {
                return recover_saved_host_credential_transaction(
                    state,
                    &before,
                    &after,
                    None,
                    saved_host_publication_failed(),
                )
                .await;
            }
            LegacyPreviousCredentialState::BackedUp
        } else {
            LegacyPreviousCredentialState::Absent
        };
        previous_states.push((owner.clone(), previous_state));
    }

    transaction =
        match activate_legacy_import_transaction_for_owners(transaction, previous_states).await {
            Ok(transaction) => transaction,
            Err(_) => {
                return recover_saved_host_credential_transaction(
                    state,
                    &before,
                    &after,
                    None,
                    saved_host_repair_required(),
                )
                .await;
            }
        };

    for (owner, action) in actions {
        let credential_kind = legacy_import_credential_kind_for_owner(&owner);
        let mutation = match action {
            SavedHostCredentialAction::Remove { target } => {
                state.persistent_credentials.delete(&target).await
            }
            SavedHostCredentialAction::Replace { target, secret } => {
                state
                    .persistent_credentials
                    .upsert(&target, credential_kind, secret)
                    .await
            }
        };
        if mutation.is_err() {
            return recover_saved_host_credential_transaction(
                state,
                &before,
                &after,
                None,
                saved_host_publication_failed(),
            )
            .await;
        }
    }

    let committed = match commit_planned_saved_host_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(primary) => {
            return recover_saved_host_credential_transaction(
                state, &before, &after, None, primary,
            )
            .await;
        }
    };
    let expected_after = (committed.revision().clone(), committed.graph().clone());
    let snapshot = match confirm_exact_saved_host_commit(
        state,
        committed.revision(),
        &after,
        committed.graph(),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(primary) => {
            return recover_saved_host_credential_transaction(
                state,
                &before,
                &after,
                Some(expected_after),
                primary,
            )
            .await;
        }
    };

    transaction = match mark_legacy_vault_durable(transaction).await {
        Ok(transaction) => transaction,
        Err(_) => {
            return recover_saved_host_credential_transaction(
                state,
                &before,
                &after,
                Some(expected_after),
                saved_host_repair_required(),
            )
            .await;
        }
    };
    if cleanup_legacy_import_backups(state, &transaction)
        .await
        .is_err()
    {
        return recover_saved_host_credential_transaction(
            state,
            &before,
            &after,
            Some(expected_after),
            saved_host_repair_required(),
        )
        .await;
    }
    if finish_legacy_import_transaction(transaction).await.is_err() {
        return recover_saved_host_credential_transaction(
            state,
            &before,
            &after,
            Some(expected_after),
            saved_host_repair_required(),
        )
        .await;
    }
    Ok(snapshot)
}

#[tauri::command]
async fn create_saved_host(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: CreateSavedHostRequest,
) -> Result<SavedHostView, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        create_saved_host_inner(&state, &owner, request).await
    })
    .await
}

async fn create_saved_host_inner(
    state: &DesktopState,
    owner: &str,
    request: CreateSavedHostRequest,
) -> Result<SavedHostView, String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let CreateSavedHostRequest {
        mut draft,
        staged_credential_reference,
    } = request;
    let credential_protocol = draft.protocol;
    let has_staged_credential = staged_credential_reference.is_some();
    validate_saved_host_authentication_selection(&draft, snapshot.graph(), has_staged_credential)?;
    let proxy_plan = draft
        .proxy
        .take()
        .map(|request| prepare_saved_host_proxy_creation(snapshot.graph(), request))
        .transpose()?;
    let mut vault_draft =
        create_vault_draft(draft, has_staged_credential).map_err(|_| saved_host_invalid())?;
    if let Some(proxy_plan) = &proxy_plan {
        vault_draft = proxy_plan.apply_to_draft(vault_draft)?;
    }
    let host = SavedHost::from_draft(vault_draft, current_unix_millis()?)
        .map_err(|_| saved_host_invalid())?;
    let target_graph = saved_host_graph_with_created_host(snapshot.graph().clone(), host.clone())?;
    let _ = plan_saved_host_chain(&target_graph, &host)?;
    let plan = plan_saved_host_graph(state, snapshot.revision().clone(), &target_graph).await?;
    let inline_proxy = proxy_plan
        .map(|prepared| prepared.into_credential(&host.id))
        .transpose()?;
    let password = match staged_credential_reference {
        Some(staged_credential_reference) => PlannedSavedHostPasswordCredentialMutation::Replace {
            staged_credential_reference,
        },
        None => PlannedSavedHostPasswordCredentialMutation::Keep,
    };
    // The complete relationship graph and CAS plan are validated before either
    // owner-bound one-shot secret is consumed.
    let actions = materialize_saved_host_credential_actions(
        state,
        owner,
        &host.id,
        credential_protocol,
        password,
        inline_proxy,
    )
    .await?;
    let committed = if actions.is_empty() {
        commit_saved_host_graph_without_credential(state, plan, target_graph).await?
    } else {
        commit_saved_host_graph_with_credentials(state, plan, target_graph, actions).await?
    };
    let committed_host = committed
        .graph()
        .hosts()
        .iter()
        .find(|candidate| candidate.id == host.id)
        .ok_or_else(saved_host_repair_required)?;
    saved_host_view_from_graph(committed_host, committed.graph())
}

#[tauri::command]
async fn update_saved_host(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: UpdateSavedHostRequest,
) -> Result<SavedHostView, String> {
    let owner = window.label().to_owned();
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        update_saved_host_inner(&state, &owner, request).await
    })
    .await
}

async fn update_saved_host_inner(
    state: &DesktopState,
    owner: &str,
    request: UpdateSavedHostRequest,
) -> Result<SavedHostView, String> {
    let UpdateSavedHostRequest {
        id,
        expected_revision,
        mut draft,
        credential_mutation,
    } = request;
    let id = SavedHostId::from_opaque(id).map_err(|_| saved_host_invalid())?;
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let current = snapshot
        .graph()
        .hosts()
        .iter()
        .find(|host| host.id == id)
        .cloned()
        .ok_or_else(saved_host_not_found)?;
    if current.revision != expected_revision {
        return Err(saved_host_revision_conflict());
    }
    let target_protocol = draft.protocol;
    if target_protocol == SavedHostProtocolRequest::Serial
        && !matches!(&credential_mutation, SavedHostCredentialMutation::Keep)
    {
        return Err(saved_host_invalid());
    }
    let target_uses_password = target_protocol != SavedHostProtocolRequest::Serial
        && (target_protocol == SavedHostProtocolRequest::Telnet
            || matches!(
                draft.auth_method,
                SavedHostAuthenticationMethodRequest::Password
            ));
    let current_protocol = if current.protocol.is_telnet() {
        SavedHostProtocolRequest::Telnet
    } else if current.protocol.is_serial() {
        SavedHostProtocolRequest::Serial
    } else {
        SavedHostProtocolRequest::Ssh
    };
    let had_credential = if target_uses_password && current_protocol == target_protocol {
        has_saved_credential(&current)
    } else if target_uses_password {
        // The flattened Vault hint describes only the active protocol.  On a
        // protocol switch, inspect the destination namespace so Keep can
        // reactivate an existing isolated account without copying or
        // overwriting the source protocol's password.
        saved_host_password_exists(state, &current.id, target_protocol).await?
    } else {
        false
    };
    let has_target_credential = if target_uses_password {
        match &credential_mutation {
            SavedHostCredentialMutation::Keep => had_credential,
            SavedHostCredentialMutation::Remove => false,
            SavedHostCredentialMutation::Replace { .. } => true,
        }
    } else {
        matches!(
            &credential_mutation,
            SavedHostCredentialMutation::Replace { .. }
        )
    };
    validate_saved_host_authentication_selection(&draft, snapshot.graph(), has_target_credential)?;
    let proxy_request = if target_protocol != SavedHostProtocolRequest::Ssh {
        SavedHostProxyMutationRequest {
            inline_proxy: HostInlineProxyMutationRequest::Remove,
            profile: HostProxyProfileMutationRequest::Remove,
        }
    } else {
        draft.proxy.take().unwrap_or(SavedHostProxyMutationRequest {
            inline_proxy: HostInlineProxyMutationRequest::Keep,
            profile: HostProxyProfileMutationRequest::Keep,
        })
    };
    let proxy_plan = prepare_saved_host_proxy_update(snapshot.graph(), &current, proxy_request)?;
    let mut update =
        create_vault_update(draft, has_target_credential).map_err(|_| saved_host_invalid())?;
    update = proxy_plan.apply_to_update(update)?;
    let updated = current
        .apply_update(update, current_unix_millis()?)
        .map_err(|_| saved_host_invalid())?;
    let target_graph =
        saved_host_graph_with_updated_host(snapshot.graph().clone(), updated.clone())?;
    let _ = plan_saved_host_chain(&target_graph, &updated)?;
    let plan = plan_saved_host_graph(state, snapshot.revision().clone(), &target_graph).await?;
    let inline_proxy = Some(proxy_plan.into_credential(&updated.id)?);
    let password = match (target_protocol, target_uses_password, credential_mutation) {
        (SavedHostProtocolRequest::Serial, false, SavedHostCredentialMutation::Keep) => {
            PlannedSavedHostPasswordCredentialMutation::Keep
        }
        (_, false, _) => PlannedSavedHostPasswordCredentialMutation::Remove,
        (_, true, SavedHostCredentialMutation::Keep) => {
            PlannedSavedHostPasswordCredentialMutation::Keep
        }
        (_, true, SavedHostCredentialMutation::Remove) => {
            PlannedSavedHostPasswordCredentialMutation::Remove
        }
        (
            _,
            true,
            SavedHostCredentialMutation::Replace {
                staged_credential_reference,
            },
        ) => PlannedSavedHostPasswordCredentialMutation::Replace {
            staged_credential_reference,
        },
    };
    let actions = materialize_saved_host_credential_actions(
        state,
        owner,
        &updated.id,
        target_protocol,
        password,
        inline_proxy,
    )
    .await?;
    let committed = if actions.is_empty() {
        commit_saved_host_graph_without_credential(state, plan, target_graph).await?
    } else {
        commit_saved_host_graph_with_credentials(state, plan, target_graph, actions).await?
    };
    let committed_host = committed
        .graph()
        .hosts()
        .iter()
        .find(|candidate| candidate.id == updated.id)
        .ok_or_else(saved_host_repair_required)?;
    saved_host_view_from_graph(committed_host, committed.graph())
}

#[tauri::command]
async fn delete_saved_host(
    state: State<'_, DesktopState>,
    request: DeleteSavedHostRequest,
) -> Result<(), String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        delete_saved_host_inner(&state, request).await
    })
    .await
}

async fn delete_saved_host_inner(
    state: &DesktopState,
    request: DeleteSavedHostRequest,
) -> Result<(), String> {
    let id = SavedHostId::from_opaque(request.id).map_err(|_| saved_host_invalid())?;
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let current = snapshot
        .graph()
        .hosts()
        .iter()
        .find(|host| host.id == id)
        .cloned()
        .ok_or_else(saved_host_not_found)?;
    if current.revision != request.expected_revision {
        return Err(saved_host_revision_conflict());
    }
    let target_graph = saved_host_graph_without_host(snapshot.graph().clone(), &current.id)?;
    let plan = plan_saved_host_graph(state, snapshot.revision().clone(), &target_graph).await?;
    let host_target = stored_reference(&current).map_err(|_| saved_host_repair_required())?;
    let telnet_target = StoredCredentialReference::for_saved_host_telnet(current.id.as_str())
        .map_err(|_| saved_host_repair_required())?;
    let proxy_target = StoredCredentialReference::for_saved_host_proxy(current.id.as_str())
        .map_err(|_| saved_host_repair_required())?;
    // Deletion probes and removes both deterministic accounts regardless of
    // their metadata hints, under one graph-bound journal decision.
    let committed = commit_saved_host_graph_with_credentials(
        state,
        plan,
        target_graph,
        vec![
            (
                LegacyImportCredentialOwner::for_saved_host(&current.id),
                SavedHostCredentialAction::Remove {
                    target: host_target,
                },
            ),
            (
                LegacyImportCredentialOwner::for_saved_host_telnet(&current.id),
                SavedHostCredentialAction::Remove {
                    target: telnet_target,
                },
            ),
            (
                LegacyImportCredentialOwner::for_host_inline_proxy(&current.id),
                SavedHostCredentialAction::Remove {
                    target: proxy_target,
                },
            ),
        ],
    )
    .await?;
    if committed
        .graph()
        .hosts()
        .iter()
        .any(|host| host.id == current.id)
    {
        return Err(saved_host_repair_required());
    }
    Ok(())
}

#[tauri::command]
async fn start_saved_host_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartSavedHostSessionRequest,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSshSession, String> {
    let owner = window.label().to_owned();
    let prepared =
        prepare_saved_host_session_operation(state.inner().clone(), owner, request).await?;
    begin_prepared_saved_host_session(&window, &state, prepared, on_control, on_data).await
}

struct PreparedSavedHostTelnetSession {
    config: netcatty_telnet::TelnetRuntimeConfig,
    connection_log: ConnectionLogCapture,
}

#[tauri::command]
async fn start_saved_telnet_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartSavedTelnetSessionRequest,
    on_control: Channel<TelnetControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedTelnetSession, String> {
    // Validate every renderer-controlled metadata field before claiming the
    // optional one-shot password. The durable host and projection are checked
    // again under the saved-host process/file coordinator below.
    let host_id =
        SavedHostId::from_opaque(request.host_id.clone()).map_err(|_| saved_host_invalid())?;
    if request.expected_revision == 0 {
        return Err(saved_host_invalid());
    }
    let terminal = SavedTelnetTerminalOptions::new(request.size.columns, request.size.rows)
        .and_then(|terminal| terminal.with_terminal_type(request.terminal.clone()))
        .map_err(|error| error.to_string())?;
    // Pixel dimensions belong to the shared terminal envelope. Telnet NAWS
    // transmits character cells only, so retain their strict u32 parse while
    // deliberately excluding them from the runtime configuration.
    let _pixel_size = (request.size.pixel_width, request.size.pixel_height);
    let one_shot = take_optional_ephemeral_secret(
        state.inner(),
        window.label(),
        request.credential_reference.as_ref(),
    )
    .await?;
    let expected_revision = request.expected_revision;

    let prepared = run_saved_host_operation(state.inner().clone(), move |state| async move {
        prepare_saved_host_telnet_session(&state, host_id, expected_revision, one_shot, terminal)
            .await
    })
    .await?;

    begin_telnet_session(
        state.inner(),
        prepared.config,
        prepared.connection_log,
        on_control,
        on_data,
    )
    .await
}

async fn prepare_saved_host_telnet_session(
    state: &DesktopState,
    host_id: SavedHostId,
    expected_revision: u64,
    one_shot: Option<SecretValue>,
    terminal: SavedTelnetTerminalOptions,
) -> Result<PreparedSavedHostTelnetSession, String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let graph = snapshot.graph().clone();
    let mut matches = graph.hosts().iter().filter(|host| host.id == host_id);
    let durable_host = matches.next().ok_or_else(saved_host_not_found)?;
    if matches.next().is_some() {
        return Err(saved_host_repair_required());
    }
    if durable_host.revision != expected_revision {
        return Err(saved_host_revision_conflict());
    }
    let projection = project_saved_host_connection(durable_host, graph.groups())
        .map_err(|_| saved_host_repair_required())?;
    let resolved: ResolvedSavedTelnetSession = resolve_saved_telnet_session(
        &state.persistent_credentials,
        &graph,
        &projection,
        one_shot,
        terminal,
    )
    .await
    .map_err(|error| error.to_string())?;
    let connection_log = ConnectionLogCapture::saved_telnet(
        projection.effective_host(),
        resolved.metadata().username(),
    );
    let (config, repairs) = resolved
        .into_runtime_config()
        .map_err(|error| error.to_string())?;

    if !repairs.is_empty() {
        let target_graph =
            apply_saved_telnet_hint_repairs_to_graph(graph, repairs, current_unix_millis()?)?;
        let plan = plan_saved_host_graph(state, snapshot.revision().clone(), &target_graph).await?;
        commit_saved_host_graph_without_credential(state, plan, target_graph).await?;
    }

    Ok(PreparedSavedHostTelnetSession {
        config,
        connection_log,
    })
}

struct PreparedSavedHostSerialSession {
    config: netcatty_serial::SerialRuntimeConfig,
    connection_log: ConnectionLogCapture,
}

#[tauri::command]
async fn start_saved_serial_session(
    state: State<'_, DesktopState>,
    request: StartSavedSerialSessionRequest,
    on_control: Channel<SerialControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSerialSession, String> {
    let host_id = SavedHostId::from_opaque(request.host_id).map_err(|_| saved_host_invalid())?;
    if request.expected_revision == 0 {
        return Err(saved_host_invalid());
    }
    let expected_revision = request.expected_revision;
    let size = request.size;
    let prepared = run_saved_host_operation(state.inner().clone(), move |state| async move {
        prepare_saved_host_serial_session(&state, host_id, expected_revision, size).await
    })
    .await?;
    begin_serial_session(
        state.inner(),
        prepared.config,
        prepared.connection_log,
        on_control,
        on_data,
    )
    .await
}

async fn prepare_saved_host_serial_session(
    state: &DesktopState,
    host_id: SavedHostId,
    expected_revision: u64,
    size: SerialTerminalSize,
) -> Result<PreparedSavedHostSerialSession, String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let graph = snapshot.graph();
    let mut matches = graph.hosts().iter().filter(|host| host.id == host_id);
    let durable_host = matches.next().ok_or_else(saved_host_not_found)?;
    if matches.next().is_some() {
        return Err(saved_host_repair_required());
    }
    if durable_host.revision != expected_revision {
        return Err(saved_host_revision_conflict());
    }
    let projection = project_saved_host_connection(durable_host, graph.groups())
        .map_err(|_| saved_host_repair_required())?;
    let effective_host = projection.effective_host();
    if !effective_host.protocol.is_serial()
        || projection.ssh_credential_owner().is_some()
        || projection.telnet_credential_owner().is_some()
        || projection.inline_proxy_credential_owner().is_some()
        || !projection.host_chain_ids().is_empty()
    {
        return Err(saved_host_invalid());
    }

    let saved_config = effective_host
        .effective_serial_config()
        .map_err(|_| saved_host_repair_required())?;
    let serial_config: netcatty_serial::SerialConfig = serde_json::from_value(
        serde_json::to_value(saved_config).map_err(|_| saved_host_repair_required())?,
    )
    .map_err(|_| saved_host_repair_required())?;
    let charset = match effective_host.compatibility_fields().get("charset") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(saved_host_repair_required()),
    };
    let config = serial_session::build_runtime_config(serial_config, size, charset)?;
    let connection_log = ConnectionLogCapture::saved_serial(effective_host);
    Ok(PreparedSavedHostSerialSession {
        config,
        connection_log,
    })
}

fn apply_saved_telnet_hint_repairs_to_graph(
    graph: SavedVaultGraph,
    repairs: Vec<SavedTelnetHintRepair>,
    now: u64,
) -> Result<SavedVaultGraph, String> {
    let (
        mut hosts,
        references,
        managed_keys,
        identities,
        mut password_identities,
        proxy_profiles,
        mut groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();

    for repair in repairs {
        match repair {
            SavedTelnetHintRepair::PasswordIdentity {
                identity_id,
                expected_revision,
            } => {
                let matching = password_identities
                    .iter()
                    .enumerate()
                    .filter(|(_, identity)| identity.id == identity_id)
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                let [index] = matching.as_slice() else {
                    return Err(saved_host_repair_required());
                };
                let current = &password_identities[*index];
                if current.revision != expected_revision || !current.has_saved_credential {
                    return Err(saved_host_repair_required());
                }
                let mut update = SavedPasswordIdentityUpdate::default();
                update.has_saved_credential = Some(false);
                password_identities[*index] = current
                    .apply_update(update, now)
                    .map_err(|_| saved_host_repair_required())?;
            }
            SavedTelnetHintRepair::Host {
                host_id,
                expected_revision,
            } => {
                let matching = hosts
                    .iter()
                    .enumerate()
                    .filter(|(_, host)| host.id == host_id)
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                let [index] = matching.as_slice() else {
                    return Err(saved_host_repair_required());
                };
                let current = &hosts[*index];
                if current.revision != expected_revision
                    || !current.protocol.is_telnet()
                    || !matches!(
                        current.compatibility_fields().get("hasSavedCredential"),
                        Some(serde_json::Value::Bool(true))
                    )
                {
                    return Err(saved_host_repair_required());
                }
                let update = SavedHostUpdate::default()
                    .with_compatibility_field("hasSavedCredential", serde_json::Value::Bool(false))
                    .map_err(|_| saved_host_repair_required())?;
                hosts[*index] = current
                    .apply_update(update, now)
                    .map_err(|_| saved_host_repair_required())?;
            }
            SavedTelnetHintRepair::Group {
                group_id,
                expected_revision,
            } => {
                let matching = groups
                    .iter()
                    .enumerate()
                    .filter(|(_, group)| group.id == group_id)
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                let [index] = matching.as_slice() else {
                    return Err(saved_host_repair_required());
                };
                let current = &groups[*index];
                if current.revision != expected_revision
                    || current.defaults.telnet_password != SavedGroupCredentialOverride::StoredHint
                {
                    return Err(saved_host_repair_required());
                }
                let mut defaults = current.defaults.clone();
                // A stale child hint disappears back into normal ancestor
                // inheritance. `Clear` would incorrectly block the parent.
                defaults.telnet_password = SavedGroupCredentialOverride::Inherit;
                groups[*index] = current
                    .apply_update(
                        SavedGroupConfigUpdate {
                            path: None,
                            defaults: Some(defaults),
                        },
                        now,
                    )
                    .map_err(|_| saved_host_repair_required())?;
            }
        }
    }

    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

struct PreparedSavedHostSession {
    client_attempt_id: ClientAttemptId,
    config: SshConnectionConfig,
    credentials: ConnectionCredentials,
    jump_hosts: Vec<PreparedSavedHostJump>,
    known_hosts: Vec<KnownHost>,
    verify_host_keys: bool,
    shell: Option<ShellOptions>,
    connection_log: ConnectionLogCapture,
    effective_mosh_enabled: bool,
}

fn project_vault_known_hosts(known_hosts: &[SavedKnownHost]) -> Vec<KnownHost> {
    known_hosts
        .iter()
        .map(|known| KnownHost {
            id: known.id.clone(),
            hostname: known.hostname.clone(),
            port: Some(known.port),
            key_type: known.key_type.clone(),
            fingerprint: known.fingerprint.clone(),
            public_key: Some(known.public_key.clone()),
        })
        .collect()
}

fn merge_connection_known_hosts(
    persisted: &[SavedKnownHost],
    requested: Vec<KnownHost>,
) -> Vec<KnownHost> {
    let mut merged = project_vault_known_hosts(persisted);
    for mut incoming in requested {
        let index = merged
            .iter()
            .position(|existing| existing.id == incoming.id)
            .or_else(|| {
                merged.iter().position(|existing| {
                    existing
                        .hostname
                        .trim()
                        .eq_ignore_ascii_case(incoming.hostname.trim())
                        && existing.port.unwrap_or(22) == incoming.port.unwrap_or(22)
                        && existing.key_type == incoming.key_type
                })
            });
        if let Some(index) = index {
            incoming.id.clone_from(&merged[index].id);
            merged[index] = incoming;
        } else {
            merged.push(incoming);
        }
    }
    merged
}

async fn load_connection_known_hosts(
    state: &DesktopState,
    requested: Vec<KnownHost>,
) -> Result<Vec<KnownHost>, String> {
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    Ok(merge_connection_known_hosts(
        snapshot.known_hosts(),
        requested,
    ))
}

struct PreparedSavedHostJump {
    host_id: String,
    config: SshConnectionConfig,
    credentials: ConnectionCredentials,
}

struct PreparedSavedHostChainResolver {
    endpoints: tokio::sync::Mutex<std::collections::HashMap<String, ResolvedSshEndpoint>>,
}

#[async_trait::async_trait]
impl HostChainResolver for PreparedSavedHostChainResolver {
    async fn resolve(&self, host_id: &str) -> Result<ResolvedSshEndpoint, TransportError> {
        self.endpoints.lock().await.remove(host_id).ok_or_else(|| {
            TransportError::new(
                TransportErrorCode::ConnectionFailed,
                "Saved jump-host resolution failed",
            )
        })
    }
}

struct StagedSavedHostSessionSecrets {
    credential: Option<SecretValue>,
    proxy_credential: Option<SecretValue>,
    key_passphrase: Option<SecretValue>,
}

async fn take_optional_ephemeral_secret(
    state: &DesktopState,
    owner: &str,
    reference: Option<&EphemeralCredentialReference>,
) -> Result<Option<SecretValue>, String> {
    match reference {
        Some(reference) => state
            .ephemeral_credentials
            .take(owner, reference)
            .await
            .map(Some)
            .map_err(|error| error.to_string()),
        None => Ok(None),
    }
}

/// Drains every one-shot reference before the saved-host process/file locks
/// and recovery boundary. All attempts always run; errors retain request-field
/// order. Any successfully drained peer secret is dropped and zeroized.
async fn drain_saved_host_session_secrets(
    state: &DesktopState,
    owner: &str,
    request: &StartSavedHostSessionRequest,
) -> Result<StagedSavedHostSessionSecrets, String> {
    let (credential, proxy_credential, key_passphrase) = tokio::join!(
        take_optional_ephemeral_secret(state, owner, request.credential_reference.as_ref()),
        take_optional_ephemeral_secret(state, owner, request.proxy_credential_reference.as_ref()),
        take_optional_ephemeral_secret(state, owner, request.key_passphrase_reference.as_ref()),
    );
    match (credential, proxy_credential, key_passphrase) {
        (Err(first), _, _) => Err(first),
        (Ok(_), Err(second), _) => Err(second),
        (Ok(_), Ok(_), Err(third)) => Err(third),
        (Ok(credential), Ok(proxy_credential), Ok(key_passphrase)) => {
            Ok(StagedSavedHostSessionSecrets {
                credential,
                proxy_credential,
                key_passphrase,
            })
        }
    }
}

async fn prepare_saved_host_session_operation(
    state: DesktopState,
    owner: String,
    request: StartSavedHostSessionRequest,
) -> Result<PreparedSavedHostSession, String> {
    // Drain on the Tauri command path before acquiring either saved-host lock
    // or attempting journal recovery. Once drained, the secret-owning values
    // move into the detached coordinator and survive invoke cancellation.
    let staged = drain_saved_host_session_secrets(&state, &owner, &request).await?;
    run_saved_host_operation(state, move |state| async move {
        prepare_saved_host_session(&state, request, staged).await
    })
    .await
}

fn saved_password_identity_hint_repair_error() -> String {
    format!(
        "{SAVED_PASSWORD_IDENTITY_HINT_REPAIR_FAILED}: Password identity metadata could not be repaired"
    )
}

async fn clear_missing_password_identity_credential_hint(
    state: &DesktopState,
    identity_id: SavedPasswordIdentityId,
    expected_record_revision: u64,
) -> Result<(), String> {
    let store = state.saved_hosts.clone();
    run_blocking_result(move || {
        let repair_error = saved_password_identity_hint_repair_error;
        let snapshot = store
            .confirm_current_snapshot_durability()
            .map_err(|_| repair_error())?;
        let expected_inventory_revision = snapshot.revision().clone();
        let mut target_graph = snapshot.graph().clone();
        let current = target_graph
            .password_identities()
            .iter()
            .find(|identity| identity.id == identity_id)
            .cloned()
            .ok_or_else(repair_error)?;
        if current.revision != expected_record_revision || !current.has_saved_credential {
            return Err(repair_error());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| repair_error())?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| repair_error())?;
        let mut update = SavedPasswordIdentityUpdate::default();
        update.has_saved_credential = Some(false);
        let updated = current
            .apply_update(update, now)
            .map_err(|_| repair_error())?;

        let (
            hosts,
            references,
            managed_keys,
            identities,
            mut password_identities,
            proxy_profiles,
            groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
        ) = target_graph.into_current_parts();
        let index = password_identities
            .iter()
            .position(|identity| identity.id == identity_id)
            .ok_or_else(repair_error)?;
        password_identities[index] = updated;
        target_graph = SavedVaultGraph::new_with_port_forward_rules(
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            proxy_profiles,
            groups,
            notes_snippets,
            port_forward_rules,
        )
        .with_group_catalog(custom_groups);

        let plan = store
            .plan_graph_replacement(expected_inventory_revision, &target_graph)
            .map_err(|_| repair_error())?;
        let committed = store
            .commit_planned_graph_replacement(plan, target_graph)
            .map_err(|_| repair_error())?;
        if committed.durability() != SavedVaultCommitDurability::Durable {
            let confirmed = store
                .confirm_current_snapshot_durability()
                .map_err(|_| repair_error())?;
            if confirmed.revision() != committed.revision()
                || confirmed.graph() != committed.graph()
            {
                return Err(repair_error());
            }
        }
        Ok(())
    })
    .await
}

fn saved_proxy_hint_repair_error() -> String {
    format!("{SAVED_PROXY_HINT_REPAIR_FAILED}: Saved proxy metadata could not be repaired")
}

async fn clear_missing_host_inline_proxy_credential_hint(
    state: &DesktopState,
    host: &SavedHost,
) -> Result<(), String> {
    let config = host
        .proxy_config()
        .map_err(|_| saved_proxy_hint_repair_error())?
        .ok_or_else(saved_proxy_hint_repair_error)?
        .with_saved_credential_hint(false)
        .map_err(|_| saved_proxy_hint_repair_error())?;
    let update = SavedHostUpdate::default()
        .with_proxy_config(config)
        .map_err(|_| saved_proxy_hint_repair_error())?;
    let store = state.saved_hosts.clone();
    let id = host.id.clone();
    let revision = host.revision;
    run_blocking_result(move || store.update(&id, revision, update))
        .await
        .map(|_| ())
        .map_err(|_| saved_proxy_hint_repair_error())
}

async fn clear_missing_proxy_profile_credential_hint(
    state: &DesktopState,
    profile_id: SavedProxyProfileId,
    expected_record_revision: u64,
) -> Result<(), String> {
    let store = state.saved_hosts.clone();
    run_blocking_result(move || {
        let repair_error = saved_proxy_hint_repair_error;
        let snapshot = store
            .confirm_current_snapshot_durability()
            .map_err(|_| repair_error())?;
        let expected_inventory_revision = snapshot.revision().clone();
        let mut target_graph = snapshot.graph().clone();
        let current = target_graph
            .proxy_profiles()
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
            .ok_or_else(repair_error)?;
        if current.revision != expected_record_revision {
            return Err(repair_error());
        }

        let config = current
            .config
            .clone()
            .with_saved_credential_hint(false)
            .map_err(|_| repair_error())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| repair_error())?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| repair_error())?;
        let mut update = SavedProxyProfileUpdate::default();
        update.config = Some(config);
        let updated = current
            .apply_update(update, now)
            .map_err(|_| repair_error())?;

        let (
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            mut profiles,
            groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
        ) = target_graph.into_current_parts();
        let index = profiles
            .iter()
            .position(|profile| profile.id == profile_id)
            .ok_or_else(repair_error)?;
        profiles[index] = updated;
        target_graph = SavedVaultGraph::new_with_port_forward_rules(
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            profiles,
            groups,
            notes_snippets,
            port_forward_rules,
        )
        .with_group_catalog(custom_groups);

        let plan = store
            .plan_graph_replacement(expected_inventory_revision, &target_graph)
            .map_err(|_| repair_error())?;
        let committed = store
            .commit_planned_graph_replacement(plan, target_graph)
            .map_err(|_| repair_error())?;
        if committed.durability() != SavedVaultCommitDurability::Durable {
            let confirmed = store
                .confirm_current_snapshot_durability()
                .map_err(|_| repair_error())?;
            if confirmed.revision() != committed.revision()
                || confirmed.graph() != committed.graph()
            {
                return Err(repair_error());
            }
        }
        Ok(())
    })
    .await
}

#[derive(Clone, Copy)]
enum SavedGroupCredentialHintKind {
    Ssh,
    Proxy,
}

fn saved_group_hint_repair_error() -> String {
    format!(
        "{SAVED_GROUP_HINT_REPAIR_FAILED}: Saved group credential metadata could not be repaired"
    )
}

async fn clear_missing_group_credential_hint(
    state: &DesktopState,
    group_id: SavedGroupId,
    expected_record_revision: u64,
    kind: SavedGroupCredentialHintKind,
) -> Result<(), String> {
    let store = state.saved_hosts.clone();
    run_blocking_result(move || {
        let repair_error = saved_group_hint_repair_error;
        let snapshot = store
            .confirm_current_snapshot_durability()
            .map_err(|_| repair_error())?;
        let expected_inventory_revision = snapshot.revision().clone();
        let mut target_graph = snapshot.graph().clone();
        let current = target_graph
            .groups()
            .iter()
            .find(|group| group.id == group_id)
            .cloned()
            .ok_or_else(repair_error)?;
        if current.revision != expected_record_revision {
            return Err(repair_error());
        }

        let mut defaults = current.defaults.clone();
        match kind {
            SavedGroupCredentialHintKind::Ssh => {
                if defaults.password != SavedGroupCredentialOverride::StoredHint {
                    return Err(repair_error());
                }
                // Removing the stale local hint restores normal ancestor
                // inheritance; `Clear` would incorrectly block a parent.
                defaults.password = SavedGroupCredentialOverride::Inherit;
            }
            SavedGroupCredentialHintKind::Proxy => {
                let SavedGroupProxyOverride::Inline(config) = defaults.proxy else {
                    return Err(repair_error());
                };
                let config = config
                    .with_saved_credential_hint(false)
                    .map_err(|_| repair_error())?;
                defaults.proxy = SavedGroupProxyOverride::Inline(config);
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| repair_error())?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| repair_error())?;
        let updated = current
            .apply_update(
                SavedGroupConfigUpdate {
                    path: None,
                    defaults: Some(defaults),
                },
                now,
            )
            .map_err(|_| repair_error())?;

        let (
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            profiles,
            mut groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
        ) = target_graph.into_current_parts();
        let index = groups
            .iter()
            .position(|group| group.id == group_id)
            .ok_or_else(repair_error)?;
        groups[index] = updated;
        target_graph = SavedVaultGraph::new_with_port_forward_rules(
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            profiles,
            groups,
            notes_snippets,
            port_forward_rules,
        )
        .with_group_catalog(custom_groups);

        let plan = store
            .plan_graph_replacement(expected_inventory_revision, &target_graph)
            .map_err(|_| repair_error())?;
        let committed = store
            .commit_planned_graph_replacement(plan, target_graph)
            .map_err(|_| repair_error())?;
        if committed.durability() != SavedVaultCommitDurability::Durable {
            let confirmed = store
                .confirm_current_snapshot_durability()
                .map_err(|_| repair_error())?;
            if confirmed.revision() != committed.revision()
                || confirmed.graph() != committed.graph()
            {
                return Err(repair_error());
            }
        }
        Ok(())
    })
    .await
}

fn saved_password_prompt_required() -> String {
    format!("{SAVED_CREDENTIAL_NOT_FOUND}: This host needs a one-time password")
}

fn saved_proxy_password_prompt_required() -> String {
    format!("{SAVED_CREDENTIAL_NOT_FOUND}: This proxy needs a one-time password")
}

fn proxy_password_from_secret(secret: SecretValue) -> Result<SecretText, String> {
    let password = secret
        .as_utf8()
        .map_err(|error| error.to_string())?
        .to_owned();
    Ok(SecretText::new(password))
}

async fn repair_missing_saved_proxy_credential_hint(
    state: &DesktopState,
    host: &SavedHost,
    graph: &SavedVaultGraph,
    action: SavedProxyCredentialAction,
) -> Result<(), String> {
    match action {
        SavedProxyCredentialAction::ClearHostInlineProxyPasswordHintThenRequireOneShot => {
            clear_missing_host_inline_proxy_credential_hint(state, host).await
        }
        SavedProxyCredentialAction::ClearGroupProxyPasswordHintThenRequireOneShot { group_id } => {
            let revision = graph
                .groups()
                .iter()
                .find(|group| group.id == group_id)
                .map(|group| group.revision)
                .ok_or_else(saved_group_hint_repair_error)?;
            clear_missing_group_credential_hint(
                state,
                group_id,
                revision,
                SavedGroupCredentialHintKind::Proxy,
            )
            .await
        }
        SavedProxyCredentialAction::ClearProfileProxyPasswordHintThenRequireOneShot {
            profile_id,
        } => {
            let revision = graph
                .proxy_profiles()
                .iter()
                .find(|profile| profile.id == profile_id)
                .map(|profile| profile.revision)
                .ok_or_else(|| SavedProxyAuthGuardError::MissingProfileReference.to_string())?;
            clear_missing_proxy_profile_credential_hint(state, profile_id, revision).await
        }
        SavedProxyCredentialAction::ClearIdentitySshPasswordHintThenRequireOneShot {
            identity_id,
        } => {
            let revision = graph
                .password_identities()
                .iter()
                .find(|identity| identity.id == identity_id)
                .map(|identity| identity.revision)
                .ok_or_else(|| SavedProxyAuthGuardError::MissingPasswordIdentity.to_string())?;
            clear_missing_password_identity_credential_hint(state, identity_id, revision).await
        }
        _ => Err(SavedProxyAuthGuardError::InvalidCredentialMode.to_string()),
    }
}

async fn resolve_saved_proxy_persistent_password(
    state: &DesktopState,
    host: &SavedHost,
    graph: &SavedVaultGraph,
    reference: StoredCredentialReference,
    kind: CredentialKind,
    action: &SavedProxyCredentialAction,
    lookup: SavedProxyCredentialLookup,
) -> Result<SecretText, String> {
    match state.persistent_credentials.resolve(&reference, kind).await {
        Ok(secret) => proxy_password_from_secret(secret),
        Err(error) => {
            let next = action.after_lookup_error(lookup, error.code());
            if next == SavedProxyCredentialAction::FailClosed {
                return Err(error.to_string());
            }
            repair_missing_saved_proxy_credential_hint(state, host, graph, next).await?;
            Err(saved_proxy_password_prompt_required())
        }
    }
}

async fn resolve_saved_proxy_session(
    state: &DesktopState,
    host: &SavedHost,
    graph: &SavedVaultGraph,
    plan: SavedProxyConnectionPlan,
    staged_credential: Option<SecretValue>,
) -> Result<(ProxyConfig, Option<SecretText>), String> {
    let (transport, username, action) = plan.into_parts();
    let password = match &action {
        SavedProxyCredentialAction::UseOneShotProxyPassword => Some(proxy_password_from_secret(
            staged_credential.ok_or_else(saved_proxy_password_prompt_required)?,
        )?),
        SavedProxyCredentialAction::ResolveHostInlineProxyPassword => {
            let reference = StoredCredentialReference::for_saved_host_proxy(host.id.as_str())
                .map_err(|error| error.to_string())?;
            Some(
                resolve_saved_proxy_persistent_password(
                    state,
                    host,
                    graph,
                    reference,
                    CredentialKind::ProxyPassword,
                    &action,
                    SavedProxyCredentialLookup::HostInlineProxyPassword,
                )
                .await?,
            )
        }
        SavedProxyCredentialAction::ResolveGroupProxyPassword { group_id } => {
            let reference = StoredCredentialReference::for_saved_group_proxy(group_id.as_str())
                .map_err(|error| error.to_string())?;
            Some(
                resolve_saved_proxy_persistent_password(
                    state,
                    host,
                    graph,
                    reference,
                    CredentialKind::ProxyPassword,
                    &action,
                    SavedProxyCredentialLookup::GroupProxyPassword,
                )
                .await?,
            )
        }
        SavedProxyCredentialAction::ResolveProfileProxyPassword { profile_id } => {
            let reference = StoredCredentialReference::for_saved_proxy_profile(profile_id.as_str())
                .map_err(|error| error.to_string())?;
            Some(
                resolve_saved_proxy_persistent_password(
                    state,
                    host,
                    graph,
                    reference,
                    CredentialKind::ProxyPassword,
                    &action,
                    SavedProxyCredentialLookup::ProfileProxyPassword,
                )
                .await?,
            )
        }
        SavedProxyCredentialAction::ResolveIdentitySshPassword { identity_id } => {
            let reference = StoredCredentialReference::for_saved_identity(identity_id.as_str())
                .map_err(|error| error.to_string())?;
            Some(
                resolve_saved_proxy_persistent_password(
                    state,
                    host,
                    graph,
                    reference,
                    CredentialKind::SshPassword,
                    &action,
                    SavedProxyCredentialLookup::IdentitySshPassword,
                )
                .await?,
            )
        }
        SavedProxyCredentialAction::RequireOneShotProxyPassword => {
            return Err(saved_proxy_password_prompt_required());
        }
        SavedProxyCredentialAction::NoCredential => None,
        _ => return Err(SavedProxyAuthGuardError::InvalidCredentialMode.to_string()),
    };
    let has_password = password.is_some();
    let proxy = match transport {
        SavedProxyTransportPlan::Http { host, port } => ProxyConfig {
            proxy_type: ProxyType::Http,
            host,
            port: Some(u32::from(port)),
            command: None,
            identity_id: None,
            username,
            has_password,
        },
        SavedProxyTransportPlan::Socks5 { host, port } => ProxyConfig {
            proxy_type: ProxyType::Socks5,
            host,
            port: Some(u32::from(port)),
            command: None,
            identity_id: None,
            username,
            has_password,
        },
        SavedProxyTransportPlan::Command { command } => ProxyConfig {
            proxy_type: ProxyType::Command,
            host: String::new(),
            port: None,
            command: Some(command),
            identity_id: None,
            username: None,
            has_password: false,
        },
    };
    Ok((proxy, password))
}

async fn resolve_saved_host_password_credential(
    state: &DesktopState,
    host: &SavedHost,
    plan: &saved_host_auth_guard::SavedPasswordAuthResolution<'_>,
) -> Result<ConnectionCredentials, String> {
    let reference = stored_reference(host)?;
    match state
        .persistent_credentials
        .resolve(&reference, CredentialKind::SshPassword)
        .await
    {
        Ok(secret) => credentials_from_secret(secret),
        Err(error) => {
            match plan.after_lookup_error(SavedPasswordCredentialLookup::Host, error.code()) {
                SavedPasswordCredentialAction::ClearHostHintThenRequireOneShot => {
                    clear_missing_credential_hint(state, host).await;
                    Err(saved_password_prompt_required())
                }
                SavedPasswordCredentialAction::FailClosed => Err(error.to_string()),
                _ => Err(
                    saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                        .to_string(),
                ),
            }
        }
    }
}

async fn resolve_saved_group_password_credential(
    state: &DesktopState,
    graph: &SavedVaultGraph,
    group_id: &SavedGroupId,
    plan: &saved_host_auth_guard::SavedPasswordAuthResolution<'_>,
) -> Result<ConnectionCredentials, String> {
    let reference = StoredCredentialReference::for_saved_group_ssh(group_id.as_str())
        .map_err(|error| error.to_string())?;
    match state
        .persistent_credentials
        .resolve(&reference, CredentialKind::SshPassword)
        .await
    {
        Ok(secret) => credentials_from_secret(secret),
        Err(error) => match plan
            .after_lookup_error(SavedPasswordCredentialLookup::Group, error.code())
        {
            SavedPasswordCredentialAction::ClearGroupHintThenRequireOneShot {
                group_id: selected_group,
            } if selected_group == group_id => {
                let revision = graph
                    .groups()
                    .iter()
                    .find(|group| &group.id == group_id)
                    .map(|group| group.revision)
                    .ok_or_else(saved_group_hint_repair_error)?;
                clear_missing_group_credential_hint(
                    state,
                    group_id.clone(),
                    revision,
                    SavedGroupCredentialHintKind::Ssh,
                )
                .await?;
                Err(saved_password_prompt_required())
            }
            SavedPasswordCredentialAction::FailClosed => Err(error.to_string()),
            _ => Err(
                saved_host_auth_guard::SavedHostAuthGuardError::InvalidCredentialOwner.to_string(),
            ),
        },
    }
}

async fn resolve_saved_password_session_credentials(
    state: &DesktopState,
    host: &SavedHost,
    graph: &SavedVaultGraph,
    credential_owner: Option<&SavedHostConnectionCredentialOwner>,
    staged_credential: Option<SecretValue>,
) -> Result<(String, ConnectionCredentials), String> {
    let plan = resolve_projected_saved_password_authentication(host, graph, credential_owner)
        .map_err(|error| error.to_string())?;
    let username = plan.effective_username(host).to_owned();
    let action = plan.first_credential_action(staged_credential.is_some());
    let credentials = match action {
        SavedPasswordCredentialAction::UseOneShot => {
            let secret = staged_credential.ok_or_else(saved_password_prompt_required)?;
            credentials_from_secret(secret)?
        }
        SavedPasswordCredentialAction::ResolveIdentity { identity_id } => {
            let reference = StoredCredentialReference::for_saved_identity(identity_id.as_str())
                .map_err(|error| error.to_string())?;
            match state
                .persistent_credentials
                .resolve(&reference, CredentialKind::SshPassword)
                .await
            {
                Ok(secret) => credentials_from_secret(secret)?,
                Err(error) => match plan
                    .after_lookup_error(SavedPasswordCredentialLookup::Identity, error.code())
                {
                    SavedPasswordCredentialAction::ClearIdentityHintThenResolveHost {
                        identity_id,
                    } => {
                        let expected_revision = plan.password_identity_revision().ok_or_else(|| {
                            saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                                .to_string()
                        })?;
                        clear_missing_password_identity_credential_hint(
                            state,
                            identity_id.clone(),
                            expected_revision,
                        )
                        .await?;
                        resolve_saved_host_password_credential(state, host, &plan).await?
                    }
                    SavedPasswordCredentialAction::ClearIdentityHintThenResolveGroup {
                        identity_id,
                        group_id,
                    } => {
                        let expected_revision = plan.password_identity_revision().ok_or_else(|| {
                            saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                                .to_string()
                        })?;
                        clear_missing_password_identity_credential_hint(
                            state,
                            identity_id.clone(),
                            expected_revision,
                        )
                        .await?;
                        resolve_saved_group_password_credential(state, graph, group_id, &plan)
                            .await?
                    }
                    SavedPasswordCredentialAction::ClearIdentityHintThenRequireOneShot {
                        identity_id,
                    } => {
                        let expected_revision = plan.password_identity_revision().ok_or_else(|| {
                            saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                                .to_string()
                        })?;
                        clear_missing_password_identity_credential_hint(
                            state,
                            identity_id.clone(),
                            expected_revision,
                        )
                        .await?;
                        return Err(saved_password_prompt_required());
                    }
                    SavedPasswordCredentialAction::FailClosed => return Err(error.to_string()),
                    _ => {
                        return Err(saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                            .to_string());
                    }
                },
            }
        }
        SavedPasswordCredentialAction::ResolveHost => {
            resolve_saved_host_password_credential(state, host, &plan).await?
        }
        SavedPasswordCredentialAction::ResolveGroup { group_id } => {
            resolve_saved_group_password_credential(state, graph, group_id, &plan).await?
        }
        SavedPasswordCredentialAction::RequireOneShot => {
            return Err(saved_password_prompt_required());
        }
        _ => {
            return Err(
                saved_host_auth_guard::SavedHostAuthGuardError::InvalidIdentityReference
                    .to_string(),
            );
        }
    };
    Ok((username, credentials))
}

struct SavedHostChainPlan {
    target: SavedHostConnectionProjection,
    jumps: Vec<(String, SavedHostConnectionProjection)>,
}

struct SavedHostEndpointSecrets {
    credential: Option<SecretValue>,
    proxy_credential: Option<SecretValue>,
    key_passphrase: Option<SecretValue>,
    selected_identity_file_paths: Vec<String>,
}

fn saved_host_chain_invalid(message: &'static str) -> String {
    format!("{SAVED_HOST_CHAIN_INVALID}: {message}")
}

fn saved_host_chain_interaction_required() -> String {
    format!(
        "{SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED}: A jump host needs a host-bound credential or key selection"
    )
}

fn plan_saved_host_chain(
    graph: &SavedVaultGraph,
    durable_target: &SavedHost,
) -> Result<SavedHostChainPlan, String> {
    let target = project_saved_host_connection(durable_target, graph.groups())
        .map_err(|_| saved_host_chain_invalid("Saved host chain metadata is invalid"))?;
    if target.host_chain_ids().len() > MAX_JUMP_HOSTS {
        return Err(saved_host_chain_invalid("Saved host chain is too long"));
    }

    let mut seen = std::collections::HashSet::with_capacity(target.host_chain_ids().len() + 1);
    seen.insert(durable_target.id.as_str());
    let mut jumps = Vec::with_capacity(target.host_chain_ids().len());
    for jump_id in target.host_chain_ids() {
        if !seen.insert(jump_id.as_str()) {
            return Err(saved_host_chain_invalid(
                "Saved host chain contains a cycle or duplicate",
            ));
        }
        let mut matches = graph.hosts().iter().filter(|host| host.id == *jump_id);
        let durable_jump = matches
            .next()
            .ok_or_else(|| saved_host_chain_invalid("A jump host is missing"))?;
        if matches.next().is_some() {
            return Err(saved_host_chain_invalid(
                "Saved host chain contains an ambiguous host",
            ));
        }
        let projection = project_saved_host_connection(durable_jump, graph.groups())
            .map_err(|_| saved_host_chain_invalid("Jump host metadata is invalid"))?;
        if !projection.effective_host().protocol.is_ssh() {
            return Err(saved_host_chain_invalid("A jump host does not support SSH"));
        }
        jumps.push((jump_id.as_str().to_owned(), projection));
    }
    Ok(SavedHostChainPlan { target, jumps })
}

fn saved_host_connection_metadata_invalid() -> String {
    "saved host connection metadata is invalid".to_owned()
}

fn optional_saved_host_bool(host: &SavedHost, key: &str) -> Result<Option<bool>, String> {
    match host.compatibility_fields().get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(saved_host_connection_metadata_invalid()),
    }
}

fn optional_saved_host_i64(host: &SavedHost, key: &str) -> Result<Option<i64>, String> {
    match host.compatibility_fields().get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(saved_host_connection_metadata_invalid),
        Some(_) => Err(saved_host_connection_metadata_invalid()),
    }
}

fn optional_saved_host_f64(host: &SavedHost, key: &str) -> Result<Option<f64>, String> {
    match host.compatibility_fields().get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_f64()
            .map(Some)
            .ok_or_else(saved_host_connection_metadata_invalid),
        Some(_) => Err(saved_host_connection_metadata_invalid()),
    }
}

fn apply_projected_saved_host_ssh_options(
    host: &SavedHost,
    config: &mut SshConnectionConfig,
) -> Result<(), String> {
    if let Some(value) = optional_saved_host_bool(host, "agentForwarding")? {
        config.auth.agent_forwarding = value;
    }
    if let Some(value) = optional_saved_host_bool(host, "legacyAlgorithms")? {
        config.legacy_algorithms = Some(value);
    }
    if let Some(value) = optional_saved_host_bool(host, "skipEcdsaHostKey")? {
        config.skip_ecdsa_host_key = value;
    }
    if let Some(value) = host.compatibility_fields().get("algorithms") {
        if !value.is_null() {
            config.algorithms = serde_json::from_value(value.clone())
                .map_err(|_| saved_host_connection_metadata_invalid())?;
        }
    }
    if let Some(value) = optional_saved_host_bool(host, "keepaliveOverride")? {
        config.keepalive.override_global = value;
    }
    config.keepalive.interval_seconds = optional_saved_host_i64(host, "keepaliveInterval")?;
    config.keepalive.count_max = optional_saved_host_i64(host, "keepaliveCountMax")?;
    config.timeouts.tcp_connect_seconds =
        optional_saved_host_f64(host, "sshTcpConnectTimeoutSeconds")?;
    config.timeouts.auth_ready_seconds =
        optional_saved_host_f64(host, "sshAuthReadyTimeoutSeconds")?;
    Ok(())
}

async fn prepare_saved_host_endpoint(
    state: &DesktopState,
    graph: &SavedVaultGraph,
    projection: &SavedHostConnectionProjection,
    secrets: SavedHostEndpointSecrets,
    is_jump: bool,
) -> Result<(SshConnectionConfig, ConnectionCredentials), String> {
    let SavedHostEndpointSecrets {
        credential: staged_credential,
        proxy_credential: staged_proxy_credential,
        key_passphrase: staged_key_passphrase,
        selected_identity_file_paths,
    } = secrets;
    let host = projection.effective_host();
    if !host.protocol.is_ssh() {
        return Err(if is_jump {
            saved_host_chain_invalid("A jump host does not support SSH")
        } else {
            "This saved host connection type is not available yet".to_owned()
        });
    }
    let network_port = host
        .network_port()
        .map_err(|_| saved_host_connection_metadata_invalid())?;
    let auth_resolution =
        resolve_saved_host_authentication(host, graph).map_err(|error| error.to_string())?;
    let proxy_plan = resolve_projected_saved_proxy_authentication(
        host,
        graph,
        staged_proxy_credential.is_some(),
        projection.inline_proxy_credential_owner(),
    )
    .map_err(|error| error.to_string())?;
    let prepared = async {
        let (mut config, mut credentials) = match auth_resolution {
            SavedHostAuthResolution::Password => {
                if staged_key_passphrase.is_some() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A password host cannot accept a private-key passphrase"
                    ));
                }
                if !selected_identity_file_paths.is_empty() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A password host cannot accept private key files"
                    ));
                }
                let (username, credentials) = resolve_saved_password_session_credentials(
                    state,
                    host,
                    graph,
                    projection.ssh_credential_owner(),
                    staged_credential,
                )
                .await?;
                (
                    SshConnectionConfig::saved_password_host(
                        host.hostname.clone(),
                        network_port,
                        username,
                    ),
                    credentials,
                )
            }
            SavedHostAuthResolution::ManagedPrivateKey { key_id, .. }
            | SavedHostAuthResolution::ManagedCertificate { key_id, .. } => {
                if staged_credential.is_some() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A key host cannot accept a password"
                    ));
                }
                if !selected_identity_file_paths.is_empty() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A managed key host cannot accept private key files"
                    ));
                }
                let has_certificate = matches!(
                    auth_resolution,
                    SavedHostAuthResolution::ManagedCertificate { .. }
                );
                let managed_key = graph
                    .managed_ssh_keys()
                    .iter()
                    .find(|key| &key.id == key_id)
                    .cloned()
                    .ok_or_else(|| {
                        saved_host_auth_guard::SavedHostAuthGuardError::MissingKeyReference
                            .to_string()
                    })?;
                let credentials = resolve_saved_managed_key_credentials(
                    state,
                    managed_key,
                    staged_key_passphrase,
                )
                .await?;
                (
                    SshConnectionConfig::saved_managed_key_host(
                        host.hostname.clone(),
                        network_port,
                        host.username.clone(),
                        has_certificate,
                    ),
                    credentials,
                )
            }
            SavedHostAuthResolution::ReferencePrivateKey { .. } => {
                if is_jump {
                    return Err(saved_host_chain_interaction_required());
                }
                if staged_credential.is_some() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A key host cannot accept a password"
                    ));
                }
                if staged_key_passphrase.is_some() {
                    return Err(format!(
                        "{SAVED_HOST_KEY_FILE_SELECTION_INVALID}: A reference key host cannot accept a managed-key passphrase"
                    ));
                }
                let selected_identity_file_paths =
                    validate_selected_identity_file_paths(selected_identity_file_paths)?;
                (
                    SshConnectionConfig::saved_key_file_host(
                        host.hostname.clone(),
                        network_port,
                        host.username.clone(),
                        selected_identity_file_paths,
                    ),
                    ConnectionCredentials::empty(),
                )
            }
        };
        if let Some(proxy_plan) = proxy_plan {
            let (proxy, proxy_password) = resolve_saved_proxy_session(
                state,
                host,
                graph,
                proxy_plan,
                staged_proxy_credential,
            )
            .await?;
            config.proxy = Some(proxy);
            if let Some(proxy_password) = proxy_password {
                credentials = credentials.with_proxy_password(proxy_password);
            }
        }
        apply_projected_saved_host_ssh_options(host, &mut config)?;
        Ok((config, credentials))
    }
    .await;

    prepared.map_err(|error: String| {
        if is_jump && error.starts_with(SAVED_CREDENTIAL_NOT_FOUND) {
            saved_host_chain_interaction_required()
        } else {
            error
        }
    })
}

async fn prepare_saved_host_session(
    state: &DesktopState,
    request: StartSavedHostSessionRequest,
    staged: StagedSavedHostSessionSecrets,
) -> Result<PreparedSavedHostSession, String> {
    let id = SavedHostId::from_opaque(request.host_id).map_err(|error| error.to_string())?;
    let snapshot = confirm_current_saved_host_snapshot(state).await?;
    let known_hosts = merge_connection_known_hosts(snapshot.known_hosts(), request.known_hosts);
    let graph = snapshot.graph().clone();
    let durable_host = graph
        .hosts()
        .iter()
        .find(|host| host.id == id)
        .cloned()
        .ok_or_else(|| "Saved host was not found".to_owned())?;
    if durable_host.revision != request.expected_revision {
        return Err(format!(
            "{SAVED_HOST_REVISION_CONFLICT}: Saved host changed; refresh and retry"
        ));
    }
    let chain = plan_saved_host_chain(&graph, &durable_host)?;
    let StagedSavedHostSessionSecrets {
        credential,
        proxy_credential,
        key_passphrase,
    } = staged;
    let (mut config, credentials) = prepare_saved_host_endpoint(
        state,
        &graph,
        &chain.target,
        SavedHostEndpointSecrets {
            credential,
            proxy_credential,
            key_passphrase,
            selected_identity_file_paths: request.selected_identity_file_paths,
        },
        false,
    )
    .await?;

    config.jump_hosts = chain
        .jumps
        .iter()
        .map(|(host_id, _)| SshJumpHost {
            host_id: host_id.clone(),
        })
        .collect();
    validate_saved_host_endpoint_config(config.clone())?;

    let connection_log =
        ConnectionLogCapture::saved_ssh(chain.target.effective_host(), &config.username);

    let mut jump_hosts = Vec::with_capacity(chain.jumps.len());
    for (host_id, projection) in chain.jumps {
        let (jump_config, jump_credentials) = prepare_saved_host_endpoint(
            state,
            &graph,
            &projection,
            SavedHostEndpointSecrets {
                credential: None,
                proxy_credential: None,
                key_passphrase: None,
                selected_identity_file_paths: Vec::new(),
            },
            true,
        )
        .await?;
        validate_saved_host_endpoint_config(jump_config.clone())?;
        jump_hosts.push(PreparedSavedHostJump {
            host_id,
            config: jump_config,
            credentials: jump_credentials,
        });
    }

    Ok(PreparedSavedHostSession {
        client_attempt_id: request.client_attempt_id,
        config,
        credentials,
        jump_hosts,
        known_hosts,
        verify_host_keys: request.verify_host_keys,
        shell: request.shell,
        connection_log,
        effective_mosh_enabled: mosh_session::effective_mosh_enabled(chain.target.effective_host()),
    })
}

async fn clear_missing_credential_hint(state: &DesktopState, host: &SavedHost) {
    let Ok(update) = SavedHostUpdate::default()
        .with_compatibility_field("hasSavedCredential", serde_json::Value::Bool(false))
    else {
        return;
    };
    let store = state.saved_hosts.clone();
    let id = host.id.clone();
    let revision = host.revision;
    let _ = run_blocking_result(move || store.update(&id, revision, update)).await;
}

#[tauri::command]
async fn start_ssh_session(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: StartSshSessionRequest,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSshSession, String> {
    // Keep the one-shot secret available when only the non-secret connection
    // configuration is invalid. The common starter validates again after the
    // credential is resolved so both entry points retain one implementation.
    let preflight = validate_connection(request.config.clone());
    if preflight.normalized.is_none() {
        return Err(preflight
            .errors
            .into_iter()
            .map(|issue| issue.message)
            .collect::<Vec<_>>()
            .join("; "));
    }
    let credentials =
        take_ephemeral_ssh_password(&state, window.label(), &request.credential_reference).await?;
    let known_hosts = load_connection_known_hosts(&state, request.known_hosts).await?;
    begin_ssh_session(
        &window,
        &state,
        request.client_attempt_id,
        request.config,
        credentials,
        known_hosts,
        request.verify_host_keys,
        request.shell,
        on_control,
        on_data,
    )
    .await
}

fn validate_ssh_session_clone_source(session_id: String) -> Result<String, String> {
    const MAX_SESSION_ID_BYTES: usize = 64;
    let Some(suffix) = session_id.strip_prefix("ssh-") else {
        return Err(
            "SSH_SESSION_REUSE_INVALID: The source SSH session identifier is invalid".to_owned(),
        );
    };
    let mut parts = suffix.split('-');
    let pid = parts.next().unwrap_or_default();
    let sequence = parts.next().unwrap_or_default();
    if session_id.len() > MAX_SESSION_ID_BYTES
        || pid.is_empty()
        || sequence.is_empty()
        || parts.next().is_some()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(
            "SSH_SESSION_REUSE_INVALID: The source SSH session identifier is invalid".to_owned(),
        );
    }
    Ok(session_id)
}

fn map_ssh_session_reuse_error(error: SessionManagerError) -> String {
    match error {
        SessionManagerError::NotFound => {
            "SSH_SESSION_REUSE_NOT_FOUND: The source SSH session no longer exists".to_owned()
        }
        SessionManagerError::NotConnected => {
            "SSH_SESSION_REUSE_NOT_CONNECTED: The source SSH session is not connected".to_owned()
        }
        SessionManagerError::TransportSessionLimit => {
            "SSH_SESSION_REUSE_LIMIT: The authenticated SSH transport has reached its session limit"
                .to_owned()
        }
        _ => "SSH_SESSION_REUSE_FAILED: The SSH shell channel could not be cloned".to_owned(),
    }
}

#[tauri::command]
async fn clone_ssh_session(
    state: State<'_, DesktopState>,
    request: CloneSshSessionRequest,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSshSession, String> {
    let source_session_id = validate_ssh_session_clone_source(request.source_session_id)?;
    let connection_log = state
        .ssh_session_logs
        .lock()
        .await
        .get(&source_session_id)
        .cloned()
        .ok_or_else(|| {
            "SSH_SESSION_REUSE_NOT_FOUND: The source SSH session no longer exists".to_owned()
        })?;
    let replay_manager = connection_log_replay_manager_for_session(&state).await;
    let started = state
        .sessions
        .begin_reuse(&source_session_id, request.shell.unwrap_or_default())
        .await
        .map_err(map_ssh_session_reuse_error)?;
    Ok(forward_started_ssh_session(
        started,
        state.inner().clone(),
        connection_log,
        replay_manager,
        on_control,
        on_data,
    )
    .await)
}

async fn connection_log_replay_manager_for_session(
    state: &DesktopState,
) -> Option<ConnectionLogReplayManager> {
    let runtime = state.connection_log_replays.as_ref()?.clone();
    runtime.manager_for_session().await
}

#[allow(clippy::too_many_arguments)]
async fn begin_ssh_session(
    window: &WebviewWindow,
    state: &DesktopState,
    client_attempt_id: ClientAttemptId,
    request_config: SshConnectionConfig,
    credentials: ConnectionCredentials,
    known_hosts: Vec<KnownHost>,
    verify_host_keys: bool,
    shell: Option<ShellOptions>,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSshSession, String> {
    let endpoint = build_resolved_ssh_endpoint(
        window,
        state,
        &client_attempt_id,
        request_config,
        credentials,
        known_hosts,
        verify_host_keys,
    )?;
    let connection_log =
        ConnectionLogCapture::quick_ssh(&endpoint.config.hostname, &endpoint.config.username);
    // Lazy replay custody is initialized on one detached blocking worker. A
    // short async wait preserves capture on the normal path, while timeout or
    // storage failure disables only replay capture rather than delaying SSH.
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let started = state
        .sessions
        .begin(
            endpoint.config,
            endpoint.auth,
            endpoint.credentials,
            endpoint.verifier,
            endpoint.interactive,
            shell.unwrap_or_default(),
        )
        .await;
    Ok(forward_started_ssh_session(
        started,
        state.clone(),
        connection_log,
        replay_manager,
        on_control,
        on_data,
    )
    .await)
}

fn validate_saved_host_endpoint_config(request_config: SshConnectionConfig) -> Result<(), String> {
    let validation = validate_connection(request_config);
    validation.normalized.map(|_| ()).ok_or_else(|| {
        validation
            .errors
            .into_iter()
            .map(|issue| issue.message)
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn build_resolved_ssh_endpoint(
    window: &WebviewWindow,
    state: &DesktopState,
    client_attempt_id: &ClientAttemptId,
    request_config: SshConnectionConfig,
    credentials: ConnectionCredentials,
    known_hosts: Vec<KnownHost>,
    verify_host_keys: bool,
) -> Result<ResolvedSshEndpoint, String> {
    let auth = request_config.auth.clone();
    let validation = validate_connection(request_config);
    let config = validation.normalized.ok_or_else(|| {
        validation
            .errors
            .into_iter()
            .map(|issue| issue.message)
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    let verifier = PromptingHostKeyVerifier::new(
        state.host_keys.clone(),
        window.label(),
        "pending",
        client_attempt_id.as_str(),
        &config.hostname,
        config.port,
        known_hosts,
    )
    .with_verification_enabled(verify_host_keys);
    let interactive = PromptingInteractiveAuthResponder::new(
        state.interactive_auth.clone(),
        window.label(),
        "pending",
        client_attempt_id.as_str(),
    );
    Ok(ResolvedSshEndpoint {
        config,
        auth,
        credentials,
        verifier: std::sync::Arc::new(verifier),
        interactive: Some(std::sync::Arc::new(interactive)),
    })
}

async fn begin_prepared_saved_host_session(
    window: &WebviewWindow,
    state: &DesktopState,
    prepared: PreparedSavedHostSession,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> Result<StartedSshSession, String> {
    let PreparedSavedHostSession {
        client_attempt_id,
        config,
        credentials,
        jump_hosts,
        known_hosts,
        verify_host_keys,
        shell,
        connection_log,
        effective_mosh_enabled: _,
    } = prepared;
    let expected_jump_ids = config
        .jump_hosts
        .iter()
        .map(|jump| jump.host_id.as_str())
        .collect::<Vec<_>>();
    if expected_jump_ids.len() != jump_hosts.len()
        || expected_jump_ids
            .iter()
            .zip(&jump_hosts)
            .any(|(expected, prepared)| **expected != prepared.host_id)
    {
        return Err(saved_host_chain_invalid(
            "Prepared saved host chain is inconsistent",
        ));
    }

    let target = build_resolved_ssh_endpoint(
        window,
        state,
        &client_attempt_id,
        config,
        credentials,
        known_hosts.clone(),
        verify_host_keys,
    )?;
    let replay_manager = connection_log_replay_manager_for_session(state).await;
    let shell = shell.unwrap_or_default();
    let started = if jump_hosts.is_empty() {
        state
            .sessions
            .begin(
                target.config,
                target.auth,
                target.credentials,
                target.verifier,
                target.interactive,
                shell,
            )
            .await
    } else {
        let mut endpoints = std::collections::HashMap::with_capacity(jump_hosts.len());
        for jump in jump_hosts {
            let endpoint = build_resolved_ssh_endpoint(
                window,
                state,
                &client_attempt_id,
                jump.config,
                jump.credentials,
                known_hosts.clone(),
                verify_host_keys,
            )?;
            if endpoints.insert(jump.host_id, endpoint).is_some() {
                return Err(saved_host_chain_invalid(
                    "Prepared saved host chain contains a duplicate",
                ));
            }
        }
        state
            .sessions
            .begin_chain(
                target,
                std::sync::Arc::new(PreparedSavedHostChainResolver {
                    endpoints: tokio::sync::Mutex::new(endpoints),
                }),
                shell,
            )
            .await
    };
    Ok(forward_started_ssh_session(
        started,
        state.clone(),
        connection_log,
        replay_manager,
        on_control,
        on_data,
    )
    .await)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionLogFinalization {
    Complete,
    MissingMetadata,
    Retry,
}

async fn finalize_connection_log_replay(
    state: DesktopState,
    replays: ConnectionLogReplayManager,
    log_id: String,
    session_id: String,
    end_time: u64,
) {
    const RETRY_DELAYS_MILLIS: [u64; 2] = [200, 800];

    for attempt in 0..=RETRY_DELAYS_MILLIS.len() {
        let attempt_replays = replays.clone();
        let attempt_log_id = log_id.clone();
        let attempt_session_id = session_id.clone();
        let outcome = run_saved_host_operation(state.clone(), move |state| async move {
            let catalog = load_connection_logs_catalog_inner(&state).await?;
            if !catalog.logs.iter().any(|log| {
                log.id == attempt_log_id
                    && log.session_id.as_deref() == Some(attempt_session_id.as_str())
            }) {
                return Ok(ConnectionLogFinalization::MissingMetadata);
            }

            // Publish endTime before the replay. A crash or replay-store fault
            // can leave a metadata-only history item, never an authorized
            // replay without metadata.
            let logs = persist_finished_connection_log_locked(
                state,
                attempt_log_id,
                attempt_session_id.clone(),
                end_time,
            )
            .await
            .map_err(|_| {
                "CONNECTION_LOGS_PUBLICATION_FAILED: Connection Logs could not be completed"
                    .to_owned()
            })?;

            if attempt_replays
                .finish_session(&attempt_session_id)
                .await
                .is_err()
            {
                return Ok(ConnectionLogFinalization::Retry);
            }
            // Honor a bookmark change that happened while the session was
            // active. Cleanup can retry at startup without weakening reads.
            let _ = attempt_replays.reconcile_catalog(logs).await;
            Ok(ConnectionLogFinalization::Complete)
        })
        .await;

        match outcome {
            Ok(ConnectionLogFinalization::Complete) => return,
            Ok(ConnectionLogFinalization::MissingMetadata) => {
                let _ = replays.discard_session(&session_id);
                return;
            }
            Ok(ConnectionLogFinalization::Retry) | Err(_) => {}
        }

        if let Some(delay) = RETRY_DELAYS_MILLIS.get(attempt) {
            tokio::time::sleep(std::time::Duration::from_millis(*delay)).await;
        }
    }

    // Coordinator/Vault failures do not advance the replay manager's own
    // failure counter, so explicitly bound memory after the final attempt.
    let _ = replays.discard_session(&session_id);
}

async fn forward_started_ssh_session(
    started: SessionStart,
    state: DesktopState,
    connection_log: ConnectionLogCapture,
    replay_manager: Option<ConnectionLogReplayManager>,
    on_control: Channel<SshControlEvent>,
    on_data: Channel<Response>,
) -> StartedSshSession {
    let session_id = started.session_id.clone();
    state
        .ssh_session_logs
        .lock()
        .await
        .insert(session_id.clone(), connection_log.clone());
    let cleanup_session_id = session_id.clone();
    let cleanup_state = state.clone();
    tauri::async_runtime::spawn(async move {
        if let Ok(mut lifecycle) = cleanup_state.sessions.subscribe(&cleanup_session_id).await {
            loop {
                match lifecycle.recv().await {
                    Ok(SessionEvent::Closed) => break,
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        cleanup_state
            .ssh_session_logs
            .lock()
            .await
            .remove(&cleanup_session_id);
    });
    let captured_session_id = session_id.clone();
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
    let mut events = started.events;
    tauri::async_runtime::spawn(async move {
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
        let mut pending = None;
        loop {
            let event = if let Some(event) = pending.take() {
                event
            } else {
                match events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        if on_control
                            .send(SshControlEvent::Error {
                                code: "outputLagged".to_owned(),
                                message: "Terminal output exceeded the desktop consumer buffer"
                                    .to_owned(),
                            })
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            };
            let result = match event {
                SessionEvent::Connecting => on_control.send(SshControlEvent::Connecting),
                SessionEvent::Connected => on_control.send(SshControlEvent::Connected),
                SessionEvent::Data(mut data) => {
                    const MAX_FRAME_BYTES: usize = 64 * 1024;
                    while data.len() < MAX_FRAME_BYTES {
                        match events.try_recv() {
                            Ok(SessionEvent::Data(next))
                                if data.len() + next.len() <= MAX_FRAME_BYTES =>
                            {
                                data.extend_from_slice(&next);
                            }
                            Ok(event) => {
                                pending = Some(event);
                                break;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                        }
                    }
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, &data);
                    }
                    on_data.send(Response::new(frame_data(0, None, data)))
                }
                SessionEvent::ExtendedData { code, data } => {
                    if let Some(replays) = replay_capture.as_ref() {
                        let _ = replays.append_session_bytes(&captured_session_id, &data);
                    }
                    on_data.send(Response::new(frame_data(1, Some(code), data)))
                }
                SessionEvent::Eof => on_control.send(SshControlEvent::Eof),
                SessionEvent::ExitStatus(status) => {
                    on_control.send(SshControlEvent::ExitStatus { status })
                }
                SessionEvent::Error { code, message } => on_control.send(SshControlEvent::Error {
                    code: format!("{code:?}"),
                    message,
                }),
                SessionEvent::Closed => {
                    let _ = on_control.send(SshControlEvent::Closed);
                    break;
                }
            };
            if result.is_err() {
                break;
            }
        }
        // Always serialize completion after the start mutation. This covers a
        // normal Closed event, event-stream shutdown, and a renderer channel
        // disconnect without delaying terminal forwarding on Vault I/O.
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

    StartedSshSession { session_id }
}

fn frame_data(kind: u8, extended_code: Option<u32>, data: Vec<u8>) -> Vec<u8> {
    let header_len = if extended_code.is_some() { 5 } else { 1 };
    let mut frame = Vec::with_capacity(header_len + data.len());
    frame.push(kind);
    if let Some(code) = extended_code {
        frame.extend_from_slice(&code.to_be_bytes());
    }
    frame.extend_from_slice(&data);
    frame
}

#[tauri::command]
async fn ssh_session_input(
    state: State<'_, DesktopState>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    state
        .sessions
        .send_input(&session_id, data)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn ssh_session_input_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    const MAX_SESSION_ID_BYTES: usize = 1024;
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => return Err("SSH input must use the raw IPC body".to_owned()),
    };
    let mut cursor = 0;
    let session_id_len = usize::from(read_u16(bytes, &mut cursor)?);
    if session_id_len == 0 || session_id_len > MAX_SESSION_ID_BYTES {
        return Err("Invalid SSH session ID".to_owned());
    }
    let session_id = std::str::from_utf8(read_slice(bytes, &mut cursor, session_id_len)?)
        .map_err(|_| "Invalid SSH session ID".to_owned())?;
    let data = bytes
        .get(cursor..)
        .ok_or_else(|| "Invalid SSH input envelope".to_owned())?
        .to_vec();
    state
        .sessions
        .send_input(session_id, data)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn resize_ssh_session(
    state: State<'_, DesktopState>,
    session_id: String,
    size: TerminalSize,
) -> Result<(), String> {
    state
        .sessions
        .resize(&session_id, size)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn close_ssh_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state
        .sessions
        .close(&session_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn cancel_ssh_session(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<(), String> {
    state
        .sessions
        .cancel(&session_id)
        .await
        .map_err(|error| error.to_string())
}

fn validate_sftp_path(path: String) -> Result<String, String> {
    const MAX_SFTP_PATH_BYTES: usize = 32 * 1024;
    if path.is_empty() || path.len() > MAX_SFTP_PATH_BYTES || path.contains('\0') {
        return Err("Invalid SFTP path".to_owned());
    }
    Ok(path)
}

#[tauri::command]
async fn sftp_read_dir(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<Vec<SftpEntry>, String> {
    state
        .sessions
        .sftp_read_dir(&session_id, validate_sftp_path(path)?)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_metadata(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<SftpMetadata, String> {
    state
        .sessions
        .sftp_metadata(&session_id, validate_sftp_path(path)?)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_create_dir(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    state
        .sessions
        .sftp_create_dir(&session_id, validate_sftp_path(path)?)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_remove_file(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    state
        .sessions
        .sftp_remove_file(&session_id, validate_sftp_path(path)?)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_remove_dir(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    state
        .sessions
        .sftp_remove_dir(&session_id, validate_sftp_path(path)?)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_rename(
    state: State<'_, DesktopState>,
    session_id: String,
    source: String,
    destination: String,
) -> Result<(), String> {
    state
        .sessions
        .sftp_rename(
            &session_id,
            validate_sftp_path(source)?,
            validate_sftp_path(destination)?,
        )
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_read_file(
    state: State<'_, DesktopState>,
    session_id: String,
    path: String,
) -> Result<Response, String> {
    state
        .sessions
        .sftp_read_file(&session_id, validate_sftp_path(path)?)
        .await
        .map(Response::new)
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn sftp_replace_file_if_unchanged_raw(
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    const MAX_SESSION_ID_BYTES: usize = 1024;
    const MAX_EDITOR_FILE_BYTES: usize = 2 * 1024 * 1024;
    const SFTP_EDITOR_DESTINATION_CHANGED: &str = "SFTP_EDITOR_DESTINATION_CHANGED";
    const SFTP_EDITOR_SAVE_FAILED: &str = "SFTP_EDITOR_SAVE_FAILED";
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => {
            return Err("SFTP editor data must use the raw IPC body".to_owned());
        }
    };
    let mut cursor = 0;
    let session_id_len = usize::from(read_u16(bytes, &mut cursor)?);
    if session_id_len == 0 || session_id_len > MAX_SESSION_ID_BYTES {
        return Err("Invalid SSH session ID".to_owned());
    }
    let session_id = std::str::from_utf8(read_slice(bytes, &mut cursor, session_id_len)?)
        .map_err(|_| "Invalid SSH session ID".to_owned())?;
    let path_len = usize::try_from(read_u32(bytes, &mut cursor)?)
        .map_err(|_| "Invalid SFTP path".to_owned())?;
    let path = std::str::from_utf8(read_slice(bytes, &mut cursor, path_len)?)
        .map_err(|_| "SFTP path must be valid UTF-8".to_owned())?;
    let path = validate_sftp_path(path.to_owned())?;
    let expected_len = usize::try_from(read_u32(bytes, &mut cursor)?)
        .map_err(|_| "Invalid expected SFTP file length".to_owned())?;
    if expected_len > MAX_EDITOR_FILE_BYTES {
        return Err("SFTP editor file is too large".to_owned());
    }
    let expected = read_slice(bytes, &mut cursor, expected_len)?.to_vec();
    let data = bytes
        .get(cursor..)
        .ok_or_else(|| "Invalid SFTP editor envelope".to_owned())?
        .to_vec();
    if data.len() > MAX_EDITOR_FILE_BYTES {
        return Err("SFTP editor file is too large".to_owned());
    }
    state
        .sessions
        .sftp_replace_file_if_unchanged(session_id, path, expected, data)
        .await
        .map_err(|error| match error {
            SessionSftpError::Sftp(SftpError::DestinationChanged) => {
                SFTP_EDITOR_DESTINATION_CHANGED.to_owned()
            }
            _ => SFTP_EDITOR_SAVE_FAILED.to_owned(),
        })
}

#[tauri::command]
async fn start_sftp_upload(
    state: State<'_, DesktopState>,
    session_id: String,
    local_path: String,
    remote_path: String,
    plan: Option<SftpUploadPlan>,
    checkpoint: Option<SftpTransferCheckpoint>,
    on_event: Channel<SftpTransferEvent>,
) -> Result<StartedSftpTransfer, String> {
    if local_path.is_empty() || local_path.contains('\0') {
        return Err("Invalid local upload path".to_owned());
    }
    let remote_path = validate_sftp_path(remote_path)?;
    let started = state
        .sessions
        .begin_sftp_upload(
            &session_id,
            std::path::PathBuf::from(local_path),
            remote_path,
            plan,
            checkpoint,
        )
        .await
        .map_err(|error| error.to_string())?;
    let transfer_id = started.transfer_id.clone();
    let plan = started.plan;
    let mut events = started.events;
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let terminal = matches!(
                        event,
                        SftpTransferEvent::Completed { .. }
                            | SftpTransferEvent::Cancelled { .. }
                            | SftpTransferEvent::Failed { .. }
                    );
                    if on_event.send(event).is_err() || terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Ok(StartedSftpTransfer { transfer_id, plan })
}

#[tauri::command]
async fn classify_local_transfer_source(
    local_path: String,
) -> Result<LocalTransferSourceKind, String> {
    if local_path.is_empty() || local_path.contains('\0') {
        return Err("Invalid local transfer source path".to_owned());
    }
    let metadata = tokio::fs::metadata(local_path)
        .await
        .map_err(|error| format!("Unable to inspect local transfer source: {error}"))?;
    classify_local_transfer_metadata(&metadata)
}

fn classify_local_transfer_metadata(
    metadata: &std::fs::Metadata,
) -> Result<LocalTransferSourceKind, String> {
    if metadata.is_file() {
        Ok(LocalTransferSourceKind::File)
    } else if metadata.is_dir() {
        Ok(LocalTransferSourceKind::Directory)
    } else {
        Err("Local transfer source is neither a file nor a directory".to_owned())
    }
}

#[tauri::command]
async fn start_sftp_upload_directory(
    state: State<'_, DesktopState>,
    session_id: String,
    local_root: String,
    remote_root: String,
    options: Option<LocalTreeOptions>,
    resume: Option<DirectoryResumeCheckpoint>,
    on_event: Channel<SftpTransferEvent>,
) -> Result<StartedSftpDirectoryTransfer, String> {
    if local_root.is_empty() || local_root.contains('\0') {
        return Err("Invalid local upload directory".to_owned());
    }
    let remote_root = validate_sftp_path(remote_root)?;
    let started = state
        .sessions
        .begin_sftp_upload_directory(
            &session_id,
            std::path::PathBuf::from(local_root),
            remote_root,
            options.unwrap_or_default(),
            resume,
        )
        .await
        .map_err(|error| error.to_string())?;
    let transfer_id = started.transfer_id.clone();
    let mut events = started.events;
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let terminal = matches!(
                        event,
                        SftpTransferEvent::DirectoryCompleted { .. }
                            | SftpTransferEvent::DirectoryCancelled { .. }
                            | SftpTransferEvent::DirectoryFailed { .. }
                    );
                    if on_event.send(event).is_err() || terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Ok(StartedSftpDirectoryTransfer { transfer_id })
}

#[tauri::command]
async fn start_sftp_download(
    state: State<'_, DesktopState>,
    session_id: String,
    remote_path: String,
    local_path: String,
    plan: Option<SftpDownloadPlan>,
    checkpoint: Option<SftpTransferCheckpoint>,
    on_event: Channel<SftpTransferEvent>,
) -> Result<StartedSftpDownload, String> {
    if local_path.is_empty() || local_path.contains('\0') {
        return Err("Invalid local download path".to_owned());
    }
    let remote_path = validate_sftp_path(remote_path)?;
    let started = state
        .sessions
        .begin_sftp_download(
            &session_id,
            remote_path,
            std::path::PathBuf::from(local_path),
            plan,
            checkpoint,
        )
        .await
        .map_err(|error| error.to_string())?;
    let transfer_id = started.transfer_id.clone();
    let plan = started.plan;
    let mut events = started.events;
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let terminal = matches!(
                        event,
                        SftpTransferEvent::Completed { .. }
                            | SftpTransferEvent::Cancelled { .. }
                            | SftpTransferEvent::Failed { .. }
                    );
                    if on_event.send(event).is_err() || terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Ok(StartedSftpDownload { transfer_id, plan })
}

#[tauri::command]
async fn start_sftp_download_directory(
    state: State<'_, DesktopState>,
    session_id: String,
    remote_root: String,
    local_root: String,
    options: Option<RemoteTreeOptions>,
    resume: Option<DirectoryResumeCheckpoint>,
    on_event: Channel<SftpTransferEvent>,
) -> Result<StartedSftpDirectoryTransfer, String> {
    if local_root.is_empty() || local_root.contains('\0') {
        return Err("Invalid local download directory".to_owned());
    }
    let remote_root = validate_sftp_path(remote_root)?;
    let started = state
        .sessions
        .begin_sftp_download_directory(
            &session_id,
            remote_root,
            std::path::PathBuf::from(local_root),
            options.unwrap_or_default(),
            resume,
        )
        .await
        .map_err(|error| error.to_string())?;
    let transfer_id = started.transfer_id.clone();
    let mut events = started.events;
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let terminal = matches!(
                        event,
                        SftpTransferEvent::DirectoryCompleted { .. }
                            | SftpTransferEvent::DirectoryCancelled { .. }
                            | SftpTransferEvent::DirectoryFailed { .. }
                    );
                    if on_event.send(event).is_err() || terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Ok(StartedSftpDirectoryTransfer { transfer_id })
}

#[tauri::command]
async fn pause_sftp_transfer(
    state: State<'_, DesktopState>,
    transfer_id: String,
) -> Result<(), String> {
    state
        .sessions
        .pause_sftp_transfer(&transfer_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn resume_sftp_transfer(
    state: State<'_, DesktopState>,
    transfer_id: String,
) -> Result<(), String> {
    state
        .sessions
        .resume_sftp_transfer(&transfer_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn cancel_sftp_transfer(
    state: State<'_, DesktopState>,
    transfer_id: String,
) -> Result<(), String> {
    state
        .sessions
        .cancel_sftp_transfer(&transfer_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn subscribe_host_key_prompts(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    on_prompt: Channel<HostKeyPrompt>,
) -> Result<(), String> {
    let owner = window.label().to_owned();
    let mut prompts = state.host_keys.subscribe();
    tauri::async_runtime::spawn(async move {
        while let Ok(prompt) = prompts.recv().await {
            if prompt.owner_id == owner && on_prompt.send(prompt).is_err() {
                break;
            }
        }
    });
    Ok(())
}

#[tauri::command]
async fn respond_to_host_key(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request_id: String,
    accept: bool,
) -> Result<(), String> {
    state
        .host_keys
        .respond(window.label(), &request_id, accept)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn subscribe_interactive_prompts(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    on_prompt: Channel<InteractivePrompt>,
) -> Result<(), String> {
    let owner = window.label().to_owned();
    let mut prompts = state.interactive_auth.subscribe();
    tauri::async_runtime::spawn(async move {
        while let Ok(prompt) = prompts.recv().await {
            if prompt.owner_id == owner && on_prompt.send(prompt).is_err() {
                break;
            }
        }
    });
    Ok(())
}

#[tauri::command]
async fn respond_to_interactive_auth(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes,
        InvokeBody::Json(_) => {
            return Err("SSH interactive answers must use the raw IPC body".to_owned());
        }
    };
    let (request_id, answers) = decode_interactive_response(bytes)?;
    state
        .interactive_auth
        .respond(window.label(), &request_id, answers)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn cancel_interactive_auth(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    request_id: String,
) -> Result<(), String> {
    state
        .interactive_auth
        .cancel(window.label(), &request_id)
        .await
        .map_err(|error| error.to_string())
}

fn decode_interactive_response(bytes: &[u8]) -> Result<(String, Vec<SecretText>), String> {
    const MAX_ANSWER_BYTES: usize = 64 * 1024;
    let mut cursor = 0;
    let request_len = usize::from(read_u16(bytes, &mut cursor)?);
    let request_id = read_slice(bytes, &mut cursor, request_len)?;
    let request_id = std::str::from_utf8(request_id)
        .map_err(|_| "Invalid interactive request ID".to_owned())?
        .to_owned();
    let count = usize::from(read_u16(bytes, &mut cursor)?);
    if count > 32 {
        return Err("Too many SSH interactive answers".to_owned());
    }
    let mut answers = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(read_u32(bytes, &mut cursor)?)
            .map_err(|_| "Interactive answer is too large".to_owned())?;
        if length > MAX_ANSWER_BYTES {
            return Err("Interactive answer is too large".to_owned());
        }
        let answer = read_slice(bytes, &mut cursor, length)?;
        let answer = std::str::from_utf8(answer)
            .map_err(|_| "Interactive answer must be valid UTF-8".to_owned())?;
        answers.push(SecretText::new(answer.to_owned()));
    }
    if cursor != bytes.len() {
        return Err("Invalid interactive response envelope".to_owned());
    }
    Ok((request_id, answers))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, String> {
    let value = read_slice(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let value = read_slice(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_slice<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], String> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| "Invalid interactive response envelope".to_owned())?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| "Invalid interactive response envelope".to_owned())?;
    *cursor = end;
    Ok(value)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_roots = app_data_compat::compatible_data_roots(
                &app.path().app_data_dir()?,
                &app.path().app_local_data_dir()?,
            )
            .map_err(std::io::Error::other)?;
            let app_data = data_roots.app_data().to_owned();
            let webview_data = data_roots.webview_data().to_owned();
            let mut state =
                DesktopState::open(app_data.join("vault")).map_err(std::io::Error::other)?;
            // Mosh availability is feature-scoped. Missing, stale, or invalid
            // packaged resources disable only Mosh and never block startup.
            state.mosh_client = std::sync::Arc::new(
                app.path()
                    .resource_dir()
                    .map_err(|_| MoshClientAvailabilityError::ResourceUnavailable)
                    .and_then(|root| resolve_trusted_mosh_client(&root)),
            );
            state.et_client = std::sync::Arc::new(
                app.path()
                    .resource_dir()
                    .map_err(|_| netcatty_et::EtClientError::ResourceRootUnavailable)
                    .and_then(|root| resolve_trusted_et_client(&root)),
            );
            // This constructor performs no I/O. Replay file locks and OS
            // keyring access run exactly once on a blocking worker after setup
            // has returned to the native event loop.
            let replay_runtime = ConnectionLogReplayRuntime::new(&app_data);
            state.connection_log_replays = Some(replay_runtime.clone());
            let recovery_state = state.clone();
            #[cfg(desktop)]
            let native_ui_locale = state
                .settings
                .load()
                .map(|snapshot| {
                    window_lifecycle::NativeUiLocale::from_locale_tag(snapshot.native_ui_locale())
                })
                .unwrap_or_default();
            app.manage(app_data_compat::CompatibleWebviewDataRoot::new(
                webview_data.clone(),
            ));
            app.manage(state);
            #[cfg(desktop)]
            app.manage(window_lifecycle::WindowLifecycleState::new(
                native_ui_locale,
            ));
            let main_window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or_else(|| std::io::Error::other("Main window configuration is unavailable"))?;
            let main_window_builder = WebviewWindowBuilder::from_config(app, main_window_config)?;
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            let main_window_builder = main_window_builder.data_directory(webview_data);
            main_window_builder.build()?;
            #[cfg(desktop)]
            window_lifecycle::install_tray(app)?;
            // Start replay custody promptly without making it a prerequisite
            // for showing or interacting with the main window. A failed open
            // remains unavailable for this launch and is retried next launch.
            tauri::async_runtime::spawn(async move {
                let _ = replay_runtime.manager().await;
            });
            // Reconcile master-key rotation first, then any interrupted
            // cross-store import, and finally best-effort blob cleanup. Every
            // later saved-host operation uses the same coordinator and safely
            // retries the same ordering after temporary backend failures.
            tauri::async_runtime::spawn(async move {
                let _ = run_saved_host_operation(recovery_state.clone(), |state| async move {
                    // Recovery completes before this best-effort maintenance
                    // pass. Any uncertainty leaves encrypted artifacts in
                    // place and a later startup/import can retry safely.
                    let _ = garbage_collect_managed_secret_blobs(&state).await;
                    Ok::<(), String>(())
                })
                .await;

                let Some(runtime) = recovery_state.connection_log_replays.clone() else {
                    return;
                };
                let Ok(replays) = runtime.manager().await else {
                    return;
                };
                let _ = run_saved_host_operation(recovery_state, move |state| async move {
                    if let Ok(catalog) = load_connection_logs_catalog_inner(&state).await {
                        let _ = replays.reconcile_catalog(catalog.logs).await;
                    }
                    Ok::<(), String>(())
                })
                .await;
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(desktop)]
            if window_lifecycle::handle_window_event(window, event) {
                return;
            }
            if matches!(event, WindowEvent::Destroyed) {
                let owner = window.label().to_owned();
                let state = window.state::<DesktopState>();
                let broker = state.host_keys.clone();
                let interactive = state.interactive_auth.clone();
                let credentials = state.ephemeral_credentials.clone();
                let managed_keys = state.managed_key_staging.clone();
                tauri::async_runtime::spawn(async move {
                    broker.reject_owner(&owner).await;
                    interactive.reject_owner(&owner).await;
                    credentials.purge_owner(&owner).await;
                    managed_keys.purge_owner(&owner).await;
                });
            }
        })
        .invoke_handler(tauri::generate_handler![
            ai_agent_discovery::discover_ai_agents,
            run_local_ai_agent,
            cancel_local_ai_agent,
            start_ai_agent_turn,
            authorize_ai_agent_tool,
            continue_ai_agent_turn,
            cancel_ai_agent_turn,
            complete_ai_chat,
            stream_ai_chat,
            list_ai_models,
            cancel_ai_chat,
            has_saved_ai_api_key,
            save_ai_api_key,
            delete_ai_api_key,
            get_backend_status,
            validate_ssh_connection,
            stage_ssh_password,
            stage_telnet_password,
            stage_ssh_key_passphrase,
            stage_group_ssh_password,
            stage_group_telnet_password,
            stage_group_proxy_password,
            stage_managed_ssh_key_bundle,
            list_managed_ssh_keys,
            create_managed_ssh_key,
            update_managed_ssh_key,
            delete_managed_ssh_key,
            rotate_managed_ssh_master_key,
            list_password_identities,
            create_password_identity,
            update_password_identity,
            delete_password_identity,
            list_proxy_profiles,
            create_proxy_profile,
            update_proxy_profile,
            delete_proxy_profile,
            list_group_configs,
            create_group_config,
            update_group_config,
            delete_group_config,
            list_port_forward_rules,
            create_port_forward_rule,
            update_port_forward_rule,
            delete_port_forward_rule,
            start_port_forward,
            stop_port_forward,
            list_known_hosts,
            list_docker_containers,
            list_docker_images,
            get_docker_stats,
            inspect_docker_container,
            run_docker_container_action,
            list_nvidia_gpus,
            get_system_overview,
            list_remote_processes,
            list_listening_ports,
            list_system_services,
            signal_remote_process,
            run_system_service_action,
            list_tmux_sessions,
            create_tmux_session,
            rename_tmux_session,
            kill_tmux_session,
            replace_known_hosts,
            scan_system_known_hosts,
            list_connection_logs,
            read_connection_log_replay,
            export_connection_log,
            replace_connection_logs,
            clear_unsaved_connection_logs,
            list_settings,
            replace_settings,
            list_vault_notes,
            create_vault_note,
            update_vault_note,
            delete_vault_note,
            list_saved_snippets,
            create_saved_snippet,
            update_saved_snippet,
            delete_saved_snippet,
            list_saved_hosts,
            list_serial_ports,
            create_saved_host,
            update_saved_host,
            delete_saved_host,
            inspect_legacy_vault,
            commit_legacy_vault_import,
            start_ssh_session,
            clone_ssh_session,
            start_saved_host_session,
            start_saved_telnet_session,
            start_saved_serial_session,
            start_telnet_session,
            start_serial_session,
            list_local_shells,
            start_local_pty_session,
            start_mosh_session,
            start_saved_mosh_session,
            start_et_session,
            ssh_session_input,
            ssh_session_input_raw,
            telnet_session_input_raw,
            serial_session_input_raw,
            local_pty_session_input_raw,
            mosh_session_input_raw,
            et_session_input_raw,
            resize_ssh_session,
            resize_telnet_session,
            resize_serial_session,
            resize_local_pty_session,
            resize_mosh_session,
            resize_et_session,
            close_ssh_session,
            close_telnet_session,
            close_serial_session,
            close_local_pty_session,
            close_mosh_session,
            close_et_session,
            cancel_ssh_session,
            cancel_telnet_session,
            cancel_serial_session,
            cancel_local_pty_session,
            cancel_mosh_session,
            cancel_et_session,
            send_serial_ymodem,
            receive_serial_ymodem,
            cancel_serial_ymodem,
            start_serial_zmodem,
            cancel_serial_zmodem,
            sftp_read_dir,
            sftp_metadata,
            sftp_create_dir,
            sftp_remove_file,
            sftp_remove_dir,
            sftp_rename,
            sftp_read_file,
            sftp_replace_file_if_unchanged_raw,
            classify_local_transfer_source,
            start_sftp_upload,
            start_sftp_upload_directory,
            start_sftp_download,
            start_sftp_download_directory,
            pause_sftp_transfer,
            resume_sftp_transfer,
            cancel_sftp_transfer,
            subscribe_host_key_prompts,
            respond_to_host_key,
            subscribe_interactive_prompts,
            respond_to_interactive_auth,
            cancel_interactive_auth,
            open_settings_window,
            hide_settings_window,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Goral desktop application");
}

#[cfg(test)]
include!("lib_tests.rs");
