mod algorithms;
mod auth;
mod directory_transfer;
mod host_key;
mod host_key_broker;
mod interactive_broker;
mod local_tree;
mod model;
mod port_forward;
mod proxy;
mod remote_tree;
mod resolved_port_forward;
mod runtime;
mod sftp;
mod transfer_path;
mod transport;
mod validation;

pub use auth::{AuthAttempt, AuthAttemptKind, AuthPlan, plan_authentication};
pub use directory_transfer::{
    DIRECTORY_RESUME_CHECKPOINT_VERSION, DirectoryResumeCheckpoint, DirectoryTraversalBudget,
    DirectoryTraversalError, EMPTY_DIRECTORY_MANIFEST_HASH, EMPTY_DIRECTORY_MANIFEST_STATE_V2,
    MAX_SFTP_DIRECTORY_TRAVERSAL_DIRECTORIES, MAX_SFTP_DIRECTORY_TRAVERSAL_ENTRIES,
    MAX_SFTP_FOLLOWED_SYMLINK_DEPTH, append_directory_manifest_identity,
    create_directory_entry_identity, normalize_canonical_directory_path,
    should_follow_symlink_directory,
};
pub use host_key::{
    HostKeyClassification, HostKeyStatus, KnownHost, LiveHostKey, classify_host_key,
    normalize_fingerprint,
};
pub use host_key_broker::{
    HostKeyBroker, HostKeyBrokerError, HostKeyPrompt, HostKeyPromptReceiver,
    PromptingHostKeyVerifier,
};
pub use interactive_broker::{
    InteractiveAuthBroker, InteractiveBrokerError, InteractivePrompt, InteractivePromptReceiver,
    PromptingInteractiveAuthResponder,
};
pub use local_tree::{
    LocalTreeDirectoryEntry, LocalTreeError, LocalTreeFileEntry, LocalTreeManifest,
    LocalTreeOptions, LocalTreeSkipReason, LocalTreeSkippedEntry, discover_local_tree,
};
pub use model::{
    AlgorithmOverrides, KeepaliveConfig, MAX_JUMP_HOSTS, NormalizedKeepaliveConfig,
    NormalizedProxyConfig, NormalizedSshConnectionConfig, NormalizedSshTimeouts, ProxyConfig,
    ProxyType, SshAuthConfig, SshAuthMethod, SshConnectionConfig, SshJumpHost, SshTimeouts,
};
pub use port_forward::{
    DirectTcpipOpener, ForwardedTcpipConnection, NormalizedPortForwardRule, PortForwardError,
    PortForwardEvent, PortForwardEventReceiver, PortForwardKind, PortForwardManager,
    PortForwardRule, PortForwardStart, PortForwardStream, RemoteTcpipForwarder,
};
pub use proxy::substitute_proxy_command;
pub use remote_tree::{
    RemoteTreeDirectoryEntry, RemoteTreeError, RemoteTreeFileEntry, RemoteTreeManifest,
    RemoteTreeOptions, RemoteTreeSkipReason, RemoteTreeSkippedEntry, RemoteTreeSource,
    discover_remote_tree,
};
pub use resolved_port_forward::{
    ResolvedPortForwardManager, ResolvedPortForwardPhase, ResolvedPortForwardRuntime,
};
pub use runtime::{
    SessionEvent, SessionEventReceiver, SessionExecError, SessionManager, SessionManagerError,
    SessionSftpError, SessionStart, SftpDirectoryTransferStart, SftpDownloadPlan,
    SftpDownloadStart, SftpTransferEvent, SftpTransferEventReceiver, SftpTransferStart,
};
pub use sftp::{
    SftpArtifactPlan, SftpClient, SftpEntry, SftpEntryKind, SftpError, SftpMetadata,
    SftpStreamUploadOutcome, SftpTransferCheckpoint, SftpTransferControl, SftpTransferDirection,
    SftpTransferProgress, SftpUploadOutcome, SftpUploadPlan,
};
pub use transfer_path::{
    TransferPathError, join_local_transfer_target, join_remote_transfer_target,
};
pub use transport::{
    AuthenticationPrompt, AuthenticationPrompts, CommandOutput, ConnectionCredentials,
    DirectConnector, ExecLimits, HostChainResolver, HostKeyVerifier, InteractiveAuthResponder,
    KnownHostsVerifier, NativeClientCredentialView, ResolvedSshEndpoint, SecretText, ShellEvent,
    ShellOptions, SshConnection, SshShell, TerminalSize, TransportError, TransportErrorCode,
};
pub use validation::{ValidationIssue, ValidationResult, validate_connection};
