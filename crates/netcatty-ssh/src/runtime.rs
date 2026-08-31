use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    CommandOutput, ConnectionCredentials, DirectConnector, DirectoryResumeCheckpoint, ExecLimits,
    HostChainResolver, HostKeyVerifier, InteractiveAuthResponder, LocalTreeFileEntry,
    LocalTreeOptions, NormalizedSshConnectionConfig, RemoteTreeFileEntry, RemoteTreeOptions,
    RemoteTreeSource, ResolvedSshEndpoint, SftpArtifactPlan, SftpClient, SftpEntry, SftpEntryKind,
    SftpError, SftpMetadata, SftpStreamUploadOutcome, SftpTransferCheckpoint, SftpTransferControl,
    SftpTransferDirection, SftpTransferProgress, SftpUploadPlan, ShellEvent, ShellOptions,
    SshAuthConfig, SshConnection, TerminalSize, TransportError, TransportErrorCode,
    discover_local_tree, discover_remote_tree, join_local_transfer_target,
    join_remote_transfer_target,
};

const COMMAND_BUFFER_SIZE: usize = 128;
const EVENT_BUFFER_SIZE: usize = 256;
const SFTP_COMMAND_BUFFER_SIZE: usize = 32;
const SFTP_TRANSFER_CONCURRENCY: usize = 2;
const SFTP_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const SFTP_TRANSFER_FINALIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_INPUT_CHUNK_BYTES: usize = 64 * 1024;
const MAX_TERMINAL_DIMENSION: u32 = 10_000;
/// One authenticated SSH transport may multiplex this many managed terminal
/// sessions. This matches the desktop's global terminal-session bound while
/// preventing an unbounded number of remote channels on one connection.
const MAX_SESSIONS_PER_TRANSPORT: usize = 64;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TRANSFER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Connecting,
    Connected,
    Data(Vec<u8>),
    ExtendedData {
        code: u32,
        data: Vec<u8>,
    },
    Eof,
    ExitStatus(u32),
    Closed,
    Error {
        code: TransportErrorCode,
        message: String,
    },
}

pub type SessionEventReceiver = broadcast::Receiver<SessionEvent>;

pub struct SessionStart {
    pub session_id: String,
    pub events: SessionEventReceiver,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SftpTransferEvent {
    Queued,
    Started,
    Progress {
        bytes_transferred: u64,
        total_bytes: u64,
    },
    Paused {
        checkpoint: Option<SftpTransferCheckpoint>,
    },
    Resumed,
    Completed {
        checkpoint: SftpTransferCheckpoint,
        replaced_existing: bool,
    },
    Cancelled {
        checkpoint: Option<SftpTransferCheckpoint>,
    },
    Failed {
        code: String,
        message: String,
        checkpoint: Option<SftpTransferCheckpoint>,
    },
    DirectoryScanning,
    DirectoryProgress {
        files_completed: u64,
        total_files: u64,
        bytes_transferred: u64,
        total_bytes: u64,
        current_path: Option<String>,
        checkpoint: DirectoryResumeCheckpoint,
    },
    DirectoryCompleted {
        files_completed: u64,
        total_bytes: u64,
        skipped_entries: u64,
        checkpoint: DirectoryResumeCheckpoint,
    },
    DirectoryCancelled {
        checkpoint: DirectoryResumeCheckpoint,
    },
    DirectoryFailed {
        message: String,
        failed_files: u64,
        checkpoint: DirectoryResumeCheckpoint,
    },
}

pub type SftpTransferEventReceiver = broadcast::Receiver<SftpTransferEvent>;

pub struct SftpTransferStart {
    pub transfer_id: String,
    pub plan: SftpUploadPlan,
    pub events: SftpTransferEventReceiver,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpDownloadPlan {
    pub artifacts: SftpArtifactPlan,
}

pub struct SftpDownloadStart {
    pub transfer_id: String,
    pub plan: SftpDownloadPlan,
    pub events: SftpTransferEventReceiver,
}

pub struct SftpDirectoryTransferStart {
    pub transfer_id: String,
    pub events: SftpTransferEventReceiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionManagerError {
    NotFound,
    NotConnected,
    TransportSessionLimit,
    InputTooLarge,
    InvalidTerminalSize,
    CommandQueueFull,
    Closed,
}

impl fmt::Display for SessionManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "SSH 会话不存在",
            Self::NotConnected => "SSH session is not connected",
            Self::TransportSessionLimit => {
                "The authenticated SSH transport has reached its session limit"
            }
            Self::InputTooLarge => "SSH 单次输入数据过大",
            Self::InvalidTerminalSize => "SSH 终端尺寸无效",
            Self::CommandQueueFull => "SSH 会话命令队列已满",
            Self::Closed => "SSH 会话已经关闭",
        })
    }
}

impl std::error::Error for SessionManagerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSftpError {
    Session(SessionManagerError),
    Sftp(SftpError),
    LocalFile,
    DestinationBusy,
}

impl fmt::Display for SessionSftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => error.fmt(formatter),
            Self::Sftp(error) => error.fmt(formatter),
            Self::LocalFile => formatter.write_str("Local transfer file is unavailable"),
            Self::DestinationBusy => {
                formatter.write_str("Another active transfer already owns this destination")
            }
        }
    }
}

impl std::error::Error for SessionSftpError {}

/// Why a session-scoped command could not be run.
///
/// Kept separate from the transport's own error so callers can tell "this
/// session is gone" from "the remote refused the channel" — the first is a
/// UI state, the second is worth surfacing to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExecError {
    Session(SessionManagerError),
    /// The session exists but is not backed by a reusable SSH transport, so
    /// there is no connection to open a second channel on.
    TransportUnavailable,
    Transport(TransportErrorCode),
}

impl fmt::Display for SessionExecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => error.fmt(formatter),
            Self::TransportUnavailable => {
                formatter.write_str("This session cannot run additional commands")
            }
            Self::Transport(_) => formatter.write_str("The remote host rejected the command"),
        }
    }
}

impl std::error::Error for SessionExecError {}

enum SessionCommand {
    Input(Vec<u8>),
    Resize(TerminalSize),
    Close,
}

enum SessionConnection {
    Direct(ResolvedSshEndpoint),
    Chain {
        target: ResolvedSshEndpoint,
        resolver: Arc<dyn HostChainResolver>,
    },
    Reuse(SharedTransportLease),
}

impl SessionConnection {
    fn endpoint_key(&self) -> String {
        match self {
            Self::Direct(target) | Self::Chain { target, .. } => format!(
                "{}@{}:{}",
                target.config.username,
                target.config.hostname.to_ascii_lowercase(),
                target.config.port
            ),
            // A cloned shell does not carry a second endpoint configuration.
            // The transport records the canonical key once, so this path stays
            // total even if a future caller constructs a reuse connection
            // directly.
            Self::Reuse(lease) => lease.transport.endpoint_key.clone(),
        }
    }
}

struct SharedSshTransport {
    connection: Arc<SshConnection>,
    endpoint_key: String,
    session_count: AtomicUsize,
    disconnected: AtomicBool,
}

impl SharedSshTransport {
    fn new(connection: SshConnection, endpoint_key: String) -> Arc<Self> {
        Arc::new(Self {
            connection: Arc::new(connection),
            endpoint_key,
            session_count: AtomicUsize::new(1),
            disconnected: AtomicBool::new(false),
        })
    }

    fn try_acquire(self: &Arc<Self>) -> Result<SharedTransportLease, SessionManagerError> {
        let mut current = self.session_count.load(Ordering::Acquire);
        loop {
            if current == 0 || self.disconnected.load(Ordering::Acquire) {
                return Err(SessionManagerError::NotConnected);
            }
            if current >= MAX_SESSIONS_PER_TRANSPORT {
                return Err(SessionManagerError::TransportSessionLimit);
            }
            match self.session_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(SharedTransportLease {
                        transport: self.clone(),
                        released: false,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn initial_lease(self: &Arc<Self>) -> SharedTransportLease {
        SharedTransportLease {
            transport: self.clone(),
            released: false,
        }
    }
}

struct SharedTransportLease {
    transport: Arc<SharedSshTransport>,
    released: bool,
}

impl SharedTransportLease {
    async fn release(mut self) {
        self.released = true;
        if self.transport.session_count.fetch_sub(1, Ordering::AcqRel) == 1
            && !self.transport.disconnected.swap(true, Ordering::AcqRel)
        {
            let _ = self.transport.connection.disconnect().await;
        }
    }
}

impl Drop for SharedTransportLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if self.transport.session_count.fetch_sub(1, Ordering::AcqRel) != 1
            || self.transport.disconnected.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let connection = self.transport.connection.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = connection.disconnect().await;
            });
        }
    }
}

enum SftpCommand {
    ReadDir {
        path: String,
        reply: oneshot::Sender<Result<Vec<SftpEntry>, SftpError>>,
    },
    Metadata {
        path: String,
        reply: oneshot::Sender<Result<SftpMetadata, SftpError>>,
    },
    Canonicalize {
        path: String,
        reply: oneshot::Sender<Result<String, SftpError>>,
    },
    FollowedMetadata {
        path: String,
        reply: oneshot::Sender<Result<SftpMetadata, SftpError>>,
    },
    CreateDir {
        path: String,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    RemoveFile {
        path: String,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    RemoveDir {
        path: String,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    Rename {
        source: String,
        destination: String,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    ReadFile {
        path: String,
        reply: oneshot::Sender<Result<Vec<u8>, SftpError>>,
    },
    WriteFile {
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    ReplaceFileIfUnchanged {
        path: String,
        expected: Vec<u8>,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), SftpError>>,
    },
    Upload {
        source: tokio::fs::File,
        total_bytes: u64,
        source_fingerprint: String,
        source_modified_at: Option<u32>,
        plan: SftpUploadPlan,
        resume: Option<SftpTransferCheckpoint>,
        control: SftpTransferControl,
        start_gate: Option<SftpTransferControl>,
        progress: mpsc::Sender<SftpTransferProgress>,
        events: broadcast::Sender<SftpTransferEvent>,
        done: oneshot::Sender<()>,
    },
    Download {
        destination: tokio::fs::File,
        remote_path: String,
        local_path: PathBuf,
        staged_path: PathBuf,
        backup_path: PathBuf,
        expected_target: Option<LocalFileSnapshot>,
        plan: SftpDownloadPlan,
        owner: LocalDownloadOwner,
        cleanup_on_cancel: bool,
        resume: Option<SftpTransferCheckpoint>,
        control: SftpTransferControl,
        start_gate: Option<SftpTransferControl>,
        progress: mpsc::Sender<SftpTransferProgress>,
        events: broadcast::Sender<SftpTransferEvent>,
        done: oneshot::Sender<()>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalFileSnapshot {
    size: u64,
    modified_nanos: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalDownloadOwner {
    magic: String,
    version: u8,
    artifact_id: String,
    target_hash: String,
    source_hash: String,
    total_bytes: u64,
    initial_target_hash: Option<String>,
}

struct PreparedLocalDownload {
    destination: tokio::fs::File,
    plan: SftpDownloadPlan,
    owner: LocalDownloadOwner,
    workspace_path: PathBuf,
    staged_path: PathBuf,
    backup_path: PathBuf,
    expected_target: Option<LocalFileSnapshot>,
    created_workspace: bool,
}

struct ManagedSession {
    commands: mpsc::Sender<SessionCommand>,
    sftp_commands: mpsc::Sender<SftpCommand>,
    events: broadcast::Sender<SessionEvent>,
    cancellation: CancellationToken,
    endpoint_key: String,
    transport: Option<Arc<SharedSshTransport>>,
}

struct ManagedTransfer {
    session_id: String,
    control: SftpTransferControl,
    events: broadcast::Sender<SftpTransferEvent>,
    write_set: Vec<TransferDestination>,
    parent_transfer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferDestination {
    endpoint: String,
    path: String,
    is_directory: bool,
    separator: char,
}

struct DirectoryChildProgress {
    entry_index: u64,
    bytes_transferred: u64,
    current_path: String,
}

struct DirectoryChildResult {
    entry: LocalTreeFileEntry,
    outcome: DirectoryChildOutcome,
}

struct DirectoryDownloadChildResult {
    entry: RemoteTreeFileEntry,
    outcome: DirectoryChildOutcome,
}

enum DirectoryChildOutcome {
    Completed,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Default)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    transfers: Arc<Mutex<HashMap<String, ManagedTransfer>>>,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn begin(
        &self,
        config: NormalizedSshConnectionConfig,
        auth: SshAuthConfig,
        credentials: ConnectionCredentials,
        verifier: Arc<dyn HostKeyVerifier>,
        interactive: Option<Arc<dyn InteractiveAuthResponder>>,
        shell_options: ShellOptions,
    ) -> SessionStart {
        self.begin_session(
            SessionConnection::Direct(ResolvedSshEndpoint {
                config,
                auth,
                credentials,
                verifier,
                interactive,
            }),
            shell_options,
        )
        .await
    }

    /// Start a managed shell over the target's ordered saved-host jump chain.
    ///
    /// The resolver and every secret-bearing endpoint remain entirely in Rust.
    /// Use [`SessionManager::begin`] when the caller intentionally wants the
    /// existing direct-connection behavior.
    pub async fn begin_chain(
        &self,
        target: ResolvedSshEndpoint,
        resolver: Arc<dyn HostChainResolver>,
        shell_options: ShellOptions,
    ) -> SessionStart {
        self.begin_session(SessionConnection::Chain { target, resolver }, shell_options)
            .await
    }

    async fn begin_session(
        &self,
        connection: SessionConnection,
        shell_options: ShellOptions,
    ) -> SessionStart {
        let session_id = next_session_id();
        let endpoint_key = connection.endpoint_key();
        let (event_sender, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let (command_sender, command_receiver) = mpsc::channel(COMMAND_BUFFER_SIZE);
        let (sftp_sender, sftp_receiver) = mpsc::channel(SFTP_COMMAND_BUFFER_SIZE);
        let cancellation = CancellationToken::new();
        self.sessions.lock().await.insert(
            session_id.clone(),
            ManagedSession {
                commands: command_sender,
                sftp_commands: sftp_sender,
                events: event_sender.clone(),
                cancellation: cancellation.clone(),
                endpoint_key,
                transport: None,
            },
        );

        let sessions = self.sessions.clone();
        let runtime_sessions = sessions.clone();
        let task_session_id = session_id.clone();
        tokio::spawn(async move {
            run_session(
                &task_session_id,
                connection,
                shell_options,
                event_sender,
                command_receiver,
                sftp_receiver,
                cancellation,
                runtime_sessions,
            )
            .await;
            sessions.lock().await.remove(&task_session_id);
        });

        SessionStart {
            session_id,
            events: event_receiver,
        }
    }

    /// Opens an independent shell channel on the exact authenticated transport
    /// owned by `source_session_id`.
    ///
    /// No endpoint, authentication method, credential, proxy, or jump-host
    /// data is accepted here, so a caller cannot redirect a source transport to
    /// another identity or host. The returned session has independent command,
    /// event, cancellation, SFTP, and transfer ownership.
    pub async fn begin_reuse(
        &self,
        source_session_id: &str,
        shell_options: ShellOptions,
    ) -> Result<SessionStart, SessionManagerError> {
        let (transport, endpoint_key) = {
            let sessions = self.sessions.lock().await;
            let source = sessions
                .get(source_session_id)
                .ok_or(SessionManagerError::NotFound)?;
            let transport = source
                .transport
                .as_ref()
                .ok_or(SessionManagerError::NotConnected)?;
            (transport.try_acquire()?, source.endpoint_key.clone())
        };

        let session_id = next_session_id();
        let (event_sender, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let (command_sender, command_receiver) = mpsc::channel(COMMAND_BUFFER_SIZE);
        let (sftp_sender, sftp_receiver) = mpsc::channel(SFTP_COMMAND_BUFFER_SIZE);
        let cancellation = CancellationToken::new();
        self.sessions.lock().await.insert(
            session_id.clone(),
            ManagedSession {
                commands: command_sender,
                sftp_commands: sftp_sender,
                events: event_sender.clone(),
                cancellation: cancellation.clone(),
                endpoint_key,
                transport: None,
            },
        );

        let sessions = self.sessions.clone();
        let runtime_sessions = sessions.clone();
        let task_session_id = session_id.clone();
        tokio::spawn(async move {
            run_session(
                &task_session_id,
                SessionConnection::Reuse(transport),
                shell_options,
                event_sender,
                command_receiver,
                sftp_receiver,
                cancellation,
                runtime_sessions,
            )
            .await;
            sessions.lock().await.remove(&task_session_id);
        });

        Ok(SessionStart {
            session_id,
            events: event_receiver,
        })
    }

    pub async fn subscribe(
        &self,
        session_id: &str,
    ) -> Result<SessionEventReceiver, SessionManagerError> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|session| session.events.subscribe())
            .ok_or(SessionManagerError::NotFound)
    }

    pub async fn send_input(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), SessionManagerError> {
        if data.len() > MAX_INPUT_CHUNK_BYTES {
            return Err(SessionManagerError::InputTooLarge);
        }
        self.send_command(session_id, SessionCommand::Input(data))
            .await
    }

    pub async fn resize(
        &self,
        session_id: &str,
        size: TerminalSize,
    ) -> Result<(), SessionManagerError> {
        if size.columns == 0
            || size.rows == 0
            || size.columns > MAX_TERMINAL_DIMENSION
            || size.rows > MAX_TERMINAL_DIMENSION
        {
            return Err(SessionManagerError::InvalidTerminalSize);
        }
        self.send_command(session_id, SessionCommand::Resize(size))
            .await
    }

    pub async fn close(&self, session_id: &str) -> Result<(), SessionManagerError> {
        self.send_command(session_id, SessionCommand::Close).await
    }

    pub async fn cancel(&self, session_id: &str) -> Result<(), SessionManagerError> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(session_id)
            .ok_or(SessionManagerError::NotFound)?;
        session.cancellation.cancel();
        drop(sessions);
        let controls = self
            .transfers
            .lock()
            .await
            .values()
            .filter(|transfer| transfer.session_id == session_id)
            .map(|transfer| transfer.control.clone())
            .collect::<Vec<_>>();
        for control in controls {
            control.cancel();
        }
        Ok(())
    }

    pub async fn active_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Runs one command on this session's connection and captures the result.
    ///
    /// Opens a second channel on the same authenticated connection rather
    /// than typing into the user's shell: the interactive session keeps its
    /// scrollback and its shell state, and parsed output can never be
    /// polluted by whatever the user happens to be running.
    pub async fn exec_capture(
        &self,
        session_id: &str,
        command: &str,
        limits: ExecLimits,
    ) -> Result<CommandOutput, SessionExecError> {
        let connection = {
            let sessions = self.sessions.lock().await;
            let session = sessions
                .get(session_id)
                .ok_or(SessionExecError::Session(SessionManagerError::NotFound))?;
            session
                .transport
                .as_ref()
                .map(|transport| transport.connection.clone())
                .ok_or(SessionExecError::TransportUnavailable)?
        };

        connection
            .exec_capture(command, limits)
            .await
            .map_err(|error| SessionExecError::Transport(error.code))
    }

    pub async fn sftp_read_dir(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<Vec<SftpEntry>, SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::ReadDir { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_metadata(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<SftpMetadata, SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::Metadata { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    async fn sftp_canonicalize(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<String, SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::Canonicalize { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    async fn sftp_followed_metadata(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<SftpMetadata, SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::FollowedMetadata { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_create_dir(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::CreateDir { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_remove_file(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::RemoveFile { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_remove_dir(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::RemoveDir { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_rename(
        &self,
        session_id: &str,
        source: String,
        destination: String,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(
            session_id,
            SftpCommand::Rename {
                source,
                destination,
                reply,
            },
        )
        .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_read_file(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<Vec<u8>, SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::ReadFile { path, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_write_file(
        &self,
        session_id: &str,
        path: String,
        data: Vec<u8>,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(session_id, SftpCommand::WriteFile { path, data, reply })
            .await?;
        receive_sftp_response(response).await
    }

    pub async fn sftp_replace_file_if_unchanged(
        &self,
        session_id: &str,
        path: String,
        expected: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), SessionSftpError> {
        let (reply, response) = oneshot::channel();
        self.send_sftp_command(
            session_id,
            SftpCommand::ReplaceFileIfUnchanged {
                path,
                expected,
                data,
                reply,
            },
        )
        .await?;
        receive_sftp_response(response).await
    }

    pub async fn begin_sftp_upload(
        &self,
        session_id: &str,
        local_path: PathBuf,
        remote_path: String,
        plan: Option<SftpUploadPlan>,
        resume: Option<SftpTransferCheckpoint>,
    ) -> Result<SftpTransferStart, SessionSftpError> {
        self.begin_sftp_upload_with_parent(
            session_id,
            local_path,
            remote_path,
            plan,
            resume,
            None,
            None,
            None,
        )
        .await
    }

    async fn begin_sftp_upload_with_parent(
        &self,
        session_id: &str,
        local_path: PathBuf,
        remote_path: String,
        plan: Option<SftpUploadPlan>,
        resume: Option<SftpTransferCheckpoint>,
        expected_source: Option<(u64, u64)>,
        parent_transfer_id: Option<String>,
        start_gate: Option<SftpTransferControl>,
    ) -> Result<SftpTransferStart, SessionSftpError> {
        let source = tokio::fs::File::open(&local_path)
            .await
            .map_err(|_| SessionSftpError::LocalFile)?;
        let metadata = source
            .metadata()
            .await
            .map_err(|_| SessionSftpError::LocalFile)?;
        if !metadata.is_file() {
            return Err(SessionSftpError::LocalFile);
        }
        let total_bytes = metadata.len();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
        let modified_millis = modified
            .as_ref()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0);
        if expected_source.is_some_and(|expected| expected != (total_bytes, modified_millis)) {
            return Err(SessionSftpError::Sftp(SftpError::SourceChanged));
        }
        let source_fingerprint = format!(
            "{total_bytes}:{}",
            modified.as_ref().map_or(0, std::time::Duration::as_nanos)
        );
        let source_modified_at =
            modified.and_then(|duration| u32::try_from(duration.as_secs()).ok());
        let plan = match plan {
            Some(plan) if plan.target_path == remote_path => plan,
            Some(_) => return Err(SessionSftpError::Sftp(SftpError::InvalidUploadPlan)),
            None => SftpClient::plan_safe_upload(&remote_path).map_err(SessionSftpError::Sftp)?,
        };
        let artifacts = plan
            .artifacts
            .as_ref()
            .ok_or(SessionSftpError::Sftp(SftpError::InvalidUploadPlan))?;
        let endpoint_key = self.session_endpoint_key(session_id).await?;
        let write_set = vec![
            remote_transfer_destination(&endpoint_key, &remote_path, false),
            remote_transfer_destination(&endpoint_key, &artifacts.workspace_path, true),
            remote_transfer_destination(&endpoint_key, &artifacts.owner_path, false),
            remote_transfer_destination(&endpoint_key, &plan.staged_path, false),
            remote_transfer_destination(&endpoint_key, &plan.backup_path, false),
        ];
        let transfer_id = next_transfer_id();
        let control = SftpTransferControl::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let _ = events.send(SftpTransferEvent::Queued);
        let (progress, mut progress_receiver) = mpsc::channel(64);
        let (done, done_receiver) = oneshot::channel();

        self.reserve_transfer_write_set(
            transfer_id.clone(),
            session_id,
            write_set,
            parent_transfer_id,
            control.clone(),
            events.clone(),
        )
        .await?;
        let command = SftpCommand::Upload {
            source,
            total_bytes,
            source_fingerprint,
            source_modified_at,
            plan: plan.clone(),
            resume,
            control,
            start_gate,
            progress,
            events: events.clone(),
            done,
        };
        if let Err(error) = self.send_sftp_command(session_id, command).await {
            self.transfers.lock().await.remove(&transfer_id);
            return Err(error);
        }

        let transfers = self.transfers.clone();
        let task_transfer_id = transfer_id.clone();
        tokio::spawn(async move {
            let mut done_receiver = std::pin::pin!(done_receiver);
            loop {
                tokio::select! {
                    progress = progress_receiver.recv() => match progress {
                        Some(progress) => {
                            let _ = events.send(SftpTransferEvent::Progress {
                                bytes_transferred: progress.bytes_transferred,
                                total_bytes: progress.total_bytes,
                            });
                        }
                        None => break,
                    },
                    _ = &mut done_receiver => break,
                }
            }
            while let Ok(progress) = progress_receiver.try_recv() {
                let _ = events.send(SftpTransferEvent::Progress {
                    bytes_transferred: progress.bytes_transferred,
                    total_bytes: progress.total_bytes,
                });
            }
            transfers.lock().await.remove(&task_transfer_id);
        });

        Ok(SftpTransferStart {
            transfer_id,
            plan,
            events: event_receiver,
        })
    }

    pub async fn begin_sftp_upload_directory(
        &self,
        session_id: &str,
        local_root: PathBuf,
        remote_root: String,
        options: LocalTreeOptions,
        resume: Option<DirectoryResumeCheckpoint>,
    ) -> Result<SftpDirectoryTransferStart, SessionSftpError> {
        if local_root.as_os_str().is_empty() {
            return Err(SessionSftpError::LocalFile);
        }
        let remote_root = normalize_remote_directory_root(&remote_root)
            .ok_or(SessionSftpError::Sftp(SftpError::InvalidUploadPlan))?;
        let endpoint_key = self.session_endpoint_key(session_id).await?;
        let transfer_id = next_transfer_id();
        let control = SftpTransferControl::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let _ = events.send(SftpTransferEvent::Queued);

        self.reserve_transfer(
            transfer_id.clone(),
            session_id,
            remote_transfer_destination(&endpoint_key, &remote_root, true),
            None,
            control.clone(),
            events.clone(),
        )
        .await?;

        let manager = self.clone();
        let task_transfer_id = transfer_id.clone();
        let task_session_id = session_id.to_owned();
        tokio::spawn(async move {
            run_sftp_upload_directory(
                manager.clone(),
                task_transfer_id.clone(),
                task_session_id,
                local_root,
                remote_root,
                options,
                resume,
                control,
                events,
            )
            .await;
            manager.transfers.lock().await.remove(&task_transfer_id);
        });

        Ok(SftpDirectoryTransferStart {
            transfer_id,
            events: event_receiver,
        })
    }

    pub async fn begin_sftp_download(
        &self,
        session_id: &str,
        remote_path: String,
        local_path: PathBuf,
        plan: Option<SftpDownloadPlan>,
        resume: Option<SftpTransferCheckpoint>,
    ) -> Result<SftpDownloadStart, SessionSftpError> {
        self.begin_sftp_download_with_parent(
            session_id,
            remote_path,
            local_path,
            plan,
            resume,
            None,
            None,
        )
        .await
    }

    async fn begin_sftp_download_with_parent(
        &self,
        session_id: &str,
        remote_path: String,
        local_path: PathBuf,
        plan: Option<SftpDownloadPlan>,
        resume: Option<SftpTransferCheckpoint>,
        parent_transfer_id: Option<String>,
        start_gate: Option<SftpTransferControl>,
    ) -> Result<SftpDownloadStart, SessionSftpError> {
        if local_path.as_os_str().is_empty() {
            return Err(SessionSftpError::LocalFile);
        }
        self.session_endpoint_key(session_id).await?;
        let remote_metadata = self
            .sftp_followed_metadata(session_id, remote_path.clone())
            .await?;
        if remote_metadata.kind != SftpEntryKind::File {
            return Err(SessionSftpError::Sftp(SftpError::DestinationNotRegularFile));
        }
        validate_download_resume_checkpoint(&remote_path, &remote_metadata, resume.as_ref())?;
        if plan.is_none()
            && resume
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.bytes_transferred > 0)
        {
            return Err(SessionSftpError::Sftp(SftpError::RecoveryArtifactConflict));
        }
        if plan.is_some() && resume.is_none() {
            return Err(SessionSftpError::Sftp(SftpError::CheckpointMismatch));
        }
        let prepared = prepare_local_download_artifacts(
            &local_path,
            &remote_path,
            &remote_metadata,
            plan,
            resume.as_ref(),
        )
        .await?;
        let transfer_id = next_transfer_id();
        let control = SftpTransferControl::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let _ = events.send(SftpTransferEvent::Queued);
        if let Err(error) = self
            .reserve_transfer_write_set(
                transfer_id.clone(),
                session_id,
                vec![
                    local_transfer_destination(&local_path, false),
                    local_transfer_destination(&prepared.workspace_path, true),
                    local_transfer_destination(&prepared.staged_path, false),
                    local_transfer_destination(&prepared.backup_path, false),
                ],
                parent_transfer_id.clone(),
                control.clone(),
                events.clone(),
            )
            .await
        {
            if prepared.created_workspace {
                let _ =
                    cleanup_owned_local_download_workspace(&prepared.plan, &prepared.owner).await;
            }
            return Err(error);
        }
        let PreparedLocalDownload {
            destination,
            plan,
            owner,
            workspace_path: _,
            staged_path,
            backup_path,
            expected_target,
            created_workspace,
        } = prepared;

        let (progress, progress_receiver) = mpsc::channel(64);
        let (done, done_receiver) = oneshot::channel();
        let command = SftpCommand::Download {
            destination,
            remote_path,
            local_path,
            staged_path,
            backup_path,
            expected_target,
            plan: plan.clone(),
            owner: owner.clone(),
            cleanup_on_cancel: parent_transfer_id.is_some(),
            resume,
            control,
            start_gate,
            progress,
            events: events.clone(),
            done,
        };
        if let Err(error) = self.send_sftp_command(session_id, command).await {
            self.transfers.lock().await.remove(&transfer_id);
            if created_workspace {
                let _ = cleanup_owned_local_download_workspace(&plan, &owner).await;
            }
            return Err(error);
        }
        spawn_transfer_forwarder(
            self.transfers.clone(),
            transfer_id.clone(),
            events,
            progress_receiver,
            done_receiver,
        );
        Ok(SftpDownloadStart {
            transfer_id,
            plan,
            events: event_receiver,
        })
    }

    pub async fn begin_sftp_download_directory(
        &self,
        session_id: &str,
        remote_root: String,
        local_root: PathBuf,
        options: RemoteTreeOptions,
        resume: Option<DirectoryResumeCheckpoint>,
    ) -> Result<SftpDirectoryTransferStart, SessionSftpError> {
        if local_root.as_os_str().is_empty() {
            return Err(SessionSftpError::LocalFile);
        }
        let remote_root = normalize_remote_directory_root(&remote_root)
            .ok_or(SessionSftpError::Sftp(SftpError::OperationFailed))?;
        self.session_endpoint_key(session_id).await?;
        let transfer_id = next_transfer_id();
        let control = SftpTransferControl::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let _ = events.send(SftpTransferEvent::Queued);

        self.reserve_transfer(
            transfer_id.clone(),
            session_id,
            local_transfer_destination(&local_root, true),
            None,
            control.clone(),
            events.clone(),
        )
        .await?;

        let manager = self.clone();
        let task_transfer_id = transfer_id.clone();
        let task_session_id = session_id.to_owned();
        tokio::spawn(async move {
            run_sftp_download_directory(
                manager.clone(),
                task_transfer_id.clone(),
                task_session_id,
                remote_root,
                local_root,
                options,
                resume,
                control,
                events,
            )
            .await;
            manager.transfers.lock().await.remove(&task_transfer_id);
        });

        Ok(SftpDirectoryTransferStart {
            transfer_id,
            events: event_receiver,
        })
    }

    pub async fn pause_sftp_transfer(&self, transfer_id: &str) -> Result<(), SessionManagerError> {
        let (controls, events) = self.transfer_family_handles(transfer_id).await?;
        for control in &controls {
            control.pause();
        }
        let checkpoint = controls[0].checkpoint().await;
        let _ = events.send(SftpTransferEvent::Paused { checkpoint });
        Ok(())
    }

    pub async fn resume_sftp_transfer(&self, transfer_id: &str) -> Result<(), SessionManagerError> {
        let (controls, events) = self.transfer_family_handles(transfer_id).await?;
        for control in controls {
            control.resume();
        }
        let _ = events.send(SftpTransferEvent::Resumed);
        Ok(())
    }

    pub async fn cancel_sftp_transfer(&self, transfer_id: &str) -> Result<(), SessionManagerError> {
        let transfers = self.transfers.lock().await;
        let root = transfers
            .get(transfer_id)
            .ok_or(SessionManagerError::NotFound)?;
        let mut controls = vec![root.control.clone()];
        controls.extend(
            transfers
                .values()
                .filter(|transfer| transfer.parent_transfer_id.as_deref() == Some(transfer_id))
                .map(|transfer| transfer.control.clone()),
        );
        drop(transfers);
        for control in controls {
            control.cancel();
        }
        Ok(())
    }

    async fn transfer_family_handles(
        &self,
        transfer_id: &str,
    ) -> Result<
        (
            Vec<SftpTransferControl>,
            broadcast::Sender<SftpTransferEvent>,
        ),
        SessionManagerError,
    > {
        let transfers = self.transfers.lock().await;
        let root = transfers
            .get(transfer_id)
            .ok_or(SessionManagerError::NotFound)?;
        let mut controls = vec![root.control.clone()];
        controls.extend(
            transfers
                .values()
                .filter(|transfer| transfer.parent_transfer_id.as_deref() == Some(transfer_id))
                .map(|transfer| transfer.control.clone()),
        );
        Ok((controls, root.events.clone()))
    }

    async fn session_endpoint_key(&self, session_id: &str) -> Result<String, SessionSftpError> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|session| session.endpoint_key.clone())
            .ok_or(SessionSftpError::Session(SessionManagerError::NotFound))
    }

    async fn reserve_transfer(
        &self,
        transfer_id: String,
        session_id: &str,
        destination: TransferDestination,
        parent_transfer_id: Option<String>,
        control: SftpTransferControl,
        events: broadcast::Sender<SftpTransferEvent>,
    ) -> Result<(), SessionSftpError> {
        self.reserve_transfer_write_set(
            transfer_id,
            session_id,
            vec![destination],
            parent_transfer_id,
            control,
            events,
        )
        .await
    }

    async fn reserve_transfer_write_set(
        &self,
        transfer_id: String,
        session_id: &str,
        write_set: Vec<TransferDestination>,
        parent_transfer_id: Option<String>,
        control: SftpTransferControl,
        events: broadcast::Sender<SftpTransferEvent>,
    ) -> Result<(), SessionSftpError> {
        if write_set.is_empty() {
            return Err(SessionSftpError::DestinationBusy);
        }
        let mut transfers = self.transfers.lock().await;
        if transfers.iter().any(|(existing_id, transfer)| {
            parent_transfer_id.as_deref() != Some(existing_id.as_str())
                && transfer.write_set.iter().any(|existing| {
                    write_set
                        .iter()
                        .any(|candidate| transfer_destinations_conflict(existing, candidate))
                })
        }) {
            return Err(SessionSftpError::DestinationBusy);
        }
        transfers.insert(
            transfer_id,
            ManagedTransfer {
                session_id: session_id.to_owned(),
                control,
                events,
                write_set,
                parent_transfer_id,
            },
        );
        Ok(())
    }

    async fn send_command(
        &self,
        session_id: &str,
        command: SessionCommand,
    ) -> Result<(), SessionManagerError> {
        let sender = self
            .sessions
            .lock()
            .await
            .get(session_id)
            .map(|session| session.commands.clone())
            .ok_or(SessionManagerError::NotFound)?;
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => SessionManagerError::CommandQueueFull,
            mpsc::error::TrySendError::Closed(_) => SessionManagerError::Closed,
        })
    }

    async fn send_sftp_command(
        &self,
        session_id: &str,
        command: SftpCommand,
    ) -> Result<(), SessionSftpError> {
        let sender = self
            .sessions
            .lock()
            .await
            .get(session_id)
            .map(|session| session.sftp_commands.clone())
            .ok_or(SessionSftpError::Session(SessionManagerError::NotFound))?;
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                SessionSftpError::Session(SessionManagerError::CommandQueueFull)
            }
            mpsc::error::TrySendError::Closed(_) => {
                SessionSftpError::Session(SessionManagerError::Closed)
            }
        })
    }
}

async fn receive_sftp_response<T>(
    response: oneshot::Receiver<Result<T, SftpError>>,
) -> Result<T, SessionSftpError> {
    tokio::time::timeout(SFTP_OPERATION_TIMEOUT, response)
        .await
        .map_err(|_| SessionSftpError::Sftp(SftpError::OperationFailed))?
        .map_err(|_| SessionSftpError::Session(SessionManagerError::Closed))?
        .map_err(SessionSftpError::Sftp)
}

async fn run_sftp_upload_directory(
    manager: SessionManager,
    root_transfer_id: String,
    session_id: String,
    local_root: PathBuf,
    remote_root: String,
    options: LocalTreeOptions,
    resume: Option<DirectoryResumeCheckpoint>,
    control: SftpTransferControl,
    events: broadcast::Sender<SftpTransferEvent>,
) {
    let _ = events.send(SftpTransferEvent::DirectoryScanning);
    let scan_remote_root = remote_root.clone();
    let scan = tokio::task::spawn_blocking(move || {
        discover_local_tree(local_root, scan_remote_root, options)
    });
    let scan = tokio::select! {
        () = control.cancelled() => {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: DirectoryResumeCheckpoint::empty(),
            });
            return;
        }
        result = scan => result,
    };
    let manifest = match scan {
        Ok(Ok(manifest)) => manifest,
        Ok(Err(error)) => {
            let _ = events.send(SftpTransferEvent::DirectoryFailed {
                message: error.to_string(),
                failed_files: 0,
                checkpoint: DirectoryResumeCheckpoint::empty(),
            });
            return;
        }
        Err(_) => {
            let _ = events.send(SftpTransferEvent::DirectoryFailed {
                message: "Local directory scan stopped unexpectedly".to_owned(),
                failed_files: 0,
                checkpoint: DirectoryResumeCheckpoint::empty(),
            });
            return;
        }
    };

    let resumed_prefix = match resume.as_ref() {
        Some(checkpoint) => match manifest.matches_checkpoint(checkpoint) {
            Ok(true) => checkpoint.completed_entries.min(manifest.total_files),
            Ok(false) | Err(_) => 0,
        },
        None => 0,
    };
    let mut directory_checkpoint = manifest.manifest_checkpoint.clone();
    directory_checkpoint.completed_entries = resumed_prefix;

    for directory in &manifest.directories {
        if control.wait_until_resumed().await.is_err() {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: directory_checkpoint,
            });
            return;
        }
        let target = if directory.relative_path.is_empty() {
            remote_root.clone()
        } else {
            match join_remote_transfer_target(&remote_root, &directory.relative_path) {
                Ok(target) => target,
                Err(error) => {
                    let _ = events.send(SftpTransferEvent::DirectoryFailed {
                        message: error.to_string(),
                        failed_files: 0,
                        checkpoint: directory_checkpoint,
                    });
                    return;
                }
            }
        };
        let ensured = tokio::select! {
            () = control.cancelled() => Err(SessionSftpError::Sftp(SftpError::Cancelled)),
            result = ensure_remote_directory(&manager, &session_id, &target) => result,
        };
        if matches!(ensured, Err(SessionSftpError::Sftp(SftpError::Cancelled))) {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: directory_checkpoint,
            });
            return;
        }
        if let Err(error) = ensured {
            let _ = events.send(SftpTransferEvent::DirectoryFailed {
                message: error.to_string(),
                failed_files: 0,
                checkpoint: directory_checkpoint,
            });
            return;
        }
    }

    let completed_prefix = usize::try_from(resumed_prefix)
        .unwrap_or(usize::MAX)
        .min(manifest.files.len());
    let mut completed_entries = vec![false; manifest.files.len()];
    completed_entries[..completed_prefix].fill(true);
    let mut files_completed = completed_prefix as u64;
    let mut completed_bytes = manifest
        .files
        .iter()
        .take(completed_prefix)
        .fold(0_u64, |total, entry| total.saturating_add(entry.size));
    let mut next_position = completed_prefix;
    let mut failed_files = 0_u64;
    let mut first_failure = None;
    let mut stop_new_work = false;
    let mut children = tokio::task::JoinSet::new();
    let (progress_sender, mut progress_receiver) = mpsc::unbounded_channel();
    let mut active_progress = HashMap::<u64, u64>::new();

    publish_directory_progress(
        &events,
        files_completed,
        manifest.total_files,
        completed_bytes,
        manifest.total_bytes,
        None,
        &directory_checkpoint,
    );

    loop {
        while !stop_new_work
            && !control.is_cancelled()
            && !control.is_paused()
            && children.len() < SFTP_TRANSFER_CONCURRENCY
            && next_position < manifest.files.len()
        {
            let entry = manifest.files[next_position].clone();
            let target_path = match join_remote_transfer_target(&remote_root, &entry.relative_path)
            {
                Ok(path) => path,
                Err(error) => {
                    next_position += 1;
                    failed_files = failed_files.saturating_add(1);
                    first_failure.get_or_insert_with(|| error.to_string());
                    continue;
                }
            };
            let source_is_current = local_tree_entry_is_current(&entry).await;
            if control.wait_until_resumed().await.is_err() {
                break;
            }
            if !source_is_current {
                next_position += 1;
                failed_files = failed_files.saturating_add(1);
                first_failure.get_or_insert_with(|| SftpError::SourceChanged.to_string());
                continue;
            }
            let target_is_current = tokio::select! {
                () = control.cancelled() => break,
                result = remote_file_matches_local(&manager, &session_id, &target_path, &entry) => result,
            };
            if control.wait_until_resumed().await.is_err() {
                break;
            }
            if target_is_current {
                next_position += 1;
                files_completed = files_completed.saturating_add(1);
                completed_bytes = completed_bytes.saturating_add(entry.size);
                if let Ok(index) = usize::try_from(entry.directory_entry_index)
                    && let Some(completed) = completed_entries.get_mut(index)
                {
                    *completed = true;
                }
                advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes,
                    manifest.total_bytes,
                    Some(entry.relative_path),
                    &directory_checkpoint,
                );
                continue;
            }
            let plan =
                match SftpClient::plan_stable_upload(&target_path, &entry.directory_entry_identity)
                {
                    Ok(plan) => plan,
                    Err(error) => {
                        next_position += 1;
                        failed_files = failed_files.saturating_add(1);
                        first_failure.get_or_insert_with(|| error.to_string());
                        continue;
                    }
                };
            let started = manager
                .begin_sftp_upload_with_parent(
                    &session_id,
                    PathBuf::from(&entry.source_path),
                    target_path,
                    Some(plan),
                    None,
                    Some((entry.size, entry.modified_at)),
                    Some(root_transfer_id.clone()),
                    Some(control.clone()),
                )
                .await;
            let started = match started {
                Ok(started) => started,
                Err(error) => {
                    next_position += 1;
                    failed_files = failed_files.saturating_add(1);
                    first_failure.get_or_insert_with(|| error.to_string());
                    if matches!(
                        error,
                        SessionSftpError::Session(SessionManagerError::NotFound)
                            | SessionSftpError::Session(SessionManagerError::Closed)
                    ) {
                        stop_new_work = true;
                    }
                    continue;
                }
            };
            next_position += 1;
            if control.is_cancelled() {
                let _ = manager.cancel_sftp_transfer(&started.transfer_id).await;
            }
            active_progress.insert(entry.directory_entry_index, 0);
            children.spawn(monitor_directory_upload_child(
                entry,
                started,
                progress_sender.clone(),
            ));
        }

        if children.is_empty() {
            if control.is_cancelled() || stop_new_work || next_position >= manifest.files.len() {
                break;
            }
            if control.wait_until_resumed().await.is_err() {
                break;
            }
            continue;
        }

        enum Wake {
            Progress(DirectoryChildProgress),
            Child(Result<DirectoryChildResult, tokio::task::JoinError>),
            State(Result<(), SftpError>),
        }

        let wake = if control.is_paused() {
            tokio::select! {
                Some(progress) = progress_receiver.recv() => Wake::Progress(progress),
                Some(child) = children.join_next() => Wake::Child(child),
                state = control.wait_until_resumed() => Wake::State(state),
            }
        } else {
            tokio::select! {
                Some(progress) = progress_receiver.recv() => Wake::Progress(progress),
                Some(child) = children.join_next() => Wake::Child(child),
                () = control.cancelled() => Wake::State(Err(SftpError::Cancelled)),
            }
        };

        match wake {
            Wake::Progress(progress) => {
                active_progress.insert(progress.entry_index, progress.bytes_transferred);
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes.saturating_add(
                        active_progress
                            .values()
                            .copied()
                            .fold(0_u64, u64::saturating_add),
                    ),
                    manifest.total_bytes,
                    Some(progress.current_path),
                    &directory_checkpoint,
                );
            }
            Wake::Child(Ok(result)) => {
                active_progress.remove(&result.entry.directory_entry_index);
                match result.outcome {
                    DirectoryChildOutcome::Completed => {
                        files_completed = files_completed.saturating_add(1);
                        completed_bytes = completed_bytes.saturating_add(result.entry.size);
                        if let Ok(index) = usize::try_from(result.entry.directory_entry_index)
                            && let Some(completed) = completed_entries.get_mut(index)
                        {
                            *completed = true;
                        }
                        advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                    }
                    DirectoryChildOutcome::Cancelled => {
                        if !control.is_cancelled() {
                            failed_files = failed_files.saturating_add(1);
                            first_failure
                                .get_or_insert_with(|| "A child upload was cancelled".to_owned());
                        }
                    }
                    DirectoryChildOutcome::Failed(message) => {
                        failed_files = failed_files.saturating_add(1);
                        first_failure.get_or_insert(message);
                        if manager.session_endpoint_key(&session_id).await.is_err() {
                            stop_new_work = true;
                        }
                    }
                }
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes.saturating_add(
                        active_progress
                            .values()
                            .copied()
                            .fold(0_u64, u64::saturating_add),
                    ),
                    manifest.total_bytes,
                    Some(result.entry.relative_path),
                    &directory_checkpoint,
                );
            }
            Wake::Child(Err(_)) => {
                failed_files = failed_files.saturating_add(1);
                first_failure
                    .get_or_insert_with(|| "A child upload stopped unexpectedly".to_owned());
                stop_new_work = true;
            }
            Wake::State(Ok(())) => {}
            Wake::State(Err(_)) => break,
        }
    }

    if control.is_cancelled() {
        let _ = manager.cancel_sftp_transfer(&root_transfer_id).await;
    }
    while let Some(result) = children.join_next().await {
        match result {
            Ok(result) => {
                active_progress.remove(&result.entry.directory_entry_index);
                match result.outcome {
                    DirectoryChildOutcome::Completed => {
                        files_completed = files_completed.saturating_add(1);
                        completed_bytes = completed_bytes.saturating_add(result.entry.size);
                        if let Ok(index) = usize::try_from(result.entry.directory_entry_index)
                            && let Some(completed) = completed_entries.get_mut(index)
                        {
                            *completed = true;
                        }
                        advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                    }
                    DirectoryChildOutcome::Cancelled => {}
                    DirectoryChildOutcome::Failed(message) => {
                        failed_files = failed_files.saturating_add(1);
                        first_failure.get_or_insert(message);
                    }
                }
            }
            Err(_) => {
                failed_files = failed_files.saturating_add(1);
                first_failure
                    .get_or_insert_with(|| "A child upload stopped unexpectedly".to_owned());
            }
        }
    }

    if control.is_cancelled() {
        let _ = events.send(SftpTransferEvent::DirectoryCancelled {
            checkpoint: directory_checkpoint,
        });
    } else if failed_files > 0 || stop_new_work {
        if stop_new_work && next_position < manifest.files.len() {
            failed_files =
                failed_files.saturating_add((manifest.files.len() - next_position) as u64);
        }
        let _ = events.send(SftpTransferEvent::DirectoryFailed {
            message: first_failure
                .unwrap_or_else(|| "One or more directory uploads failed".to_owned()),
            failed_files,
            checkpoint: directory_checkpoint,
        });
    } else {
        let _ = events.send(SftpTransferEvent::DirectoryCompleted {
            files_completed,
            total_bytes: manifest.total_bytes,
            skipped_entries: manifest.skipped_entries.len() as u64,
            checkpoint: directory_checkpoint,
        });
    }
}

async fn monitor_directory_upload_child(
    entry: LocalTreeFileEntry,
    mut started: SftpTransferStart,
    progress: mpsc::UnboundedSender<DirectoryChildProgress>,
) -> DirectoryChildResult {
    loop {
        match started.events.recv().await {
            Ok(SftpTransferEvent::Progress {
                bytes_transferred, ..
            }) => {
                let _ = progress.send(DirectoryChildProgress {
                    entry_index: entry.directory_entry_index,
                    bytes_transferred,
                    current_path: entry.relative_path.clone(),
                });
            }
            Ok(SftpTransferEvent::Completed { .. }) => {
                return DirectoryChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Completed,
                };
            }
            Ok(SftpTransferEvent::Cancelled { .. }) => {
                return DirectoryChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Cancelled,
                };
            }
            Ok(SftpTransferEvent::Failed { message, .. }) => {
                return DirectoryChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Failed(message),
                };
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => {
                return DirectoryChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Failed(
                        "Child upload event stream closed unexpectedly".to_owned(),
                    ),
                };
            }
        }
    }
}

fn publish_directory_progress(
    events: &broadcast::Sender<SftpTransferEvent>,
    files_completed: u64,
    total_files: u64,
    bytes_transferred: u64,
    total_bytes: u64,
    current_path: Option<String>,
    checkpoint: &DirectoryResumeCheckpoint,
) {
    let _ = events.send(SftpTransferEvent::DirectoryProgress {
        files_completed,
        total_files,
        bytes_transferred: bytes_transferred.min(total_bytes),
        total_bytes,
        current_path,
        checkpoint: checkpoint.clone(),
    });
}

fn advance_directory_checkpoint(
    completed_entries: &[bool],
    checkpoint: &mut DirectoryResumeCheckpoint,
) {
    while let Some(true) = completed_entries.get(checkpoint.completed_entries as usize) {
        checkpoint.completed_entries = checkpoint.completed_entries.saturating_add(1);
    }
}

async fn ensure_remote_directory(
    manager: &SessionManager,
    session_id: &str,
    path: &str,
) -> Result<(), SessionSftpError> {
    match manager.sftp_create_dir(session_id, path.to_owned()).await {
        Ok(()) => Ok(()),
        Err(create_error) => match manager.sftp_metadata(session_id, path.to_owned()).await {
            Ok(metadata) if metadata.kind == SftpEntryKind::Directory => Ok(()),
            Ok(_) => Err(SessionSftpError::Sftp(SftpError::DestinationNotRegularFile)),
            Err(_) => Err(create_error),
        },
    }
}

struct ManagedRemoteTreeSource<'a> {
    manager: &'a SessionManager,
    session_id: &'a str,
    control: &'a SftpTransferControl,
}

#[async_trait::async_trait]
impl RemoteTreeSource for ManagedRemoteTreeSource<'_> {
    async fn canonicalize(&self, path: &str) -> Result<String, SftpError> {
        self.control.wait_until_resumed().await?;
        tokio::select! {
            () = self.control.cancelled() => Err(SftpError::Cancelled),
            result = self.manager.sftp_canonicalize(self.session_id, path.to_owned()) => {
                result.map_err(session_sftp_error_to_sftp)
            }
        }
    }

    async fn read_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
        self.control.wait_until_resumed().await?;
        tokio::select! {
            () = self.control.cancelled() => Err(SftpError::Cancelled),
            result = self.manager.sftp_read_dir(self.session_id, path.to_owned()) => {
                result.map_err(session_sftp_error_to_sftp)
            }
        }
    }

    async fn followed_metadata(&self, path: &str) -> Result<SftpMetadata, SftpError> {
        self.control.wait_until_resumed().await?;
        tokio::select! {
            () = self.control.cancelled() => Err(SftpError::Cancelled),
            result = self.manager.sftp_followed_metadata(self.session_id, path.to_owned()) => {
                result.map_err(session_sftp_error_to_sftp)
            }
        }
    }
}

fn session_sftp_error_to_sftp(error: SessionSftpError) -> SftpError {
    match error {
        SessionSftpError::Sftp(error) => error,
        SessionSftpError::Session(_)
        | SessionSftpError::LocalFile
        | SessionSftpError::DestinationBusy => SftpError::OperationFailed,
    }
}

async fn run_sftp_download_directory(
    manager: SessionManager,
    root_transfer_id: String,
    session_id: String,
    remote_root: String,
    local_root: PathBuf,
    options: RemoteTreeOptions,
    resume: Option<DirectoryResumeCheckpoint>,
    control: SftpTransferControl,
    events: broadcast::Sender<SftpTransferEvent>,
) {
    let _ = events.send(SftpTransferEvent::DirectoryScanning);
    let source = ManagedRemoteTreeSource {
        manager: &manager,
        session_id: &session_id,
        control: &control,
    };
    let manifest = match discover_remote_tree(&source, &remote_root, &local_root, options).await {
        Ok(manifest) => manifest,
        Err(_error) if control.is_cancelled() => {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: DirectoryResumeCheckpoint::empty(),
            });
            return;
        }
        Err(error) => {
            let _ = events.send(SftpTransferEvent::DirectoryFailed {
                message: error.to_string(),
                failed_files: 0,
                checkpoint: DirectoryResumeCheckpoint::empty(),
            });
            return;
        }
    };

    let resumed_prefix = match resume.as_ref() {
        Some(checkpoint) => match manifest.matches_checkpoint(checkpoint) {
            Ok(true) => checkpoint.completed_entries.min(manifest.total_files),
            Ok(false) | Err(_) => 0,
        },
        None => 0,
    };
    let mut directory_checkpoint = manifest.manifest_checkpoint.clone();
    directory_checkpoint.completed_entries = resumed_prefix;

    for directory in &manifest.directories {
        if control.wait_until_resumed().await.is_err() {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: directory_checkpoint,
            });
            return;
        }
        let target = if directory.relative_path.is_empty() {
            local_root.clone()
        } else {
            match join_local_transfer_target(&local_root, &directory.relative_path) {
                Ok(target) => target,
                Err(error) => {
                    let _ = events.send(SftpTransferEvent::DirectoryFailed {
                        message: error.to_string(),
                        failed_files: 0,
                        checkpoint: directory_checkpoint,
                    });
                    return;
                }
            }
        };
        let ensured = tokio::select! {
            () = control.cancelled() => Err(SftpError::Cancelled),
            result = ensure_local_directory(&target) => result,
        };
        if ensured == Err(SftpError::Cancelled) {
            let _ = events.send(SftpTransferEvent::DirectoryCancelled {
                checkpoint: directory_checkpoint,
            });
            return;
        }
        if let Err(error) = ensured {
            let _ = events.send(SftpTransferEvent::DirectoryFailed {
                message: error.to_string(),
                failed_files: 0,
                checkpoint: directory_checkpoint,
            });
            return;
        }
    }

    let completed_prefix = usize::try_from(resumed_prefix)
        .unwrap_or(usize::MAX)
        .min(manifest.files.len());
    let mut completed_entries = vec![false; manifest.files.len()];
    completed_entries[..completed_prefix].fill(true);
    let mut files_completed = completed_prefix as u64;
    let mut completed_bytes = manifest
        .files
        .iter()
        .take(completed_prefix)
        .fold(0_u64, |total, entry| total.saturating_add(entry.size));
    let mut next_position = completed_prefix;
    let mut failed_files = 0_u64;
    let mut first_failure = None;
    let mut stop_new_work = false;
    let mut children = tokio::task::JoinSet::new();
    let (progress_sender, mut progress_receiver) = mpsc::unbounded_channel();
    let mut active_progress = HashMap::<u64, u64>::new();

    publish_directory_progress(
        &events,
        files_completed,
        manifest.total_files,
        completed_bytes,
        manifest.total_bytes,
        None,
        &directory_checkpoint,
    );

    loop {
        while !stop_new_work
            && !control.is_cancelled()
            && !control.is_paused()
            && children.len() < SFTP_TRANSFER_CONCURRENCY
            && next_position < manifest.files.len()
        {
            let entry = manifest.files[next_position].clone();
            let target_path = match join_local_transfer_target(&local_root, &entry.relative_path) {
                Ok(path) => path,
                Err(error) => {
                    next_position += 1;
                    failed_files = failed_files.saturating_add(1);
                    first_failure.get_or_insert_with(|| error.to_string());
                    continue;
                }
            };

            let target_is_current = tokio::select! {
                () = control.cancelled() => break,
                result = local_file_matches_remote(&manager, &session_id, &target_path, &entry) => result,
            };
            if control.wait_until_resumed().await.is_err() {
                break;
            }
            if target_is_current {
                next_position += 1;
                files_completed = files_completed.saturating_add(1);
                completed_bytes = completed_bytes.saturating_add(entry.size);
                if let Ok(index) = usize::try_from(entry.directory_entry_index)
                    && let Some(completed) = completed_entries.get_mut(index)
                {
                    *completed = true;
                }
                advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes,
                    manifest.total_bytes,
                    Some(entry.relative_path),
                    &directory_checkpoint,
                );
                continue;
            }

            let started = manager
                .begin_sftp_download_with_parent(
                    &session_id,
                    entry.source_path.clone(),
                    target_path,
                    None,
                    Some(SftpTransferCheckpoint {
                        direction: SftpTransferDirection::Download,
                        remote_path: entry.source_path.clone(),
                        bytes_transferred: 0,
                        total_bytes: entry.size,
                        source_fingerprint: None,
                        remote_modified_at: (entry.modified_at > 0)
                            .then_some((entry.modified_at / 1_000) as u32),
                    }),
                    Some(root_transfer_id.clone()),
                    Some(control.clone()),
                )
                .await;
            let (child_transfer_id, child_events) = match started {
                Ok(started) => (started.transfer_id, started.events),
                Err(error) => {
                    next_position += 1;
                    failed_files = failed_files.saturating_add(1);
                    first_failure.get_or_insert_with(|| error.to_string());
                    if matches!(
                        error,
                        SessionSftpError::Session(SessionManagerError::NotFound)
                            | SessionSftpError::Session(SessionManagerError::Closed)
                    ) {
                        stop_new_work = true;
                    }
                    continue;
                }
            };
            next_position += 1;
            if control.is_cancelled() {
                let _ = manager.cancel_sftp_transfer(&child_transfer_id).await;
            }
            active_progress.insert(entry.directory_entry_index, 0);
            children.spawn(monitor_directory_download_child(
                entry,
                child_events,
                progress_sender.clone(),
            ));
        }

        if children.is_empty() {
            if control.is_cancelled() || stop_new_work || next_position >= manifest.files.len() {
                break;
            }
            if control.wait_until_resumed().await.is_err() {
                break;
            }
            continue;
        }

        enum Wake {
            Progress(DirectoryChildProgress),
            Child(Result<DirectoryDownloadChildResult, tokio::task::JoinError>),
            State(Result<(), SftpError>),
        }

        let wake = if control.is_paused() {
            tokio::select! {
                Some(progress) = progress_receiver.recv() => Wake::Progress(progress),
                Some(child) = children.join_next() => Wake::Child(child),
                state = control.wait_until_resumed() => Wake::State(state),
            }
        } else {
            tokio::select! {
                Some(progress) = progress_receiver.recv() => Wake::Progress(progress),
                Some(child) = children.join_next() => Wake::Child(child),
                () = control.cancelled() => Wake::State(Err(SftpError::Cancelled)),
            }
        };

        match wake {
            Wake::Progress(progress) => {
                active_progress.insert(progress.entry_index, progress.bytes_transferred);
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes.saturating_add(
                        active_progress
                            .values()
                            .copied()
                            .fold(0_u64, u64::saturating_add),
                    ),
                    manifest.total_bytes,
                    Some(progress.current_path),
                    &directory_checkpoint,
                );
            }
            Wake::Child(Ok(result)) => {
                active_progress.remove(&result.entry.directory_entry_index);
                match result.outcome {
                    DirectoryChildOutcome::Completed => {
                        files_completed = files_completed.saturating_add(1);
                        completed_bytes = completed_bytes.saturating_add(result.entry.size);
                        if let Ok(index) = usize::try_from(result.entry.directory_entry_index)
                            && let Some(completed) = completed_entries.get_mut(index)
                        {
                            *completed = true;
                        }
                        advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                    }
                    DirectoryChildOutcome::Cancelled => {
                        if !control.is_cancelled() {
                            failed_files = failed_files.saturating_add(1);
                            first_failure
                                .get_or_insert_with(|| "A child download was cancelled".to_owned());
                        }
                    }
                    DirectoryChildOutcome::Failed(message) => {
                        failed_files = failed_files.saturating_add(1);
                        first_failure.get_or_insert(message);
                        if manager.session_endpoint_key(&session_id).await.is_err() {
                            stop_new_work = true;
                        }
                    }
                }
                publish_directory_progress(
                    &events,
                    files_completed,
                    manifest.total_files,
                    completed_bytes.saturating_add(
                        active_progress
                            .values()
                            .copied()
                            .fold(0_u64, u64::saturating_add),
                    ),
                    manifest.total_bytes,
                    Some(result.entry.relative_path),
                    &directory_checkpoint,
                );
            }
            Wake::Child(Err(_)) => {
                failed_files = failed_files.saturating_add(1);
                first_failure
                    .get_or_insert_with(|| "A child download stopped unexpectedly".to_owned());
                stop_new_work = true;
            }
            Wake::State(Ok(())) => {}
            Wake::State(Err(_)) => break,
        }
    }

    if control.is_cancelled() {
        let _ = manager.cancel_sftp_transfer(&root_transfer_id).await;
    }
    while let Some(result) = children.join_next().await {
        match result {
            Ok(result) => match result.outcome {
                DirectoryChildOutcome::Completed => {
                    files_completed = files_completed.saturating_add(1);
                    completed_bytes = completed_bytes.saturating_add(result.entry.size);
                    if let Ok(index) = usize::try_from(result.entry.directory_entry_index)
                        && let Some(completed) = completed_entries.get_mut(index)
                    {
                        *completed = true;
                    }
                    advance_directory_checkpoint(&completed_entries, &mut directory_checkpoint);
                }
                DirectoryChildOutcome::Cancelled => {}
                DirectoryChildOutcome::Failed(message) => {
                    failed_files = failed_files.saturating_add(1);
                    first_failure.get_or_insert(message);
                }
            },
            Err(_) => {
                failed_files = failed_files.saturating_add(1);
                first_failure
                    .get_or_insert_with(|| "A child download stopped unexpectedly".to_owned());
            }
        }
    }

    if control.is_cancelled() {
        let _ = events.send(SftpTransferEvent::DirectoryCancelled {
            checkpoint: directory_checkpoint,
        });
    } else if failed_files > 0 || stop_new_work {
        if stop_new_work && next_position < manifest.files.len() {
            failed_files =
                failed_files.saturating_add((manifest.files.len() - next_position) as u64);
        }
        let _ = events.send(SftpTransferEvent::DirectoryFailed {
            message: first_failure
                .unwrap_or_else(|| "One or more directory downloads failed".to_owned()),
            failed_files,
            checkpoint: directory_checkpoint,
        });
    } else {
        let _ = events.send(SftpTransferEvent::DirectoryCompleted {
            files_completed,
            total_bytes: manifest.total_bytes,
            skipped_entries: manifest.skipped_entries.len() as u64,
            checkpoint: directory_checkpoint,
        });
    }
}

async fn monitor_directory_download_child(
    entry: RemoteTreeFileEntry,
    mut events: SftpTransferEventReceiver,
    progress: mpsc::UnboundedSender<DirectoryChildProgress>,
) -> DirectoryDownloadChildResult {
    loop {
        match events.recv().await {
            Ok(SftpTransferEvent::Progress {
                bytes_transferred, ..
            }) => {
                let _ = progress.send(DirectoryChildProgress {
                    entry_index: entry.directory_entry_index,
                    bytes_transferred,
                    current_path: entry.relative_path.clone(),
                });
            }
            Ok(SftpTransferEvent::Completed { .. }) => {
                return DirectoryDownloadChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Completed,
                };
            }
            Ok(SftpTransferEvent::Cancelled { .. }) => {
                return DirectoryDownloadChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Cancelled,
                };
            }
            Ok(SftpTransferEvent::Failed { message, .. }) => {
                return DirectoryDownloadChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Failed(message),
                };
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => {
                return DirectoryDownloadChildResult {
                    entry,
                    outcome: DirectoryChildOutcome::Failed(
                        "Child download event stream closed unexpectedly".to_owned(),
                    ),
                };
            }
        }
    }
}

async fn ensure_local_directory(path: &std::path::Path) -> Result<(), SftpError> {
    match tokio::fs::create_dir(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = tokio::fs::symlink_metadata(path)
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            if metadata.is_dir() {
                Ok(())
            } else {
                Err(SftpError::DestinationNotRegularFile)
            }
        }
        Err(_) => Err(SftpError::OperationFailed),
    }
}

async fn local_file_matches_remote(
    manager: &SessionManager,
    session_id: &str,
    path: &std::path::Path,
    entry: &RemoteTreeFileEntry,
) -> bool {
    if entry.is_symlink || entry.modified_at == 0 {
        return false;
    }
    let Ok(remote) = manager
        .sftp_followed_metadata(session_id, entry.source_path.clone())
        .await
    else {
        return false;
    };
    if remote.kind != SftpEntryKind::File
        || remote.size != entry.size
        || u64::from(remote.modified_at.unwrap_or(0)).saturating_mul(1_000) != entry.modified_at
    {
        return false;
    }
    let Ok(metadata) = tokio::fs::symlink_metadata(path).await else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != entry.size {
        return false;
    }
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .is_some_and(|modified| modified.as_secs() == entry.modified_at / 1_000)
}

async fn remote_file_matches_local(
    manager: &SessionManager,
    session_id: &str,
    remote_path: &str,
    entry: &LocalTreeFileEntry,
) -> bool {
    if entry.is_symlink {
        return false;
    }
    let Ok(local) = tokio::fs::metadata(&entry.source_path).await else {
        return false;
    };
    let Some(modified_at) = local
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u32::try_from(duration.as_secs()).ok())
        .filter(|modified_at| *modified_at > 0)
    else {
        return false;
    };
    if !local.is_file() || local.len() != entry.size {
        return false;
    }
    manager
        .sftp_metadata(session_id, remote_path.to_owned())
        .await
        .is_ok_and(|remote| {
            remote.kind == SftpEntryKind::File
                && remote.size == local.len()
                && remote.modified_at == Some(modified_at)
        })
}

async fn local_tree_entry_is_current(entry: &LocalTreeFileEntry) -> bool {
    let Ok(metadata) = tokio::fs::metadata(&entry.source_path).await else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != entry.size {
        return false;
    }
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0);
    modified_at == entry.modified_at
}

fn spawn_transfer_forwarder(
    transfers: Arc<Mutex<HashMap<String, ManagedTransfer>>>,
    transfer_id: String,
    events: broadcast::Sender<SftpTransferEvent>,
    mut progress_receiver: mpsc::Receiver<SftpTransferProgress>,
    done_receiver: oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut done_receiver = std::pin::pin!(done_receiver);
        loop {
            tokio::select! {
                progress = progress_receiver.recv() => match progress {
                    Some(progress) => {
                        let _ = events.send(SftpTransferEvent::Progress {
                            bytes_transferred: progress.bytes_transferred,
                            total_bytes: progress.total_bytes,
                        });
                    }
                    None => break,
                },
                _ = &mut done_receiver => break,
            }
        }
        while let Ok(progress) = progress_receiver.try_recv() {
            let _ = events.send(SftpTransferEvent::Progress {
                bytes_transferred: progress.bytes_transferred,
                total_bytes: progress.total_bytes,
            });
        }
        transfers.lock().await.remove(&transfer_id);
    });
}

fn remote_transfer_destination(
    endpoint_key: &str,
    path: &str,
    is_directory: bool,
) -> TransferDestination {
    TransferDestination {
        endpoint: format!("remote:{endpoint_key}"),
        path: normalize_remote_reservation_path(path),
        is_directory,
        separator: '/',
    }
}

fn normalize_remote_reservation_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if segments.last().is_some_and(|previous| *previous != "..") => {
                segments.pop();
            }
            ".." if !absolute => segments.push(".."),
            ".." => {}
            _ => segments.push(segment),
        }
    }
    let joined = segments.join("/");
    if absolute {
        if joined.is_empty() {
            "/".to_owned()
        } else {
            format!("/{joined}")
        }
    } else if joined.is_empty() {
        ".".to_owned()
    } else if joined == ".." || joined.starts_with("../") {
        joined
    } else {
        format!("./{joined}")
    }
}

fn normalize_remote_directory_root(path: &str) -> Option<String> {
    if path.trim().is_empty() || path.contains('\0') {
        return None;
    }
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() && normalized.starts_with('/') {
        Some("/".to_owned())
    } else if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn local_transfer_destination(path: &std::path::Path, is_directory: bool) -> TransferDestination {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let normalized = normalize_local_reservation_path(&absolute);
    let normalized = normalized.to_string_lossy();
    #[cfg(windows)]
    let normalized = normalized.replace('/', "\\").to_lowercase();
    #[cfg(not(windows))]
    let normalized = normalized.into_owned();
    TransferDestination {
        endpoint: "local".to_owned(),
        path: normalized,
        is_directory,
        separator: std::path::MAIN_SEPARATOR,
    }
}

fn normalize_local_reservation_path(path: &std::path::Path) -> PathBuf {
    let mut base = PathBuf::new();
    let mut normal = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => base.push(prefix.as_os_str()),
            std::path::Component::RootDir => base.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            std::path::Component::Normal(value) => normal.push(value.to_os_string()),
        }
    }
    for component in normal {
        base.push(component);
    }
    base
}

fn transfer_destinations_conflict(
    existing: &TransferDestination,
    candidate: &TransferDestination,
) -> bool {
    if existing.endpoint != candidate.endpoint {
        return false;
    }
    if existing.path == candidate.path {
        return true;
    }
    (existing.is_directory || candidate.is_directory)
        && (is_transfer_path_descendant(&existing.path, &candidate.path, existing.separator)
            || is_transfer_path_descendant(&candidate.path, &existing.path, candidate.separator))
}

fn is_transfer_path_descendant(parent: &str, candidate: &str, separator: char) -> bool {
    if parent.is_empty() || parent == candidate {
        return false;
    }
    let mut prefix = parent.to_owned();
    if !prefix.ends_with(separator) {
        prefix.push(separator);
    }
    candidate.starts_with(&prefix)
}

#[cfg(test)]
fn local_recovery_path(target: &std::path::Path, suffix: &str) -> PathBuf {
    let mut path = target.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn validate_download_resume_checkpoint(
    remote_path: &str,
    remote: &SftpMetadata,
    checkpoint: Option<&SftpTransferCheckpoint>,
) -> Result<(), SessionSftpError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    if checkpoint.direction != SftpTransferDirection::Download
        || checkpoint.remote_path != remote_path
        || checkpoint.total_bytes != remote.size
        || checkpoint.bytes_transferred > remote.size
        || checkpoint.remote_modified_at != remote.modified_at
    {
        return Err(SessionSftpError::Sftp(SftpError::CheckpointMismatch));
    }
    Ok(())
}

async fn prepare_local_download_artifacts(
    target_path: &std::path::Path,
    remote_path: &str,
    remote: &SftpMetadata,
    plan: Option<SftpDownloadPlan>,
    checkpoint: Option<&SftpTransferCheckpoint>,
) -> Result<PreparedLocalDownload, SessionSftpError> {
    let expected_target = local_file_snapshot(target_path).await?;
    match (plan, checkpoint) {
        (Some(plan), Some(checkpoint)) => {
            let (workspace_path, owner_path, staged_path, backup_path) =
                validate_local_download_plan(target_path, &plan).map_err(SessionSftpError::Sftp)?;
            let owner = build_local_download_owner(
                &plan,
                target_path,
                remote_path,
                remote,
                expected_target,
            );
            validate_local_download_workspace(
                &workspace_path,
                &owner_path,
                &staged_path,
                &backup_path,
                &owner,
                checkpoint.bytes_transferred,
            )
            .await
            .map_err(SessionSftpError::Sftp)?;
            let destination = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&staged_path)
                .await
                .map_err(|_| SessionSftpError::LocalFile)?;
            Ok(PreparedLocalDownload {
                destination,
                plan,
                owner,
                workspace_path,
                staged_path,
                backup_path,
                expected_target,
                created_workspace: false,
            })
        }
        (None, None) | (None, Some(_)) => {
            for _ in 0..16 {
                let artifact_id = uuid::Uuid::new_v4().simple().to_string();
                let plan = build_local_download_plan(target_path, &artifact_id)
                    .map_err(SessionSftpError::Sftp)?;
                let (workspace_path, owner_path, staged_path, backup_path) =
                    validate_local_download_plan(target_path, &plan)
                        .map_err(SessionSftpError::Sftp)?;
                match tokio::fs::create_dir(&workspace_path).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => return Err(SessionSftpError::LocalFile),
                }
                let owner = build_local_download_owner(
                    &plan,
                    target_path,
                    remote_path,
                    remote,
                    expected_target,
                );
                let marker = serde_json::to_vec(&owner)
                    .map_err(|_| SessionSftpError::Sftp(SftpError::OperationFailed))?;
                if marker.len() > 4 * 1024 {
                    let _ = tokio::fs::remove_dir(&workspace_path).await;
                    return Err(SessionSftpError::Sftp(SftpError::OperationFailed));
                }
                let mut owner_created = false;
                let mut stage_created = false;
                let initialized = async {
                    let mut owner_file = tokio::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&owner_path)
                        .await
                        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
                    owner_created = true;
                    owner_file
                        .write_all(&marker)
                        .await
                        .map_err(|_| SftpError::OperationFailed)?;
                    owner_file
                        .sync_all()
                        .await
                        .map_err(|_| SftpError::OperationFailed)?;
                    drop(owner_file);
                    let destination = tokio::fs::OpenOptions::new()
                        .create_new(true)
                        .read(true)
                        .write(true)
                        .open(&staged_path)
                        .await
                        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
                    stage_created = true;
                    if local_path_lexically_exists(&backup_path).await? {
                        return Err(SftpError::RecoveryArtifactConflict);
                    }
                    Ok::<_, SftpError>(destination)
                }
                .await;
                match initialized {
                    Ok(destination) => {
                        return Ok(PreparedLocalDownload {
                            destination,
                            plan,
                            owner,
                            workspace_path,
                            staged_path,
                            backup_path,
                            expected_target,
                            created_workspace: true,
                        });
                    }
                    Err(error) => {
                        if stage_created {
                            let _ = tokio::fs::remove_file(&staged_path).await;
                        }
                        if owner_created {
                            let _ = tokio::fs::remove_file(&owner_path).await;
                        }
                        let _ = tokio::fs::remove_dir(&workspace_path).await;
                        return Err(SessionSftpError::Sftp(error));
                    }
                }
            }
            Err(SessionSftpError::Sftp(SftpError::RecoveryArtifactConflict))
        }
        (Some(_), None) => Err(SessionSftpError::Sftp(SftpError::CheckpointMismatch)),
    }
}

fn build_local_download_plan(
    target_path: &std::path::Path,
    artifact_id: &str,
) -> Result<SftpDownloadPlan, SftpError> {
    if !valid_artifact_id(artifact_id) {
        return Err(SftpError::InvalidUploadPlan);
    }
    let target = target_path.to_str().ok_or(SftpError::OperationFailed)?;
    let parent = target_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let workspace = parent.join(format!(".netcatty-xfer-v1-{artifact_id}"));
    let owner = workspace.join("owner.json");
    let staged = workspace.join("staged.part");
    let backup = workspace.join("backup.bak");
    Ok(SftpDownloadPlan {
        artifacts: SftpArtifactPlan {
            version: 1,
            artifact_id: artifact_id.to_owned(),
            target_path: target.to_owned(),
            workspace_path: workspace
                .to_str()
                .ok_or(SftpError::OperationFailed)?
                .to_owned(),
            owner_path: owner.to_str().ok_or(SftpError::OperationFailed)?.to_owned(),
            staged_path: staged
                .to_str()
                .ok_or(SftpError::OperationFailed)?
                .to_owned(),
            backup_path: backup
                .to_str()
                .ok_or(SftpError::OperationFailed)?
                .to_owned(),
        },
    })
}

fn validate_local_download_plan(
    target_path: &std::path::Path,
    plan: &SftpDownloadPlan,
) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), SftpError> {
    let expected = build_local_download_plan(target_path, &plan.artifacts.artifact_id)?;
    if plan != &expected {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    Ok((
        PathBuf::from(&plan.artifacts.workspace_path),
        PathBuf::from(&plan.artifacts.owner_path),
        PathBuf::from(&plan.artifacts.staged_path),
        PathBuf::from(&plan.artifacts.backup_path),
    ))
}

fn valid_artifact_id(artifact_id: &str) -> bool {
    artifact_id.len() == 32
        && artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn build_local_download_owner(
    plan: &SftpDownloadPlan,
    target_path: &std::path::Path,
    remote_path: &str,
    remote: &SftpMetadata,
    initial_target: Option<LocalFileSnapshot>,
) -> LocalDownloadOwner {
    let target_hash = sha256_text(&format!(
        "local:{}",
        local_transfer_destination(target_path, false).path
    ));
    let source_hash = sha256_text(&format!(
        "download:{remote_path}:{}:{:?}",
        remote.size, remote.modified_at
    ));
    let initial_target_hash = initial_target
        .map(|snapshot| sha256_text(&format!("{}:{}", snapshot.size, snapshot.modified_nanos)));
    LocalDownloadOwner {
        magic: "netcatty-transfer-owner".to_owned(),
        version: 1,
        artifact_id: plan.artifacts.artifact_id.clone(),
        target_hash,
        source_hash,
        total_bytes: remote.size,
        initial_target_hash,
    }
}

fn sha256_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn validate_local_download_workspace(
    workspace_path: &std::path::Path,
    owner_path: &std::path::Path,
    staged_path: &std::path::Path,
    backup_path: &std::path::Path,
    expected_owner: &LocalDownloadOwner,
    expected_offset: u64,
) -> Result<(), SftpError> {
    let workspace = tokio::fs::symlink_metadata(workspace_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    let owner = tokio::fs::symlink_metadata(owner_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    let staged = tokio::fs::symlink_metadata(staged_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    if !workspace.is_dir()
        || !owner.is_file()
        || owner.len() > 4 * 1024
        || !staged.is_file()
        || staged.len() != expected_offset
        || local_path_lexically_exists(backup_path).await?
    {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    let marker = tokio::fs::read(owner_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    let actual: LocalDownloadOwner =
        serde_json::from_slice(&marker).map_err(|_| SftpError::RecoveryArtifactConflict)?;
    if &actual != expected_owner {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    Ok(())
}

async fn cleanup_owned_local_download_workspace(
    plan: &SftpDownloadPlan,
    expected_owner: &LocalDownloadOwner,
) -> Result<(), SftpError> {
    let target = PathBuf::from(&plan.artifacts.target_path);
    let (workspace_path, owner_path, staged_path, backup_path) =
        validate_local_download_plan(&target, plan)?;
    let workspace = tokio::fs::symlink_metadata(&workspace_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    let owner = tokio::fs::symlink_metadata(&owner_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    if !workspace.is_dir() || !owner.is_file() || owner.len() > 4 * 1024 {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    let marker = tokio::fs::read(&owner_path)
        .await
        .map_err(|_| SftpError::RecoveryArtifactConflict)?;
    let actual: LocalDownloadOwner =
        serde_json::from_slice(&marker).map_err(|_| SftpError::RecoveryArtifactConflict)?;
    if &actual != expected_owner || local_path_lexically_exists(&backup_path).await? {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    let mut entries = tokio::fs::read_dir(&workspace_path)
        .await
        .map_err(|_| SftpError::OperationFailed)?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| SftpError::OperationFailed)?
    {
        let path = entry.path();
        if path != owner_path && path != staged_path {
            return Err(SftpError::RecoveryArtifactConflict);
        }
    }
    if local_path_lexically_exists(&staged_path).await? {
        let staged = tokio::fs::symlink_metadata(&staged_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if !staged.is_file() {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        tokio::fs::remove_file(&staged_path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
    }
    tokio::fs::remove_file(&owner_path)
        .await
        .map_err(|_| SftpError::OperationFailed)?;
    tokio::fs::remove_dir(&workspace_path)
        .await
        .map_err(|_| SftpError::OperationFailed)
}

async fn local_file_snapshot(
    path: &std::path::Path,
) -> Result<Option<LocalFileSnapshot>, SessionSftpError> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SessionSftpError::LocalFile),
    };
    if !metadata.is_file() {
        return Err(SessionSftpError::Sftp(SftpError::DestinationNotRegularFile));
    }
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    Ok(Some(LocalFileSnapshot {
        size: metadata.len(),
        modified_nanos,
    }))
}

async fn local_path_lexically_exists(path: &std::path::Path) -> Result<bool, SftpError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SftpError::OperationFailed),
    }
}

async fn set_local_modified_time(
    path: &std::path::Path,
    modified_at: u32,
) -> Result<(), SftpError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| SftpError::OperationFailed)?;
        let modified =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(modified_at));
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .map_err(|_| SftpError::OperationFailed)
    })
    .await
    .map_err(|_| SftpError::OperationFailed)?
}

async fn bounded_transfer_finalize<T>(
    operation: impl std::future::Future<Output = Result<T, SftpError>>,
) -> Result<T, SftpError> {
    bounded_sftp_operation(SFTP_TRANSFER_FINALIZE_TIMEOUT, operation).await
}

async fn bounded_sftp_operation<T>(
    timeout: std::time::Duration,
    operation: impl std::future::Future<Output = Result<T, SftpError>>,
) -> Result<T, SftpError> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| SftpError::OperationFailed)?
}

async fn close_transfer_sftp_client(client: &SftpClient) -> Result<(), SftpError> {
    bounded_transfer_finalize(client.close()).await
}

fn merge_transfer_and_close_result<T>(
    transfer: Result<T, SftpError>,
    close: Result<(), SftpError>,
) -> Result<T, SftpError> {
    match transfer {
        Ok(value) => close.map(|()| value),
        Err(error) => Err(error),
    }
}

async fn opened_local_file_fingerprint(file: &tokio::fs::File) -> Result<String, SftpError> {
    let metadata = file
        .metadata()
        .await
        .map_err(|_| SftpError::OperationFailed)?;
    if !metadata.is_file() {
        return Err(SftpError::SourceChanged);
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    Ok(format!("{}:{modified}", metadata.len()))
}

async fn promote_local_download(
    staged_path: &std::path::Path,
    target_path: &std::path::Path,
    backup_path: &std::path::Path,
    expected_target: Option<LocalFileSnapshot>,
) -> Result<bool, SftpError> {
    if local_path_lexically_exists(backup_path).await? {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    let current = local_file_snapshot(target_path)
        .await
        .map_err(|_| SftpError::OperationFailed)?;
    if current != expected_target {
        return Err(SftpError::DestinationChanged);
    }

    let replaced_existing = expected_target.is_some();
    if replaced_existing {
        if tokio::fs::hard_link(target_path, backup_path)
            .await
            .is_err()
        {
            return if local_path_lexically_exists(backup_path).await? {
                Err(SftpError::RecoveryArtifactConflict)
            } else {
                Err(SftpError::OperationFailed)
            };
        }
        let acquired = match local_file_snapshot(backup_path).await {
            Ok(acquired) => acquired,
            Err(_) => {
                return Err(SftpError::OperationFailed);
            }
        };
        if acquired != expected_target {
            let _ = tokio::fs::remove_file(backup_path).await;
            return Err(SftpError::DestinationChanged);
        }
        let still_current = local_file_snapshot(target_path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
        if still_current != expected_target {
            return Err(SftpError::DestinationChanged);
        }
        tokio::fs::remove_file(target_path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
    }

    publish_staged_local_download(staged_path, target_path, backup_path, replaced_existing).await
}

async fn promote_and_cleanup_local_download(
    staged_path: &std::path::Path,
    target_path: &std::path::Path,
    backup_path: &std::path::Path,
    expected_target: Option<LocalFileSnapshot>,
    plan: &SftpDownloadPlan,
    owner: &LocalDownloadOwner,
) -> Result<bool, SftpError> {
    let replaced_existing =
        promote_local_download(staged_path, target_path, backup_path, expected_target).await?;
    cleanup_owned_local_download_workspace(plan, owner).await?;
    Ok(replaced_existing)
}

async fn publish_staged_local_download(
    staged_path: &std::path::Path,
    target_path: &std::path::Path,
    backup_path: &std::path::Path,
    replaced_existing: bool,
) -> Result<bool, SftpError> {
    if tokio::fs::hard_link(staged_path, target_path)
        .await
        .is_err()
    {
        let destination_appeared = local_path_lexically_exists(target_path).await?;
        if replaced_existing && !destination_appeared {
            restore_local_backup_no_replace(backup_path, target_path).await?;
        }
        return if destination_appeared {
            Err(SftpError::DestinationChanged)
        } else {
            Err(SftpError::OperationFailed)
        };
    }

    if tokio::fs::remove_file(staged_path).await.is_err() {
        return Err(SftpError::BackupCleanupFailed);
    }
    if replaced_existing && tokio::fs::remove_file(backup_path).await.is_err() {
        return Err(SftpError::BackupCleanupFailed);
    }
    Ok(replaced_existing)
}

async fn restore_local_backup_no_replace(
    backup_path: &std::path::Path,
    target_path: &std::path::Path,
) -> Result<(), SftpError> {
    tokio::fs::hard_link(backup_path, target_path)
        .await
        .map_err(|_| SftpError::RecoveryFailed)?;
    tokio::fs::remove_file(backup_path)
        .await
        .map_err(|_| SftpError::BackupCleanupFailed)
}

async fn run_session(
    session_id: &str,
    connection: SessionConnection,
    shell_options: ShellOptions,
    events: broadcast::Sender<SessionEvent>,
    commands: mpsc::Receiver<SessionCommand>,
    sftp_commands: mpsc::Receiver<SftpCommand>,
    cancellation: CancellationToken,
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
) {
    let _ = events.send(SessionEvent::Connecting);
    let endpoint_key = connection.endpoint_key();
    let connector = DirectConnector::new();
    let cancel_connector = connector.clone();
    let cancel_watcher = cancellation.clone();
    let cancellation_task = tokio::spawn(async move {
        cancel_watcher.cancelled().await;
        cancel_connector.cancel();
    });
    let transport = match connection {
        SessionConnection::Direct(target) => {
            connector
                .connect(
                    &target.config,
                    &target.auth,
                    &target.credentials,
                    target.verifier,
                    target.interactive,
                )
                .await
        }
        SessionConnection::Chain { target, resolver } => {
            tokio::select! {
                result = connector.connect_chain(target, resolver.as_ref()) => result,
                () = cancellation.cancelled() => {
                    connector.cancel();
                    Err(TransportError::new(
                        TransportErrorCode::Cancelled,
                        "SSH connection cancelled",
                    ))
                }
            }
        }
        SessionConnection::Reuse(transport) => {
            cancellation_task.abort();
            let connection = transport.transport.connection.clone();
            let shell = tokio::select! {
                result = connection.open_shell(shell_options) => result,
                () = cancellation.cancelled() => {
                    transport.release().await;
                    let _ = events.send(SessionEvent::Closed);
                    return;
                }
            };
            let mut shell = match shell {
                Ok(shell) => shell,
                Err(error) => {
                    let _ = events.send(SessionEvent::Error {
                        code: error.code,
                        message: error.to_string(),
                    });
                    transport.release().await;
                    let _ = events.send(SessionEvent::Closed);
                    return;
                }
            };
            if let Some(session) = sessions.lock().await.get_mut(session_id) {
                session.transport = Some(transport.transport.clone());
            }
            let _ = events.send(SessionEvent::Connected);
            run_connected_session(
                &mut shell,
                connection,
                events,
                commands,
                sftp_commands,
                cancellation,
            )
            .await;
            transport.release().await;
            let _ = session_id;
            return;
        }
    };
    cancellation_task.abort();
    let transport = match transport {
        Ok(connection) => SharedSshTransport::new(connection, endpoint_key.clone()),
        Err(error) => {
            let _ = events.send(SessionEvent::Error {
                code: error.code,
                message: error.to_string(),
            });
            let _ = events.send(SessionEvent::Closed);
            return;
        }
    };

    let connection = transport.connection.clone();
    let mut shell = match connection.open_shell(shell_options).await {
        Ok(shell) => shell,
        Err(error) => {
            let _ = events.send(SessionEvent::Error {
                code: error.code,
                message: error.to_string(),
            });
            transport.initial_lease().release().await;
            let _ = events.send(SessionEvent::Closed);
            return;
        }
    };
    if let Some(session) = sessions.lock().await.get_mut(session_id) {
        session.transport = Some(transport.clone());
    }
    let _ = events.send(SessionEvent::Connected);
    run_connected_session(
        &mut shell,
        connection,
        events,
        commands,
        sftp_commands,
        cancellation,
    )
    .await;
    transport.initial_lease().release().await;
    let _ = session_id;
}

async fn run_connected_session(
    shell: &mut crate::SshShell,
    connection: Arc<SshConnection>,
    events: broadcast::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<SessionCommand>,
    sftp_commands: mpsc::Receiver<SftpCommand>,
    cancellation: CancellationToken,
) {
    let sftp_cancellation = CancellationToken::new();
    let sftp_task = tokio::spawn(run_sftp_worker(
        connection.clone(),
        sftp_commands,
        sftp_cancellation.clone(),
    ));

    loop {
        tokio::select! {
            () = cancellation.cancelled() => {
                let _ = shell.close().await;
                break;
            }
            command = commands.recv() => match command {
                Some(SessionCommand::Input(data)) => {
                    if let Err(error) = shell.write(&data).await {
                        let _ = events.send(SessionEvent::Error { code: error.code, message: error.to_string() });
                        break;
                    }
                }
                Some(SessionCommand::Resize(size)) => {
                    if let Err(error) = shell.resize(size).await {
                        let _ = events.send(SessionEvent::Error { code: error.code, message: error.to_string() });
                        break;
                    }
                }
                Some(SessionCommand::Close) | None => {
                    let _ = shell.close().await;
                    break;
                }
            },
            event = shell.next_event() => match event {
                Ok(ShellEvent::Data(data)) => { let _ = events.send(SessionEvent::Data(data)); }
                Ok(ShellEvent::ExtendedData { code, data }) => { let _ = events.send(SessionEvent::ExtendedData { code, data }); }
                Ok(ShellEvent::Eof) => { let _ = events.send(SessionEvent::Eof); }
                Ok(ShellEvent::ExitStatus(status)) => { let _ = events.send(SessionEvent::ExitStatus(status)); }
                Ok(ShellEvent::Closed) => break,
                Err(error) => {
                    let _ = events.send(SessionEvent::Error { code: error.code, message: error.to_string() });
                    break;
                }
            }
        }
    }
    sftp_cancellation.cancel();
    let _ = sftp_task.await;
    let _ = events.send(SessionEvent::Closed);
}

async fn run_sftp_worker(
    connection: Arc<SshConnection>,
    mut commands: mpsc::Receiver<SftpCommand>,
    cancellation: CancellationToken,
) {
    let mut client: Option<SftpClient> = None;
    let transfer_slots = Arc::new(Semaphore::new(SFTP_TRANSFER_CONCURRENCY));
    let mut transfer_tasks = tokio::task::JoinSet::new();
    loop {
        let command = tokio::select! {
            () = cancellation.cancelled() => break,
            result = transfer_tasks.join_next(), if !transfer_tasks.is_empty() => {
                let _ = result;
                continue;
            }
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            }
        };
        if matches!(
            command,
            SftpCommand::Upload { .. } | SftpCommand::Download { .. }
        ) {
            transfer_tasks.spawn(run_sftp_transfer(
                connection.clone(),
                command,
                transfer_slots.clone(),
                cancellation.clone(),
            ));
            continue;
        }
        if client.is_none() {
            match connection.open_sftp().await {
                Ok(opened) => client = Some(opened),
                Err(_) => {
                    reject_sftp_command(command, SftpError::OperationFailed);
                    continue;
                }
            }
        }
        // The initialization branch above should always populate the client.
        // Keep this worker total if that invariant ever changes: reject the
        // pending request instead of panicking the desktop process.
        let Some(client) = client.as_ref() else {
            reject_sftp_command(command, SftpError::OperationFailed);
            continue;
        };
        match command {
            SftpCommand::ReadDir { path, reply } => {
                let _ = reply.send(client.read_dir(&path).await);
            }
            SftpCommand::Metadata { path, reply } => {
                let _ = reply.send(client.metadata(&path).await);
            }
            SftpCommand::Canonicalize { path, reply } => {
                let _ = reply.send(client.canonicalize(&path).await);
            }
            SftpCommand::FollowedMetadata { path, reply } => {
                let _ = reply.send(client.followed_metadata(&path).await);
            }
            SftpCommand::CreateDir { path, reply } => {
                let _ = reply.send(client.create_dir(&path).await);
            }
            SftpCommand::RemoveFile { path, reply } => {
                let _ = reply.send(client.remove_file(&path).await);
            }
            SftpCommand::RemoveDir { path, reply } => {
                let _ = reply.send(client.remove_dir(&path).await);
            }
            SftpCommand::Rename {
                source,
                destination,
                reply,
            } => {
                let _ = reply.send(client.rename(&source, &destination).await);
            }
            SftpCommand::ReadFile { path, reply } => {
                let _ = reply.send(client.read_file(&path).await);
            }
            SftpCommand::WriteFile { path, data, reply } => {
                let _ = reply.send(client.write_file(&path, &data).await);
            }
            SftpCommand::ReplaceFileIfUnchanged {
                path,
                expected,
                data,
                reply,
            } => {
                let _ = reply.send(
                    client
                        .replace_file_if_unchanged(&path, &expected, &data)
                        .await
                        .map(|_| ()),
                );
            }
            transfer @ (SftpCommand::Upload { .. } | SftpCommand::Download { .. }) => {
                // Transfer commands are normally routed to the task set above.
                // Reject safely if that routing changes instead of taking the
                // whole desktop process down.
                reject_sftp_command(transfer, SftpError::OperationFailed);
            }
        }
    }
    cancellation.cancel();
    while transfer_tasks.join_next().await.is_some() {}
    if let Some(client) = client {
        let _ = close_transfer_sftp_client(&client).await;
    }
}

async fn run_sftp_transfer(
    connection: Arc<SshConnection>,
    command: SftpCommand,
    transfer_slots: Arc<Semaphore>,
    cancellation: CancellationToken,
) {
    match command {
        SftpCommand::Upload {
            mut source,
            total_bytes,
            source_fingerprint,
            source_modified_at,
            plan,
            resume,
            control,
            start_gate,
            progress,
            events,
            done,
        } => {
            let permit =
                acquire_transfer_slot(transfer_slots, start_gate.as_ref(), &control, &cancellation)
                    .await;
            let Some(_permit) = permit else {
                let _ = events.send(SftpTransferEvent::Cancelled {
                    checkpoint: control.checkpoint().await,
                });
                drop(progress);
                let _ = done.send(());
                return;
            };
            let _ = events.send(SftpTransferEvent::Started);
            let opened = tokio::select! {
                () = cancellation.cancelled() => Err(SftpError::Cancelled),
                () = control.cancelled() => Err(SftpError::Cancelled),
                result = connection.open_sftp() => result.map_err(|_| SftpError::OperationFailed),
            };
            let result = match opened {
                Ok(client) => {
                    let staged = tokio::select! {
                        () = cancellation.cancelled() => {
                            control.cancel();
                            Err(SftpError::Cancelled)
                        }
                        result = client.stage_stream_safe_upload(
                            &plan,
                            &mut source,
                            total_bytes,
                            Some(&source_fingerprint),
                            resume.as_ref(),
                            &control,
                            Some(&progress),
                        ) => result,
                    };
                    let result = match staged {
                        Ok((mut checkpoint, initial)) => {
                            let current_fingerprint = opened_local_file_fingerprint(&source).await;
                            if current_fingerprint.as_deref() != Ok(source_fingerprint.as_str()) {
                                Err(SftpError::SourceChanged)
                            } else if control.is_cancelled() || cancellation.is_cancelled() {
                                Err(SftpError::Cancelled)
                            } else {
                                if let Some(modified_at) = source_modified_at {
                                    let modified = bounded_transfer_finalize(
                                        client.set_modified_time(&plan.staged_path, modified_at),
                                    )
                                    .await;
                                    if let Err(error) = modified {
                                        Err(error)
                                    } else {
                                        checkpoint.remote_modified_at = Some(modified_at);
                                        if control.is_cancelled() || cancellation.is_cancelled() {
                                            Err(SftpError::Cancelled)
                                        } else {
                                            client
                                                .promote_staged_stream_upload(
                                                    &plan,
                                                    total_bytes,
                                                    initial,
                                                )
                                                .await
                                                .map(|upload| SftpStreamUploadOutcome {
                                                    upload,
                                                    checkpoint,
                                                })
                                        }
                                    }
                                } else if control.is_cancelled() || cancellation.is_cancelled() {
                                    Err(SftpError::Cancelled)
                                } else {
                                    client
                                        .promote_staged_stream_upload(&plan, total_bytes, initial)
                                        .await
                                        .map(|upload| SftpStreamUploadOutcome {
                                            upload,
                                            checkpoint,
                                        })
                                }
                            }
                        }
                        Err(error) => Err(error),
                    };
                    let close = close_transfer_sftp_client(&client).await;
                    merge_transfer_and_close_result(result, close)
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(outcome) => {
                    let _ = events.send(SftpTransferEvent::Completed {
                        checkpoint: outcome.checkpoint,
                        replaced_existing: outcome.upload.replaced_existing,
                    });
                }
                Err(SftpError::Cancelled) => {
                    let _ = events.send(SftpTransferEvent::Cancelled {
                        checkpoint: control.checkpoint().await,
                    });
                }
                Err(error) => {
                    let _ = events.send(SftpTransferEvent::Failed {
                        code: format!("{error:?}"),
                        message: error.to_string(),
                        checkpoint: control.checkpoint().await,
                    });
                }
            }
            drop(progress);
            let _ = done.send(());
        }
        SftpCommand::Download {
            mut destination,
            remote_path,
            local_path,
            staged_path,
            backup_path,
            expected_target,
            plan,
            owner,
            cleanup_on_cancel,
            resume,
            control,
            start_gate,
            progress,
            events,
            done,
        } => {
            let permit =
                acquire_transfer_slot(transfer_slots, start_gate.as_ref(), &control, &cancellation)
                    .await;
            let Some(_permit) = permit else {
                let checkpoint = control.checkpoint().await;
                if cleanup_on_cancel || checkpoint.is_none() {
                    let _ = cleanup_owned_local_download_workspace(&plan, &owner).await;
                }
                let _ = events.send(SftpTransferEvent::Cancelled { checkpoint });
                drop(progress);
                let _ = done.send(());
                return;
            };
            let _ = events.send(SftpTransferEvent::Started);
            let opened = tokio::select! {
                () = cancellation.cancelled() => Err(SftpError::Cancelled),
                () = control.cancelled() => Err(SftpError::Cancelled),
                result = connection.open_sftp() => result.map_err(|_| SftpError::OperationFailed),
            };
            let result = match opened {
                Ok(client) => {
                    let result = tokio::select! {
                        () = cancellation.cancelled() => {
                            control.cancel();
                            Err(SftpError::Cancelled)
                        }
                        result = client.stream_download(
                            &remote_path,
                            &mut destination,
                            resume.as_ref(),
                            &control,
                            Some(&progress),
                        ) => result,
                    };
                    let result = match result {
                        Ok(checkpoint) => tokio::select! {
                            () = cancellation.cancelled() => {
                                control.cancel();
                                Err(SftpError::Cancelled)
                            },
                            () = control.cancelled() => Err(SftpError::Cancelled),
                            result = destination.sync_all() => result
                                .map(|()| checkpoint)
                                .map_err(|_| SftpError::OperationFailed),
                        },
                        Err(error) => Err(error),
                    };
                    let close = close_transfer_sftp_client(&client).await;
                    merge_transfer_and_close_result(result, close)
                }
                Err(error) => Err(error),
            };
            drop(destination);
            let result = match result {
                Ok(_checkpoint) if control.is_cancelled() || cancellation.is_cancelled() => {
                    Err(SftpError::Cancelled)
                }
                Ok(checkpoint) => {
                    if let Some(modified_at) = checkpoint.remote_modified_at {
                        bounded_transfer_finalize(set_local_modified_time(
                            &staged_path,
                            modified_at,
                        ))
                        .await
                        .map(|()| checkpoint)
                    } else {
                        Ok(checkpoint)
                    }
                }
                Err(error) => Err(error),
            };
            let result = match result {
                Ok(_) if control.is_cancelled() || cancellation.is_cancelled() => {
                    Err(SftpError::Cancelled)
                }
                result => result,
            };
            match result {
                Ok(checkpoint) => match promote_and_cleanup_local_download(
                    &staged_path,
                    &local_path,
                    &backup_path,
                    expected_target,
                    &plan,
                    &owner,
                )
                .await
                {
                    Ok(replaced_existing) => {
                        let _ = events.send(SftpTransferEvent::Completed {
                            checkpoint,
                            replaced_existing,
                        });
                    }
                    Err(error) => {
                        let _ = events.send(SftpTransferEvent::Failed {
                            code: format!("{error:?}"),
                            message: error.to_string(),
                            checkpoint: control.checkpoint().await,
                        });
                    }
                },
                Err(SftpError::Cancelled) => {
                    let checkpoint = control.checkpoint().await;
                    if cleanup_on_cancel || checkpoint.is_none() {
                        let _ = cleanup_owned_local_download_workspace(&plan, &owner).await;
                    }
                    let _ = events.send(SftpTransferEvent::Cancelled { checkpoint });
                }
                Err(error) => {
                    let _ = events.send(SftpTransferEvent::Failed {
                        code: format!("{error:?}"),
                        message: error.to_string(),
                        checkpoint: control.checkpoint().await,
                    });
                }
            }
            drop(progress);
            let _ = done.send(());
        }
        command => reject_sftp_command(command, SftpError::OperationFailed),
    }
}

async fn acquire_transfer_slot(
    transfer_slots: Arc<Semaphore>,
    start_gate: Option<&SftpTransferControl>,
    control: &SftpTransferControl,
    cancellation: &CancellationToken,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    loop {
        if !wait_for_transfer_start(start_gate, control, cancellation).await {
            return None;
        }
        let permit = tokio::select! {
            () = cancellation.cancelled() => return None,
            () = control.cancelled() => return None,
            permit = transfer_slots.clone().acquire_owned() => permit.ok()?,
        };
        if cancellation.is_cancelled()
            || control.is_cancelled()
            || control.is_paused()
            || start_gate.is_some_and(|gate| gate.is_cancelled() || gate.is_paused())
        {
            drop(permit);
            if cancellation.is_cancelled()
                || control.is_cancelled()
                || start_gate.is_some_and(SftpTransferControl::is_cancelled)
            {
                return None;
            }
            continue;
        }
        return Some(permit);
    }
}

async fn wait_for_transfer_start(
    start_gate: Option<&SftpTransferControl>,
    control: &SftpTransferControl,
    cancellation: &CancellationToken,
) -> bool {
    loop {
        if cancellation.is_cancelled()
            || control.is_cancelled()
            || start_gate.is_some_and(SftpTransferControl::is_cancelled)
        {
            return false;
        }
        if control.is_paused() {
            let resumed = tokio::select! {
                () = cancellation.cancelled() => return false,
                result = control.wait_until_resumed() => result.is_ok(),
            };
            if !resumed {
                return false;
            }
            continue;
        }
        if let Some(start_gate) = start_gate
            && start_gate.is_paused()
        {
            let resumed = tokio::select! {
                () = cancellation.cancelled() => return false,
                () = control.cancelled() => return false,
                result = start_gate.wait_until_resumed() => result.is_ok(),
            };
            if !resumed {
                return false;
            }
            continue;
        }
        return true;
    }
}

fn reject_sftp_command(command: SftpCommand, error: SftpError) {
    match command {
        SftpCommand::ReadDir { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::Metadata { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::Canonicalize { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::FollowedMetadata { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::CreateDir { reply, .. }
        | SftpCommand::RemoveFile { reply, .. }
        | SftpCommand::RemoveDir { reply, .. }
        | SftpCommand::Rename { reply, .. }
        | SftpCommand::WriteFile { reply, .. }
        | SftpCommand::ReplaceFileIfUnchanged { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::ReadFile { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        SftpCommand::Upload {
            control,
            events,
            done,
            ..
        } => {
            let _ = events.send(SftpTransferEvent::Failed {
                code: format!("{error:?}"),
                message: error.to_string(),
                checkpoint: None,
            });
            control.cancel();
            let _ = done.send(());
        }
        SftpCommand::Download {
            control,
            events,
            done,
            ..
        } => {
            let _ = events.send(SftpTransferEvent::Failed {
                code: format!("{error:?}"),
                message: error.to_string(),
                checkpoint: None,
            });
            control.cancel();
            let _ = done.send(());
        }
    }
}

fn next_session_id() -> String {
    let sequence = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    format!("ssh-{}-{sequence}", std::process::id())
}

fn next_transfer_id() -> String {
    let sequence = NEXT_TRANSFER_ID.fetch_add(1, Ordering::Relaxed);
    format!("sftp-{}-{sequence}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{
        SessionManager, SessionManagerError, SessionSftpError, acquire_transfer_slot,
        advance_directory_checkpoint, bounded_sftp_operation,
        cleanup_owned_local_download_workspace, local_file_snapshot, local_recovery_path,
        local_transfer_destination, merge_transfer_and_close_result,
        normalize_remote_directory_root, normalize_remote_reservation_path,
        prepare_local_download_artifacts, promote_and_cleanup_local_download,
        promote_local_download, publish_staged_local_download, remote_transfer_destination,
        set_local_modified_time, transfer_destinations_conflict,
    };
    use crate::{
        ConnectionCredentials, DirectoryResumeCheckpoint, HostChainResolver, KnownHostsVerifier,
        ResolvedSshEndpoint, SessionEvent, SftpEntryKind, SftpError, SftpMetadata,
        SftpTransferCheckpoint, SftpTransferControl, SftpTransferDirection, ShellOptions,
        SshConnectionConfig, SshJumpHost, TerminalSize, TransportError, TransportErrorCode,
        validate_connection,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt as _;

    struct FailingChainResolver {
        calls: Arc<AtomicUsize>,
    }

    struct BlockingChainResolver {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl HostChainResolver for FailingChainResolver {
        async fn resolve(&self, _: &str) -> Result<ResolvedSshEndpoint, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(TransportError::new(
                TransportErrorCode::JumpHostUnavailable,
                "jump host unavailable",
            ))
        }
    }

    #[async_trait::async_trait]
    impl HostChainResolver for BlockingChainResolver {
        async fn resolve(&self, _: &str) -> Result<ResolvedSshEndpoint, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            std::future::pending().await
        }
    }

    fn unique_test_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "netcatty-{name}-{}-{}",
            std::process::id(),
            crate::runtime::NEXT_TRANSFER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn transfer_finalization_timeout_and_close_failure_cannot_report_success() {
        let timed_out = bounded_sftp_operation(
            std::time::Duration::from_millis(1),
            std::future::pending::<Result<(), SftpError>>(),
        )
        .await;
        assert_eq!(timed_out, Err(SftpError::OperationFailed));
        assert_eq!(
            merge_transfer_and_close_result(Ok(7_u8), Err(SftpError::OperationFailed)),
            Err(SftpError::OperationFailed)
        );
        assert_eq!(
            merge_transfer_and_close_result::<u8>(
                Err(SftpError::Cancelled),
                Err(SftpError::OperationFailed),
            ),
            Err(SftpError::Cancelled)
        );
    }

    #[test]
    fn transfer_destinations_normalize_remote_and_local_aliases() {
        assert_eq!(
            remote_transfer_destination("user@example:22", "/folder/file/", false),
            remote_transfer_destination("user@example:22", "/folder/file", false)
        );
        assert_ne!(
            remote_transfer_destination("user@example:22", "/folder/file", false),
            remote_transfer_destination("user@other:22", "/folder/file", false)
        );
        assert_eq!(
            remote_transfer_destination("user@example:22", "/folder/other/../file//", false),
            remote_transfer_destination("user@example:22", "/folder/file", false)
        );

        let path = std::path::PathBuf::from("folder").join("file.txt");
        assert_eq!(local_transfer_destination(&path, false).endpoint, "local");
        assert_eq!(
            local_transfer_destination(
                &std::path::PathBuf::from("folder")
                    .join("..")
                    .join("file.txt"),
                false,
            ),
            local_transfer_destination(std::path::Path::new("file.txt"), false)
        );
        assert_eq!(normalize_remote_directory_root("///"), Some("/".to_owned()));
        assert_eq!(normalize_remote_directory_root("\0"), None);
        assert_eq!(normalize_remote_reservation_path("."), ".");
        assert_eq!(normalize_remote_reservation_path("./child"), "./child");
        assert_eq!(normalize_remote_reservation_path("child"), "./child");
        assert_eq!(normalize_remote_reservation_path("../.."), "../..");
        assert_eq!(normalize_remote_reservation_path("../../x"), "../../x");
    }

    #[test]
    fn tree_reservations_use_component_boundaries_and_endpoint_scope() {
        let tree = remote_transfer_destination("host", "/data/tree", true);
        let child = remote_transfer_destination("host", "/data/tree/file", false);
        let ancestor = remote_transfer_destination("host", "/data", false);
        let sibling_prefix = remote_transfer_destination("host", "/data/treehouse", false);
        let other_endpoint = remote_transfer_destination("other", "/data/tree/file", false);
        assert!(transfer_destinations_conflict(&tree, &child));
        assert!(transfer_destinations_conflict(&tree, &ancestor));
        assert!(!transfer_destinations_conflict(&tree, &sibling_prefix));
        assert!(!transfer_destinations_conflict(&tree, &other_endpoint));

        let relative_root = remote_transfer_destination("host", ".", true);
        let relative_child = remote_transfer_destination("host", "./child", false);
        let parent_root = remote_transfer_destination("host", "../..", true);
        let parent_child = remote_transfer_destination("host", "../../x", false);
        assert!(transfer_destinations_conflict(
            &relative_root,
            &relative_child
        ));
        assert!(transfer_destinations_conflict(&parent_root, &parent_child));
        assert!(!transfer_destinations_conflict(
            &relative_root,
            &parent_child
        ));
    }

    #[test]
    fn directory_checkpoint_advances_only_across_a_completed_prefix() {
        let mut checkpoint = DirectoryResumeCheckpoint {
            version: 2,
            covered_entries: 4,
            completed_entries: 0,
            manifest_hash: "a".repeat(64),
        };
        let mut completed = vec![false, false, true, false];
        advance_directory_checkpoint(&completed, &mut checkpoint);
        assert_eq!(checkpoint.completed_entries, 0);
        completed[0] = true;
        advance_directory_checkpoint(&completed, &mut checkpoint);
        assert_eq!(checkpoint.completed_entries, 1);
        completed[1] = true;
        advance_directory_checkpoint(&completed, &mut checkpoint);
        assert_eq!(checkpoint.completed_entries, 3);
    }

    #[tokio::test]
    async fn active_transfers_reserve_each_destination_once() {
        let manager = SessionManager::new();
        let (events, _) = tokio::sync::broadcast::channel(4);
        manager
            .reserve_transfer(
                "first".to_owned(),
                "session-a",
                local_transfer_destination(std::path::Path::new("target"), false),
                None,
                SftpTransferControl::new(),
                events.clone(),
            )
            .await
            .expect("reserve first transfer");
        assert_eq!(
            manager
                .reserve_transfer(
                    "second".to_owned(),
                    "session-b",
                    local_transfer_destination(std::path::Path::new("target"), false),
                    None,
                    SftpTransferControl::new(),
                    events.clone(),
                )
                .await,
            Err(SessionSftpError::DestinationBusy)
        );
        manager
            .reserve_transfer(
                "third".to_owned(),
                "session-b",
                local_transfer_destination(std::path::Path::new("other"), false),
                None,
                SftpTransferControl::new(),
                events.clone(),
            )
            .await
            .expect("reserve independent destination");

        let directory_manager = SessionManager::new();
        directory_manager
            .reserve_transfer(
                "root".to_owned(),
                "session-a",
                remote_transfer_destination("host", "/tree", true),
                None,
                SftpTransferControl::new(),
                events.clone(),
            )
            .await
            .expect("reserve directory root");
        assert_eq!(
            directory_manager
                .reserve_transfer(
                    "external-child".to_owned(),
                    "session-b",
                    remote_transfer_destination("host", "/tree/file.bin", false),
                    None,
                    SftpTransferControl::new(),
                    events.clone(),
                )
                .await,
            Err(SessionSftpError::DestinationBusy)
        );
        directory_manager
            .reserve_transfer(
                "owned-child".to_owned(),
                "session-a",
                remote_transfer_destination("host", "/tree/file.bin", false),
                Some("root".to_owned()),
                SftpTransferControl::new(),
                events,
            )
            .await
            .expect("directory owner reserves its child");
    }

    #[tokio::test]
    async fn transfer_write_sets_reserve_stage_and_backup_artifacts() {
        let manager = SessionManager::new();
        let (events, _) = tokio::sync::broadcast::channel(4);
        let local_target = std::path::PathBuf::from("artifact-target.bin");
        let local_stage = local_recovery_path(&local_target, ".netcatty-download.part");
        let local_backup = local_recovery_path(&local_target, ".netcatty-download.backup");
        manager
            .reserve_transfer_write_set(
                "local-owner".to_owned(),
                "session-a",
                vec![
                    local_transfer_destination(&local_target, false),
                    local_transfer_destination(&local_stage, false),
                    local_transfer_destination(&local_backup, false),
                ],
                None,
                SftpTransferControl::new(),
                events.clone(),
            )
            .await
            .expect("reserve local write set");
        assert_eq!(
            manager
                .reserve_transfer(
                    "local-stage-writer".to_owned(),
                    "session-b",
                    local_transfer_destination(&local_stage, false),
                    None,
                    SftpTransferControl::new(),
                    events.clone(),
                )
                .await,
            Err(SessionSftpError::DestinationBusy)
        );
        assert_eq!(
            manager
                .reserve_transfer(
                    "local-backup-writer".to_owned(),
                    "session-b",
                    local_transfer_destination(&local_backup, false),
                    None,
                    SftpTransferControl::new(),
                    events.clone(),
                )
                .await,
            Err(SessionSftpError::DestinationBusy)
        );

        let remote_manager = SessionManager::new();
        let remote_target = remote_transfer_destination("host", "/data/file", false);
        let remote_stage =
            remote_transfer_destination("host", "/data/.netcatty-upload-stable-file.part", false);
        let remote_backup =
            remote_transfer_destination("host", "/data/.netcatty-backup-stable-file.bak", false);
        remote_manager
            .reserve_transfer_write_set(
                "remote-owner".to_owned(),
                "session-a",
                vec![remote_target, remote_stage.clone(), remote_backup.clone()],
                None,
                SftpTransferControl::new(),
                events.clone(),
            )
            .await
            .expect("reserve remote write set");
        for (id, artifact) in [
            ("remote-stage-writer", remote_stage),
            ("remote-backup-writer", remote_backup),
        ] {
            assert_eq!(
                remote_manager
                    .reserve_transfer(
                        id.to_owned(),
                        "session-b",
                        artifact,
                        None,
                        SftpTransferControl::new(),
                        events.clone(),
                    )
                    .await,
                Err(SessionSftpError::DestinationBusy)
            );
        }
    }

    #[tokio::test]
    async fn directory_pause_and_resume_propagate_to_active_children() {
        let manager = SessionManager::new();
        let (events, _) = tokio::sync::broadcast::channel(4);
        let root_control = SftpTransferControl::new();
        let child_control = SftpTransferControl::new();
        manager
            .reserve_transfer(
                "root".to_owned(),
                "session-a",
                remote_transfer_destination("host", "/tree", true),
                None,
                root_control.clone(),
                events.clone(),
            )
            .await
            .expect("reserve root");
        manager
            .reserve_transfer(
                "child".to_owned(),
                "session-a",
                remote_transfer_destination("host", "/tree/file", false),
                Some("root".to_owned()),
                child_control.clone(),
                events,
            )
            .await
            .expect("reserve child");

        manager
            .pause_sftp_transfer("root")
            .await
            .expect("pause root");
        assert!(root_control.is_paused());
        assert!(child_control.is_paused());
        manager
            .resume_sftp_transfer("root")
            .await
            .expect("resume root");
        assert!(!root_control.is_paused());
        assert!(!child_control.is_paused());
    }

    #[tokio::test]
    async fn transfer_slots_bound_parallel_work_and_wake_the_queue() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let first_control = SftpTransferControl::new();
        let second_control = SftpTransferControl::new();
        let third_control = SftpTransferControl::new();
        let first = acquire_transfer_slot(slots.clone(), None, &first_control, &cancellation)
            .await
            .expect("first slot");
        let _second = acquire_transfer_slot(slots.clone(), None, &second_control, &cancellation)
            .await
            .expect("second slot");
        let waiting = acquire_transfer_slot(slots, None, &third_control, &cancellation);
        let mut waiting = std::pin::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        drop(first);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .expect("queued slot wakes")
                .is_some()
        );
    }

    #[tokio::test]
    async fn paused_transfer_gates_never_hold_scheduler_slots() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let parent = SftpTransferControl::new();
        parent.pause();

        let spawn_waiter = |control: SftpTransferControl| {
            let slots = slots.clone();
            let cancellation = cancellation.clone();
            let parent = parent.clone();
            tokio::spawn(async move {
                acquire_transfer_slot(slots, Some(&parent), &control, &cancellation).await
            })
        };
        let first = spawn_waiter(SftpTransferControl::new());
        let second = spawn_waiter(SftpTransferControl::new());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(slots.available_permits(), 2);

        let independent = SftpTransferControl::new();
        let independent_permit = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            acquire_transfer_slot(slots.clone(), None, &independent, &cancellation),
        )
        .await
        .expect("independent transfer was not starved")
        .expect("independent transfer acquired a slot");
        drop(independent_permit);

        parent.resume();
        let first_permit = tokio::time::timeout(std::time::Duration::from_secs(1), first)
            .await
            .expect("first waiter resumed")
            .expect("first waiter task")
            .expect("first waiter permit");
        let second_permit = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .expect("second waiter resumed")
            .expect("second waiter task")
            .expect("second waiter permit");
        drop((first_permit, second_permit));

        let queued = SftpTransferControl::new();
        queued.pause();
        let waiting = acquire_transfer_slot(slots.clone(), None, &queued, &cancellation);
        let mut waiting = std::pin::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        assert_eq!(slots.available_permits(), 2);
        queued.resume();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .expect("queued transfer resumed")
                .is_some()
        );
    }

    #[tokio::test]
    async fn local_download_promotion_creates_and_replaces_atomically() {
        let directory = unique_test_directory("download-promotion");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let staged = local_recovery_path(&target, ".netcatty-download.part");
        let backup = local_recovery_path(&target, ".netcatty-download.backup");

        tokio::fs::write(&staged, b"first")
            .await
            .expect("write first stage");
        assert_eq!(
            promote_local_download(&staged, &target, &backup, None).await,
            Ok(false)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"first"
        );
        assert!(!tokio::fs::try_exists(&staged).await.expect("stage state"));

        let expected = local_file_snapshot(&target).await.expect("snapshot target");
        tokio::fs::write(&staged, b"second")
            .await
            .expect("write replacement stage");
        assert_eq!(
            promote_local_download(&staged, &target, &backup, expected).await,
            Ok(true)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read replacement"),
            b"second"
        );
        assert!(!tokio::fs::try_exists(&backup).await.expect("backup state"));

        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_workspace_never_claims_legacy_suffix_files() {
        let directory = unique_test_directory("download-owned-workspace");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let legacy_stage = local_recovery_path(&target, ".netcatty-download.part");
        let legacy_backup = local_recovery_path(&target, ".netcatty-download.backup");
        tokio::fs::write(&legacy_stage, b"user stage")
            .await
            .expect("write legacy stage");
        tokio::fs::write(&legacy_backup, b"user backup")
            .await
            .expect("write legacy backup");
        let remote = SftpMetadata {
            kind: SftpEntryKind::File,
            size: 3,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            accessed_at: None,
            modified_at: Some(1_700_000_000),
        };

        let prepared =
            prepare_local_download_artifacts(&target, "/remote/download.bin", &remote, None, None)
                .await
                .expect("prepare owned workspace");
        assert_ne!(prepared.staged_path, legacy_stage);
        assert_ne!(prepared.backup_path, legacy_backup);
        assert_eq!(
            tokio::fs::read(&legacy_stage)
                .await
                .expect("read legacy stage"),
            b"user stage"
        );
        assert_eq!(
            tokio::fs::read(&legacy_backup)
                .await
                .expect("read legacy backup"),
            b"user backup"
        );
        drop(prepared.destination);
        cleanup_owned_local_download_workspace(&prepared.plan, &prepared.owner)
            .await
            .expect("cleanup owned workspace");
        assert_eq!(
            tokio::fs::read(&legacy_stage)
                .await
                .expect("legacy stage survives cleanup"),
            b"user stage"
        );
        assert_eq!(
            tokio::fs::read(&legacy_backup)
                .await
                .expect("legacy backup survives cleanup"),
            b"user backup"
        );
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_cleanup_failure_is_not_a_successful_commit() {
        let directory = unique_test_directory("download-cleanup-failure");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let remote = SftpMetadata {
            kind: SftpEntryKind::File,
            size: 7,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            accessed_at: None,
            modified_at: Some(1_700_000_000),
        };
        let mut prepared =
            prepare_local_download_artifacts(&target, "/remote/download.bin", &remote, None, None)
                .await
                .expect("prepare owned workspace");
        prepared
            .destination
            .write_all(b"payload")
            .await
            .expect("write stage");
        prepared.destination.sync_all().await.expect("sync stage");
        let foreign_path = prepared.workspace_path.join("foreign.file");
        tokio::fs::write(&foreign_path, b"foreign")
            .await
            .expect("create foreign workspace entry");
        drop(prepared.destination);

        assert_eq!(
            promote_and_cleanup_local_download(
                &prepared.staged_path,
                &target,
                &prepared.backup_path,
                prepared.expected_target,
                &prepared.plan,
                &prepared.owner,
            )
            .await,
            Err(SftpError::RecoveryArtifactConflict)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("published payload"),
            b"payload"
        );
        assert_eq!(
            tokio::fs::read(&foreign_path)
                .await
                .expect("foreign entry preserved"),
            b"foreign"
        );

        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_resume_requires_matching_owner_marker_and_offset() {
        let directory = unique_test_directory("download-owned-resume");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let remote = SftpMetadata {
            kind: SftpEntryKind::File,
            size: 3,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            accessed_at: None,
            modified_at: Some(1_700_000_001),
        };
        let mut prepared =
            prepare_local_download_artifacts(&target, "/remote/download.bin", &remote, None, None)
                .await
                .expect("prepare fresh workspace");
        prepared
            .destination
            .write_all(b"abc")
            .await
            .expect("write resumable stage");
        prepared
            .destination
            .sync_all()
            .await
            .expect("sync resumable stage");
        let plan = prepared.plan.clone();
        let owner = prepared.owner.clone();
        let stage = prepared.staged_path.clone();
        drop(prepared.destination);
        let checkpoint = SftpTransferCheckpoint {
            direction: SftpTransferDirection::Download,
            remote_path: "/remote/download.bin".to_owned(),
            bytes_transferred: 3,
            total_bytes: 3,
            source_fingerprint: None,
            remote_modified_at: remote.modified_at,
        };
        let resumed = prepare_local_download_artifacts(
            &target,
            "/remote/download.bin",
            &remote,
            Some(plan.clone()),
            Some(&checkpoint),
        )
        .await
        .expect("resume owned workspace");
        assert!(!resumed.created_workspace);
        assert_eq!(
            resumed
                .destination
                .metadata()
                .await
                .expect("resumed stage metadata")
                .len(),
            3
        );
        drop(resumed.destination);

        tokio::fs::write(&plan.artifacts.owner_path, b"{}")
            .await
            .expect("corrupt marker");
        assert!(matches!(
            prepare_local_download_artifacts(
                &target,
                "/remote/download.bin",
                &remote,
                Some(plan),
                Some(&checkpoint),
            )
            .await,
            Err(SessionSftpError::Sftp(SftpError::RecoveryArtifactConflict))
        ));
        assert_eq!(
            tokio::fs::read(stage)
                .await
                .expect("stage survives mismatch"),
            b"abc"
        );
        let _ = owner;
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_publication_never_restores_over_a_new_target() {
        let directory = unique_test_directory("download-no-overwrite-restore");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let staged = directory.join("stage.part");
        let backup = directory.join("backup.bak");
        tokio::fs::write(&staged, b"download")
            .await
            .expect("write stage");
        tokio::fs::write(&backup, b"original")
            .await
            .expect("write backup");
        tokio::fs::write(&target, b"new external target")
            .await
            .expect("write competing target");

        assert_eq!(
            publish_staged_local_download(&staged, &target, &backup, true).await,
            Err(SftpError::DestinationChanged)
        );
        assert_eq!(
            tokio::fs::read(&target)
                .await
                .expect("read competing target"),
            b"new external target"
        );
        assert_eq!(
            tokio::fs::read(&backup)
                .await
                .expect("read preserved backup"),
            b"original"
        );
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_promotion_preserves_unknown_backup() {
        let directory = unique_test_directory("download-unknown-backup");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let staged = directory.join("stage.part");
        let backup = directory.join("backup.bak");
        tokio::fs::write(&target, b"original")
            .await
            .expect("write target");
        tokio::fs::write(&staged, b"download")
            .await
            .expect("write stage");
        tokio::fs::write(&backup, b"user backup")
            .await
            .expect("write unknown backup");
        let expected = local_file_snapshot(&target).await.expect("snapshot target");

        assert_eq!(
            promote_local_download(&staged, &target, &backup, expected).await,
            Err(SftpError::RecoveryArtifactConflict)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("target preserved"),
            b"original"
        );
        assert_eq!(
            tokio::fs::read(&backup).await.expect("backup preserved"),
            b"user backup"
        );
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn downloaded_files_receive_the_remote_modified_time() {
        let directory = unique_test_directory("download-modified-time");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        tokio::fs::write(&target, b"content")
            .await
            .expect("write target");

        let expected = 1_700_000_123_u32;
        set_local_modified_time(&target, expected)
            .await
            .expect("set modified time");
        let actual = tokio::fs::metadata(&target)
            .await
            .expect("metadata")
            .modified()
            .expect("modified")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        assert_eq!(actual, u64::from(expected));

        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_promotion_rejects_changed_target() {
        let directory = unique_test_directory("download-conflict");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let staged = local_recovery_path(&target, ".netcatty-download.part");
        let backup = local_recovery_path(&target, ".netcatty-download.backup");
        tokio::fs::write(&target, b"original")
            .await
            .expect("write original target");
        let expected = local_file_snapshot(&target).await.expect("snapshot target");
        tokio::fs::write(&target, b"changed while downloading")
            .await
            .expect("change target");
        tokio::fs::write(&staged, b"download")
            .await
            .expect("write stage");

        assert_eq!(
            promote_local_download(&staged, &target, &backup, expected).await,
            Err(SftpError::DestinationChanged)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read changed target"),
            b"changed while downloading"
        );
        assert_eq!(
            tokio::fs::read(&staged)
                .await
                .expect("read preserved stage"),
            b"download"
        );

        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn local_download_promotion_restores_target_when_publication_fails() {
        let directory = unique_test_directory("download-recovery");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test directory");
        let target = directory.join("download.bin");
        let staged = local_recovery_path(&target, ".netcatty-download.part");
        let backup = local_recovery_path(&target, ".netcatty-download.backup");
        tokio::fs::write(&target, b"original")
            .await
            .expect("write original target");
        let expected = local_file_snapshot(&target).await.expect("snapshot target");

        assert_eq!(
            promote_local_download(&staged, &target, &backup, expected).await,
            Err(SftpError::OperationFailed)
        );
        assert_eq!(
            tokio::fs::read(&target)
                .await
                .expect("read restored target"),
            b"original"
        );
        assert!(!tokio::fs::try_exists(&backup).await.expect("backup state"));

        tokio::fs::remove_dir_all(directory)
            .await
            .expect("remove test directory");
    }

    #[tokio::test]
    async fn missing_sessions_fail_without_creating_state() {
        let manager = SessionManager::new();

        assert_eq!(
            manager.send_input("missing", vec![1]).await,
            Err(SessionManagerError::NotFound)
        );
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn chain_begin_resolves_jump_and_forwards_failure_events() {
        let request = SshConnectionConfig::saved_password_host("127.0.0.1", 22, "tester");
        let auth = request.auth.clone();
        let mut config = validate_connection(request)
            .normalized
            .expect("normalized target");
        config.jump_hosts = vec![SshJumpHost {
            host_id: "missing-jump".to_owned(),
        }];
        let target = ResolvedSshEndpoint {
            config,
            auth,
            credentials: ConnectionCredentials::empty(),
            verifier: Arc::new(KnownHostsVerifier::disabled("127.0.0.1", 22)),
            interactive: None,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(FailingChainResolver {
            calls: calls.clone(),
        });
        let manager = SessionManager::new();
        let mut started = manager
            .begin_chain(target, resolver, ShellOptions::default())
            .await;

        assert_eq!(
            started.events.recv().await.expect("connecting event"),
            SessionEvent::Connecting
        );
        assert!(matches!(
            started.events.recv().await.expect("resolution error"),
            SessionEvent::Error {
                code: TransportErrorCode::JumpHostUnavailable,
                ..
            }
        ));
        assert_eq!(
            started.events.recv().await.expect("closed event"),
            SessionEvent::Closed
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while manager.active_count().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed chain session cleanup");
    }

    #[tokio::test]
    async fn chain_begin_cancellation_interrupts_a_pending_resolver() {
        let request = SshConnectionConfig::saved_password_host("127.0.0.1", 22, "tester");
        let auth = request.auth.clone();
        let mut config = validate_connection(request)
            .normalized
            .expect("normalized target");
        config.jump_hosts = vec![SshJumpHost {
            host_id: "pending-jump".to_owned(),
        }];
        let target = ResolvedSshEndpoint {
            config,
            auth,
            credentials: ConnectionCredentials::empty(),
            verifier: Arc::new(KnownHostsVerifier::disabled("127.0.0.1", 22)),
            interactive: None,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(BlockingChainResolver {
            calls: calls.clone(),
        });
        let manager = SessionManager::new();
        let mut started = manager
            .begin_chain(target, resolver, ShellOptions::default())
            .await;

        assert_eq!(
            started.events.recv().await.expect("connecting event"),
            SessionEvent::Connecting
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver invocation");
        manager
            .cancel(&started.session_id)
            .await
            .expect("cancel pending chain");
        assert!(matches!(
            started.events.recv().await.expect("cancellation error"),
            SessionEvent::Error {
                code: TransportErrorCode::Cancelled,
                ..
            }
        ));
        assert_eq!(
            started.events.recv().await.expect("closed event"),
            SessionEvent::Closed
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while manager.active_count().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled chain session cleanup");
    }

    #[tokio::test]
    async fn input_and_resize_limits_are_enforced_before_lookup() {
        let manager = SessionManager::new();

        assert_eq!(
            manager.send_input("missing", vec![0; 65_537]).await,
            Err(SessionManagerError::InputTooLarge)
        );
        assert_eq!(
            manager
                .resize(
                    "missing",
                    TerminalSize {
                        columns: 0,
                        ..TerminalSize::default()
                    }
                )
                .await,
            Err(SessionManagerError::InvalidTerminalSize)
        );
    }
}
