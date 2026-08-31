use std::fmt;
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use russh_sftp::client::fs::{File as SftpFile, Metadata};
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::transfer_path::join_remote_transfer_target;

const MAX_IN_MEMORY_FILE_BYTES: u64 = 64 * 1024 * 1024;
const ARTIFACT_PLAN_VERSION: u32 = 1;
const ARTIFACT_OWNER_MAGIC: &str = "netcatty-sftp-upload-owner";
const ARTIFACT_OWNER_MAX_BYTES: u64 = 4 * 1024;
const BACKUP_DELETE_ATTEMPTS: usize = 3;
const STREAM_CHUNK_BYTES: usize = 256 * 1024;
const SFTP_FILE_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SftpEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpMetadata {
    pub kind: SftpEntryKind,
    pub size: u64,
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub gid: Option<u32>,
    pub group: Option<String>,
    pub permissions: Option<u32>,
    pub accessed_at: Option<u32>,
    pub modified_at: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub metadata: SftpMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpError {
    OperationFailed,
    FileTooLarge,
    InvalidUploadPlan,
    DestinationNotRegularFile,
    DestinationChanged,
    RecoveryArtifactConflict,
    UploadSizeMismatch,
    PromotionFailed,
    RecoveryFailed,
    BackupCleanupFailed,
    Cancelled,
    CheckpointMismatch,
    SourceChanged,
}

impl fmt::Display for SftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OperationFailed => "SFTP operation failed",
            Self::FileTooLarge => "SFTP file exceeds the in-memory operation limit",
            Self::InvalidUploadPlan => "SFTP upload plan is invalid",
            Self::DestinationNotRegularFile => "SFTP transfer destination is not a regular file",
            Self::DestinationChanged => "Transfer destination changed while data was in flight",
            Self::RecoveryArtifactConflict => {
                "A transfer recovery path already exists and is not owned by this transfer"
            }
            Self::UploadSizeMismatch => "SFTP staged transfer size verification failed",
            Self::PromotionFailed => "SFTP staged transfer could not be published",
            Self::RecoveryFailed => {
                "Transfer publication failed and the original destination could not be restored"
            }
            Self::BackupCleanupFailed => {
                "Transfer completed but its recoverable backup could not be removed"
            }
            Self::Cancelled => "SFTP transfer was cancelled",
            Self::CheckpointMismatch => "SFTP transfer checkpoint does not match the transfer",
            Self::SourceChanged => "SFTP transfer source changed during transfer",
        })
    }
}

impl std::error::Error for SftpError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpArtifactPlan {
    pub version: u32,
    pub artifact_id: String,
    pub target_path: String,
    pub workspace_path: String,
    pub owner_path: String,
    pub staged_path: String,
    pub backup_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpUploadPlan {
    pub target_path: String,
    pub staged_path: String,
    pub backup_path: String,
    #[serde(default)]
    pub artifacts: Option<SftpArtifactPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpArtifactOwner {
    magic: String,
    version: u32,
    artifact_id: String,
    target_hash: String,
    source_fingerprint: Option<String>,
    total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpUploadOutcome {
    pub replaced_existing: bool,
    pub bytes_written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpStreamUploadOutcome {
    pub upload: SftpUploadOutcome,
    pub checkpoint: SftpTransferCheckpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SftpTransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpTransferCheckpoint {
    pub direction: SftpTransferDirection,
    pub remote_path: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub source_fingerprint: Option<String>,
    pub remote_modified_at: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpTransferProgress {
    pub bytes_transferred: u64,
    pub total_bytes: u64,
}

#[derive(Clone)]
pub struct SftpTransferControl {
    cancellation: CancellationToken,
    paused: watch::Sender<bool>,
    checkpoint: Arc<RwLock<Option<SftpTransferCheckpoint>>>,
}

impl Default for SftpTransferControl {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpTransferControl {
    pub fn new() -> Self {
        let (paused, _) = watch::channel(false);
        Self {
            cancellation: CancellationToken::new(),
            paused,
            checkpoint: Arc::new(RwLock::new(None)),
        }
    }

    pub fn pause(&self) {
        self.paused.send_replace(true);
    }

    pub fn resume(&self) {
        self.paused.send_replace(false);
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    #[must_use]
    pub(crate) fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub(crate) async fn wait_until_resumed(&self) -> Result<(), SftpError> {
        let mut paused = self.paused.subscribe();
        self.wait_until_ready(&mut paused).await
    }

    pub async fn checkpoint(&self) -> Option<SftpTransferCheckpoint> {
        self.checkpoint.read().await.clone()
    }

    async fn wait_until_ready(&self, paused: &mut watch::Receiver<bool>) -> Result<(), SftpError> {
        loop {
            if self.cancellation.is_cancelled() {
                return Err(SftpError::Cancelled);
            }
            if !*paused.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => return Err(SftpError::Cancelled),
                changed = paused.changed() => {
                    if changed.is_err() {
                        return Err(SftpError::Cancelled);
                    }
                }
            }
        }
    }

    async fn record(&self, checkpoint: SftpTransferCheckpoint) {
        *self.checkpoint.write().await = Some(checkpoint);
    }
}

pub struct SftpClient {
    session: SftpSession,
}

impl SftpClient {
    pub(crate) async fn from_stream<S>(stream: S) -> Result<Self, SftpError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let session = SftpSession::new_with_config(
            stream,
            russh_sftp::client::Config {
                max_packet_len: 256 * 1024,
                max_concurrent_writes: 8,
                request_timeout_secs: 30,
            },
        )
        .await
        .map_err(|_| SftpError::OperationFailed)?;
        Ok(Self { session })
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, SftpError> {
        self.session
            .canonicalize(path)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn read_dir(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
        let entries = self
            .session
            .read_dir(path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
        entries
            .map(|entry| {
                let name = entry.file_name();
                let child_path = join_remote_transfer_target(path, &name)
                    .map_err(|_| SftpError::OperationFailed)?;
                Ok(SftpEntry {
                    name,
                    path: child_path,
                    metadata: metadata(entry.metadata()),
                })
            })
            .collect()
    }

    pub async fn metadata(&self, path: &str) -> Result<SftpMetadata, SftpError> {
        self.session
            .symlink_metadata(path)
            .await
            .map(metadata)
            .map_err(|_| SftpError::OperationFailed)
    }

    /// Returns target metadata for a symlink, equivalent to SFTP `STAT`.
    /// `metadata` intentionally remains the no-follow `LSTAT` operation.
    pub async fn followed_metadata(&self, path: &str) -> Result<SftpMetadata, SftpError> {
        self.session
            .metadata(path)
            .await
            .map(metadata)
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn try_exists(&self, path: &str) -> Result<bool, SftpError> {
        self.session
            .try_exists(path)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn set_permissions(&self, path: &str, mode: u32) -> Result<(), SftpError> {
        self.session
            .set_metadata(
                path,
                FileAttributes {
                    permissions: Some(mode),
                    ..FileAttributes::default()
                },
            )
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn set_modified_time(&self, path: &str, modified_at: u32) -> Result<(), SftpError> {
        self.session
            .set_metadata(
                path,
                FileAttributes {
                    mtime: Some(modified_at),
                    ..FileAttributes::default()
                },
            )
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub fn plan_safe_upload(target_path: &str) -> Result<SftpUploadPlan, SftpError> {
        build_upload_plan(target_path)
    }

    pub fn plan_stable_upload(
        target_path: &str,
        stable_identity: &str,
    ) -> Result<SftpUploadPlan, SftpError> {
        if stable_identity.is_empty() || stable_identity.contains('\0') {
            return Err(SftpError::InvalidUploadPlan);
        }
        build_upload_plan_with_seed(target_path, &format!("stable:{stable_identity}"))
    }

    /// Writes to a sibling stage and publishes it with backup-based recovery.
    ///
    /// The returned plan contains every recovery location up front, so callers
    /// can persist it before starting a future resumable transfer.
    pub async fn safe_upload(
        &self,
        plan: &SftpUploadPlan,
        data: &[u8],
    ) -> Result<SftpUploadOutcome, SftpError> {
        self.safe_upload_inner(plan, data, None).await
    }

    /// Replaces an existing regular file only while it still contains the
    /// exact bytes the caller previously read.
    ///
    /// The new body is written into the same-parent staging workspace used by
    /// [`Self::safe_upload`]; the destination is never opened with
    /// `TRUNCATE`. The expected body is checked before staging and immediately
    /// before publication. The destination is then acquired with a
    /// no-overwrite rename into this operation's private backup path, and the
    /// acquired backup is checked again before the staged body may publish.
    /// SFTP v3 has no compare-and-swap primitive, so a mismatching acquired
    /// backup is restored without overwrite or retained for manual recovery.
    pub async fn replace_file_if_unchanged(
        &self,
        target_path: &str,
        expected: &[u8],
        data: &[u8],
    ) -> Result<SftpUploadOutcome, SftpError> {
        if expected.len() as u64 > MAX_IN_MEMORY_FILE_BYTES {
            return Err(SftpError::FileTooLarge);
        }
        let plan = Self::plan_safe_upload(target_path)?;
        self.safe_upload_inner(&plan, data, Some(expected)).await
    }

    async fn safe_upload_inner(
        &self,
        plan: &SftpUploadPlan,
        data: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<SftpUploadOutcome, SftpError> {
        validate_upload_plan(plan)?;
        require_artifact_plan(plan)?;
        if data.len() as u64 > MAX_IN_MEMORY_FILE_BYTES {
            return Err(SftpError::FileTooLarge);
        }

        let initial = self.optional_metadata(&plan.target_path).await?;
        if initial
            .as_ref()
            .is_some_and(|metadata| metadata.kind != SftpEntryKind::File)
        {
            return Err(SftpError::DestinationNotRegularFile);
        }
        if let Some(expected) = expected {
            if initial.is_none() || self.read_file(&plan.target_path).await? != expected {
                return Err(SftpError::DestinationChanged);
            }
        }
        let source_fingerprint = format!("sha256:{}", sha256_hex(data));
        let owner = self
            .prepare_fresh_artifact_upload(plan, data.len() as u64, Some(&source_fingerprint))
            .await?;

        if let Err(error) = self.write_precreated_file(&plan.staged_path, data).await {
            self.discard_owned_fresh_artifacts(plan, &owner).await;
            return Err(error);
        }
        let staged = match self.metadata(&plan.staged_path).await {
            Ok(staged) => staged,
            Err(error) => {
                self.discard_owned_fresh_artifacts(plan, &owner).await;
                return Err(error);
            }
        };
        if staged.kind != SftpEntryKind::File || staged.size != data.len() as u64 {
            self.discard_owned_fresh_artifacts(plan, &owner).await;
            return Err(SftpError::UploadSizeMismatch);
        }

        if let Some(expected) = expected {
            let current_metadata = self.optional_metadata(&plan.target_path).await;
            let current = match current_metadata {
                Ok(metadata) if metadata == initial => self.read_file(&plan.target_path).await,
                Ok(_) => {
                    self.discard_owned_fresh_artifacts(plan, &owner).await;
                    return Err(SftpError::DestinationChanged);
                }
                Err(error) => {
                    self.discard_owned_fresh_artifacts(plan, &owner).await;
                    return Err(error);
                }
            };
            match current {
                Ok(bytes) if bytes == expected => {}
                Ok(_) => {
                    self.discard_owned_fresh_artifacts(plan, &owner).await;
                    return Err(SftpError::DestinationChanged);
                }
                Err(error) => {
                    self.discard_owned_fresh_artifacts(plan, &owner).await;
                    return Err(error);
                }
            }
        }

        let promotion = self
            .promote_staged_upload_inner(plan, data.len() as u64, initial, expected)
            .await;
        if expected.is_some() && promotion.is_err() {
            // Conditional editor plans are generated inside this call and
            // cannot be resumed by the caller. Remove only artifacts whose
            // exact owner is still ours and only when no recovery backup is
            // present. A failed recovery therefore remains untouched.
            self.discard_owned_fresh_artifacts(plan, &owner).await;
        }
        promotion
    }

    pub async fn stream_safe_upload<R>(
        &self,
        plan: &SftpUploadPlan,
        source: &mut R,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
        resume: Option<&SftpTransferCheckpoint>,
        control: &SftpTransferControl,
        progress: Option<&mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<SftpStreamUploadOutcome, SftpError>
    where
        R: AsyncRead + AsyncSeek + Unpin,
    {
        let (checkpoint, initial) = self
            .stage_stream_safe_upload(
                plan,
                source,
                total_bytes,
                source_fingerprint,
                resume,
                control,
                progress,
            )
            .await?;
        if control.is_cancelled() {
            return Err(SftpError::Cancelled);
        }
        let upload = self
            .promote_staged_upload(plan, total_bytes, initial)
            .await?;
        Ok(SftpStreamUploadOutcome { upload, checkpoint })
    }

    pub(crate) async fn stage_stream_safe_upload<R>(
        &self,
        plan: &SftpUploadPlan,
        source: &mut R,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
        resume: Option<&SftpTransferCheckpoint>,
        control: &SftpTransferControl,
        progress: Option<&mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<(SftpTransferCheckpoint, Option<SftpMetadata>), SftpError>
    where
        R: AsyncRead + AsyncSeek + Unpin,
    {
        let transferred =
            validate_upload_checkpoint(&plan.staged_path, total_bytes, source_fingerprint, resume)?;
        validate_upload_plan(plan)?;
        if plan.artifacts.is_none() {
            return Err(if transferred > 0 {
                SftpError::RecoveryArtifactConflict
            } else {
                SftpError::InvalidUploadPlan
            });
        }
        if control.is_cancelled() {
            return Err(SftpError::Cancelled);
        }
        let initial = tokio::select! {
            _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
            result = self.optional_metadata(&plan.target_path) => result?,
        };
        if initial
            .as_ref()
            .is_some_and(|metadata| metadata.kind != SftpEntryKind::File)
        {
            return Err(SftpError::DestinationNotRegularFile);
        }
        let mut discovered_resume = None;
        let precreated_stage = if let Some(checkpoint) = resume {
            self.validate_resume_artifact_upload(plan, total_bytes, source_fingerprint, checkpoint)
                .await?;
            false
        } else {
            match self
                .prepare_fresh_artifact_upload(plan, total_bytes, source_fingerprint)
                .await
            {
                Ok(_) => {
                    control
                        .record(SftpTransferCheckpoint {
                            direction: SftpTransferDirection::Upload,
                            remote_path: plan.staged_path.clone(),
                            bytes_transferred: 0,
                            total_bytes,
                            source_fingerprint: source_fingerprint.map(str::to_owned),
                            remote_modified_at: None,
                        })
                        .await;
                    true
                }
                Err(SftpError::RecoveryArtifactConflict) => {
                    let checkpoint = self
                        .discover_owned_artifact_checkpoint(plan, total_bytes, source_fingerprint)
                        .await?;
                    control.record(checkpoint.clone()).await;
                    discovered_resume = Some(checkpoint);
                    false
                }
                Err(error) => return Err(error),
            }
        };
        let effective_resume = resume.or(discovered_resume.as_ref());
        if control.is_cancelled() {
            return Err(SftpError::Cancelled);
        }
        let checkpoint = match self
            .stream_upload_inner(
                &plan.staged_path,
                source,
                total_bytes,
                source_fingerprint,
                effective_resume,
                control,
                progress,
                precreated_stage,
            )
            .await
        {
            Ok(checkpoint) => checkpoint,
            Err(error) => return Err(error),
        };
        Ok((checkpoint, initial))
    }

    pub(crate) async fn promote_staged_stream_upload(
        &self,
        plan: &SftpUploadPlan,
        expected_size: u64,
        initial: Option<SftpMetadata>,
    ) -> Result<SftpUploadOutcome, SftpError> {
        self.promote_staged_upload(plan, expected_size, initial)
            .await
    }

    pub async fn stream_upload<R>(
        &self,
        remote_path: &str,
        source: &mut R,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
        resume: Option<&SftpTransferCheckpoint>,
        control: &SftpTransferControl,
        progress: Option<&mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<SftpTransferCheckpoint, SftpError>
    where
        R: AsyncRead + AsyncSeek + Unpin,
    {
        self.stream_upload_inner(
            remote_path,
            source,
            total_bytes,
            source_fingerprint,
            resume,
            control,
            progress,
            false,
        )
        .await
    }

    async fn stream_upload_inner<R>(
        &self,
        remote_path: &str,
        source: &mut R,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
        resume: Option<&SftpTransferCheckpoint>,
        control: &SftpTransferControl,
        progress: Option<&mpsc::Sender<SftpTransferProgress>>,
        precreated_stage: bool,
    ) -> Result<SftpTransferCheckpoint, SftpError>
    where
        R: AsyncRead + AsyncSeek + Unpin,
    {
        let mut paused = control.paused.subscribe();
        control.wait_until_ready(&mut paused).await?;
        let transferred =
            validate_upload_checkpoint(remote_path, total_bytes, source_fingerprint, resume)?;
        let mut destination = if transferred == 0 {
            if resume.is_some() || precreated_stage {
                let metadata = tokio::select! {
                    _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                    result = self.metadata(remote_path) => result?,
                };
                if metadata.kind != SftpEntryKind::File || metadata.size != 0 {
                    return Err(SftpError::CheckpointMismatch);
                }
            }
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = self.session.open_with_flags(
                    remote_path,
                    if resume.is_some() || precreated_stage {
                        OpenFlags::WRITE
                    } else {
                        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
                    },
                ) => {
                    result.map_err(|_| if precreated_stage {
                        SftpError::RecoveryArtifactConflict
                    } else {
                        SftpError::OperationFailed
                    })?
                }
            }
        } else {
            let metadata = tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = self.metadata(remote_path) => result?,
            };
            if metadata.kind != SftpEntryKind::File || metadata.size != transferred {
                return Err(SftpError::CheckpointMismatch);
            }
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = self.session.open_with_flags(remote_path, OpenFlags::WRITE) => {
                    result.map_err(|_| SftpError::OperationFailed)?
                }
            }
        };
        let mut checkpoint = SftpTransferCheckpoint {
            direction: SftpTransferDirection::Upload,
            remote_path: remote_path.to_owned(),
            bytes_transferred: transferred,
            total_bytes,
            source_fingerprint: source_fingerprint.map(str::to_owned),
            remote_modified_at: None,
        };
        let transfer_result: Result<SftpTransferCheckpoint, SftpError> = async {
            source
                .seek(std::io::SeekFrom::Start(transferred))
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = destination.seek(std::io::SeekFrom::Start(transferred)) => {
                    result.map_err(|_| SftpError::OperationFailed)?;
                }
            }

            control.record(checkpoint.clone()).await;
            let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
            while checkpoint.bytes_transferred < total_bytes {
                control.wait_until_ready(&mut paused).await?;
                let remaining = total_bytes - checkpoint.bytes_transferred;
                let limit = usize::try_from(remaining.min(STREAM_CHUNK_BYTES as u64)).unwrap();
                let count = tokio::select! {
                    _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                    result = source.read(&mut buffer[..limit]) => {
                        result.map_err(|_| SftpError::OperationFailed)?
                    }
                };
                if count == 0 {
                    return Err(SftpError::SourceChanged);
                }
                tokio::select! {
                    _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                    result = destination.write_all(&buffer[..count]) => {
                        result.map_err(|_| SftpError::OperationFailed)?;
                    }
                }
                checkpoint.bytes_transferred += count as u64;
                control.record(checkpoint.clone()).await;
                publish_progress(progress, &checkpoint);
            }
            let mut extra = [0_u8; 1];
            let extra_count = tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = source.read(&mut extra) => {
                    result.map_err(|_| SftpError::OperationFailed)?
                }
            };
            if extra_count != 0 {
                return Err(SftpError::SourceChanged);
            }
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = destination.flush() => {
                    result.map_err(|_| SftpError::OperationFailed)?;
                }
            }
            Ok(checkpoint)
        }
        .await;
        let mut checkpoint =
            finish_sftp_file(destination, transfer_result, SftpError::OperationFailed).await?;
        if control.is_cancelled() {
            return Err(SftpError::Cancelled);
        }
        let remote = tokio::select! {
            _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
            result = self.metadata(remote_path) => result?,
        };
        if remote.size != total_bytes {
            return Err(SftpError::UploadSizeMismatch);
        }
        checkpoint.remote_modified_at = remote.modified_at;
        control.record(checkpoint.clone()).await;
        Ok(checkpoint)
    }

    pub async fn stream_download<W>(
        &self,
        remote_path: &str,
        destination: &mut W,
        resume: Option<&SftpTransferCheckpoint>,
        control: &SftpTransferControl,
        progress: Option<&mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<SftpTransferCheckpoint, SftpError>
    where
        W: AsyncWrite + AsyncSeek + Unpin,
    {
        let mut paused = control.paused.subscribe();
        control.wait_until_ready(&mut paused).await?;
        let remote = tokio::select! {
            _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
            result = self.followed_metadata(remote_path) => result?,
        };
        if remote.kind != SftpEntryKind::File {
            return Err(SftpError::DestinationNotRegularFile);
        }
        let transferred = validate_download_checkpoint(remote_path, &remote, resume)?;
        let mut source = tokio::select! {
            _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
            result = self.session.open(remote_path) => {
                result.map_err(|_| SftpError::OperationFailed)?
            }
        };
        let mut checkpoint = SftpTransferCheckpoint {
            direction: SftpTransferDirection::Download,
            remote_path: remote_path.to_owned(),
            bytes_transferred: transferred,
            total_bytes: remote.size,
            source_fingerprint: None,
            remote_modified_at: remote.modified_at,
        };
        let transfer_result: Result<(), SftpError> = async {
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = source.seek(std::io::SeekFrom::Start(transferred)) => {
                    result.map_err(|_| SftpError::OperationFailed)?;
                }
            }
            destination
                .seek(std::io::SeekFrom::Start(transferred))
                .await
                .map_err(|_| SftpError::OperationFailed)?;

            control.record(checkpoint.clone()).await;
            let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
            while checkpoint.bytes_transferred < checkpoint.total_bytes {
                control.wait_until_ready(&mut paused).await?;
                let remaining = checkpoint.total_bytes - checkpoint.bytes_transferred;
                let limit = usize::try_from(remaining.min(STREAM_CHUNK_BYTES as u64)).unwrap();
                let count = tokio::select! {
                    _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                    result = source.read(&mut buffer[..limit]) => {
                        result.map_err(|_| SftpError::OperationFailed)?
                    }
                };
                if count == 0 {
                    return Err(SftpError::SourceChanged);
                }
                tokio::select! {
                    _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                    result = destination.write_all(&buffer[..count]) => {
                        result.map_err(|_| SftpError::OperationFailed)?;
                    }
                }
                checkpoint.bytes_transferred += count as u64;
                control.record(checkpoint.clone()).await;
                publish_progress(progress, &checkpoint);
            }
            tokio::select! {
                _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
                result = destination.flush() => {
                    result.map_err(|_| SftpError::OperationFailed)?;
                }
            }
            Ok(())
        }
        .await;
        finish_sftp_file(source, transfer_result, SftpError::OperationFailed).await?;
        let final_remote = tokio::select! {
            _ = control.cancellation.cancelled() => return Err(SftpError::Cancelled),
            result = self.followed_metadata(remote_path) => result?,
        };
        if final_remote.kind != SftpEntryKind::File
            || final_remote.size != remote.size
            || final_remote.modified_at != remote.modified_at
        {
            return Err(SftpError::SourceChanged);
        }
        control.record(checkpoint.clone()).await;
        Ok(checkpoint)
    }

    pub async fn create_dir(&self, path: &str) -> Result<(), SftpError> {
        self.session
            .create_dir(path)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn remove_file(&self, path: &str) -> Result<(), SftpError> {
        self.session
            .remove_file(path)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn remove_dir(&self, path: &str) -> Result<(), SftpError> {
        self.session
            .remove_dir(path)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn rename(&self, source: &str, destination: &str) -> Result<(), SftpError> {
        self.session
            .rename(source, destination)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    /// Uses the SFTP v3 `SSH_FXP_RENAME` no-replace contract.
    ///
    /// Do not replace this with `posix-rename@openssh.com`: that extension has
    /// overwrite semantics and would let a destination created during the
    /// publication window be destroyed.
    async fn rename_no_overwrite(&self, source: &str, destination: &str) -> Result<(), SftpError> {
        self.session
            .rename(source, destination)
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, SftpError> {
        let mut file = self
            .session
            .open(path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
        let read_result: Result<Vec<u8>, SftpError> = async {
            if file
                .metadata()
                .await
                .map_err(|_| SftpError::OperationFailed)?
                .len()
                > MAX_IN_MEMORY_FILE_BYTES
            {
                return Err(SftpError::FileTooLarge);
            }
            let mut data = Vec::new();
            (&mut file)
                .take(MAX_IN_MEMORY_FILE_BYTES + 1)
                .read_to_end(&mut data)
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            if data.len() as u64 > MAX_IN_MEMORY_FILE_BYTES {
                return Err(SftpError::FileTooLarge);
            }
            Ok(data)
        }
        .await;
        finish_sftp_file(file, read_result, SftpError::OperationFailed).await
    }

    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), SftpError> {
        if data.len() as u64 > MAX_IN_MEMORY_FILE_BYTES {
            return Err(SftpError::FileTooLarge);
        }
        let mut file = self
            .session
            .create(path)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
        let write_result = async {
            file.write_all(data)
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            file.flush().await.map_err(|_| SftpError::OperationFailed)
        }
        .await;
        finish_sftp_file(file, write_result, SftpError::OperationFailed).await
    }

    pub async fn close(&self) -> Result<(), SftpError> {
        self.session
            .close()
            .await
            .map_err(|_| SftpError::OperationFailed)
    }

    async fn optional_metadata(&self, path: &str) -> Result<Option<SftpMetadata>, SftpError> {
        if !self.try_exists(path).await? {
            return Ok(None);
        }
        self.metadata(path).await.map(Some)
    }

    async fn prepare_fresh_artifact_upload(
        &self,
        plan: &SftpUploadPlan,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
    ) -> Result<SftpArtifactOwner, SftpError> {
        let artifacts = require_artifact_plan(plan)?;
        let owner = artifact_owner(plan, total_bytes, source_fingerprint)?;
        let encoded = encode_artifact_owner(&owner)?;
        self.session
            .create_dir(&artifacts.workspace_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if let Err(error) = self
            .write_exclusive_file(&artifacts.owner_path, &encoded)
            .await
        {
            self.remove_fresh_owner_and_workspace_if_exact(plan, &owner)
                .await;
            return Err(error);
        }

        let staged = match self
            .session
            .open_with_flags(
                &artifacts.staged_path,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            )
            .await
        {
            Ok(staged) => staged,
            Err(_) => {
                self.remove_fresh_owner_and_workspace_if_exact(plan, &owner)
                    .await;
                return Err(SftpError::RecoveryArtifactConflict);
            }
        };
        if finish_sftp_file(staged, Ok(()), SftpError::OperationFailed)
            .await
            .is_err()
        {
            let _ = self.remove_file(&artifacts.staged_path).await;
            self.remove_fresh_owner_and_workspace_if_exact(plan, &owner)
                .await;
            return Err(SftpError::OperationFailed);
        }
        Ok(owner)
    }

    async fn remove_fresh_owner_and_workspace_if_exact(
        &self,
        plan: &SftpUploadPlan,
        expected_owner: &SftpArtifactOwner,
    ) {
        let Ok(artifacts) = require_artifact_plan(plan) else {
            return;
        };
        if self
            .try_exists(&artifacts.backup_path)
            .await
            .unwrap_or(true)
        {
            return;
        }
        if self.read_artifact_owner(artifacts).await.as_ref() != Ok(expected_owner) {
            return;
        }
        if self.remove_file(&artifacts.owner_path).await.is_ok() {
            let _ = self.remove_dir(&artifacts.workspace_path).await;
        }
    }

    async fn discard_owned_fresh_artifacts(
        &self,
        plan: &SftpUploadPlan,
        expected_owner: &SftpArtifactOwner,
    ) {
        let Ok(artifacts) = require_artifact_plan(plan) else {
            return;
        };
        if self
            .try_exists(&artifacts.backup_path)
            .await
            .unwrap_or(true)
            || self.read_artifact_owner(artifacts).await.as_ref() != Ok(expected_owner)
        {
            return;
        }
        let staged = self.metadata(&artifacts.staged_path).await;
        if staged
            .as_ref()
            .is_ok_and(|metadata| metadata.kind == SftpEntryKind::File)
        {
            let _ = self.remove_file(&artifacts.staged_path).await;
        }
        self.remove_fresh_owner_and_workspace_if_exact(plan, expected_owner)
            .await;
    }

    async fn validate_resume_artifact_upload(
        &self,
        plan: &SftpUploadPlan,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
        checkpoint: &SftpTransferCheckpoint,
    ) -> Result<(), SftpError> {
        let transferred = validate_upload_checkpoint(
            &plan.staged_path,
            total_bytes,
            source_fingerprint,
            Some(checkpoint),
        )?;
        let artifacts = require_artifact_plan(plan)?;
        let workspace = self
            .metadata(&artifacts.workspace_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if workspace.kind != SftpEntryKind::Directory {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let expected = artifact_owner(plan, total_bytes, source_fingerprint)?;
        if self.read_artifact_owner(artifacts).await? != expected {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let staged = self
            .metadata(&artifacts.staged_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if staged.kind != SftpEntryKind::File || staged.size != transferred {
            return Err(SftpError::CheckpointMismatch);
        }
        if self
            .try_exists(&artifacts.backup_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?
        {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        Ok(())
    }

    async fn discover_owned_artifact_checkpoint(
        &self,
        plan: &SftpUploadPlan,
        total_bytes: u64,
        source_fingerprint: Option<&str>,
    ) -> Result<SftpTransferCheckpoint, SftpError> {
        let artifacts = require_artifact_plan(plan)?;
        let workspace = self
            .metadata(&artifacts.workspace_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if workspace.kind != SftpEntryKind::Directory {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let expected_owner = artifact_owner(plan, total_bytes, source_fingerprint)?;
        let actual_owner = self.read_artifact_owner(artifacts).await?;
        if self
            .try_exists(&artifacts.backup_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?
        {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let staged = self
            .metadata(&artifacts.staged_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        checkpoint_for_owned_stage(
            plan,
            total_bytes,
            source_fingerprint,
            &expected_owner,
            &actual_owner,
            &staged,
        )
    }

    async fn read_artifact_owner(
        &self,
        artifacts: &SftpArtifactPlan,
    ) -> Result<SftpArtifactOwner, SftpError> {
        let metadata = self
            .metadata(&artifacts.owner_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if metadata.kind != SftpEntryKind::File || metadata.size > ARTIFACT_OWNER_MAX_BYTES {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let mut file = self
            .session
            .open(&artifacts.owner_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        let read_result: Result<Vec<u8>, SftpError> = async {
            let mut encoded = Vec::new();
            (&mut file)
                .take(ARTIFACT_OWNER_MAX_BYTES + 1)
                .read_to_end(&mut encoded)
                .await
                .map_err(|_| SftpError::RecoveryArtifactConflict)?;
            if encoded.len() as u64 > ARTIFACT_OWNER_MAX_BYTES {
                return Err(SftpError::RecoveryArtifactConflict);
            }
            Ok(encoded)
        }
        .await;
        let encoded =
            finish_sftp_file(file, read_result, SftpError::RecoveryArtifactConflict).await?;
        serde_json::from_slice(&encoded).map_err(|_| SftpError::RecoveryArtifactConflict)
    }

    async fn validate_artifact_owner_for_commit(
        &self,
        plan: &SftpUploadPlan,
        expected_size: u64,
    ) -> Result<SftpArtifactOwner, SftpError> {
        let artifacts = require_artifact_plan(plan)?;
        let workspace = self
            .metadata(&artifacts.workspace_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        if workspace.kind != SftpEntryKind::Directory {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let owner = self.read_artifact_owner(artifacts).await?;
        if !artifact_owner_matches_plan(&owner, plan, expected_size) {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        Ok(owner)
    }

    async fn write_exclusive_file(&self, path: &str, data: &[u8]) -> Result<(), SftpError> {
        let mut file = self
            .session
            .open_with_flags(
                path,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            )
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        let write_result = async {
            file.write_all(data)
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            file.flush().await.map_err(|_| SftpError::OperationFailed)
        }
        .await;
        finish_sftp_file(file, write_result, SftpError::OperationFailed).await
    }

    async fn write_precreated_file(&self, path: &str, data: &[u8]) -> Result<(), SftpError> {
        let metadata = self.metadata(path).await?;
        if metadata.kind != SftpEntryKind::File || metadata.size != 0 {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let mut file = self
            .session
            .open_with_flags(path, OpenFlags::WRITE)
            .await
            .map_err(|_| SftpError::OperationFailed)?;
        let write_result = async {
            file.write_all(data)
                .await
                .map_err(|_| SftpError::OperationFailed)?;
            file.flush().await.map_err(|_| SftpError::OperationFailed)
        }
        .await;
        finish_sftp_file(file, write_result, SftpError::OperationFailed).await
    }

    async fn cleanup_committed_artifact_workspace(
        &self,
        plan: &SftpUploadPlan,
        expected_size: u64,
    ) -> Result<(), SftpError> {
        let artifacts = require_artifact_plan(plan)?;
        let owner = self
            .validate_artifact_owner_for_commit(plan, expected_size)
            .await?;
        if self.try_exists(&artifacts.staged_path).await?
            || self.try_exists(&artifacts.backup_path).await?
        {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        let (_, owner_name) = split_remote_path(&artifacts.owner_path);
        let entries = self
            .session
            .read_dir(&artifacts.workspace_path)
            .await
            .map_err(|_| SftpError::RecoveryArtifactConflict)?;
        let mut owner_entries = 0_usize;
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            if name != owner_name {
                return Err(SftpError::RecoveryArtifactConflict);
            }
            owner_entries += 1;
        }
        if owner_entries != 1 {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        self.remove_file(&artifacts.owner_path)
            .await
            .map_err(|_| SftpError::BackupCleanupFailed)?;
        if self.remove_dir(&artifacts.workspace_path).await.is_err() {
            if let Ok(encoded) = encode_artifact_owner(&owner) {
                let _ = self
                    .write_exclusive_file(&artifacts.owner_path, &encoded)
                    .await;
            }
            return Err(SftpError::BackupCleanupFailed);
        }
        Ok(())
    }

    async fn promote_staged_upload(
        &self,
        plan: &SftpUploadPlan,
        expected_size: u64,
        initial: Option<SftpMetadata>,
    ) -> Result<SftpUploadOutcome, SftpError> {
        self.promote_staged_upload_inner(plan, expected_size, initial, None)
            .await
    }

    async fn promote_staged_upload_inner(
        &self,
        plan: &SftpUploadPlan,
        expected_size: u64,
        initial: Option<SftpMetadata>,
        conditional_expected: Option<&[u8]>,
    ) -> Result<SftpUploadOutcome, SftpError> {
        self.validate_artifact_owner_for_commit(plan, expected_size)
            .await?;
        let staged = self.metadata(&plan.staged_path).await?;
        if staged.kind != SftpEntryKind::File || staged.size != expected_size {
            return Err(SftpError::UploadSizeMismatch);
        }
        if self.try_exists(&plan.backup_path).await? {
            return Err(SftpError::RecoveryArtifactConflict);
        }
        if let Some(mode) = initial.as_ref().and_then(|metadata| metadata.permissions)
            && self.set_permissions(&plan.staged_path, mode).await.is_err()
        {
            return Err(SftpError::OperationFailed);
        }
        if self.optional_metadata(&plan.target_path).await? != initial {
            return Err(SftpError::DestinationChanged);
        }
        if conditional_expected.is_some() && initial.is_none() {
            return Err(SftpError::DestinationChanged);
        }

        let replaced_existing = initial.is_some();
        if replaced_existing
            && self
                .rename_no_overwrite(&plan.target_path, &plan.backup_path)
                .await
                .is_err()
        {
            return Err(SftpError::PromotionFailed);
        }
        if let (Some(expected), Some(initial)) = (conditional_expected, initial.as_ref()) {
            match self.backup_matches_expected(plan, initial, expected).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(self
                        .restore_conditional_backup(plan, SftpError::DestinationChanged)
                        .await);
                }
                Err(error) => {
                    return Err(self.restore_conditional_backup(plan, error).await);
                }
            }
        }
        if self
            .rename_no_overwrite(&plan.staged_path, &plan.target_path)
            .await
            .is_err()
        {
            if replaced_existing {
                let target_exists = self.try_exists(&plan.target_path).await;
                let backup = self.optional_metadata(&plan.backup_path).await;
                if !can_restore_backup_after_failed_promotion(
                    target_exists,
                    backup,
                    initial.as_ref(),
                ) || self
                    .rename_no_overwrite(&plan.backup_path, &plan.target_path)
                    .await
                    .is_err()
                {
                    return Err(SftpError::RecoveryFailed);
                }
            }
            return Err(SftpError::PromotionFailed);
        }
        if replaced_existing {
            if let (Some(expected), Some(initial)) = (conditional_expected, initial.as_ref())
                && self.backup_matches_expected(plan, initial, expected).await != Ok(true)
            {
                // Publication is already visible, but the backup is no longer
                // proven to be the expected old version. Retain it (and its
                // owner record) rather than deleting unknown concurrent data.
                return Err(SftpError::BackupCleanupFailed);
            }
            self.remove_backup_with_retry(plan).await?;
        }
        self.cleanup_committed_artifact_workspace(plan, expected_size)
            .await?;
        Ok(SftpUploadOutcome {
            replaced_existing,
            bytes_written: expected_size,
        })
    }

    async fn backup_matches_expected(
        &self,
        plan: &SftpUploadPlan,
        initial: &SftpMetadata,
        expected: &[u8],
    ) -> Result<bool, SftpError> {
        if self.optional_metadata(&plan.backup_path).await?.as_ref() != Some(initial) {
            return Ok(false);
        }
        self.read_file(&plan.backup_path)
            .await
            .map(|body| body == expected)
    }

    async fn restore_conditional_backup(
        &self,
        plan: &SftpUploadPlan,
        restored_error: SftpError,
    ) -> SftpError {
        if self
            .rename_no_overwrite(&plan.backup_path, &plan.target_path)
            .await
            .is_ok()
        {
            restored_error
        } else {
            // No-overwrite rename is the only safe recovery attempt: if a
            // newer target appeared, both it and our acquired backup survive.
            SftpError::RecoveryFailed
        }
    }

    async fn remove_backup_with_retry(&self, plan: &SftpUploadPlan) -> Result<(), SftpError> {
        for attempt in 1..=BACKUP_DELETE_ATTEMPTS {
            if self.remove_file(&plan.backup_path).await.is_ok() {
                return Ok(());
            }
            if attempt < BACKUP_DELETE_ATTEMPTS {
                sleep(Duration::from_millis((attempt * 25) as u64)).await;
            }
        }
        Err(SftpError::BackupCleanupFailed)
    }
}

/// Completes an operation that owns a remote file handle and then explicitly
/// closes it. `russh-sftp`'s `Drop` path sends a best-effort CLOSE without
/// decrementing its negotiated `limits@openssh.com` handle count, so it cannot
/// be the normal cleanup path for an opened file.
async fn finish_sftp_file<T>(
    file: SftpFile,
    operation: Result<T, SftpError>,
    close_error: SftpError,
) -> Result<T, SftpError> {
    let close_result = match timeout(SFTP_FILE_CLOSE_TIMEOUT, file.close()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(close_error),
    };
    match operation {
        Err(error) => {
            let _ = close_result;
            Err(error)
        }
        Ok(value) => {
            close_result?;
            Ok(value)
        }
    }
}

fn can_restore_backup_after_failed_promotion(
    target_exists: Result<bool, SftpError>,
    backup: Result<Option<SftpMetadata>, SftpError>,
    initial: Option<&SftpMetadata>,
) -> bool {
    matches!(target_exists, Ok(false)) && backup.is_ok_and(|backup| backup.as_ref() == initial)
}

fn publish_progress(
    sender: Option<&mpsc::Sender<SftpTransferProgress>>,
    checkpoint: &SftpTransferCheckpoint,
) {
    if let Some(sender) = sender {
        let _ = sender.try_send(SftpTransferProgress {
            bytes_transferred: checkpoint.bytes_transferred,
            total_bytes: checkpoint.total_bytes,
        });
    }
}

fn validate_upload_checkpoint(
    remote_path: &str,
    total_bytes: u64,
    source_fingerprint: Option<&str>,
    checkpoint: Option<&SftpTransferCheckpoint>,
) -> Result<u64, SftpError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(0);
    };
    if checkpoint.direction != SftpTransferDirection::Upload
        || checkpoint.remote_path != remote_path
        || checkpoint.total_bytes != total_bytes
        || checkpoint.bytes_transferred > total_bytes
        || checkpoint.source_fingerprint.as_deref() != source_fingerprint
    {
        return Err(SftpError::CheckpointMismatch);
    }
    Ok(checkpoint.bytes_transferred)
}

fn validate_download_checkpoint(
    remote_path: &str,
    remote: &SftpMetadata,
    checkpoint: Option<&SftpTransferCheckpoint>,
) -> Result<u64, SftpError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(0);
    };
    if checkpoint.direction != SftpTransferDirection::Download
        || checkpoint.remote_path != remote_path
        || checkpoint.total_bytes != remote.size
        || checkpoint.bytes_transferred > remote.size
        || checkpoint.remote_modified_at != remote.modified_at
    {
        return Err(SftpError::CheckpointMismatch);
    }
    Ok(checkpoint.bytes_transferred)
}

fn require_artifact_plan(plan: &SftpUploadPlan) -> Result<&SftpArtifactPlan, SftpError> {
    plan.artifacts
        .as_ref()
        .ok_or(SftpError::RecoveryArtifactConflict)
}

fn artifact_owner(
    plan: &SftpUploadPlan,
    total_bytes: u64,
    source_fingerprint: Option<&str>,
) -> Result<SftpArtifactOwner, SftpError> {
    let artifacts = require_artifact_plan(plan)?;
    Ok(SftpArtifactOwner {
        magic: ARTIFACT_OWNER_MAGIC.to_owned(),
        version: artifacts.version,
        artifact_id: artifacts.artifact_id.clone(),
        target_hash: sha256_hex(plan.target_path.as_bytes()),
        source_fingerprint: source_fingerprint.map(str::to_owned),
        total_bytes,
    })
}

fn artifact_owner_matches_plan(
    owner: &SftpArtifactOwner,
    plan: &SftpUploadPlan,
    total_bytes: u64,
) -> bool {
    let Ok(artifacts) = require_artifact_plan(plan) else {
        return false;
    };
    owner.magic == ARTIFACT_OWNER_MAGIC
        && owner.version == artifacts.version
        && owner.artifact_id == artifacts.artifact_id
        && owner.target_hash == sha256_hex(plan.target_path.as_bytes())
        && owner.total_bytes == total_bytes
}

fn checkpoint_for_owned_stage(
    plan: &SftpUploadPlan,
    total_bytes: u64,
    source_fingerprint: Option<&str>,
    expected_owner: &SftpArtifactOwner,
    actual_owner: &SftpArtifactOwner,
    staged: &SftpMetadata,
) -> Result<SftpTransferCheckpoint, SftpError> {
    if actual_owner != expected_owner
        || staged.kind != SftpEntryKind::File
        || staged.size > total_bytes
    {
        return Err(SftpError::RecoveryArtifactConflict);
    }
    Ok(SftpTransferCheckpoint {
        direction: SftpTransferDirection::Upload,
        remote_path: plan.staged_path.clone(),
        bytes_transferred: staged.size,
        total_bytes,
        source_fingerprint: source_fingerprint.map(str::to_owned),
        remote_modified_at: staged.modified_at,
    })
}

fn encode_artifact_owner(owner: &SftpArtifactOwner) -> Result<Vec<u8>, SftpError> {
    let encoded = serde_json::to_vec(owner).map_err(|_| SftpError::InvalidUploadPlan)?;
    if encoded.len() as u64 > ARTIFACT_OWNER_MAX_BYTES {
        return Err(SftpError::InvalidUploadPlan);
    }
    Ok(encoded)
}

fn build_upload_plan(target_path: &str) -> Result<SftpUploadPlan, SftpError> {
    build_artifact_upload_plan(target_path, &Uuid::new_v4().simple().to_string())
}

fn build_upload_plan_with_seed(
    target_path: &str,
    stage_seed: &str,
) -> Result<SftpUploadPlan, SftpError> {
    let artifact_id = digest_prefix(
        &format!("netcatty-stable-upload-v1\0{target_path}\0{stage_seed}"),
        32,
    );
    build_artifact_upload_plan(target_path, &artifact_id)
}

fn build_artifact_upload_plan(
    target_path: &str,
    artifact_id: &str,
) -> Result<SftpUploadPlan, SftpError> {
    if target_path.trim().is_empty()
        || target_path.contains('\0')
        || target_path.ends_with(['/', '\\'])
        || !valid_artifact_id(artifact_id)
    {
        return Err(SftpError::InvalidUploadPlan);
    }
    let (directory, base_name) = split_remote_path(target_path);
    if base_name.is_empty() {
        return Err(SftpError::InvalidUploadPlan);
    }
    let workspace_path = format!("{directory}.netcatty-xfer-v1-{artifact_id}");
    let child_separator = if directory.ends_with('\\') { '\\' } else { '/' };
    let owner_path = format!("{workspace_path}{child_separator}owner.json");
    let staged_path = format!("{workspace_path}{child_separator}staged.part");
    let backup_path = format!("{workspace_path}{child_separator}backup.bak");
    let artifacts = SftpArtifactPlan {
        version: ARTIFACT_PLAN_VERSION,
        artifact_id: artifact_id.to_owned(),
        target_path: target_path.to_owned(),
        workspace_path,
        owner_path,
        staged_path: staged_path.clone(),
        backup_path: backup_path.clone(),
    };
    Ok(SftpUploadPlan {
        target_path: target_path.to_owned(),
        staged_path,
        backup_path,
        artifacts: Some(artifacts),
    })
}

fn validate_upload_plan(plan: &SftpUploadPlan) -> Result<(), SftpError> {
    if plan.target_path.trim().is_empty()
        || plan.target_path.contains('\0')
        || plan.staged_path.contains('\0')
        || plan.backup_path.contains('\0')
        || plan.target_path.ends_with(['/', '\\'])
        || plan.staged_path == plan.target_path
        || plan.backup_path == plan.target_path
        || plan.staged_path == plan.backup_path
    {
        return Err(SftpError::InvalidUploadPlan);
    }
    if let Some(artifacts) = &plan.artifacts {
        if artifacts.version != ARTIFACT_PLAN_VERSION
            || !valid_artifact_id(&artifacts.artifact_id)
            || artifacts.target_path != plan.target_path
            || artifacts.staged_path != plan.staged_path
            || artifacts.backup_path != plan.backup_path
        {
            return Err(SftpError::InvalidUploadPlan);
        }
        let expected = build_artifact_upload_plan(&plan.target_path, &artifacts.artifact_id)?;
        if expected != *plan {
            return Err(SftpError::InvalidUploadPlan);
        }
        return Ok(());
    }

    // Legacy plans remain deserializable so callers can reject unsafe persisted
    // checkpoints deliberately. They are never granted artifact ownership.
    let (target_directory, _) = split_remote_path(&plan.target_path);
    let (stage_directory, stage_name) = split_remote_path(&plan.staged_path);
    let (backup_directory, backup_name) = split_remote_path(&plan.backup_path);
    if target_directory != stage_directory
        || target_directory != backup_directory
        || !stage_name.starts_with(".netcatty-upload-")
        || !stage_name.ends_with(".part")
        || !backup_name.starts_with(".netcatty-backup-")
        || !backup_name.ends_with(".bak")
    {
        return Err(SftpError::InvalidUploadPlan);
    }
    Ok(())
}

fn valid_artifact_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn split_remote_path(path: &str) -> (&str, &str) {
    let separator = path.rfind(['/', '\\']);
    match separator {
        Some(index) => (&path[..=index], &path[index + 1..]),
        None => ("", path),
    }
}

fn digest_prefix(value: &str, length: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut result = String::with_capacity(length);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
        if result.len() >= length {
            result.truncate(length);
            break;
        }
    }
    result
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn metadata(value: Metadata) -> SftpMetadata {
    let kind = if value.is_dir() {
        SftpEntryKind::Directory
    } else if value.is_regular() {
        SftpEntryKind::File
    } else if value.is_symlink() {
        SftpEntryKind::Symlink
    } else {
        SftpEntryKind::Other
    };
    SftpMetadata {
        kind,
        size: value.len(),
        uid: value.uid,
        user: value.user,
        gid: value.gid,
        group: value.group,
        permissions: value.permissions,
        accessed_at: value.atime,
        modified_at: value.mtime,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ARTIFACT_OWNER_MAX_BYTES, SftpArtifactOwner, SftpClient, SftpEntryKind, SftpError,
        SftpMetadata, SftpTransferCheckpoint, SftpTransferDirection, SftpUploadPlan,
        artifact_owner, artifact_owner_matches_plan, build_upload_plan,
        can_restore_backup_after_failed_promotion, checkpoint_for_owned_stage,
        encode_artifact_owner, metadata, split_remote_path, validate_upload_checkpoint,
        validate_upload_plan,
    };
    use russh_sftp::protocol::FileAttributes;

    #[test]
    fn metadata_preserves_wire_fields_and_file_kind() {
        let mut source = FileAttributes {
            size: Some(42),
            uid: Some(1000),
            permissions: Some(0o100644),
            ..FileAttributes::default()
        };
        source.set_regular(true);
        let result = metadata(source);
        assert_eq!(result.kind, SftpEntryKind::File);
        assert_eq!(result.size, 42);
        assert_eq!(result.uid, Some(1000));
    }

    #[test]
    fn failed_promotion_never_restores_backup_over_a_new_target() {
        let initial = SftpMetadata {
            kind: SftpEntryKind::File,
            size: 42,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: Some(0o100600),
            accessed_at: None,
            modified_at: Some(7),
        };

        assert!(!can_restore_backup_after_failed_promotion(
            Ok(true),
            Ok(Some(initial.clone())),
            Some(&initial),
        ));
        assert!(!can_restore_backup_after_failed_promotion(
            Err(SftpError::OperationFailed),
            Ok(Some(initial.clone())),
            Some(&initial),
        ));
        assert!(!can_restore_backup_after_failed_promotion(
            Ok(false),
            Err(SftpError::OperationFailed),
            Some(&initial),
        ));
        assert!(can_restore_backup_after_failed_promotion(
            Ok(false),
            Ok(Some(initial.clone())),
            Some(&initial),
        ));
    }

    #[test]
    fn safe_upload_paths_are_sibling_bounded_and_utf8_safe() {
        let target = format!("/remote/{}.txt", "文件".repeat(100));
        let plan = build_upload_plan(&target).expect("upload plan");
        let artifacts = plan.artifacts.as_ref().expect("artifact plan");
        assert!(
            artifacts
                .workspace_path
                .starts_with("/remote/.netcatty-xfer-v1-")
        );
        assert_eq!(
            plan.staged_path,
            format!("{}/staged.part", artifacts.workspace_path)
        );
        assert_eq!(
            plan.backup_path,
            format!("{}/backup.bak", artifacts.workspace_path)
        );
        assert!(plan.staged_path.rsplit('/').next().unwrap().len() <= 255);
        assert!(plan.backup_path.rsplit('/').next().unwrap().len() <= 255);
        validate_upload_plan(&plan).expect("valid plan");
    }

    #[test]
    fn safe_upload_plan_rejects_broad_or_unrelated_recovery_paths() {
        assert_eq!(
            build_upload_plan("/remote/").unwrap_err(),
            SftpError::InvalidUploadPlan
        );
        let mut plan = build_upload_plan("/remote/file.txt").expect("upload plan");
        plan.backup_path = "/unrelated/backup.bak".to_owned();
        assert_eq!(
            validate_upload_plan(&plan),
            Err(SftpError::InvalidUploadPlan)
        );
    }

    #[test]
    fn stable_upload_plan_is_repeatable_and_identity_scoped() {
        let target = "/remote/file.txt";
        let first = SftpClient::plan_stable_upload(target, "entry-a").expect("stable plan");
        let repeated = SftpClient::plan_stable_upload(target, "entry-a").expect("stable plan");
        let other = SftpClient::plan_stable_upload(target, "entry-b").expect("stable plan");

        assert_eq!(first, repeated);
        assert_ne!(first.staged_path, other.staged_path);
        assert_eq!(first.target_path, other.target_path);
        assert_ne!(first.backup_path, other.backup_path);
        assert_ne!(first.artifacts, other.artifacts);
        validate_upload_plan(&first).expect("valid stable plan");
        validate_upload_plan(&other).expect("valid identity-scoped plan");
    }

    #[test]
    fn stable_upload_recovery_paths_remain_target_siblings() {
        let targets = [
            "file.txt",
            "/remote/nested/file.txt",
            r"C:\remote\nested\file.txt",
        ];
        let identities = [
            "entry",
            "../../untrusted/identity",
            r"..\untrusted\identity",
        ];

        for target in targets {
            let (target_directory, _) = split_remote_path(target);
            for identity in identities {
                let plan = SftpClient::plan_stable_upload(target, identity).expect("stable plan");
                let artifacts = plan.artifacts.as_ref().expect("artifact plan");
                let (workspace_directory, _) = split_remote_path(&artifacts.workspace_path);
                let expected_artifact_directory = if artifacts.workspace_path.contains('\\') {
                    format!("{}\\", artifacts.workspace_path)
                } else {
                    format!("{}/", artifacts.workspace_path)
                };
                let (staged_directory, _) = split_remote_path(&artifacts.staged_path);
                let (backup_directory, _) = split_remote_path(&artifacts.backup_path);

                assert_eq!(workspace_directory, target_directory);
                assert_eq!(staged_directory, expected_artifact_directory);
                assert_eq!(backup_directory, expected_artifact_directory);
                assert_ne!(plan.staged_path, target);
                assert_ne!(plan.backup_path, target);
                validate_upload_plan(&plan).expect("valid sibling-bounded plan");
            }
        }
    }

    #[test]
    fn stable_upload_plan_rejects_unsafe_identity_and_target_boundaries() {
        for identity in ["", "\0", "entry\0identity"] {
            assert_eq!(
                SftpClient::plan_stable_upload("/remote/file.txt", identity),
                Err(SftpError::InvalidUploadPlan),
                "identity {identity:?}"
            );
        }

        for target in [
            "",
            " \t\r\n",
            "/",
            r"\",
            "/remote/",
            r"C:\remote\",
            "/remote/file\0.txt",
        ] {
            assert_eq!(
                SftpClient::plan_stable_upload(target, "entry"),
                Err(SftpError::InvalidUploadPlan),
                "target {target:?}"
            );
        }
    }

    #[test]
    fn fresh_upload_plan_uses_uuid_v4_and_unique_owned_workspaces() {
        let first = SftpClient::plan_safe_upload("/remote/file.txt").expect("first plan");
        let second = SftpClient::plan_safe_upload("/remote/file.txt").expect("second plan");
        let first_artifacts = first.artifacts.as_ref().expect("first artifacts");
        let second_artifacts = second.artifacts.as_ref().expect("second artifacts");

        assert_eq!(first_artifacts.artifact_id.len(), 32);
        assert_eq!(
            uuid::Uuid::parse_str(&first_artifacts.artifact_id)
                .expect("uuid")
                .get_version_num(),
            4
        );
        assert_ne!(first_artifacts.artifact_id, second_artifacts.artifact_id);
        assert_ne!(
            first_artifacts.workspace_path,
            second_artifacts.workspace_path
        );
    }

    #[test]
    fn artifact_plan_validation_rejects_path_or_identity_tampering() {
        let original =
            SftpClient::plan_stable_upload("/remote/file.txt", "entry").expect("stable plan");

        let mut changed_workspace = original.clone();
        changed_workspace
            .artifacts
            .as_mut()
            .expect("artifacts")
            .workspace_path =
            "/remote/.netcatty-xfer-v1-00000000000000000000000000000000".to_owned();
        assert_eq!(
            validate_upload_plan(&changed_workspace),
            Err(SftpError::InvalidUploadPlan)
        );

        let mut changed_owner = original.clone();
        changed_owner
            .artifacts
            .as_mut()
            .expect("artifacts")
            .owner_path = "/remote/unowned/owner.json".to_owned();
        assert_eq!(
            validate_upload_plan(&changed_owner),
            Err(SftpError::InvalidUploadPlan)
        );

        let mut changed_id = original;
        changed_id
            .artifacts
            .as_mut()
            .expect("artifacts")
            .artifact_id = "ABCDEF0123456789ABCDEF0123456789".to_owned();
        assert_eq!(
            validate_upload_plan(&changed_id),
            Err(SftpError::InvalidUploadPlan)
        );
    }

    #[test]
    fn legacy_upload_plan_deserializes_without_gaining_ownership() {
        let encoded = serde_json::json!({
            "targetPath": "/remote/file.txt",
            "stagedPath": "/remote/.netcatty-upload-deadbeef-file.txt.part",
            "backupPath": "/remote/.netcatty-backup-deadbeefdeadbeef-file.txt.bak"
        });
        let plan: SftpUploadPlan = serde_json::from_value(encoded).expect("legacy plan");
        assert!(plan.artifacts.is_none());
        validate_upload_plan(&plan).expect("legacy shape remains recognizable");
    }

    #[test]
    fn owner_marker_binds_plan_source_and_size_and_rejects_extensions() {
        let plan =
            SftpClient::plan_stable_upload("/remote/file.txt", "entry").expect("stable plan");
        let owner = artifact_owner(&plan, 42, Some("source-v1")).expect("owner");
        let encoded = encode_artifact_owner(&owner).expect("encoded owner");
        assert!(encoded.len() as u64 <= ARTIFACT_OWNER_MAX_BYTES);
        assert!(artifact_owner_matches_plan(&owner, &plan, 42));
        assert!(!artifact_owner_matches_plan(&owner, &plan, 43));

        let mut wrong_source = owner.clone();
        wrong_source.source_fingerprint = Some("source-v2".to_owned());
        assert_ne!(wrong_source, owner);

        let mut extended = serde_json::to_value(&owner).expect("owner value");
        extended
            .as_object_mut()
            .expect("owner object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<SftpArtifactOwner>(extended).is_err());

        let oversized = artifact_owner(
            &plan,
            42,
            Some(&"x".repeat(ARTIFACT_OWNER_MAX_BYTES as usize)),
        )
        .expect("owner shape");
        assert_eq!(
            encode_artifact_owner(&oversized),
            Err(SftpError::InvalidUploadPlan)
        );
    }

    #[test]
    fn upload_checkpoint_must_match_stage_source_total_and_offset() {
        let checkpoint = SftpTransferCheckpoint {
            direction: SftpTransferDirection::Upload,
            remote_path: "/remote/workspace/staged.part".to_owned(),
            bytes_transferred: 5,
            total_bytes: 10,
            source_fingerprint: Some("source-v1".to_owned()),
            remote_modified_at: None,
        };
        assert_eq!(
            validate_upload_checkpoint(
                "/remote/workspace/staged.part",
                10,
                Some("source-v1"),
                Some(&checkpoint),
            ),
            Ok(5)
        );
        for result in [
            validate_upload_checkpoint(
                "/remote/other/staged.part",
                10,
                Some("source-v1"),
                Some(&checkpoint),
            ),
            validate_upload_checkpoint(
                "/remote/workspace/staged.part",
                11,
                Some("source-v1"),
                Some(&checkpoint),
            ),
            validate_upload_checkpoint(
                "/remote/workspace/staged.part",
                10,
                Some("source-v2"),
                Some(&checkpoint),
            ),
        ] {
            assert_eq!(result, Err(SftpError::CheckpointMismatch));
        }

        let mut invalid_offset = checkpoint;
        invalid_offset.bytes_transferred = 11;
        assert_eq!(
            validate_upload_checkpoint(
                "/remote/workspace/staged.part",
                10,
                Some("source-v1"),
                Some(&invalid_offset),
            ),
            Err(SftpError::CheckpointMismatch)
        );
    }

    #[test]
    fn owned_partial_stage_can_supply_a_strict_implicit_resume_checkpoint() {
        let plan = SftpClient::plan_stable_upload("/remote/file.txt", "directory-child")
            .expect("stable plan");
        let owner = artifact_owner(&plan, 10, Some("source-v1")).expect("owner");
        let mut staged = SftpMetadata {
            kind: SftpEntryKind::File,
            size: 6,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: Some(0o100600),
            accessed_at: None,
            modified_at: Some(7),
        };

        let checkpoint =
            checkpoint_for_owned_stage(&plan, 10, Some("source-v1"), &owner, &owner, &staged)
                .expect("implicit resume checkpoint");
        assert_eq!(checkpoint.remote_path, plan.staged_path);
        assert_eq!(checkpoint.bytes_transferred, 6);
        assert_eq!(checkpoint.source_fingerprint.as_deref(), Some("source-v1"));

        let mut mismatched_owner = owner.clone();
        mismatched_owner.source_fingerprint = Some("source-v2".to_owned());
        assert_eq!(
            checkpoint_for_owned_stage(
                &plan,
                10,
                Some("source-v1"),
                &owner,
                &mismatched_owner,
                &staged,
            ),
            Err(SftpError::RecoveryArtifactConflict)
        );

        staged.size = 11;
        assert_eq!(
            checkpoint_for_owned_stage(&plan, 10, Some("source-v1"), &owner, &owner, &staged,),
            Err(SftpError::RecoveryArtifactConflict)
        );
    }
}
