use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use netcatty_ssh::{
    AlgorithmOverrides, AuthenticationPrompts, ConnectionCredentials, DirectConnector,
    HostChainResolver, InteractiveAuthResponder, KnownHostsVerifier, LocalTreeOptions,
    NormalizedKeepaliveConfig, NormalizedProxyConfig, NormalizedSshConnectionConfig,
    NormalizedSshTimeouts, ProxyType, RemoteTreeOptions, ResolvedSshEndpoint, SecretText,
    SessionEvent, SessionManager, SftpTransferEvent, ShellEvent, ShellOptions, SshAuthConfig,
    SshAuthMethod, SshJumpHost, TransportError, TransportErrorCode,
};
use russh::keys::ssh_key::certificate;
use russh::keys::{Algorithm, PrivateKey, ssh_key};
use russh::server::{self, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_sftp::extensions::LimitsExtension;
use russh_sftp::protocol::{
    Attrs, Data, ExtendedReply, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status,
    StatusCode, Version,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct EchoServer {
    channels: Arc<Mutex<HashMap<ChannelId, Channel<server::Msg>>>>,
    echo_channels: Arc<Mutex<HashSet<ChannelId>>>,
    sftp_filesystem: Arc<StdMutex<MemoryFilesystem>>,
    accepted_clients: Arc<AtomicUsize>,
}

impl server::Server for EchoServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.accepted_clients.fetch_add(1, Ordering::Relaxed);
        Self {
            channels: Arc::default(),
            echo_channels: Arc::default(),
            sftp_filesystem: self.sftp_filesystem.clone(),
            accepted_clients: self.accepted_clients.clone(),
        }
    }
}

impl server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "tester" && password == "correct horse battery staple" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if user == "tester" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &ssh_key::Certificate,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "tester"
                && certificate
                    .valid_principals()
                    .iter()
                    .any(|principal| principal == "tester")
            {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        let Some(mut response) = response else {
            return Ok(server::Auth::Partial {
                name: Cow::Borrowed("Test MFA"),
                instructions: Cow::Borrowed("Enter the one-time code"),
                prompts: Cow::Borrowed(&[(Cow::Borrowed("OTP: "), false)]),
            });
        };
        Ok(
            if user == "tester" && response.next().as_deref() == Some(b"otp-123") {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.echo_channels.lock().await.insert(channel.id());
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(channel_stream) = self.channels.lock().await.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        self.echo_channels.lock().await.remove(&channel);
        session.channel_success(channel)?;
        russh_sftp::server::run(
            channel_stream.into_stream(),
            MemorySftp::new(self.sftp_filesystem.clone()),
        )
        .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(port) = u16::try_from(port_to_connect) else {
            return Ok(());
        };
        let Ok(mut target) = tokio::net::TcpStream::connect((host_to_connect, port)).await else {
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut channel, &mut target).await;
            let _ = channel.shutdown().await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ready\r\n".to_vec())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.echo_channels.lock().await.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }
}

#[derive(Clone)]
enum MemoryHandle {
    File(String),
    Directory(String),
}

struct MemoryFilesystem {
    files: HashMap<String, Vec<u8>>,
    file_permissions: HashMap<String, u32>,
    directories: HashSet<String>,
    rename_destination_injections: HashMap<String, Vec<u8>>,
    advertised_extensions: HashMap<String, String>,
    extension_limits: Option<MemorySftpLimits>,
    extended_requests: Vec<String>,
    transfer_events: Vec<MemorySftpEvent>,
    max_read_request_len: u32,
    max_write_request_len: usize,
    write_failures_remaining: HashMap<String, usize>,
    replace_target_after_stage_write: Option<(String, Vec<u8>)>,
    replace_source_before_rename: Option<(String, Vec<u8>)>,
    replace_backup_after_stage_promotion: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct MemorySftpLimits {
    max_packet_len: u64,
    max_read_len: u64,
    max_write_len: u64,
    max_open_handles: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MemorySftpEvent {
    Write { path: String, len: usize },
    Fsync { path: String },
    Close { path: String },
    Rename { source: String, destination: String },
}

struct CancelOnFirstRead {
    source: std::io::Cursor<Vec<u8>>,
    control: netcatty_ssh::SftpTransferControl,
    cancelled: bool,
}

impl CancelOnFirstRead {
    fn new(data: Vec<u8>, control: netcatty_ssh::SftpTransferControl) -> Self {
        Self {
            source: std::io::Cursor::new(data),
            control,
            cancelled: false,
        }
    }
}

impl AsyncRead for CancelOnFirstRead {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.cancelled {
            this.cancelled = true;
            this.control.cancel();
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut this.source).poll_read(context, buffer)
    }
}

impl AsyncSeek for CancelOnFirstRead {
    fn start_seek(self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.get_mut().source).start_seek(position)
    }

    fn poll_complete(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.get_mut().source).poll_complete(context)
    }
}

impl Default for MemoryFilesystem {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
            file_permissions: HashMap::new(),
            directories: HashSet::from(["/".to_owned()]),
            rename_destination_injections: HashMap::new(),
            advertised_extensions: HashMap::new(),
            extension_limits: None,
            extended_requests: Vec::new(),
            transfer_events: Vec::new(),
            max_read_request_len: 0,
            max_write_request_len: 0,
            write_failures_remaining: HashMap::new(),
            replace_target_after_stage_write: None,
            replace_source_before_rename: None,
            replace_backup_after_stage_promotion: None,
        }
    }
}

struct MemorySftp {
    filesystem: Arc<StdMutex<MemoryFilesystem>>,
    handles: HashMap<String, MemoryHandle>,
    completed_directory_reads: HashSet<String>,
}

impl Default for MemorySftp {
    fn default() -> Self {
        Self::new(Arc::default())
    }
}

impl MemorySftp {
    fn new(filesystem: Arc<StdMutex<MemoryFilesystem>>) -> Self {
        Self {
            filesystem,
            handles: HashMap::new(),
            completed_directory_reads: HashSet::new(),
        }
    }
    fn normalized(path: &str) -> String {
        let normalized = path.replace('\\', "/");
        let normalized = normalized.trim_end_matches('/');
        if normalized.is_empty() {
            "/".to_owned()
        } else if normalized.starts_with('/') {
            normalized.to_owned()
        } else {
            format!("/{normalized}")
        }
    }

    fn file_attributes(data: &[u8], permissions: Option<u32>) -> FileAttributes {
        let mut attributes = FileAttributes {
            size: Some(data.len() as u64),
            permissions: Some(permissions.unwrap_or(0o644)),
            ..FileAttributes::default()
        };
        attributes.set_regular(true);
        attributes
    }

    fn directory_attributes() -> FileAttributes {
        let mut attributes = FileAttributes {
            size: Some(0),
            permissions: Some(0o755),
            ..FileAttributes::default()
        };
        attributes.set_dir(true);
        attributes
    }

    fn attributes(&self, path: &str) -> Result<FileAttributes, StatusCode> {
        let filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        if let Some(data) = filesystem.files.get(path) {
            Ok(Self::file_attributes(
                data,
                filesystem.file_permissions.get(path).copied(),
            ))
        } else if filesystem.directories.contains(path) {
            Ok(Self::directory_attributes())
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    fn ok(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_owned(),
            language_tag: "en-US".to_owned(),
        }
    }
}

impl russh_sftp::server::Handler for MemorySftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        let extensions = self
            .filesystem
            .lock()
            .expect("SFTP test filesystem")
            .advertised_extensions
            .clone();
        Ok(Version {
            version: russh_sftp::protocol::VERSION,
            extensions,
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = Self::normalized(&filename);
        {
            let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
            if flags.contains(OpenFlags::EXCLUDE) && filesystem.files.contains_key(&path) {
                return Err(StatusCode::Failure);
            }
            if flags.contains(OpenFlags::CREATE) {
                filesystem.files.entry(path.clone()).or_default();
                filesystem
                    .file_permissions
                    .entry(path.clone())
                    .or_insert(0o644);
            }
            let Some(file) = filesystem.files.get_mut(&path) else {
                return Err(StatusCode::NoSuchFile);
            };
            if flags.contains(OpenFlags::TRUNCATE) {
                file.clear();
            }
        }
        let handle = format!("file-{id}");
        self.handles
            .insert(handle.clone(), MemoryHandle::File(path));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if let Some(MemoryHandle::File(path)) = self.handles.remove(&handle) {
            self.filesystem
                .lock()
                .expect("SFTP test filesystem")
                .transfer_events
                .push(MemorySftpEvent::Close { path });
        }
        self.completed_directory_reads.remove(&handle);
        Ok(Self::ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(MemoryHandle::File(path)) = self.handles.get(&handle).cloned() else {
            return Err(StatusCode::Failure);
        };
        let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        filesystem.max_read_request_len = filesystem.max_read_request_len.max(len);
        let data = filesystem.files.get(&path).ok_or(StatusCode::NoSuchFile)?;
        let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        if offset >= data.len() {
            return Err(StatusCode::Eof);
        }
        let end = offset.saturating_add(len as usize).min(data.len());
        Ok(Data {
            id,
            data: data[offset..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(MemoryHandle::File(path)) = self.handles.get(&handle).cloned() else {
            return Err(StatusCode::Failure);
        };
        let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        filesystem.max_write_request_len = filesystem.max_write_request_len.max(data.len());
        filesystem.transfer_events.push(MemorySftpEvent::Write {
            path: path.clone(),
            len: data.len(),
        });
        if let Some(remaining) = filesystem.write_failures_remaining.get_mut(&path)
            && *remaining > 0
        {
            *remaining -= 1;
            return Err(StatusCode::Failure);
        }
        let file = filesystem
            .files
            .get_mut(&path)
            .ok_or(StatusCode::NoSuchFile)?;
        let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        if file.len() < offset {
            file.resize(offset, 0);
        }
        let end = offset.checked_add(data.len()).ok_or(StatusCode::Failure)?;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[offset..end].copy_from_slice(&data);
        if path.ends_with("/staged.part")
            && let Some((target, replacement)) = filesystem.replace_target_after_stage_write.take()
        {
            filesystem.files.insert(target, replacement);
        }
        Ok(Self::ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs {
            id,
            attrs: self.attributes(&Self::normalized(&path))?,
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.lstat(id, path).await
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attributes: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = Self::normalized(&path);
        let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        if !filesystem.files.contains_key(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        if let Some(permissions) = attributes.permissions {
            filesystem.file_permissions.insert(path, permissions);
        }
        Ok(Self::ok(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let path = match self.handles.get(&handle) {
            Some(MemoryHandle::File(path)) | Some(MemoryHandle::Directory(path)) => path,
            None => return Err(StatusCode::Failure),
        };
        Ok(Attrs {
            id,
            attrs: self.attributes(path)?,
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = Self::normalized(&path);
        if !self
            .filesystem
            .lock()
            .expect("SFTP test filesystem")
            .directories
            .contains(&path)
        {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = format!("directory-{id}");
        self.handles
            .insert(handle.clone(), MemoryHandle::Directory(path));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if !self.completed_directory_reads.insert(handle.clone()) {
            return Err(StatusCode::Eof);
        }
        let Some(MemoryHandle::Directory(directory)) = self.handles.get(&handle).cloned() else {
            return Err(StatusCode::Failure);
        };
        let prefix = if directory == "/" {
            "/".to_owned()
        } else {
            format!("{directory}/")
        };
        let filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        let mut files = Vec::new();
        for (path, data) in &filesystem.files {
            if let Some(name) = path.strip_prefix(&prefix)
                && !name.contains('/')
            {
                files.push(File::new(
                    name,
                    Self::file_attributes(data, filesystem.file_permissions.get(path).copied()),
                ));
            }
        }
        for path in &filesystem.directories {
            if let Some(name) = path.strip_prefix(&prefix)
                && !name.is_empty()
                && !name.contains('/')
            {
                files.push(File::new(name, Self::directory_attributes()));
            }
        }
        files.sort_by(|left, right| left.filename.cmp(&right.filename));
        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = Self::normalized(&path);
        if !self
            .filesystem
            .lock()
            .expect("SFTP test filesystem")
            .directories
            .insert(path)
        {
            return Err(StatusCode::Failure);
        }
        Ok(Self::ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let path = Self::normalized(&path);
        if path == "/"
            || !self
                .filesystem
                .lock()
                .expect("SFTP test filesystem")
                .directories
                .remove(&path)
        {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Self::ok(id))
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let path = Self::normalized(&path);
        let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        if filesystem.files.remove(&path).is_none() {
            return Err(StatusCode::NoSuchFile);
        }
        filesystem.file_permissions.remove(&path);
        Ok(Self::ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        source: String,
        destination: String,
    ) -> Result<Status, Self::Error> {
        let source = Self::normalized(&source);
        let destination = Self::normalized(&destination);
        let mut filesystem = self.filesystem.lock().expect("SFTP test filesystem");
        let replace_source = filesystem
            .replace_source_before_rename
            .as_ref()
            .is_some_and(|(path, _)| path == &source);
        if replace_source
            && let Some((_, replacement)) = filesystem.replace_source_before_rename.take()
        {
            filesystem.files.insert(source.clone(), replacement);
        }
        filesystem.transfer_events.push(MemorySftpEvent::Rename {
            source: source.clone(),
            destination: destination.clone(),
        });
        if let Some(data) = filesystem
            .rename_destination_injections
            .remove(&destination)
        {
            filesystem.files.insert(destination.clone(), data);
            filesystem
                .file_permissions
                .insert(destination.clone(), 0o600);
        }
        if filesystem.files.contains_key(&destination)
            || filesystem.directories.contains(&destination)
        {
            return Err(StatusCode::Failure);
        }
        let promoted_stage = source.ends_with("/staged.part");
        if let Some(data) = filesystem.files.remove(&source) {
            let permissions = filesystem.file_permissions.remove(&source);
            let permission_path = destination.clone();
            filesystem.files.insert(destination, data);
            if let Some(permissions) = permissions {
                filesystem
                    .file_permissions
                    .insert(permission_path, permissions);
            }
        } else if filesystem.directories.remove(&source) {
            filesystem.directories.insert(destination);
        } else {
            return Err(StatusCode::NoSuchFile);
        }
        if promoted_stage
            && let Some(replacement) = filesystem.replace_backup_after_stage_promotion.take()
            && let Some(backup_path) = filesystem
                .files
                .keys()
                .find(|path| path.ends_with("/backup.bak"))
                .cloned()
        {
            filesystem.files.insert(backup_path, replacement);
        }
        Ok(Self::ok(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        self.filesystem
            .lock()
            .expect("SFTP test filesystem")
            .extended_requests
            .push(request.clone());
        if request == russh_sftp::extensions::LIMITS {
            let limits = self
                .filesystem
                .lock()
                .expect("SFTP test filesystem")
                .extension_limits
                .ok_or(StatusCode::OpUnsupported)?;
            let reply = LimitsExtension {
                max_packet_len: limits.max_packet_len,
                max_read_len: limits.max_read_len,
                max_write_len: limits.max_write_len,
                max_open_handles: limits.max_open_handles,
            };
            let data = russh_sftp::ser::to_bytes(&reply)
                .map_err(|_| StatusCode::Failure)?
                .to_vec();
            return Ok(ExtendedReply { id, data }.into());
        }
        if request == russh_sftp::extensions::FSYNC {
            let handle = decode_sftp_string(&data).ok_or(StatusCode::BadMessage)?;
            let Some(MemoryHandle::File(path)) = self.handles.get(&handle).cloned() else {
                return Err(StatusCode::Failure);
            };
            self.filesystem
                .lock()
                .expect("SFTP test filesystem")
                .transfer_events
                .push(MemorySftpEvent::Fsync { path });
            return Ok(Self::ok(id).into());
        }
        Err(StatusCode::OpUnsupported)
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(Self::normalized(&path))],
        })
    }
}

fn decode_sftp_string(data: &[u8]) -> Option<String> {
    let length = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    if data.len() != length.checked_add(4)? {
        return None;
    }
    String::from_utf8(data[4..].to_vec()).ok()
}

async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    let (port, server_task, _) = start_server_with_filesystem().await;
    (port, server_task)
}

async fn start_counted_server() -> (u16, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server_config = Arc::new(server::Config {
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("server key")],
        ..server::Config::default()
    });
    let mut server = EchoServer::default();
    let accepted_clients = server.accepted_clients.clone();
    let server_task = tokio::spawn(async move {
        server
            .run_on_socket(server_config, &listener)
            .await
            .expect("test server");
    });
    (port, server_task, accepted_clients)
}

async fn start_server_with_filesystem() -> (
    u16,
    tokio::task::JoinHandle<()>,
    Arc<StdMutex<MemoryFilesystem>>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server_config = Arc::new(server::Config {
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("server key")],
        ..server::Config::default()
    });
    let mut server = EchoServer::default();
    let filesystem = server.sftp_filesystem.clone();
    let server_task = tokio::spawn(async move {
        server
            .run_on_socket(server_config, &listener)
            .await
            .expect("test server");
    });
    (port, server_task, filesystem)
}

fn connection_config(port: u16, method: SshAuthMethod) -> NormalizedSshConnectionConfig {
    NormalizedSshConnectionConfig {
        hostname: "127.0.0.1".to_owned(),
        port,
        username: "tester".to_owned(),
        auth_method: method,
        proxy: None,
        jump_hosts: Vec::new(),
        legacy_algorithms: false,
        legacy_algorithms_explicit: false,
        skip_ecdsa_host_key: false,
        algorithms: AlgorithmOverrides::default(),
        keepalive: NormalizedKeepaliveConfig {
            override_global: false,
            interval_seconds: None,
            count_max: None,
        },
        timeouts: NormalizedSshTimeouts {
            tcp_connect_seconds: 3,
            auth_ready_seconds: 3,
        },
    }
}

#[tokio::test]
async fn direct_password_connection_opens_a_pty_and_streams_bytes() {
    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Password);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_password(SecretText::new("correct horse battery staple"));
    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await
        .expect("connect and authenticate");
    let mut shell = connection
        .open_shell(ShellOptions::default())
        .await
        .expect("open shell");

    let ready = tokio::time::timeout(Duration::from_secs(2), shell.next_event())
        .await
        .expect("ready timeout")
        .expect("ready event");
    assert_eq!(ready, ShellEvent::Data(b"ready\r\n".to_vec()));

    shell.write(b"hello-rust").await.expect("send input");
    let echo = tokio::time::timeout(Duration::from_secs(2), shell.next_event())
        .await
        .expect("echo timeout")
        .expect("echo event");
    assert_eq!(echo, ShellEvent::Data(b"hello-rust".to_vec()));

    shell.close().await.expect("close shell");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn sftp_subsystem_performs_real_directory_and_file_operations() {
    let (port, server_task) = start_server().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");

    assert_eq!(sftp.canonicalize("/").await.expect("canonicalize"), "/");
    sftp.create_dir("/uploads").await.expect("create directory");
    sftp.write_file("/uploads/hello.txt", b"hello from rust")
        .await
        .expect("write file");
    assert_eq!(
        sftp.read_file("/uploads/hello.txt")
            .await
            .expect("read file"),
        b"hello from rust"
    );

    let metadata = sftp
        .metadata("/uploads/hello.txt")
        .await
        .expect("file metadata");
    assert_eq!(metadata.kind, netcatty_ssh::SftpEntryKind::File);
    assert_eq!(metadata.size, 15);
    let entries = sftp.read_dir("/uploads").await.expect("read directory");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].path, "/uploads/hello.txt");

    sftp.rename("/uploads/hello.txt", "/uploads/renamed.txt")
        .await
        .expect("rename file");
    sftp.remove_file("/uploads/renamed.txt")
        .await
        .expect("remove file");
    sftp.remove_dir("/uploads").await.expect("remove directory");
    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn conditional_sftp_replace_preserves_permissions_and_cleans_staging() {
    let (port, server_task) = start_server().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");

    sftp.write_file("/sshd_config", b"PermitRootLogin yes\n")
        .await
        .expect("seed editor target");
    sftp.set_permissions("/sshd_config", 0o100640)
        .await
        .expect("set editor target permissions");
    sftp.replace_file_if_unchanged(
        "/sshd_config",
        b"PermitRootLogin yes\n",
        b"PermitRootLogin no\n",
    )
    .await
    .expect("publish conditional editor save");

    assert_eq!(
        sftp.read_file("/sshd_config")
            .await
            .expect("read saved file"),
        b"PermitRootLogin no\n"
    );
    assert_eq!(
        sftp.metadata("/sshd_config")
            .await
            .expect("saved metadata")
            .permissions,
        Some(0o100640)
    );
    let entries = sftp.read_dir("/").await.expect("read root after save");
    assert_eq!(entries.len(), 1, "the staging workspace must be removed");
    assert_eq!(entries[0].name, "sshd_config");

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn conditional_sftp_replace_detects_same_metadata_change_after_staging() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");

    sftp.write_file("/service.conf", b"alpha")
        .await
        .expect("seed editor target");
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .replace_target_after_stage_write = Some(("/service.conf".to_owned(), b"omega".to_vec()));

    assert_eq!(
        sftp.replace_file_if_unchanged("/service.conf", b"alpha", b"bravo")
            .await,
        Err(netcatty_ssh::SftpError::DestinationChanged)
    );
    assert_eq!(
        sftp.read_file("/service.conf")
            .await
            .expect("read concurrent writer's file"),
        b"omega"
    );
    let entries = sftp.read_dir("/").await.expect("read root after conflict");
    assert_eq!(entries.len(), 1, "conflict cleanup must remove staging");
    assert_eq!(entries[0].name, "service.conf");

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn conditional_sftp_replace_rechecks_the_atomically_acquired_backup() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");
    let target = "/atomic-editor-race.conf";

    sftp.write_file(target, b"alpha")
        .await
        .expect("seed editor target");
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .replace_source_before_rename = Some((target.to_owned(), b"omega".to_vec()));

    let result = sftp
        .replace_file_if_unchanged(target, b"alpha", b"bravo")
        .await;
    assert_eq!(result, Err(netcatty_ssh::SftpError::DestinationChanged));
    assert_eq!(
        sftp.read_file(target)
            .await
            .expect("read restored concurrent version"),
        b"omega"
    );

    let filesystem = filesystem.lock().expect("SFTP test filesystem");
    assert!(
        filesystem
            .files
            .keys()
            .all(|path| !path.contains(".netcatty-xfer-v1-")),
        "a safely restored conflict must discard only its owned staging workspace"
    );
    assert!(
        !filesystem.transfer_events.iter().any(|event| matches!(
            event,
            MemorySftpEvent::Rename { source, .. } if source.ends_with("/staged.part")
        )),
        "a mismatching acquired backup must never publish the editor stage"
    );
    drop(filesystem);

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn conditional_sftp_replace_preserves_every_version_when_restore_races() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");
    let target = "/atomic-editor-recovery-race.conf";
    let acquired_concurrent = b"omega".to_vec();
    let later_concurrent = b"sigma".to_vec();
    let editor_draft = b"bravo".to_vec();

    sftp.write_file(target, b"alpha")
        .await
        .expect("seed editor target");
    {
        let mut filesystem = filesystem.lock().expect("SFTP test filesystem");
        filesystem.replace_source_before_rename =
            Some((target.to_owned(), acquired_concurrent.clone()));
        filesystem
            .rename_destination_injections
            .insert(target.to_owned(), later_concurrent.clone());
    }

    let result = sftp
        .replace_file_if_unchanged(target, b"alpha", &editor_draft)
        .await;
    assert_eq!(result, Err(netcatty_ssh::SftpError::RecoveryFailed));
    let error = result
        .expect_err("restore race must fail closed")
        .to_string();
    assert!(!error.contains(target));
    assert!(!error.contains("omega"));
    assert!(!error.contains("sigma"));
    assert_eq!(
        sftp.read_file(target)
            .await
            .expect("read later concurrent version"),
        later_concurrent
    );

    let filesystem = filesystem.lock().expect("SFTP test filesystem");
    let backup = filesystem
        .files
        .iter()
        .find(|(path, _)| path.ends_with("/backup.bak"))
        .map(|(_, body)| body)
        .expect("acquired concurrent version retained as backup");
    assert_eq!(backup, &acquired_concurrent);
    let staged = filesystem
        .files
        .iter()
        .find(|(path, _)| path.ends_with("/staged.part"))
        .map(|(_, body)| body)
        .expect("editor draft retained in owned stage");
    assert_eq!(staged, &editor_draft);
    assert!(
        !filesystem.transfer_events.iter().any(|event| matches!(
            event,
            MemorySftpEvent::Rename { source, .. } if source.ends_with("/staged.part")
        )),
        "a recovery race must not publish the editor stage"
    );
    drop(filesystem);

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn conditional_sftp_replace_never_deletes_a_backup_that_changed_after_proof() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");
    let target = "/backup-proof-race.conf";

    sftp.write_file(target, b"alpha")
        .await
        .expect("seed editor target");
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .replace_backup_after_stage_promotion = Some(b"omega".to_vec());

    assert_eq!(
        sftp.replace_file_if_unchanged(target, b"alpha", b"bravo")
            .await,
        Err(netcatty_ssh::SftpError::BackupCleanupFailed)
    );
    assert_eq!(
        sftp.read_file(target)
            .await
            .expect("read published editor version"),
        b"bravo"
    );

    let filesystem = filesystem.lock().expect("SFTP test filesystem");
    let backup = filesystem
        .files
        .iter()
        .find(|(path, _)| path.ends_with("/backup.bak"))
        .map(|(_, body)| body)
        .expect("changed backup retained");
    assert_eq!(backup, b"omega");
    assert!(
        filesystem
            .files
            .keys()
            .any(|path| path.ends_with("/owner.json")),
        "the recovery owner must remain while an unverified backup exists"
    );
    drop(filesystem);

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn safe_sftp_upload_stages_replaces_and_restores_permissions() {
    let (port, server_task) = start_server().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");
    sftp.write_file("/deploy.sh", b"old release")
        .await
        .expect("write original");
    sftp.set_permissions("/deploy.sh", 0o100755)
        .await
        .expect("make executable");
    let plan = netcatty_ssh::SftpClient::plan_safe_upload("/deploy.sh").expect("safe upload plan");

    let outcome = sftp
        .safe_upload(&plan, b"new release")
        .await
        .expect("safe replacement");
    assert!(outcome.replaced_existing);
    assert_eq!(outcome.bytes_written, 11);
    assert_eq!(
        sftp.read_file("/deploy.sh")
            .await
            .expect("read published file"),
        b"new release"
    );
    assert_eq!(
        sftp.metadata("/deploy.sh")
            .await
            .expect("published metadata")
            .permissions,
        Some(0o100755)
    );
    assert!(
        !sftp
            .try_exists(&plan.staged_path)
            .await
            .expect("stage absent")
    );
    assert!(
        !sftp
            .try_exists(&plan.backup_path)
            .await
            .expect("backup absent")
    );

    let create_plan =
        netcatty_ssh::SftpClient::plan_safe_upload("/new.txt").expect("new upload plan");
    let create_outcome = sftp
        .safe_upload(&create_plan, b"brand new")
        .await
        .expect("safe create");
    assert!(!create_outcome.replaced_existing);
    assert_eq!(
        sftp.read_file("/new.txt").await.expect("new file"),
        b"brand new"
    );

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn safe_sftp_upload_preserves_a_target_created_during_final_publication() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");

    let create_target = "/publish-race-new.txt";
    let concurrent_create = b"created by another writer".to_vec();
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .rename_destination_injections
        .insert(create_target.to_owned(), concurrent_create.clone());
    let create_plan =
        netcatty_ssh::SftpClient::plan_safe_upload(create_target).expect("new target plan");
    assert_eq!(
        sftp.safe_upload(&create_plan, b"netcatty staged data")
            .await,
        Err(netcatty_ssh::SftpError::PromotionFailed)
    );
    assert_eq!(
        sftp.read_file(create_target)
            .await
            .expect("concurrent file"),
        concurrent_create
    );
    assert_eq!(
        sftp.read_file(&create_plan.staged_path)
            .await
            .expect("owned stage remains recoverable"),
        b"netcatty staged data"
    );

    let replace_target = "/publish-race-replace.txt";
    sftp.write_file(replace_target, b"original target")
        .await
        .expect("seed original target");
    let concurrent_replace = b"replacement from another writer".to_vec();
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .rename_destination_injections
        .insert(replace_target.to_owned(), concurrent_replace.clone());
    let replace_plan =
        netcatty_ssh::SftpClient::plan_safe_upload(replace_target).expect("replacement plan");
    assert_eq!(
        sftp.safe_upload(&replace_plan, b"netcatty replacement")
            .await,
        Err(netcatty_ssh::SftpError::RecoveryFailed)
    );
    assert_eq!(
        sftp.read_file(replace_target)
            .await
            .expect("concurrent replacement remains"),
        concurrent_replace
    );
    assert_eq!(
        sftp.read_file(&replace_plan.backup_path)
            .await
            .expect("original remains recoverable"),
        b"original target"
    );
    assert_eq!(
        sftp.read_file(&replace_plan.staged_path)
            .await
            .expect("replacement stage remains recoverable"),
        b"netcatty replacement"
    );

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn advertised_sftp_limits_and_fsync_are_enforced_before_safe_publication() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    {
        let mut filesystem = filesystem.lock().expect("SFTP test filesystem");
        filesystem.advertised_extensions = HashMap::from([
            (russh_sftp::extensions::LIMITS.to_owned(), "1".to_owned()),
            (russh_sftp::extensions::FSYNC.to_owned(), "1".to_owned()),
            ("unknown@example.test".to_owned(), "1".to_owned()),
        ]);
        filesystem.extension_limits = Some(MemorySftpLimits {
            max_packet_len: 4 * 1024,
            max_read_len: 1024,
            max_write_len: 1024,
            max_open_handles: 1,
        });
    }

    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open limited SFTP");
    let target = "/extension-contract.bin";
    let payload: Vec<u8> = (0..12_345).map(|index| (index % 251) as u8).collect();
    let plan = netcatty_ssh::SftpClient::plan_safe_upload(target).expect("safe upload plan");
    let mut source = std::io::Cursor::new(payload.clone());
    sftp.stream_safe_upload(
        &plan,
        &mut source,
        payload.len() as u64,
        Some("extension-contract-v1"),
        None,
        &netcatty_ssh::SftpTransferControl::new(),
        None,
    )
    .await
    .expect("stream upload within advertised limits");

    assert_eq!(
        sftp.read_file(target).await.expect("first bounded read"),
        payload
    );
    assert_eq!(
        sftp.read_file(target).await.expect("second bounded read"),
        payload
    );
    let mut downloaded = std::io::Cursor::new(Vec::new());
    sftp.stream_download(
        target,
        &mut downloaded,
        None,
        &netcatty_ssh::SftpTransferControl::new(),
        None,
    )
    .await
    .expect("bounded stream download");
    assert_eq!(downloaded.into_inner(), payload);
    assert_eq!(
        sftp.read_file(target)
            .await
            .expect("read after explicitly closed stream"),
        payload
    );

    sftp.close().await.expect("close limited SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();

    let filesystem = filesystem.lock().expect("SFTP test filesystem");
    assert!(filesystem.max_read_request_len <= 1024);
    assert!(filesystem.max_write_request_len <= 1024);
    assert!(
        filesystem
            .extended_requests
            .iter()
            .any(|request| request == russh_sftp::extensions::LIMITS)
    );
    assert!(
        !filesystem
            .extended_requests
            .iter()
            .any(|request| request == "unknown@example.test")
    );

    let staged_path = &plan.staged_path;
    let last_write = filesystem
        .transfer_events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| match event {
            MemorySftpEvent::Write { path, len } if path == staged_path && *len > 0 => Some(index),
            _ => None,
        })
        .last()
        .expect("staged payload write event");
    let fsync = filesystem
        .transfer_events
        .iter()
        .enumerate()
        .skip(last_write + 1)
        .find_map(|(index, event)| match event {
            MemorySftpEvent::Fsync { path } if path == staged_path => Some(index),
            _ => None,
        })
        .expect("staged fsync after writes");
    let close = filesystem
        .transfer_events
        .iter()
        .enumerate()
        .skip(fsync + 1)
        .find_map(|(index, event)| match event {
            MemorySftpEvent::Close { path } if path == staged_path => Some(index),
            _ => None,
        })
        .expect("staged close after fsync");
    let rename = filesystem
        .transfer_events
        .iter()
        .enumerate()
        .skip(close + 1)
        .find_map(|(index, event)| match event {
            MemorySftpEvent::Rename {
                source,
                destination,
            } if source == staged_path && destination == target => Some(index),
            _ => None,
        })
        .expect("publication rename after close");
    assert!(last_write < fsync && fsync < close && close < rename);
}

fn assert_remote_file_closed(filesystem: &Arc<StdMutex<MemoryFilesystem>>, remote_path: &str) {
    let filesystem = filesystem.lock().expect("SFTP test filesystem");
    assert_eq!(
        filesystem
            .transfer_events
            .iter()
            .rev()
            .find(|event| match event {
                MemorySftpEvent::Write { path, .. }
                | MemorySftpEvent::Fsync { path }
                | MemorySftpEvent::Close { path } => path == remote_path,
                MemorySftpEvent::Rename { .. } => false,
            }),
        Some(&MemorySftpEvent::Close {
            path: remote_path.to_owned(),
        })
    );
}

#[tokio::test]
async fn limited_sftp_releases_upload_handles_after_cancel_source_change_and_write_failures() {
    let (port, server_task, filesystem) = start_server_with_filesystem().await;
    {
        let mut filesystem = filesystem.lock().expect("SFTP test filesystem");
        filesystem.advertised_extensions = HashMap::from([
            (russh_sftp::extensions::LIMITS.to_owned(), "1".to_owned()),
            (russh_sftp::extensions::FSYNC.to_owned(), "1".to_owned()),
        ]);
        filesystem.extension_limits = Some(MemorySftpLimits {
            max_packet_len: 4 * 1024,
            max_read_len: 1024,
            max_write_len: 1024,
            max_open_handles: 1,
        });
    }

    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open limited SFTP");

    let cancel_control = netcatty_ssh::SftpTransferControl::new();
    let cancel_content = vec![0x11; 4096];
    let mut cancel_source = CancelOnFirstRead::new(cancel_content.clone(), cancel_control.clone());
    assert_eq!(
        sftp.stream_upload(
            "/cancelled-upload.bin",
            &mut cancel_source,
            4096,
            Some("cancelled-source-v1"),
            None,
            &cancel_control,
            None,
        )
        .await,
        Err(netcatty_ssh::SftpError::Cancelled)
    );
    assert_remote_file_closed(&filesystem, "/cancelled-upload.bin");
    let cancel_checkpoint = cancel_control
        .checkpoint()
        .await
        .expect("cancelled upload checkpoint");
    let cancelled_remote = filesystem
        .lock()
        .expect("SFTP test filesystem")
        .files
        .get("/cancelled-upload.bin")
        .expect("cancelled upload file")
        .clone();
    assert_eq!(
        cancelled_remote.len() as u64,
        cancel_checkpoint.bytes_transferred
    );
    assert_eq!(
        cancelled_remote,
        cancel_content[..cancel_checkpoint.bytes_transferred as usize]
    );
    let mut resumed_cancel_source = std::io::Cursor::new(cancel_content.clone());
    sftp.stream_upload(
        "/cancelled-upload.bin",
        &mut resumed_cancel_source,
        cancel_content.len() as u64,
        Some("cancelled-source-v1"),
        Some(&cancel_checkpoint),
        &netcatty_ssh::SftpTransferControl::new(),
        None,
    )
    .await
    .expect("resume after cancellation");
    assert_eq!(
        sftp.read_file("/cancelled-upload.bin")
            .await
            .expect("read resumed cancelled upload"),
        cancel_content
    );
    sftp.write_file("/after-cancel.bin", b"still usable")
        .await
        .expect("open after cancellation");

    let complete_source: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    let partial_source = complete_source[..1536].to_vec();
    let changed_control = netcatty_ssh::SftpTransferControl::new();
    let mut short_source = std::io::Cursor::new(partial_source.clone());
    assert_eq!(
        sftp.stream_upload(
            "/source-changed.bin",
            &mut short_source,
            complete_source.len() as u64,
            Some("resumable-source-v1"),
            None,
            &changed_control,
            None,
        )
        .await,
        Err(netcatty_ssh::SftpError::SourceChanged)
    );
    assert_remote_file_closed(&filesystem, "/source-changed.bin");
    let checkpoint = changed_control
        .checkpoint()
        .await
        .expect("partial upload checkpoint");
    assert_eq!(checkpoint.bytes_transferred, partial_source.len() as u64);
    assert_eq!(
        sftp.read_file("/source-changed.bin")
            .await
            .expect("source-changed handle was explicitly closed"),
        partial_source
    );
    let mut resumed_source = std::io::Cursor::new(complete_source.clone());
    sftp.stream_upload(
        "/source-changed.bin",
        &mut resumed_source,
        complete_source.len() as u64,
        Some("resumable-source-v1"),
        Some(&checkpoint),
        &netcatty_ssh::SftpTransferControl::new(),
        None,
    )
    .await
    .expect("resume after source change");
    assert_eq!(
        sftp.read_file("/source-changed.bin")
            .await
            .expect("read resumed upload"),
        complete_source
    );

    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .write_failures_remaining
        .insert("/failed-direct-write.bin".to_owned(), 1);
    assert_eq!(
        sftp.write_file("/failed-direct-write.bin", b"fails once")
            .await,
        Err(netcatty_ssh::SftpError::OperationFailed)
    );
    assert_remote_file_closed(&filesystem, "/failed-direct-write.bin");
    sftp.write_file("/after-direct-write-error.bin", b"still usable")
        .await
        .expect("open after direct write error");

    let owner_failure_plan = netcatty_ssh::SftpClient::plan_safe_upload("/owner-write-error.bin")
        .expect("owner failure plan");
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .write_failures_remaining
        .insert(
            owner_failure_plan
                .artifacts
                .as_ref()
                .unwrap()
                .owner_path
                .clone(),
            1,
        );
    assert_eq!(
        sftp.safe_upload(&owner_failure_plan, b"owner marker write fails")
            .await,
        Err(netcatty_ssh::SftpError::OperationFailed)
    );
    assert_remote_file_closed(
        &filesystem,
        &owner_failure_plan.artifacts.as_ref().unwrap().owner_path,
    );
    sftp.write_file("/after-owner-write-error.bin", b"still usable")
        .await
        .expect("open after exclusive owner write error");

    let stage_failure_plan = netcatty_ssh::SftpClient::plan_safe_upload("/stage-write-error.bin")
        .expect("stage failure plan");
    filesystem
        .lock()
        .expect("SFTP test filesystem")
        .write_failures_remaining
        .insert(stage_failure_plan.staged_path.clone(), 1);
    assert_eq!(
        sftp.safe_upload(&stage_failure_plan, b"stage write fails")
            .await,
        Err(netcatty_ssh::SftpError::OperationFailed)
    );
    assert_remote_file_closed(&filesystem, &stage_failure_plan.staged_path);
    sftp.write_file("/after-stage-write-error.bin", b"still usable")
        .await
        .expect("open after precreated stage write error");

    sftp.close().await.expect("close limited SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn empty_unknown_and_wrong_version_sftp_extensions_fall_back_safely() {
    for advertised_extensions in [
        HashMap::new(),
        HashMap::from([
            (russh_sftp::extensions::LIMITS.to_owned(), "2".to_owned()),
            (russh_sftp::extensions::FSYNC.to_owned(), "2".to_owned()),
            ("unknown@example.test".to_owned(), "1".to_owned()),
        ]),
    ] {
        let (port, server_task, filesystem) = start_server_with_filesystem().await;
        {
            let mut filesystem = filesystem.lock().expect("SFTP test filesystem");
            filesystem.advertised_extensions = advertised_extensions;
            filesystem.extension_limits = Some(MemorySftpLimits {
                max_packet_len: 4 * 1024,
                max_read_len: 16,
                max_write_len: 16,
                max_open_handles: 1,
            });
        }
        let connection =
            connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
        let sftp = connection.open_sftp().await.expect("open fallback SFTP");
        let payload = vec![0x5a; 4096];
        sftp.write_file("/fallback.bin", &payload)
            .await
            .expect("fallback write");
        assert_eq!(
            sftp.read_file("/fallback.bin")
                .await
                .expect("fallback read"),
            payload
        );
        sftp.close().await.expect("close fallback SFTP");
        connection.disconnect().await.expect("disconnect");
        server_task.abort();
        assert!(
            filesystem
                .lock()
                .expect("SFTP test filesystem")
                .extended_requests
                .is_empty(),
            "unrecognized extensions must not be invoked"
        );
    }
}

#[tokio::test]
async fn external_openssh_server_supports_the_sftp_compatibility_contract() {
    let Some(port) = std::env::var("NETCATTY_OPENSSH_TEST_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return;
    };
    let mut config = connection_config(port, SshAuthMethod::Password);
    config.username = "netcatty".to_owned();
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &ConnectionCredentials::empty()
                .with_password(SecretText::new("netcatty-integration-password")),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await
        .expect("connect to external OpenSSH server");
    let sftp = connection.open_sftp().await.expect("open OpenSSH SFTP");
    let home = sftp.canonicalize(".").await.expect("canonicalize home");
    assert!(!home.is_empty());
    let directory = format!(
        ".netcatty-compat-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    sftp.create_dir(&directory).await.expect("create directory");
    let target = format!("{directory}/payload.bin");
    sftp.write_file(&target, b"old").await.expect("seed target");
    sftp.set_permissions(&target, 0o100600)
        .await
        .expect("set target permissions");
    let plan = netcatty_ssh::SftpClient::plan_safe_upload(&target).expect("safe upload plan");
    let payload: Vec<u8> = (0..900_000).map(|index| (index % 251) as u8).collect();
    let mut source = std::io::Cursor::new(payload.clone());
    let outcome = sftp
        .stream_safe_upload(
            &plan,
            &mut source,
            payload.len() as u64,
            Some("openssh-fixture-v1"),
            None,
            &netcatty_ssh::SftpTransferControl::new(),
            None,
        )
        .await
        .expect("stream safe upload to OpenSSH");
    assert!(outcome.upload.replaced_existing);
    assert_eq!(
        sftp.metadata(&target)
            .await
            .expect("OpenSSH target metadata")
            .permissions
            .map(|mode| mode & 0o777),
        Some(0o600)
    );
    let mut downloaded = std::io::Cursor::new(Vec::new());
    let checkpoint = sftp
        .stream_download(
            &target,
            &mut downloaded,
            None,
            &netcatty_ssh::SftpTransferControl::new(),
            None,
        )
        .await
        .expect("stream download from OpenSSH");
    assert_eq!(checkpoint.bytes_transferred, payload.len() as u64);
    assert_eq!(downloaded.into_inner(), payload);
    let renamed = format!("{directory}/renamed.bin");
    sftp.rename(&target, &renamed).await.expect("rename file");
    assert_eq!(
        sftp.read_dir(&directory)
            .await
            .expect("list OpenSSH directory")
            .len(),
        1
    );
    sftp.remove_file(&renamed).await.expect("remove file");
    sftp.remove_dir(&directory).await.expect("remove directory");
    sftp.close().await.expect("close OpenSSH SFTP");
    connection.disconnect().await.expect("disconnect OpenSSH");
}

#[tokio::test]
async fn streaming_sftp_transfers_pause_resume_cancel_and_checkpoint() {
    use std::io::Cursor;

    let (port, server_task) = start_server().await;
    let connection = connect_with_password(&connection_config(port, SshAuthMethod::Password)).await;
    let sftp = connection.open_sftp().await.expect("open SFTP subsystem");
    let content: Vec<u8> = (0..700_000).map(|index| (index % 251) as u8).collect();
    let mut source = Cursor::new(content.clone());
    let control = netcatty_ssh::SftpTransferControl::new();
    control.pause();
    let resume_control = control.clone();
    let resume_after_observation = async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(resume_control.checkpoint().await.is_none());
        resume_control.resume();
    };
    let (progress_sender, mut progress_receiver) = tokio::sync::mpsc::channel(8);
    let upload = sftp.stream_upload(
        "/stream.bin",
        &mut source,
        content.len() as u64,
        Some("source-v1"),
        None,
        &control,
        Some(&progress_sender),
    );
    let (checkpoint, ()) = tokio::join!(upload, resume_after_observation);
    let checkpoint = checkpoint.expect("stream upload");
    assert_eq!(checkpoint.bytes_transferred, content.len() as u64);
    assert_eq!(
        control
            .checkpoint()
            .await
            .expect("stored upload checkpoint"),
        checkpoint
    );
    assert!(progress_receiver.recv().await.is_some());

    let mut downloaded = Cursor::new(Vec::<u8>::new());
    let download_control = netcatty_ssh::SftpTransferControl::new();
    let download_checkpoint = sftp
        .stream_download(
            "/stream.bin",
            &mut downloaded,
            None,
            &download_control,
            None,
        )
        .await
        .expect("stream download");
    assert_eq!(download_checkpoint.bytes_transferred, content.len() as u64);
    assert_eq!(downloaded.into_inner(), content);

    let split = 300_000;
    sftp.write_file("/resumed.bin", &content[..split])
        .await
        .expect("seed partial upload");
    let resume_checkpoint = netcatty_ssh::SftpTransferCheckpoint {
        direction: netcatty_ssh::SftpTransferDirection::Upload,
        remote_path: "/resumed.bin".to_owned(),
        bytes_transferred: split as u64,
        total_bytes: content.len() as u64,
        source_fingerprint: Some("source-v1".to_owned()),
        remote_modified_at: None,
    };
    let mut resumed_source = Cursor::new(content.clone());
    sftp.stream_upload(
        "/resumed.bin",
        &mut resumed_source,
        content.len() as u64,
        Some("source-v1"),
        Some(&resume_checkpoint),
        &netcatty_ssh::SftpTransferControl::new(),
        None,
    )
    .await
    .expect("resume upload");
    assert_eq!(
        sftp.read_file("/resumed.bin").await.expect("resumed file"),
        content
    );

    let cancelled = netcatty_ssh::SftpTransferControl::new();
    cancelled.cancel();
    let mut cancelled_source = Cursor::new(vec![1_u8; 1024]);
    assert_eq!(
        sftp.stream_upload(
            "/cancelled.bin",
            &mut cancelled_source,
            1024,
            None,
            None,
            &cancelled,
            None,
        )
        .await,
        Err(netcatty_ssh::SftpError::Cancelled)
    );
    assert!(
        !sftp
            .try_exists("/cancelled.bin")
            .await
            .expect("cancelled path absent")
    );

    sftp.write_file("/stream-safe.bin", b"old")
        .await
        .expect("safe stream original");
    let safe_plan =
        netcatty_ssh::SftpClient::plan_safe_upload("/stream-safe.bin").expect("safe stream plan");
    let mut safe_source = Cursor::new(content.clone());
    let safe_outcome = sftp
        .stream_safe_upload(
            &safe_plan,
            &mut safe_source,
            content.len() as u64,
            Some("source-v1"),
            None,
            &netcatty_ssh::SftpTransferControl::new(),
            None,
        )
        .await
        .expect("safe stream upload");
    assert!(safe_outcome.upload.replaced_existing);
    assert_eq!(safe_outcome.checkpoint.remote_path, safe_plan.staged_path);
    assert_eq!(
        sftp.read_file("/stream-safe.bin")
            .await
            .expect("safe stream published"),
        content
    );

    sftp.close().await.expect("close SFTP");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn direct_private_key_connection_authenticates_without_plaintext_frontend_contract() {
    let (port, server_task) = start_server().await;
    let private_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("client key")
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("serialize key");
    let config = connection_config(port, SshAuthMethod::Key);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Key),
        has_private_key: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_private_key(SecretText::new(private_key.to_string()), None);

    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await
        .expect("public key authentication");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

#[tokio::test]
async fn openssh_user_certificate_authenticates_with_its_private_key() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let (port, server_task) = start_server().await;
    let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("CA key");
    let user_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("user key");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        user_key.public_key(),
        now.saturating_sub(60),
        now + 3600,
    )
    .expect("certificate builder");
    builder.serial(1).expect("serial");
    builder.key_id("netcatty-test").expect("key id");
    builder
        .cert_type(certificate::CertType::User)
        .expect("user certificate");
    builder.valid_principal("tester").expect("principal");
    let certificate = builder.sign(&ca_key).expect("sign certificate");
    let private_key = user_key
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("serialize user key");
    let config = connection_config(port, SshAuthMethod::Certificate);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Certificate),
        has_private_key: true,
        has_certificate: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_private_key(SecretText::new(private_key.to_string()), None)
        .with_certificate(certificate.to_openssh().expect("serialize certificate"));

    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await
        .expect("OpenSSH certificate authentication");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

struct OtpResponder;

#[async_trait::async_trait]
impl InteractiveAuthResponder for OtpResponder {
    async fn respond(
        &self,
        request: AuthenticationPrompts,
    ) -> Result<Vec<SecretText>, TransportError> {
        assert_eq!(request.name, "Test MFA");
        assert_eq!(request.prompts.len(), 1);
        assert!(!request.prompts[0].echo);
        Ok(vec![SecretText::new("otp-123")])
    }
}

#[tokio::test]
async fn keyboard_interactive_authentication_supports_mfa_prompts() {
    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Password);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        requires_mfa: true,
        ..SshAuthConfig::default()
    };

    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &ConnectionCredentials::empty(),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            Some(Arc::new(OtpResponder)),
        )
        .await
        .expect("keyboard-interactive authentication");
    connection.disconnect().await.expect("disconnect");
    server_task.abort();
}

async fn connect_with_password(
    config: &NormalizedSshConnectionConfig,
) -> netcatty_ssh::SshConnection {
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_password(SecretText::new("correct horse battery staple"));
    DirectConnector::new()
        .connect(
            config,
            &auth,
            &credentials,
            Arc::new(KnownHostsVerifier::disabled(&config.hostname, config.port)),
            None,
        )
        .await
        .expect("proxied SSH connection")
}

async fn start_http_proxy(target_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("HTTP proxy bind");
    let port = listener.local_addr().expect("HTTP proxy address").port();
    let task = tokio::spawn(async move {
        let (mut incoming, _) = listener.accept().await.expect("HTTP proxy accept");
        let mut header = Vec::new();
        let mut byte = [0_u8; 1];
        while !header.ends_with(b"\r\n\r\n") {
            incoming.read_exact(&mut byte).await.expect("HTTP request");
            header.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&header).starts_with("CONNECT 127.0.0.1:"));
        let mut target = tokio::net::TcpStream::connect(("127.0.0.1", target_port))
            .await
            .expect("HTTP proxy target");
        incoming
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .expect("HTTP proxy response");
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut target).await;
    });
    (port, task)
}

async fn start_socks5_proxy(target_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("SOCKS proxy bind");
    let port = listener.local_addr().expect("SOCKS proxy address").port();
    let task = tokio::spawn(async move {
        let (mut incoming, _) = listener.accept().await.expect("SOCKS proxy accept");
        let mut greeting = [0_u8; 3];
        incoming
            .read_exact(&mut greeting)
            .await
            .expect("SOCKS greeting");
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        incoming
            .write_all(&[0x05, 0x00])
            .await
            .expect("SOCKS method");

        let mut request_header = [0_u8; 5];
        incoming
            .read_exact(&mut request_header)
            .await
            .expect("SOCKS request");
        assert_eq!(&request_header[..4], &[0x05, 0x01, 0x00, 0x03]);
        let host_len = usize::from(request_header[4]);
        let mut destination = vec![0_u8; host_len + 2];
        incoming
            .read_exact(&mut destination)
            .await
            .expect("SOCKS destination");
        assert_eq!(&destination[..host_len], b"127.0.0.1");
        let mut target = tokio::net::TcpStream::connect(("127.0.0.1", target_port))
            .await
            .expect("SOCKS target");
        incoming
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .expect("SOCKS response");
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut target).await;
    });
    (port, task)
}

#[tokio::test]
async fn http_connect_proxy_tunnels_a_real_ssh_handshake() {
    let (ssh_port, ssh_task) = start_server().await;
    let (proxy_port, proxy_task) = start_http_proxy(ssh_port).await;
    let mut config = connection_config(ssh_port, SshAuthMethod::Password);
    config.proxy = Some(NormalizedProxyConfig {
        proxy_type: ProxyType::Http,
        host: Some("127.0.0.1".to_owned()),
        port: Some(proxy_port),
        command: None,
        identity_id: None,
        username: None,
        has_password: false,
    });

    connect_with_password(&config)
        .await
        .disconnect()
        .await
        .expect("disconnect");
    proxy_task.abort();
    ssh_task.abort();
}

#[tokio::test]
async fn socks5_proxy_tunnels_a_real_ssh_handshake() {
    let (ssh_port, ssh_task) = start_server().await;
    let (proxy_port, proxy_task) = start_socks5_proxy(ssh_port).await;
    let mut config = connection_config(ssh_port, SshAuthMethod::Password);
    config.proxy = Some(NormalizedProxyConfig {
        proxy_type: ProxyType::Socks5,
        host: Some("127.0.0.1".to_owned()),
        port: Some(proxy_port),
        command: None,
        identity_id: None,
        username: None,
        has_password: false,
    });

    connect_with_password(&config)
        .await
        .disconnect()
        .await
        .expect("disconnect");
    proxy_task.abort();
    ssh_task.abort();
}

struct TestChainResolver {
    endpoints: tokio::sync::Mutex<HashMap<String, ResolvedSshEndpoint>>,
    resolutions: tokio::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HostChainResolver for TestChainResolver {
    async fn resolve(&self, host_id: &str) -> Result<ResolvedSshEndpoint, TransportError> {
        self.resolutions.lock().await.push(host_id.to_owned());
        self.endpoints.lock().await.remove(host_id).ok_or_else(|| {
            TransportError::new(
                TransportErrorCode::JumpHostUnavailable,
                "jump host unavailable",
            )
        })
    }
}

fn password_endpoint(port: u16) -> ResolvedSshEndpoint {
    ResolvedSshEndpoint {
        config: connection_config(port, SshAuthMethod::Password),
        auth: SshAuthConfig {
            method: Some(SshAuthMethod::Password),
            has_password: true,
            ..SshAuthConfig::default()
        },
        credentials: ConnectionCredentials::empty()
            .with_password(SecretText::new("correct horse battery staple")),
        verifier: Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
        interactive: None,
    }
}

#[tokio::test]
async fn saved_host_ids_build_a_real_two_jump_ssh_chain() {
    let (target_port, target_task) = start_server().await;
    let (second_port, second_task) = start_server().await;
    let (first_port, first_task) = start_server().await;
    let mut target = password_endpoint(target_port);
    target.config.jump_hosts = vec![
        SshJumpHost {
            host_id: "first".to_owned(),
        },
        SshJumpHost {
            host_id: "second".to_owned(),
        },
    ];
    target.config.legacy_algorithms = true;
    let mut first = password_endpoint(first_port);
    first.config.legacy_algorithms_explicit = false;
    let mut second = password_endpoint(second_port);
    second.config.legacy_algorithms = false;
    second.config.legacy_algorithms_explicit = true;
    let resolver = TestChainResolver {
        endpoints: tokio::sync::Mutex::new(HashMap::from([
            ("first".to_owned(), first),
            ("second".to_owned(), second),
        ])),
        resolutions: tokio::sync::Mutex::new(Vec::new()),
    };

    let connection = DirectConnector::new()
        .connect_chain(target, &resolver)
        .await
        .expect("two jump SSH chain");
    let mut shell = connection
        .open_shell(ShellOptions::default())
        .await
        .expect("target shell");
    assert_eq!(
        shell.next_event().await.expect("target ready"),
        ShellEvent::Data(b"ready\r\n".to_vec())
    );
    shell.write(b"through-two-jumps").await.expect("write");
    assert_eq!(
        shell.next_event().await.expect("target echo"),
        ShellEvent::Data(b"through-two-jumps".to_vec())
    );
    connection.disconnect().await.expect("disconnect chain");

    first_task.abort();
    second_task.abort();
    target_task.abort();
}

#[tokio::test]
async fn managed_session_uses_real_two_jump_chain_for_shell_sftp_and_cancellation() {
    let (target_port, target_task) = start_server().await;
    let (second_port, second_task) = start_server().await;
    let (first_port, first_task) = start_server().await;
    let mut target = password_endpoint(target_port);
    target.config.jump_hosts = vec![
        SshJumpHost {
            host_id: "first".to_owned(),
        },
        SshJumpHost {
            host_id: "second".to_owned(),
        },
    ];
    let resolver = Arc::new(TestChainResolver {
        endpoints: tokio::sync::Mutex::new(HashMap::from([
            ("first".to_owned(), password_endpoint(first_port)),
            ("second".to_owned(), password_endpoint(second_port)),
        ])),
        resolutions: tokio::sync::Mutex::new(Vec::new()),
    });
    let manager = SessionManager::new();
    let mut started = manager
        .begin_chain(target, resolver.clone(), ShellOptions::default())
        .await;

    assert_eq!(
        started.events.recv().await.expect("connecting event"),
        SessionEvent::Connecting
    );
    assert_eq!(
        started.events.recv().await.expect("connected event"),
        SessionEvent::Connected
    );
    assert_eq!(
        started.events.recv().await.expect("target ready"),
        SessionEvent::Data(b"ready\r\n".to_vec())
    );
    assert_eq!(
        resolver.resolutions.lock().await.as_slice(),
        ["first", "second"]
    );

    manager
        .send_input(&started.session_id, b"managed-chain-shell".to_vec())
        .await
        .expect("managed chain input");
    assert_eq!(
        started.events.recv().await.expect("target echo"),
        SessionEvent::Data(b"managed-chain-shell".to_vec())
    );

    manager
        .sftp_create_dir(&started.session_id, "/managed-chain".to_owned())
        .await
        .expect("managed chain SFTP directory");
    manager
        .sftp_write_file(
            &started.session_id,
            "/managed-chain/file.txt".to_owned(),
            b"managed chain SFTP".to_vec(),
        )
        .await
        .expect("managed chain SFTP write");
    assert_eq!(
        manager
            .sftp_read_file(&started.session_id, "/managed-chain/file.txt".to_owned())
            .await
            .expect("managed chain SFTP read"),
        b"managed chain SFTP"
    );

    manager
        .cancel(&started.session_id)
        .await
        .expect("cancel managed chain");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match started.events.recv().await.expect("managed chain event") {
                SessionEvent::Closed => break,
                SessionEvent::Error { code, message } => {
                    panic!("managed chain cancellation failed: {code:?}: {message}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("managed chain close event");
    tokio::time::timeout(Duration::from_secs(1), async {
        while manager.active_count().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("managed chain cleanup");

    first_task.abort();
    second_task.abort();
    target_task.abort();
}

#[tokio::test]
async fn direct_tcpip_channel_builds_a_real_one_jump_ssh_connection() {
    let (target_port, target_task) = start_server().await;
    let (jump_port, jump_task) = start_server().await;
    let connector = DirectConnector::new();
    let jump_endpoint = password_endpoint(jump_port);
    let jump = connector
        .connect(
            &jump_endpoint.config,
            &jump_endpoint.auth,
            &jump_endpoint.credentials,
            jump_endpoint.verifier,
            None,
        )
        .await
        .expect("connect jump");
    let target_endpoint = password_endpoint(target_port);
    let target = connector
        .connect_via_jump(
            &jump,
            &target_endpoint.config,
            &target_endpoint.auth,
            &target_endpoint.credentials,
            target_endpoint.verifier,
            None,
        )
        .await
        .expect("connect through jump");
    let mut shell = target
        .open_shell(ShellOptions::default())
        .await
        .expect("target shell");
    assert_eq!(
        shell.next_event().await.expect("target ready"),
        ShellEvent::Data(b"ready\r\n".to_vec())
    );
    target.disconnect().await.expect("target disconnect");
    jump.disconnect().await.expect("jump disconnect");
    jump_task.abort();
    target_task.abort();
}

#[tokio::test]
async fn cancellation_prevents_network_connection_attempts() {
    let connector = DirectConnector::new();
    connector.cancel();
    let config = connection_config(9, SshAuthMethod::Auto);
    let result = connector
        .connect(
            &config,
            &SshAuthConfig::default(),
            &ConnectionCredentials::empty(),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", 9)),
            None,
        )
        .await;
    let error = match result {
        Ok(_) => panic!("cancelled connector unexpectedly connected"),
        Err(error) => error,
    };

    assert_eq!(error.code, TransportErrorCode::Cancelled);
}

#[cfg(windows)]
#[tokio::test]
async fn unavailable_windows_agent_pipe_fails_closed_without_falling_back() {
    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Key);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Key),
        has_public_key: true,
        use_ssh_agent: Some(true),
        identity_agent: Some(format!(
            r"\\.\pipe\netcatty-agent-that-does-not-exist-{}",
            std::process::id()
        )),
        ..SshAuthConfig::default()
    };
    let result = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &ConnectionCredentials::empty(),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await;
    let error = match result {
        Ok(_) => panic!("missing Agent pipe unexpectedly authenticated"),
        Err(error) => error,
    };
    assert_eq!(error.code, TransportErrorCode::CredentialUnavailable);
    server_task.abort();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_named_pipe_agent_signs_only_with_the_selected_identity() {
    use futures::SinkExt as _;
    use russh::keys::agent::{client::AgentClient, server as agent_server};
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = format!(
        r"\\.\pipe\netcatty-agent-integration-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let (mut incoming_sender, incoming_receiver) = futures::channel::mpsc::unbounded();
    let (ready_sender, mut ready_receiver) = tokio::sync::mpsc::unbounded_channel();
    let accept_pipe_name = pipe_name.clone();
    let accept_task = tokio::spawn(async move {
        let mut first = true;
        loop {
            let mut options = ServerOptions::new();
            options.first_pipe_instance(first);
            let server = options
                .create(&accept_pipe_name)
                .expect("create test Agent pipe");
            first = false;
            ready_sender.send(()).expect("announce Agent pipe");
            server.connect().await.expect("connect test Agent client");
            if incoming_sender.send(Ok(server)).await.is_err() {
                break;
            }
        }
    });
    let agent_task = tokio::spawn(async move {
        agent_server::serve(incoming_receiver, ())
            .await
            .expect("serve test Agent");
    });

    ready_receiver.recv().await.expect("first Agent listener");
    let selected_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("selected Agent key");
    let selected_public = selected_key
        .public_key()
        .to_openssh()
        .expect("selected public key");
    let wrong_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong Agent key");
    let wrong_public = wrong_key
        .public_key()
        .to_openssh()
        .expect("wrong public key");
    let mut provisioning = AgentClient::connect_named_pipe(&pipe_name)
        .await
        .expect("connect provisioning client");
    provisioning
        .add_identity(&selected_key, &[])
        .await
        .expect("add Agent identity");
    drop(provisioning);

    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Key);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Key),
        has_public_key: true,
        use_ssh_agent: Some(true),
        identity_agent: Some(pipe_name),
        identities_only: Some(true),
        ..SshAuthConfig::default()
    };

    ready_receiver
        .recv()
        .await
        .expect("mismatch Agent listener");
    let mismatch = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &ConnectionCredentials::empty().with_agent_public_keys(vec![wrong_public]),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await;
    let mismatch_error = match mismatch {
        Ok(_) => panic!("unselected identity unexpectedly authenticated"),
        Err(error) => error,
    };
    assert_eq!(
        mismatch_error.code,
        TransportErrorCode::AuthenticationFailed
    );

    ready_receiver
        .recv()
        .await
        .expect("selected Agent listener");
    let connection = DirectConnector::new()
        .connect(
            &config,
            &auth,
            &ConnectionCredentials::empty().with_agent_public_keys(vec![selected_public]),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
        )
        .await
        .expect("selected Agent identity authenticates");
    connection.disconnect().await.expect("disconnect");

    accept_task.abort();
    agent_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn managed_session_streams_bounded_events_and_accepts_commands() {
    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Password);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_password(SecretText::new("correct horse battery staple"));
    let manager = SessionManager::new();
    let mut started = manager
        .begin(
            config,
            auth,
            credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
            ShellOptions::default(),
        )
        .await;

    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Connecting)
    ));
    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Connected)
    ));
    assert_eq!(
        started.events.recv().await.expect("ready event"),
        SessionEvent::Data(b"ready\r\n".to_vec())
    );

    manager
        .send_input(&started.session_id, b"managed-input".to_vec())
        .await
        .expect("managed input");
    assert_eq!(
        started.events.recv().await.expect("echo event"),
        SessionEvent::Data(b"managed-input".to_vec())
    );

    manager
        .sftp_create_dir(&started.session_id, "/managed".to_owned())
        .await
        .expect("managed SFTP directory");
    manager
        .sftp_write_file(
            &started.session_id,
            "/managed/file.txt".to_owned(),
            b"managed SFTP".to_vec(),
        )
        .await
        .expect("managed SFTP write");
    assert_eq!(
        manager
            .sftp_read_file(&started.session_id, "/managed/file.txt".to_owned())
            .await
            .expect("managed SFTP read"),
        b"managed SFTP"
    );
    assert_eq!(
        manager
            .sftp_read_dir(&started.session_id, "/managed".to_owned())
            .await
            .expect("managed SFTP list")
            .len(),
        1
    );

    let upload_bytes: Vec<u8> = (0..600_000).map(|index| (index % 239) as u8).collect();
    let local_upload = std::env::temp_dir().join(format!(
        "netcatty-managed-upload-{}-{}.bin",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::write(&local_upload, &upload_bytes)
        .await
        .expect("write local transfer fixture");
    let mut transfer = manager
        .begin_sftp_upload(
            &started.session_id,
            local_upload.clone(),
            "/managed/uploaded.bin".to_owned(),
            None,
            None,
        )
        .await
        .expect("start managed upload");
    let mut saw_progress = false;
    loop {
        match transfer.events.recv().await.expect("transfer event") {
            netcatty_ssh::SftpTransferEvent::Progress { .. } => saw_progress = true,
            netcatty_ssh::SftpTransferEvent::Completed {
                checkpoint,
                replaced_existing,
            } => {
                assert!(!replaced_existing);
                assert_eq!(checkpoint.bytes_transferred, upload_bytes.len() as u64);
                break;
            }
            netcatty_ssh::SftpTransferEvent::Failed { message, .. } => {
                panic!("managed upload failed: {message}")
            }
            _ => {}
        }
    }
    assert!(saw_progress);
    assert_eq!(
        manager
            .sftp_read_file(&started.session_id, "/managed/uploaded.bin".to_owned())
            .await
            .expect("read managed upload"),
        upload_bytes
    );

    let local_download = std::env::temp_dir().join(format!(
        "netcatty-managed-download-{}-{}.bin",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::write(&local_download, b"previous local contents")
        .await
        .expect("write previous local download");
    let download = manager
        .begin_sftp_download(
            &started.session_id,
            "/managed/uploaded.bin".to_owned(),
            local_download.clone(),
            None,
            None,
        )
        .await
        .expect("start managed download");
    let download_id = download.transfer_id;
    let mut download_events = download.events;
    assert!(!download_id.is_empty());
    let mut saw_download_progress = false;
    loop {
        match download_events.recv().await.expect("download event") {
            netcatty_ssh::SftpTransferEvent::Progress { .. } => {
                saw_download_progress = true;
            }
            netcatty_ssh::SftpTransferEvent::Completed {
                checkpoint,
                replaced_existing,
            } => {
                assert!(replaced_existing);
                assert_eq!(checkpoint.bytes_transferred, upload_bytes.len() as u64);
                break;
            }
            netcatty_ssh::SftpTransferEvent::Failed { message, .. } => {
                panic!("managed download failed: {message}")
            }
            _ => {}
        }
    }
    assert!(saw_download_progress);
    assert_eq!(
        tokio::fs::read(&local_download)
            .await
            .expect("read managed download"),
        upload_bytes
    );
    assert!(
        !tokio::fs::try_exists(format!(
            "{}.netcatty-download.part",
            local_download.display()
        ))
        .await
        .expect("download stage absent")
    );
    assert!(
        !tokio::fs::try_exists(format!(
            "{}.netcatty-download.backup",
            local_download.display()
        ))
        .await
        .expect("download backup absent")
    );

    tokio::fs::remove_file(&local_upload)
        .await
        .expect("remove local transfer fixture");
    tokio::fs::remove_file(&local_download)
        .await
        .expect("remove local download fixture");

    manager
        .close(&started.session_id)
        .await
        .expect("managed close");
    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Closed)
    ));
    tokio::task::yield_now().await;
    assert_eq!(manager.active_count().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn managed_session_reuses_exact_authenticated_transport_with_isolated_shell_lifecycle() {
    let (port, server_task, accepted_clients) = start_counted_server().await;
    let config = connection_config(port, SshAuthMethod::Password);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_password(SecretText::new("correct horse battery staple"));
    let manager = SessionManager::new();
    let mut source = manager
        .begin(
            config,
            auth,
            credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
            ShellOptions::default(),
        )
        .await;

    assert_eq!(
        source.events.recv().await.expect("source connecting"),
        SessionEvent::Connecting
    );
    assert_eq!(
        source.events.recv().await.expect("source connected"),
        SessionEvent::Connected
    );
    assert_eq!(
        source.events.recv().await.expect("source ready"),
        SessionEvent::Data(b"ready\r\n".to_vec())
    );
    assert_eq!(accepted_clients.load(Ordering::Relaxed), 1);

    let mut clone = manager
        .begin_reuse(&source.session_id, ShellOptions::default())
        .await
        .expect("reuse authenticated source transport");
    assert_eq!(
        clone.events.recv().await.expect("clone connecting"),
        SessionEvent::Connecting
    );
    assert_eq!(
        clone.events.recv().await.expect("clone connected"),
        SessionEvent::Connected
    );
    assert_eq!(
        clone.events.recv().await.expect("clone ready"),
        SessionEvent::Data(b"ready\r\n".to_vec())
    );
    assert_eq!(
        accepted_clients.load(Ordering::Relaxed),
        1,
        "opening a cloned shell must not perform another TCP/SSH authentication"
    );

    manager
        .send_input(&source.session_id, b"source-only".to_vec())
        .await
        .expect("source input");
    assert_eq!(
        source.events.recv().await.expect("source echo"),
        SessionEvent::Data(b"source-only".to_vec())
    );
    manager
        .send_input(&clone.session_id, b"clone-only".to_vec())
        .await
        .expect("clone input");
    assert_eq!(
        clone.events.recv().await.expect("clone echo"),
        SessionEvent::Data(b"clone-only".to_vec())
    );

    manager
        .cancel(&source.session_id)
        .await
        .expect("cancel exact source session");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if source.events.recv().await.expect("source close event") == SessionEvent::Closed {
                break;
            }
        }
    })
    .await
    .expect("source closes independently");

    manager
        .send_input(&clone.session_id, b"clone-survives".to_vec())
        .await
        .expect("clone survives source cancellation");
    assert_eq!(
        clone.events.recv().await.expect("surviving clone echo"),
        SessionEvent::Data(b"clone-survives".to_vec())
    );
    manager
        .sftp_create_dir(&clone.session_id, "/clone-owned".to_owned())
        .await
        .expect("clone owns an independent SFTP worker");

    let late_clone = manager
        .begin_reuse(&source.session_id, ShellOptions::default())
        .await;
    assert!(matches!(
        late_clone,
        Err(netcatty_ssh::SessionManagerError::NotFound)
            | Err(netcatty_ssh::SessionManagerError::NotConnected)
    ));

    manager.close(&clone.session_id).await.expect("close clone");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if clone.events.recv().await.expect("clone close event") == SessionEvent::Closed {
                break;
            }
        }
        while manager.active_count().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("clone cleanup");
    server_task.abort();
}

#[tokio::test]
async fn managed_transport_reuse_has_a_bounded_shell_session_count() {
    let (port, server_task) = start_server().await;
    let manager = SessionManager::new();
    let mut source = manager
        .begin(
            connection_config(port, SshAuthMethod::Password),
            SshAuthConfig {
                method: Some(SshAuthMethod::Password),
                has_password: true,
                ..SshAuthConfig::default()
            },
            ConnectionCredentials::empty()
                .with_password(SecretText::new("correct horse battery staple")),
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
            ShellOptions::default(),
        )
        .await;
    while source.events.recv().await.expect("source event") != SessionEvent::Connected {}

    let mut session_ids = vec![source.session_id.clone()];
    for _ in 1..64 {
        let clone = manager
            .begin_reuse(&source.session_id, ShellOptions::default())
            .await
            .expect("session within transport limit");
        session_ids.push(clone.session_id);
    }
    assert!(matches!(
        manager
            .begin_reuse(&source.session_id, ShellOptions::default())
            .await,
        Err(netcatty_ssh::SessionManagerError::TransportSessionLimit)
    ));

    for session_id in &session_ids {
        manager
            .cancel(session_id)
            .await
            .expect("cancel bounded session");
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager.active_count().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded sessions clean up");
    server_task.abort();
}

#[tokio::test]
async fn managed_sftp_recursively_uploads_and_downloads_nested_tree_with_empty_directories() {
    let (port, server_task) = start_server().await;
    let config = connection_config(port, SshAuthMethod::Password);
    let auth = SshAuthConfig {
        method: Some(SshAuthMethod::Password),
        has_password: true,
        ..SshAuthConfig::default()
    };
    let credentials = ConnectionCredentials::empty()
        .with_password(SecretText::new("correct horse battery staple"));
    let manager = SessionManager::new();
    let mut started = manager
        .begin(
            config,
            auth,
            credentials,
            Arc::new(KnownHostsVerifier::disabled("127.0.0.1", port)),
            None,
            ShellOptions::default(),
        )
        .await;

    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Connecting)
    ));
    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Connected)
    ));
    assert_eq!(
        started.events.recv().await.expect("ready event"),
        SessionEvent::Data(b"ready\r\n".to_vec())
    );

    let fixture_root = std::env::temp_dir().join(format!(
        "netcatty-managed-directory-transfer-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let upload_root = fixture_root.join("upload-source");
    let download_root = fixture_root.join("download-target");
    tokio::fs::create_dir_all(upload_root.join("nested/deeper"))
        .await
        .expect("create nested upload fixture");
    tokio::fs::create_dir_all(upload_root.join("empty/leaf"))
        .await
        .expect("create empty upload fixture");
    tokio::fs::write(upload_root.join("root.txt"), b"root-level contents")
        .await
        .expect("write root upload fixture");
    tokio::fs::write(
        upload_root.join("nested/child.bin"),
        (0..180_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    )
    .await
    .expect("write nested upload fixture");
    tokio::fs::write(
        upload_root.join("nested/deeper/grandchild.txt"),
        b"deeply nested contents",
    )
    .await
    .expect("write deeply nested upload fixture");

    let expected_root = tokio::fs::read(upload_root.join("root.txt"))
        .await
        .expect("read root upload fixture");
    let expected_child = tokio::fs::read(upload_root.join("nested/child.bin"))
        .await
        .expect("read nested upload fixture");
    let expected_grandchild = tokio::fs::read(upload_root.join("nested/deeper/grandchild.txt"))
        .await
        .expect("read deeply nested upload fixture");
    let expected_total_bytes =
        (expected_root.len() + expected_child.len() + expected_grandchild.len()) as u64;

    let mut upload = manager
        .begin_sftp_upload_directory(
            &started.session_id,
            upload_root.clone(),
            "/managed-tree".to_owned(),
            LocalTreeOptions::default(),
            None,
        )
        .await
        .expect("start managed directory upload");
    assert!(!upload.transfer_id.is_empty());
    let upload_checkpoint = tokio::time::timeout(Duration::from_secs(15), async {
        let mut saw_scanning = false;
        let mut saw_progress = false;
        loop {
            match upload.events.recv().await.expect("directory upload event") {
                SftpTransferEvent::DirectoryScanning => saw_scanning = true,
                SftpTransferEvent::DirectoryProgress {
                    total_files,
                    total_bytes,
                    ..
                } => {
                    saw_progress = true;
                    assert_eq!(total_files, 3);
                    assert_eq!(total_bytes, expected_total_bytes);
                }
                SftpTransferEvent::DirectoryCompleted {
                    files_completed,
                    total_bytes,
                    skipped_entries,
                    checkpoint,
                } => {
                    assert!(saw_scanning);
                    assert!(saw_progress);
                    assert_eq!(files_completed, 3);
                    assert_eq!(total_bytes, expected_total_bytes);
                    assert_eq!(skipped_entries, 0);
                    assert_eq!(checkpoint.covered_entries, 3);
                    assert_eq!(checkpoint.completed_entries, 3);
                    break checkpoint;
                }
                SftpTransferEvent::DirectoryCancelled { checkpoint } => panic!(
                    "managed directory upload was cancelled after {} entries",
                    checkpoint.completed_entries
                ),
                SftpTransferEvent::DirectoryFailed {
                    message,
                    failed_files,
                    ..
                } => panic!("managed directory upload failed for {failed_files} files: {message}"),
                _ => {}
            }
        }
    })
    .await
    .expect("managed directory upload timed out");
    assert_eq!(upload_checkpoint.completed_entries, 3);

    assert_eq!(
        manager
            .sftp_read_file(&started.session_id, "/managed-tree/root.txt".to_owned())
            .await
            .expect("read uploaded root file"),
        expected_root
    );
    assert_eq!(
        manager
            .sftp_read_file(
                &started.session_id,
                "/managed-tree/nested/child.bin".to_owned(),
            )
            .await
            .expect("read uploaded nested file"),
        expected_child
    );
    assert_eq!(
        manager
            .sftp_read_file(
                &started.session_id,
                "/managed-tree/nested/deeper/grandchild.txt".to_owned(),
            )
            .await
            .expect("read uploaded deeply nested file"),
        expected_grandchild
    );
    assert!(
        manager
            .sftp_read_dir(&started.session_id, "/managed-tree/empty/leaf".to_owned())
            .await
            .expect("read uploaded empty directory")
            .is_empty()
    );

    let mut download = manager
        .begin_sftp_download_directory(
            &started.session_id,
            "/managed-tree".to_owned(),
            download_root.clone(),
            RemoteTreeOptions::default(),
            None,
        )
        .await
        .expect("start managed directory download");
    assert!(!download.transfer_id.is_empty());
    let download_checkpoint = tokio::time::timeout(Duration::from_secs(15), async {
        let mut saw_scanning = false;
        let mut saw_progress = false;
        loop {
            match download
                .events
                .recv()
                .await
                .expect("directory download event")
            {
                SftpTransferEvent::DirectoryScanning => saw_scanning = true,
                SftpTransferEvent::DirectoryProgress {
                    total_files,
                    total_bytes,
                    ..
                } => {
                    saw_progress = true;
                    assert_eq!(total_files, 3);
                    assert_eq!(total_bytes, expected_total_bytes);
                }
                SftpTransferEvent::DirectoryCompleted {
                    files_completed,
                    total_bytes,
                    skipped_entries,
                    checkpoint,
                } => {
                    assert!(saw_scanning);
                    assert!(saw_progress);
                    assert_eq!(files_completed, 3);
                    assert_eq!(total_bytes, expected_total_bytes);
                    assert_eq!(skipped_entries, 0);
                    assert_eq!(checkpoint.covered_entries, 3);
                    assert_eq!(checkpoint.completed_entries, 3);
                    break checkpoint;
                }
                SftpTransferEvent::DirectoryCancelled { checkpoint } => panic!(
                    "managed directory download was cancelled after {} entries",
                    checkpoint.completed_entries
                ),
                SftpTransferEvent::DirectoryFailed {
                    message,
                    failed_files,
                    ..
                } => {
                    panic!("managed directory download failed for {failed_files} files: {message}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("managed directory download timed out");
    assert_eq!(download_checkpoint.covered_entries, 3);
    assert_eq!(download_checkpoint.completed_entries, 3);

    assert_eq!(
        tokio::fs::read(download_root.join("root.txt"))
            .await
            .expect("read downloaded root file"),
        expected_root
    );
    assert_eq!(
        tokio::fs::read(download_root.join("nested/child.bin"))
            .await
            .expect("read downloaded nested file"),
        expected_child
    );
    assert_eq!(
        tokio::fs::read(download_root.join("nested/deeper/grandchild.txt"))
            .await
            .expect("read downloaded deeply nested file"),
        expected_grandchild
    );
    assert!(
        tokio::fs::metadata(download_root.join("empty/leaf"))
            .await
            .expect("downloaded empty directory metadata")
            .is_dir()
    );
    assert!(
        tokio::fs::read_dir(download_root.join("empty/leaf"))
            .await
            .expect("read downloaded empty directory")
            .next_entry()
            .await
            .expect("read downloaded empty directory entry")
            .is_none()
    );

    let mut resumed_download = manager
        .begin_sftp_download_directory(
            &started.session_id,
            "/managed-tree".to_owned(),
            download_root.clone(),
            RemoteTreeOptions::default(),
            Some(download_checkpoint.clone()),
        )
        .await
        .expect("resume completed managed directory download");
    let resumed_checkpoint = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match resumed_download
                .events
                .recv()
                .await
                .expect("resumed directory download event")
            {
                SftpTransferEvent::DirectoryCompleted {
                    files_completed,
                    checkpoint,
                    ..
                } => {
                    assert_eq!(files_completed, 3);
                    break checkpoint;
                }
                SftpTransferEvent::DirectoryCancelled { .. } => {
                    panic!("resumed directory download was cancelled")
                }
                SftpTransferEvent::DirectoryFailed { message, .. } => {
                    panic!("resumed directory download failed: {message}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("resumed managed directory download timed out");
    assert_eq!(resumed_checkpoint, download_checkpoint);

    tokio::fs::remove_dir_all(&fixture_root)
        .await
        .expect("remove managed directory transfer fixtures");
    manager
        .close(&started.session_id)
        .await
        .expect("managed directory transfer close");
    assert!(matches!(
        started.events.recv().await,
        Ok(SessionEvent::Closed)
    ));
    server_task.abort();
}
