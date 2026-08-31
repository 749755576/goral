use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, ChannelOpenHandle, KeyboardInteractiveAuthResponse, Session};
use russh::keys::agent::{AgentIdentity, client::AgentClient};
use russh::keys::{Certificate, PrivateKeyWithHashAlg, decode_secret_key, ssh_key};
use russh::{Channel, ChannelMsg, ChannelOpenFailure, Disconnect, Preferred};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::proxy::{AsyncStream, connect_proxy};
use crate::{
    AuthAttemptKind, HostKeyClassification, HostKeyStatus, KnownHost, LiveHostKey,
    NormalizedSshConnectionConfig, SshAuthConfig, classify_host_key, plan_authentication,
};

const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 16;
const MAX_PENDING_FORWARDED_TCPIP_CHANNELS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportErrorCode {
    Cancelled,
    TcpTimeout,
    HandshakeTimeout,
    ConnectionFailed,
    HostKeyRejected,
    UnsupportedAlgorithm,
    CredentialUnavailable,
    InvalidPrivateKey,
    InvalidCertificate,
    ProxyFailed,
    AuthenticationFailed,
    InteractiveAuthFailed,
    JumpHostUnavailable,
    SftpFailed,
    ChannelFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    pub code: TransportErrorCode,
    message: &'static str,
}

impl TransportError {
    pub const fn new(code: TransportErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for TransportError {}

impl From<russh::Error> for TransportError {
    fn from(_: russh::Error) -> Self {
        Self::new(
            TransportErrorCode::ConnectionFailed,
            "SSH 连接或协议协商失败",
        )
    }
}

/// A zeroizing secret container that intentionally does not implement Debug, Clone, or Serialize.
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

pub struct ConnectionCredentials {
    password: Option<SecretText>,
    private_key: Option<SecretText>,
    private_key_passphrase: Option<SecretText>,
    certificate: Option<String>,
    agent_public_keys: Vec<String>,
    proxy_password: Option<SecretText>,
}

/// Borrowed, native-only access to credentials that have already passed the
/// saved-host custody boundary.
///
/// The view is deliberately neither cloneable nor serializable. It can only
/// live for the duration of [`ConnectionCredentials::expose_to_native_client`]
/// and its `Debug` output reports presence, never values.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<netcatty_ssh::NativeClientCredentialView<'static>>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<netcatty_ssh::NativeClientCredentialView<'static>>();
/// ```
pub struct NativeClientCredentialView<'a> {
    password: Option<&'a str>,
    private_key: Option<&'a str>,
    private_key_passphrase: Option<&'a str>,
    certificate: Option<&'a str>,
    agent_public_keys: &'a [String],
}

impl NativeClientCredentialView<'_> {
    #[must_use]
    pub fn password_bytes(&self) -> Option<&[u8]> {
        self.password.map(str::as_bytes)
    }

    #[must_use]
    pub fn private_key_bytes(&self) -> Option<&[u8]> {
        self.private_key.map(str::as_bytes)
    }

    #[must_use]
    pub fn private_key_passphrase_bytes(&self) -> Option<&[u8]> {
        self.private_key_passphrase.map(str::as_bytes)
    }

    #[must_use]
    pub fn certificate_bytes(&self) -> Option<&[u8]> {
        self.certificate.map(str::as_bytes)
    }

    #[must_use]
    pub fn agent_public_keys(&self) -> &[String] {
        self.agent_public_keys
    }
}

impl fmt::Debug for NativeClientCredentialView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeClientCredentialView")
            .field("has_password", &self.password.is_some())
            .field("has_private_key", &self.private_key.is_some())
            .field(
                "has_private_key_passphrase",
                &self.private_key_passphrase.is_some(),
            )
            .field("has_certificate", &self.certificate.is_some())
            .field("agent_public_key_count", &self.agent_public_keys.len())
            .finish()
    }
}

impl ConnectionCredentials {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            password: None,
            private_key: None,
            private_key_passphrase: None,
            certificate: None,
            agent_public_keys: Vec::new(),
            proxy_password: None,
        }
    }

    #[must_use]
    pub fn with_password(mut self, password: SecretText) -> Self {
        self.password = Some(password);
        self
    }

    #[must_use]
    pub fn with_private_key(
        mut self,
        private_key: SecretText,
        passphrase: Option<SecretText>,
    ) -> Self {
        self.private_key = Some(private_key);
        self.private_key_passphrase = passphrase;
        self
    }

    #[must_use]
    pub fn with_certificate(mut self, certificate: impl Into<String>) -> Self {
        self.certificate = Some(certificate.into());
        self
    }

    #[must_use]
    pub fn with_agent_public_keys(mut self, public_keys: Vec<String>) -> Self {
        self.agent_public_keys = public_keys;
        self
    }

    #[must_use]
    pub fn with_proxy_password(mut self, password: SecretText) -> Self {
        self.proxy_password = Some(password);
        self
    }

    /// Exposes already-resolved credentials to one native client adapter
    /// without making secret-bearing fields generally accessible.
    ///
    /// ```compile_fail
    /// let credentials = netcatty_ssh::ConnectionCredentials::empty()
    ///     .with_password(netcatty_ssh::SecretText::new("example"));
    /// let escaped = credentials.expose_to_native_client(|view| view.password_bytes());
    /// drop(credentials);
    /// let _ = escaped;
    /// ```
    pub fn expose_to_native_client<R>(
        &self,
        callback: impl for<'a> FnOnce(NativeClientCredentialView<'a>) -> R,
    ) -> R {
        callback(NativeClientCredentialView {
            password: self.password.as_ref().map(SecretText::expose),
            private_key: self.private_key.as_ref().map(SecretText::expose),
            private_key_passphrase: self.private_key_passphrase.as_ref().map(SecretText::expose),
            certificate: self.certificate.as_deref(),
            agent_public_keys: &self.agent_public_keys,
        })
    }

    pub(crate) fn proxy_password(&self) -> Option<&str> {
        self.proxy_password.as_ref().map(SecretText::expose)
    }

    fn take_proxy_password(&mut self) -> Option<SecretText> {
        self.proxy_password.take()
    }
}

impl Default for ConnectionCredentials {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationPrompt {
    pub text: String,
    pub echo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationPrompts {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<AuthenticationPrompt>,
}

#[async_trait]
pub trait InteractiveAuthResponder: Send + Sync {
    async fn respond(
        &self,
        request: AuthenticationPrompts,
    ) -> Result<Vec<SecretText>, TransportError>;
}

#[async_trait]
pub trait HostKeyVerifier: Send + Sync {
    async fn verify(&self, key: &LiveHostKey) -> Result<bool, TransportError>;
}

/// All secret-bearing material for one resolved host. This type stays entirely
/// inside Rust and is intentionally neither serializable nor cloneable.
pub struct ResolvedSshEndpoint {
    pub config: NormalizedSshConnectionConfig,
    pub auth: SshAuthConfig,
    pub credentials: ConnectionCredentials,
    pub verifier: Arc<dyn HostKeyVerifier>,
    pub interactive: Option<Arc<dyn InteractiveAuthResponder>>,
}

#[async_trait]
pub trait HostChainResolver: Send + Sync {
    async fn resolve(&self, host_id: &str) -> Result<ResolvedSshEndpoint, TransportError>;
}

pub struct KnownHostsVerifier {
    hostname: String,
    port: u16,
    known_hosts: Vec<KnownHost>,
    verification_enabled: bool,
}

impl KnownHostsVerifier {
    #[must_use]
    pub fn new(hostname: impl Into<String>, port: u16, known_hosts: Vec<KnownHost>) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            known_hosts,
            verification_enabled: true,
        }
    }

    #[must_use]
    pub fn disabled(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            known_hosts: Vec::new(),
            verification_enabled: false,
        }
    }

    #[must_use]
    pub fn classify(&self, key: &LiveHostKey) -> HostKeyClassification {
        classify_host_key(&self.known_hosts, &self.hostname, self.port, key)
    }
}

#[async_trait]
impl HostKeyVerifier for KnownHostsVerifier {
    async fn verify(&self, key: &LiveHostKey) -> Result<bool, TransportError> {
        Ok(!self.verification_enabled || self.classify(key).status == HostKeyStatus::Trusted)
    }
}

struct ClientHandler {
    verifier: Arc<dyn HostKeyVerifier>,
    forwarded_tcpip: mpsc::Sender<crate::ForwardedTcpipConnection>,
}

impl client::Handler for ClientHandler {
    type Error = TransportError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.verifier
            .verify(&LiveHostKey::from_public_key(server_public_key))
            .await
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(connected_port) = u16::try_from(connected_port) else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let Ok(originator_port) = u16::try_from(originator_port) else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let Ok(permit) = self.forwarded_tcpip.clone().try_reserve_owned() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        reply.accept().await;
        permit.send(crate::ForwardedTcpipConnection {
            connected_address: connected_address.to_owned(),
            connected_port,
            originator_address: originator_address.to_owned(),
            originator_port,
            stream: Box::new(channel.into_stream()),
        });
        Ok(())
    }
}

#[derive(Clone)]
pub struct DirectConnector {
    cancellation: CancellationToken,
}

impl DirectConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
        }
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Resolve the saved jump-host IDs in order and build the complete nested
    /// SSH route. The returned target connection owns every parent connection,
    /// so dropping temporary resolver values cannot tear down the tunnel.
    pub async fn connect_chain(
        &self,
        mut target: ResolvedSshEndpoint,
        resolver: &dyn HostChainResolver,
    ) -> Result<SshConnection, TransportError> {
        let jump_ids = target.config.jump_hosts.clone();
        let mut connections = Vec::with_capacity(jump_ids.len());

        for (index, jump_id) in jump_ids.iter().enumerate() {
            if self.cancellation.is_cancelled() {
                return Err(cancelled());
            }
            let mut endpoint = resolver.resolve(&jump_id.host_id).await?;

            // Legacy mode historically widened the whole chain unless a hop
            // explicitly chose true/false. Narrowing settings remain per-host.
            if !endpoint.config.legacy_algorithms_explicit {
                endpoint.config.legacy_algorithms = target.config.legacy_algorithms;
            }

            // The target proxy is the route into the first bastion when that
            // bastion has no explicit proxy of its own.
            if index == 0 && endpoint.config.proxy.is_none() {
                endpoint.config.proxy.clone_from(&target.config.proxy);
                endpoint.credentials.proxy_password = target.credentials.take_proxy_password();
            }

            let connection = if let Some(parent) = connections.last() {
                self.connect_via_jump(
                    parent,
                    &endpoint.config,
                    &endpoint.auth,
                    &endpoint.credentials,
                    endpoint.verifier,
                    endpoint.interactive,
                )
                .await?
            } else {
                self.connect(
                    &endpoint.config,
                    &endpoint.auth,
                    &endpoint.credentials,
                    endpoint.verifier,
                    endpoint.interactive,
                )
                .await?
            };
            connections.push(connection);
        }

        let mut connection = if let Some(parent) = connections.last() {
            self.connect_via_jump(
                parent,
                &target.config,
                &target.auth,
                &target.credentials,
                target.verifier,
                target.interactive,
            )
            .await?
        } else {
            self.connect(
                &target.config,
                &target.auth,
                &target.credentials,
                target.verifier,
                target.interactive,
            )
            .await?
        };
        connection.parents = connections;
        Ok(connection)
    }

    pub async fn connect(
        &self,
        config: &NormalizedSshConnectionConfig,
        auth: &SshAuthConfig,
        credentials: &ConnectionCredentials,
        verifier: Arc<dyn HostKeyVerifier>,
        interactive: Option<Arc<dyn InteractiveAuthResponder>>,
    ) -> Result<SshConnection, TransportError> {
        let tcp_timeout = Duration::from_secs(u64::from(config.timeouts.tcp_connect_seconds));
        let stream: Box<dyn AsyncStream> = if let Some(proxy) = config.proxy.as_ref() {
            tokio::select! {
                () = self.cancellation.cancelled() => return Err(cancelled()),
                result = tokio::time::timeout(tcp_timeout, connect_proxy(proxy, &config.hostname, config.port, credentials.proxy_password())) => {
                    match result {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => return Err(error),
                        Err(_) => return Err(TransportError::new(TransportErrorCode::TcpTimeout, "SSH 代理连接超时")),
                    }
                }
            }
        } else {
            let address = (config.hostname.as_str(), config.port);
            let stream = tokio::select! {
                () = self.cancellation.cancelled() => return Err(cancelled()),
                result = tokio::time::timeout(tcp_timeout, TcpStream::connect(address)) => {
                    match result {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(_)) => return Err(TransportError::new(TransportErrorCode::ConnectionFailed, "无法建立 SSH TCP 连接")),
                        Err(_) => return Err(TransportError::new(TransportErrorCode::TcpTimeout, "SSH TCP 连接超时")),
                    }
                }
            };
            stream.set_nodelay(true).map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ConnectionFailed,
                    "无法配置 SSH TCP 连接",
                )
            })?;
            Box::new(stream)
        };

        self.connect_stream(config, auth, credentials, verifier, interactive, stream)
            .await
    }

    pub async fn connect_via_jump(
        &self,
        jump: &SshConnection,
        config: &NormalizedSshConnectionConfig,
        auth: &SshAuthConfig,
        credentials: &ConnectionCredentials,
        verifier: Arc<dyn HostKeyVerifier>,
        interactive: Option<Arc<dyn InteractiveAuthResponder>>,
    ) -> Result<SshConnection, TransportError> {
        let channel = jump
            .handle
            .channel_open_direct_tcpip(&config.hostname, u32::from(config.port), "127.0.0.1", 0)
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ConnectionFailed,
                    "跳板机无法打开目标 SSH 通道",
                )
            })?;
        self.connect_stream(
            config,
            auth,
            credentials,
            verifier,
            interactive,
            channel.into_stream(),
        )
        .await
    }

    pub async fn connect_stream<R>(
        &self,
        config: &NormalizedSshConnectionConfig,
        auth: &SshAuthConfig,
        credentials: &ConnectionCredentials,
        verifier: Arc<dyn HostKeyVerifier>,
        interactive: Option<Arc<dyn InteractiveAuthResponder>>,
        stream: R,
    ) -> Result<SshConnection, TransportError>
    where
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let client_config = Arc::new(build_client_config(config)?);
        let (forwarded_tcpip_sender, forwarded_tcpip_receiver) =
            mpsc::channel(MAX_PENDING_FORWARDED_TCPIP_CHANNELS);
        let handler = ClientHandler {
            verifier,
            forwarded_tcpip: forwarded_tcpip_sender,
        };
        let handshake_timeout = Duration::from_secs(u64::from(config.timeouts.auth_ready_seconds));
        let mut handle = tokio::select! {
            () = self.cancellation.cancelled() => return Err(cancelled()),
            result = tokio::time::timeout(handshake_timeout, client::connect_stream(client_config, stream, handler)) => {
                match result {
                    Ok(Ok(handle)) => handle,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(TransportError::new(TransportErrorCode::HandshakeTimeout, "SSH 协议握手超时")),
                }
            }
        };

        let authentication = authenticate(
            &mut handle,
            &config.username,
            auth,
            credentials,
            interactive.as_deref(),
            &self.cancellation,
        );
        let authenticated = tokio::select! {
            () = self.cancellation.cancelled() => return Err(cancelled()),
            result = tokio::time::timeout(handshake_timeout, authentication) => {
                result.map_err(|_| TransportError::new(TransportErrorCode::HandshakeTimeout, "SSH 认证等待超时"))??
            }
        };
        if !authenticated {
            return Err(TransportError::new(
                TransportErrorCode::AuthenticationFailed,
                "SSH 身份认证失败",
            ));
        }

        Ok(SshConnection {
            handle,
            parents: Vec::new(),
            forwarded_tcpip: Mutex::new(forwarded_tcpip_receiver),
        })
    }
}

impl Default for DirectConnector {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SshConnection {
    handle: client::Handle<ClientHandler>,
    parents: Vec<SshConnection>,
    forwarded_tcpip: Mutex<mpsc::Receiver<crate::ForwardedTcpipConnection>>,
}

impl SshConnection {
    /// Starts the fixed Mosh bootstrap command in a remote PTY.
    ///
    /// Keeping the command inside the transport boundary prevents renderer
    /// payloads from turning the Mosh bootstrap into a general SSH exec API.
    pub async fn open_mosh_server(&self, size: TerminalSize) -> Result<SshShell, TransportError> {
        self.open_fixed_exec_pty(
            ShellOptions {
                terminal: "xterm-256color".to_owned(),
                size,
                environment: Vec::new(),
            },
            "mosh-server new -s -c 256",
        )
        .await
    }

    pub(crate) async fn open_direct_tcpip_stream(
        &self,
        destination_host: &str,
        destination_port: u16,
        originator: SocketAddr,
    ) -> Result<Box<dyn crate::PortForwardStream>, TransportError> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(
                destination_host,
                u32::from(destination_port),
                originator.ip().to_string(),
                u32::from(originator.port()),
            )
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "无法打开 SSH 端口转发通道",
                )
            })?;
        Ok(Box::new(channel.into_stream()))
    }

    pub(crate) async fn request_remote_tcpip_forward(
        &self,
        address: &str,
        port: u16,
    ) -> Result<u16, TransportError> {
        let assigned_port = self
            .handle
            .tcpip_forward(address, u32::from(port))
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "远程 SSH 服务器拒绝端口转发请求",
                )
            })?;
        if assigned_port == 0 {
            Ok(port)
        } else {
            u16::try_from(assigned_port).map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "远程 SSH 服务器返回了无效端口",
                )
            })
        }
    }

    pub(crate) async fn cancel_remote_tcpip_forward(
        &self,
        address: &str,
        port: u16,
    ) -> Result<(), TransportError> {
        self.handle
            .cancel_tcpip_forward(address, u32::from(port))
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "无法停止远程 SSH 端口转发",
                )
            })
    }

    pub(crate) async fn accept_remote_tcpip_forward(
        &self,
    ) -> Result<crate::ForwardedTcpipConnection, TransportError> {
        self.forwarded_tcpip
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "远程 SSH 端口转发通道已关闭",
                )
            })
    }

    pub async fn open_sftp(&self) -> Result<crate::SftpClient, TransportError> {
        let channel = self.handle.channel_open_session().await.map_err(|_| {
            TransportError::new(
                TransportErrorCode::SftpFailed,
                "Unable to open SFTP channel",
            )
        })?;
        channel.request_subsystem(true, "sftp").await.map_err(|_| {
            TransportError::new(
                TransportErrorCode::SftpFailed,
                "Remote host rejected the SFTP subsystem",
            )
        })?;
        crate::SftpClient::from_stream(channel.into_stream())
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::SftpFailed,
                    "Unable to initialize the SFTP subsystem",
                )
            })
    }

    pub async fn open_shell(&self, options: ShellOptions) -> Result<SshShell, TransportError> {
        let channel = self.handle.channel_open_session().await.map_err(|_| {
            TransportError::new(TransportErrorCode::ChannelFailed, "无法打开 SSH 会话通道")
        })?;
        for (name, value) in options.environment {
            channel.set_env(false, name, value).await.map_err(|_| {
                TransportError::new(TransportErrorCode::ChannelFailed, "无法设置 SSH 环境变量")
            })?;
        }
        channel
            .request_pty(
                true,
                &options.terminal,
                options.size.columns,
                options.size.rows,
                options.size.pixel_width,
                options.size.pixel_height,
                &[],
            )
            .await
            .map_err(|_| {
                TransportError::new(TransportErrorCode::ChannelFailed, "远程主机拒绝分配终端")
            })?;
        channel.request_shell(true).await.map_err(|_| {
            TransportError::new(TransportErrorCode::ChannelFailed, "远程主机拒绝启动 Shell")
        })?;
        Ok(SshShell { channel })
    }

    /// Runs one command on its own channel and captures the result.
    ///
    /// Deliberately does NOT request a PTY. A PTY merges stderr into stdout,
    /// echoes the command back, and lets the remote emit control sequences —
    /// all of which corrupt machine-readable output such as
    /// `docker ps --format '{{json .}}'`. Callers that want a terminal want
    /// `open_shell` instead.
    ///
    /// Output is bounded on both streams: a remote that never stops writing
    /// must not be able to exhaust this process's memory. Hitting the bound
    /// truncates and reports it rather than failing, because a truncated
    /// listing is still useful and the caller can narrow its query.
    pub async fn exec_capture(
        &self,
        command: &str,
        limits: ExecLimits,
    ) -> Result<CommandOutput, TransportError> {
        let channel = self.handle.channel_open_session().await.map_err(|_| {
            TransportError::new(TransportErrorCode::ChannelFailed, "无法打开 SSH 命令通道")
        })?;
        channel.exec(true, command).await.map_err(|_| {
            TransportError::new(TransportErrorCode::ChannelFailed, "远程主机拒绝执行命令")
        })?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        let mut truncated = false;
        let mut channel = channel;

        let drain = async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        truncated |= append_bounded(&mut stdout, &data, limits.max_output_bytes);
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        truncated |= append_bounded(&mut stderr, &data, limits.max_output_bytes);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status: code }) => {
                        exit_status = Some(code);
                    }
                    // Keep draining after EOF: the exit status often arrives
                    // after it, and dropping it would report every command as
                    // "status unknown".
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        };

        let timed_out = tokio::time::timeout(limits.timeout, drain).await.is_err();
        if timed_out {
            let _ = channel.close().await;
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_status,
            truncated,
            timed_out,
        })
    }

    async fn open_fixed_exec_pty(
        &self,
        options: ShellOptions,
        command: &'static str,
    ) -> Result<SshShell, TransportError> {
        let channel = self.handle.channel_open_session().await.map_err(|_| {
            TransportError::new(
                TransportErrorCode::ChannelFailed,
                "Unable to open the SSH bootstrap channel",
            )
        })?;
        for (name, value) in options.environment {
            channel.set_env(false, name, value).await.map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "Unable to set the SSH bootstrap environment",
                )
            })?;
        }
        channel
            .request_pty(
                true,
                &options.terminal,
                options.size.columns,
                options.size.rows,
                options.size.pixel_width,
                options.size.pixel_height,
                &[],
            )
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorCode::ChannelFailed,
                    "The remote host rejected the bootstrap terminal",
                )
            })?;
        channel.exec(true, command).await.map_err(|_| {
            TransportError::new(
                TransportErrorCode::ChannelFailed,
                "The remote host rejected the Mosh bootstrap",
            )
        })?;
        Ok(SshShell { channel })
    }

    pub async fn disconnect(&self) -> Result<(), TransportError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .map_err(TransportError::from)?;
        for parent in self.parents.iter().rev() {
            let _ = parent
                .handle
                .disconnect(Disconnect::ByApplication, "", "")
                .await;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            columns: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellOptions {
    pub terminal: String,
    pub size: TerminalSize,
    pub environment: Vec<(String, String)>,
}

impl Default for ShellOptions {
    fn default() -> Self {
        Self {
            terminal: "xterm-256color".to_owned(),
            size: TerminalSize::default(),
            environment: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEvent {
    Data(Vec<u8>),
    ExtendedData { code: u32, data: Vec<u8> },
    Eof,
    ExitStatus(u32),
    Closed,
}

/// Bounds for a single captured command.
///
/// Both fields exist to keep a hostile or merely broken remote from
/// wedging the client: unbounded output exhausts memory, and a command that
/// never exits pins a channel forever.
#[derive(Debug, Clone, Copy)]
pub struct ExecLimits {
    pub max_output_bytes: usize,
    pub timeout: Duration,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            // Comfortably larger than a long `docker ps` or process listing,
            // far smaller than anything that threatens the process.
            max_output_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_secs(20),
        }
    }
}

/// The result of one captured command.
///
/// `exit_status` is optional because a remote may close the channel without
/// sending one; that is reported rather than guessed at, so a caller never
/// mistakes "no status" for success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    pub truncated: bool,
    pub timed_out: bool,
}

impl CommandOutput {
    /// True only for an explicit zero exit status. A missing status is not
    /// success — callers parsing machine output must not run on a command
    /// whose completion was never confirmed.
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.exit_status == Some(0)
    }

    pub fn stdout_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    pub fn stderr_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

/// Appends up to the remaining budget and reports whether anything was cut.
fn append_bounded(sink: &mut Vec<u8>, data: &[u8], max: usize) -> bool {
    if sink.len() >= max {
        return !data.is_empty();
    }
    let room = max - sink.len();
    if data.len() <= room {
        sink.extend_from_slice(data);
        false
    } else {
        sink.extend_from_slice(&data[..room]);
        true
    }
}

pub struct SshShell {
    channel: Channel<client::Msg>,
}

impl SshShell {
    pub async fn write(&self, data: &[u8]) -> Result<(), TransportError> {
        self.channel
            .data_bytes(data.to_vec())
            .await
            .map_err(|_| TransportError::new(TransportErrorCode::ChannelFailed, "SSH 输入发送失败"))
    }

    pub async fn resize(&self, size: TerminalSize) -> Result<(), TransportError> {
        self.channel
            .window_change(size.columns, size.rows, size.pixel_width, size.pixel_height)
            .await
            .map_err(|_| {
                TransportError::new(TransportErrorCode::ChannelFailed, "SSH 终端尺寸更新失败")
            })
    }

    pub async fn next_event(&mut self) -> Result<ShellEvent, TransportError> {
        loop {
            match self.channel.wait().await {
                Some(ChannelMsg::Data { data }) => return Ok(ShellEvent::Data(data.to_vec())),
                Some(ChannelMsg::ExtendedData { ext, data }) => {
                    return Ok(ShellEvent::ExtendedData {
                        code: ext,
                        data: data.to_vec(),
                    });
                }
                Some(ChannelMsg::Eof) => return Ok(ShellEvent::Eof),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    return Ok(ShellEvent::ExitStatus(exit_status));
                }
                Some(ChannelMsg::Close) | None => return Ok(ShellEvent::Closed),
                Some(_) => {}
            }
        }
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        let _ = self.channel.eof().await;
        self.channel
            .close()
            .await
            .map_err(|_| TransportError::new(TransportErrorCode::ChannelFailed, "SSH 会话关闭失败"))
    }
}

fn build_client_config(
    config: &NormalizedSshConnectionConfig,
) -> Result<client::Config, TransportError> {
    let algorithms = crate::algorithms::effective_algorithms(
        config.legacy_algorithms,
        config.skip_ecdsa_host_key,
        &config.algorithms,
    );
    let preferred = Preferred {
        kex: Cow::Owned(parse_names(&algorithms.kex)?),
        cipher: Cow::Owned(parse_names(&algorithms.cipher)?),
        mac: Cow::Owned(parse_names(&algorithms.hmac)?),
        compression: Cow::Owned(parse_names(&algorithms.compress)?),
        key: Cow::Owned(
            algorithms
                .server_host_key
                .iter()
                .map(|name| ssh_key::Algorithm::from_str(name).map_err(|_| unsupported_algorithm()))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };

    let keepalive_interval = config
        .keepalive
        .override_global
        .then(|| {
            config
                .keepalive
                .interval_seconds
                .filter(|seconds| *seconds > 0)
                .map(|seconds| Duration::from_secs(u64::from(seconds)))
        })
        .flatten();

    Ok(client::Config {
        preferred,
        keepalive_interval,
        keepalive_max: config.keepalive.count_max.map_or(3, |value| value as usize),
        nodelay: true,
        ..client::Config::default()
    })
}

fn parse_names<T>(values: &[String]) -> Result<Vec<T>, TransportError>
where
    for<'a> T: TryFrom<&'a str>,
{
    values
        .iter()
        .map(|name| T::try_from(name.as_str()).map_err(|_| unsupported_algorithm()))
        .collect()
}

async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    auth: &SshAuthConfig,
    credentials: &ConnectionCredentials,
    interactive: Option<&dyn InteractiveAuthResponder>,
    cancellation: &CancellationToken,
) -> Result<bool, TransportError> {
    let plan = plan_authentication(auth);
    for attempt in plan.attempts {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let success = match attempt.kind {
            AuthAttemptKind::None => handle.authenticate_none(username).await?.success(),
            AuthAttemptKind::Password => match credentials.password.as_ref() {
                Some(password) => handle
                    .authenticate_password(username, password.expose())
                    .await?
                    .success(),
                None => false,
            },
            AuthAttemptKind::SelectedKey => {
                authenticate_selected_key(handle, username, auth, credentials).await?
            }
            AuthAttemptKind::Certificate => {
                authenticate_certificate(handle, username, credentials).await?
            }
            AuthAttemptKind::KeyboardInteractive => match interactive {
                Some(responder) => {
                    authenticate_interactive(handle, username, responder, cancellation).await?
                }
                None => false,
            },
            AuthAttemptKind::SshAgent => {
                authenticate_agent(handle, username, auth, credentials).await?
            }
            AuthAttemptKind::DefaultKeys => false,
        };
        if success {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn authenticate_selected_key(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    auth: &SshAuthConfig,
    credentials: &ConnectionCredentials,
) -> Result<bool, TransportError> {
    if let Some(private_key) = credentials.private_key.as_ref() {
        let key = decode_secret_key(
            private_key.expose(),
            credentials
                .private_key_passphrase
                .as_ref()
                .map(SecretText::expose),
        )
        .map_err(|_| invalid_private_key())?;
        return authenticate_key(handle, username, key).await;
    }

    for path in &auth.identity_file_paths {
        let key = russh::keys::load_secret_key(
            path,
            credentials
                .private_key_passphrase
                .as_ref()
                .map(SecretText::expose),
        )
        .map_err(|_| invalid_private_key())?;
        if authenticate_key(handle, username, key).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn authenticate_key(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    key: ssh_key::PrivateKey,
) -> Result<bool, TransportError> {
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    Ok(handle
        .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await?
        .success())
}

async fn authenticate_certificate(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    credentials: &ConnectionCredentials,
) -> Result<bool, TransportError> {
    let Some(private_key) = credentials.private_key.as_ref() else {
        return Ok(false);
    };
    let Some(certificate) = credentials.certificate.as_deref() else {
        return Ok(false);
    };
    let key = decode_secret_key(
        private_key.expose(),
        credentials
            .private_key_passphrase
            .as_ref()
            .map(SecretText::expose),
    )
    .map_err(|_| invalid_private_key())?;
    let certificate = Certificate::from_openssh(certificate).map_err(|_| {
        TransportError::new(TransportErrorCode::InvalidCertificate, "SSH 证书格式无效")
    })?;
    Ok(handle
        .authenticate_openssh_cert(username, Arc::new(key), certificate)
        .await?
        .success())
}

async fn authenticate_interactive(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    responder: &dyn InteractiveAuthResponder,
    cancellation: &CancellationToken,
) -> Result<bool, TransportError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await?;
    for _ in 0..MAX_KEYBOARD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if cancellation.is_cancelled() {
                    return Err(cancelled());
                }
                let expected = prompts.len();
                let answers = responder
                    .respond(AuthenticationPrompts {
                        name,
                        instructions,
                        prompts: prompts
                            .into_iter()
                            .map(|prompt| AuthenticationPrompt {
                                text: prompt.prompt,
                                echo: prompt.echo,
                            })
                            .collect(),
                    })
                    .await?;
                if answers.len() != expected {
                    return Err(TransportError::new(
                        TransportErrorCode::InteractiveAuthFailed,
                        "SSH 交互认证回答数量不匹配",
                    ));
                }
                response = handle
                    .authenticate_keyboard_interactive_respond(
                        answers
                            .into_iter()
                            .map(|answer| answer.expose().to_owned())
                            .collect(),
                    )
                    .await?;
            }
        }
    }
    Err(TransportError::new(
        TransportErrorCode::InteractiveAuthFailed,
        "SSH 交互认证轮次过多",
    ))
}

async fn authenticate_agent(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    auth: &SshAuthConfig,
    credentials: &ConnectionCredentials,
) -> Result<bool, TransportError> {
    let Some(path) = resolve_agent_path(auth) else {
        return Ok(false);
    };

    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(|_| agent_unavailable())?;
        authenticate_agent_stream(handle, username, auth, credentials, stream).await
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;

        let stream = ClientOptions::new()
            .open(path)
            .map_err(|_| agent_unavailable())?;
        authenticate_agent_stream(handle, username, auth, credentials, stream).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, username, auth, credentials, path);
        Ok(false)
    }
}

async fn authenticate_agent_stream<R>(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    auth: &SshAuthConfig,
    credentials: &ConnectionCredentials,
    stream: R,
) -> Result<bool, TransportError>
where
    R: russh::keys::agent::client::AgentStream + Send + Unpin,
{
    let mut agent = AgentClient::connect(stream);
    let identities = agent
        .request_identities()
        .await
        .map_err(|_| agent_unavailable())?;
    for identity in identities {
        let public_key = identity.public_key();
        if !agent_identity_is_selected(public_key.as_ref(), auth, credentials) {
            continue;
        }
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        let result = match identity {
            AgentIdentity::PublicKey { key, .. } => handle
                .authenticate_publickey_with(username, key, hash, &mut agent)
                .await
                .map_err(|_| agent_unavailable())?,
            AgentIdentity::Certificate { certificate, .. } => handle
                .authenticate_certificate_with(username, certificate, hash, &mut agent)
                .await
                .map_err(|_| agent_unavailable())?,
        };
        if result.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn agent_identity_is_selected(
    key: &ssh_key::PublicKey,
    auth: &SshAuthConfig,
    credentials: &ConnectionCredentials,
) -> bool {
    let restrict =
        auth.selected_method() == crate::SshAuthMethod::Key || auth.identities_only == Some(true);
    if !restrict {
        return true;
    }
    credentials.agent_public_keys.iter().any(|selected| {
        ssh_key::PublicKey::from_openssh(selected)
            .is_ok_and(|selected| selected.key_data() == key.key_data())
    })
}

fn resolve_agent_path(auth: &SshAuthConfig) -> Option<String> {
    if auth.use_ssh_agent == Some(false) {
        return None;
    }
    if let Some(value) = auth.identity_agent.as_deref().map(str::trim) {
        if value.eq_ignore_ascii_case("none") {
            return None;
        }
        if !value.is_empty() && value != "$SSH_AUTH_SOCK" {
            return Some(value.to_owned());
        }
    }
    if let Ok(value) = std::env::var("SSH_AUTH_SOCK") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    #[cfg(windows)]
    {
        Some(r"\\.\pipe\openssh-ssh-agent".to_owned())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn unsupported_algorithm() -> TransportError {
    TransportError::new(
        TransportErrorCode::UnsupportedAlgorithm,
        "SSH 算法覆盖包含当前传输库不支持的算法",
    )
}

fn invalid_private_key() -> TransportError {
    TransportError::new(
        TransportErrorCode::InvalidPrivateKey,
        "SSH 私钥无法读取或解密",
    )
}

fn agent_unavailable() -> TransportError {
    TransportError::new(
        TransportErrorCode::CredentialUnavailable,
        "SSH Agent 不可用或无法完成签名",
    )
}

fn cancelled() -> TransportError {
    TransportError::new(TransportErrorCode::Cancelled, "SSH 连接已取消")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        ConnectionCredentials, KnownHostsVerifier, SecretText, build_client_config,
        resolve_agent_path,
    };
    use crate::{
        AlgorithmOverrides, HostKeyStatus, LiveHostKey, NormalizedKeepaliveConfig,
        NormalizedSshConnectionConfig, NormalizedSshTimeouts, SshAuthConfig, SshAuthMethod,
    };

    fn config() -> NormalizedSshConnectionConfig {
        NormalizedSshConnectionConfig {
            hostname: "127.0.0.1".to_owned(),
            port: 22,
            username: "tester".to_owned(),
            auth_method: SshAuthMethod::Auto,
            proxy: None,
            jump_hosts: Vec::new(),
            legacy_algorithms: false,
            legacy_algorithms_explicit: false,
            skip_ecdsa_host_key: false,
            algorithms: AlgorithmOverrides::default(),
            keepalive: NormalizedKeepaliveConfig {
                override_global: true,
                interval_seconds: Some(30),
                count_max: Some(4),
            },
            timeouts: NormalizedSshTimeouts {
                tcp_connect_seconds: 2,
                auth_ready_seconds: 2,
            },
        }
    }

    #[test]
    fn native_client_credential_view_is_borrowed_and_debug_redacted() {
        const PASSWORD: &str = "password-sentinel-native-view";
        const PRIVATE_KEY: &str = "private-key-sentinel-native-view";
        const PASSPHRASE: &str = "passphrase-sentinel-native-view";
        const CERTIFICATE: &str = "certificate-sentinel-native-view";
        let credentials = ConnectionCredentials::empty()
            .with_password(SecretText::new(PASSWORD))
            .with_private_key(
                SecretText::new(PRIVATE_KEY),
                Some(SecretText::new(PASSPHRASE)),
            )
            .with_certificate(CERTIFICATE)
            .with_agent_public_keys(vec!["ssh-ed25519 AAAATEST".to_owned()])
            .with_proxy_password(SecretText::new("proxy-sentinel-native-view"));

        credentials.expose_to_native_client(|view| {
            assert_eq!(view.password_bytes(), Some(PASSWORD.as_bytes()));
            assert_eq!(view.private_key_bytes(), Some(PRIVATE_KEY.as_bytes()));
            assert_eq!(
                view.private_key_passphrase_bytes(),
                Some(PASSPHRASE.as_bytes())
            );
            assert_eq!(view.certificate_bytes(), Some(CERTIFICATE.as_bytes()));
            assert_eq!(view.agent_public_keys(), ["ssh-ed25519 AAAATEST"]);

            let debug = format!("{view:?}");
            assert!(debug.contains("has_password"));
            assert!(debug.contains("agent_public_key_count"));
            for sentinel in [
                PASSWORD,
                PRIVATE_KEY,
                PASSPHRASE,
                CERTIFICATE,
                "proxy-sentinel-native-view",
                "AAAATEST",
            ] {
                assert!(!debug.contains(sentinel));
            }
        });
    }

    #[test]
    fn client_config_maps_keepalive_and_algorithm_overrides() {
        let mut config = config();
        config.algorithms.kex = vec!["curve25519-sha256".to_owned()];
        let client = build_client_config(&config).expect("supported config");

        assert_eq!(client.keepalive_interval.unwrap().as_secs(), 30);
        assert_eq!(client.keepalive_max, 4);
        assert_eq!(client.preferred.kex.len(), 1);
        assert!(client.nodelay);
    }

    #[test]
    fn unsupported_algorithm_fails_before_network_access() {
        let mut config = config();
        config.algorithms.cipher = vec!["not-a-real-cipher".to_owned()];

        assert!(build_client_config(&config).is_err());
    }

    #[test]
    fn explicit_agent_path_and_agent_opt_out_are_respected() {
        let explicit = SshAuthConfig {
            identity_agent: Some("custom-agent-endpoint".to_owned()),
            ..SshAuthConfig::default()
        };
        assert_eq!(
            resolve_agent_path(&explicit).as_deref(),
            Some("custom-agent-endpoint")
        );

        let disabled = SshAuthConfig {
            use_ssh_agent: Some(false),
            identity_agent: Some("custom-agent-endpoint".to_owned()),
            ..SshAuthConfig::default()
        };
        assert!(resolve_agent_path(&disabled).is_none());

        let none = SshAuthConfig {
            identity_agent: Some("none".to_owned()),
            ..SshAuthConfig::default()
        };
        assert!(resolve_agent_path(&none).is_none());
    }

    #[tokio::test]
    async fn known_hosts_verifier_rejects_unknown_keys() {
        use super::HostKeyVerifier;

        let verifier = Arc::new(KnownHostsVerifier::new("host", 22, Vec::new()));
        let live = LiveHostKey {
            key_type: "ssh-ed25519".to_owned(),
            fingerprint: "new".to_owned(),
            public_key: String::new(),
        };

        assert_eq!(verifier.classify(&live).status, HostKeyStatus::Unknown);
        assert!(!verifier.verify(&live).await.expect("verification result"));
    }
}

#[cfg(test)]
mod exec_capture_tests {
    use super::*;

    #[test]
    fn append_bounded_keeps_everything_within_budget() {
        let mut sink = Vec::new();
        assert!(!append_bounded(&mut sink, b"hello", 16));
        assert!(!append_bounded(&mut sink, b" world", 16));
        assert_eq!(sink, b"hello world");
    }

    #[test]
    fn append_bounded_truncates_at_the_bound_and_reports_it() {
        let mut sink = Vec::new();
        assert!(append_bounded(&mut sink, b"0123456789", 4));
        assert_eq!(sink, b"0123");
    }

    #[test]
    fn append_bounded_stays_truncated_once_full() {
        let mut sink = vec![b'x'; 4];
        // Already at the bound: further data is dropped, and that is reported
        // so a caller never parses a silently clipped listing as complete.
        assert!(append_bounded(&mut sink, b"more", 4));
        assert_eq!(sink.len(), 4);
    }

    #[test]
    fn append_bounded_ignores_an_empty_chunk_at_the_bound() {
        let mut sink = vec![b'x'; 4];
        assert!(!append_bounded(&mut sink, b"", 4));
    }

    #[test]
    fn a_missing_exit_status_is_not_success() {
        let output = CommandOutput {
            stdout: b"{}".to_vec(),
            stderr: Vec::new(),
            exit_status: None,
            truncated: false,
            timed_out: false,
        };
        assert!(!output.succeeded(), "no status must never read as success");
    }

    #[test]
    fn a_timeout_is_not_success_even_with_a_zero_status() {
        let output = CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            truncated: false,
            timed_out: true,
        };
        assert!(!output.succeeded());
    }

    #[test]
    fn only_an_explicit_zero_status_succeeds() {
        let ok = CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            truncated: false,
            timed_out: false,
        };
        let failed = CommandOutput {
            exit_status: Some(127),
            ..ok.clone()
        };
        assert!(ok.succeeded());
        assert!(!failed.succeeded());
    }

    #[test]
    fn default_limits_are_bounded_on_both_axes() {
        let limits = ExecLimits::default();
        assert!(limits.max_output_bytes > 0);
        assert!(limits.timeout > Duration::ZERO);
    }
}
