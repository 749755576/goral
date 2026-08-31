use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{SshConnection, TransportError};

const EVENT_BUFFER_SIZE: usize = 64;
const MAX_RULE_ID_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 512;
const MAX_BIND_ADDRESS_BYTES: usize = 1_024;
const MAX_REMOTE_HOST_BYTES: usize = 1_024;
const MAX_FORWARD_CONNECTIONS_PER_RULE: usize = 128;
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);

pub trait PortForwardStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> PortForwardStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub struct ForwardedTcpipConnection {
    pub connected_address: String,
    pub connected_port: u16,
    pub originator_address: String,
    pub originator_port: u16,
    pub stream: Box<dyn PortForwardStream>,
}

#[async_trait]
pub trait DirectTcpipOpener: Send + Sync {
    async fn open_direct_tcpip(
        &self,
        destination_host: &str,
        destination_port: u16,
        originator: SocketAddr,
    ) -> Result<Box<dyn PortForwardStream>, PortForwardError>;
}

#[async_trait]
impl DirectTcpipOpener for SshConnection {
    async fn open_direct_tcpip(
        &self,
        destination_host: &str,
        destination_port: u16,
        originator: SocketAddr,
    ) -> Result<Box<dyn PortForwardStream>, PortForwardError> {
        self.open_direct_tcpip_stream(destination_host, destination_port, originator)
            .await
            .map_err(PortForwardError::Transport)
    }
}

#[async_trait]
pub trait RemoteTcpipForwarder: Send + Sync {
    async fn request_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<u16, PortForwardError>;

    async fn accept_remote_forward(&self) -> Result<ForwardedTcpipConnection, PortForwardError>;

    async fn cancel_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<(), PortForwardError>;
}

#[async_trait]
impl RemoteTcpipForwarder for SshConnection {
    async fn request_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<u16, PortForwardError> {
        self.request_remote_tcpip_forward(bind_address, bind_port)
            .await
            .map_err(PortForwardError::Transport)
    }

    async fn accept_remote_forward(&self) -> Result<ForwardedTcpipConnection, PortForwardError> {
        self.accept_remote_tcpip_forward()
            .await
            .map_err(PortForwardError::Transport)
    }

    async fn cancel_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<(), PortForwardError> {
        self.cancel_remote_tcpip_forward(bind_address, bind_port)
            .await
            .map_err(PortForwardError::Transport)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortForwardKind {
    Local,
    Remote,
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortForwardRule {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: PortForwardKind,
    pub local_port: u16,
    pub bind_address: String,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub host_id: String,
    #[serde(default)]
    pub auto_start: bool,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub order: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortForwardRuleDocument {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: PortForwardKind,
    local_port: u16,
    bind_address: String,
    remote_host: Option<String>,
    remote_port: Option<u16>,
    host_id: String,
    #[serde(default)]
    auto_start: bool,
    created_at: u64,
    last_used_at: Option<u64>,
    order: Option<i64>,
    #[serde(default)]
    status: Option<LegacyPortForwardStatus>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum LegacyPortForwardStatus {
    Inactive,
    Connecting,
    Active,
    Error,
    Unknown,
}

impl<'de> Deserialize<'de> for PortForwardRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = PortForwardRuleDocument::deserialize(deserializer)?;
        // Runtime phase/error are accepted only for migration from the legacy
        // local-storage/sync shape and are intentionally discarded here.
        let _ = (document.status, document.error);
        Ok(Self {
            id: document.id,
            label: document.label,
            kind: document.kind,
            local_port: document.local_port,
            bind_address: document.bind_address,
            remote_host: document.remote_host,
            remote_port: document.remote_port,
            host_id: document.host_id,
            auto_start: document.auto_start,
            created_at: document.created_at,
            last_used_at: document.last_used_at,
            order: document.order,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPortForwardRule {
    pub id: String,
    pub label: String,
    pub kind: PortForwardKind,
    pub bind_address: String,
    pub local_port: u16,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub host_id: String,
    pub auto_start: bool,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub order: Option<i64>,
}

impl PortForwardRule {
    pub fn normalize(&self) -> Result<NormalizedPortForwardRule, PortForwardError> {
        let id = self.id.trim();
        let label = self.label.trim();
        let host_id = self.host_id.trim();
        if id.is_empty()
            || id.len() > MAX_RULE_ID_BYTES
            || label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || host_id.is_empty()
            || host_id.len() > MAX_RULE_ID_BYTES
            || self.local_port == 0
        {
            return Err(PortForwardError::InvalidRule);
        }
        let bind_address = self.bind_address.trim();
        if bind_address.is_empty()
            || bind_address.len() > MAX_BIND_ADDRESS_BYTES
            || bind_address.chars().any(char::is_whitespace)
            || bind_address.chars().any(char::is_control)
        {
            return Err(PortForwardError::InvalidRule);
        }

        let (remote_host, remote_port) = match self.kind {
            PortForwardKind::Dynamic => {
                if self
                    .remote_host
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                    || self.remote_port.is_some()
                {
                    return Err(PortForwardError::InvalidRule);
                }
                (None, None)
            }
            PortForwardKind::Local | PortForwardKind::Remote => {
                let remote_host = self
                    .remote_host
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(PortForwardError::InvalidRule)?;
                if remote_host.len() > MAX_REMOTE_HOST_BYTES
                    || remote_host.chars().any(char::is_control)
                {
                    return Err(PortForwardError::InvalidRule);
                }
                let remote_port = self
                    .remote_port
                    .filter(|port| *port > 0)
                    .ok_or(PortForwardError::InvalidRule)?;
                (Some(remote_host.to_owned()), Some(remote_port))
            }
        };

        Ok(NormalizedPortForwardRule {
            id: id.to_owned(),
            label: label.to_owned(),
            kind: self.kind,
            bind_address: bind_address.to_owned(),
            local_port: self.local_port,
            remote_host,
            remote_port,
            host_id: host_id.to_owned(),
            auto_start: self.auto_start,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            order: self.order,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PortForwardEvent {
    Active { address: String, port: u16 },
    ConnectionError { message: String },
    Stopped,
}

pub type PortForwardEventReceiver = broadcast::Receiver<PortForwardEvent>;

pub struct PortForwardStart {
    pub tunnel_id: String,
    pub address: String,
    pub port: u16,
    pub events: PortForwardEventReceiver,
}

#[derive(Debug)]
pub enum PortForwardError {
    InvalidRule,
    DuplicateRule,
    NotFound,
    UnsupportedKind,
    BindFailed,
    ChannelFailed,
    CapacityReached,
    SocksProtocol,
    Transport(TransportError),
}

impl fmt::Display for PortForwardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRule => "端口转发规则无效",
            Self::DuplicateRule => "该端口转发规则已经在运行",
            Self::NotFound => "端口转发不存在",
            Self::UnsupportedKind => "这种端口转发类型尚不可用",
            Self::BindFailed => "无法监听端口转发地址",
            Self::ChannelFailed => "无法打开 SSH 端口转发通道",
            Self::CapacityReached => "端口转发并发连接数已达到上限",
            Self::SocksProtocol => "SOCKS5 请求无效或不受支持",
            Self::Transport(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for PortForwardError {}

struct ManagedForward {
    tunnel_id: String,
    cancellation: CancellationToken,
    events: broadcast::Sender<PortForwardEvent>,
    task: JoinHandle<()>,
}

#[derive(Clone, Default)]
pub struct PortForwardManager {
    rules: Arc<Mutex<HashMap<String, ManagedForward>>>,
}

impl PortForwardManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(
        &self,
        rule: NormalizedPortForwardRule,
        opener: Arc<dyn DirectTcpipOpener>,
    ) -> Result<PortForwardStart, PortForwardError> {
        if rule.kind == PortForwardKind::Remote {
            return Err(PortForwardError::UnsupportedKind);
        }
        let listener = TcpListener::bind((rule.bind_address.as_str(), rule.local_port))
            .await
            .map_err(|_| PortForwardError::BindFailed)?;
        let local_address = listener
            .local_addr()
            .map_err(|_| PortForwardError::BindFailed)?;

        let mut rules = self.rules.lock().await;
        if rules.contains_key(&rule.id) {
            return Err(PortForwardError::DuplicateRule);
        }

        let tunnel_id = format!(
            "pf-{}-{}",
            rule.id,
            NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed)
        );
        let cancellation = CancellationToken::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let task_events = events.clone();
        let task_cancellation = cancellation.clone();
        let rule_id = rule.id.clone();
        let task = tokio::spawn(async move {
            run_listener(
                listener,
                rule,
                opener,
                task_events.clone(),
                task_cancellation,
            )
            .await;
            let _ = task_events.send(PortForwardEvent::Stopped);
        });
        rules.insert(
            rule_id,
            ManagedForward {
                tunnel_id: tunnel_id.clone(),
                cancellation,
                events: events.clone(),
                task,
            },
        );
        drop(rules);
        let _ = events.send(PortForwardEvent::Active {
            address: local_address.ip().to_string(),
            port: local_address.port(),
        });
        Ok(PortForwardStart {
            tunnel_id,
            address: local_address.ip().to_string(),
            port: local_address.port(),
            events: event_receiver,
        })
    }

    pub async fn start_remote(
        &self,
        rule: NormalizedPortForwardRule,
        forwarder: Arc<dyn RemoteTcpipForwarder>,
    ) -> Result<PortForwardStart, PortForwardError> {
        if rule.kind != PortForwardKind::Remote {
            return Err(PortForwardError::UnsupportedKind);
        }
        if self.rules.lock().await.contains_key(&rule.id) {
            return Err(PortForwardError::DuplicateRule);
        }
        let bind_address = rule.bind_address.clone();
        let assigned_port = forwarder
            .request_remote_forward(&bind_address, rule.local_port)
            .await?;
        if assigned_port == 0 {
            let _ = forwarder
                .cancel_remote_forward(&bind_address, rule.local_port)
                .await;
            return Err(PortForwardError::ChannelFailed);
        }

        let mut rules = self.rules.lock().await;
        if rules.contains_key(&rule.id) {
            drop(rules);
            let _ = forwarder
                .cancel_remote_forward(&bind_address, assigned_port)
                .await;
            return Err(PortForwardError::DuplicateRule);
        }
        let tunnel_id = format!(
            "pf-{}-{}",
            rule.id,
            NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed)
        );
        let cancellation = CancellationToken::new();
        let (events, event_receiver) = broadcast::channel(EVENT_BUFFER_SIZE);
        let task_events = events.clone();
        let task_cancellation = cancellation.clone();
        let task_bind_address = bind_address.clone();
        let rule_id = rule.id.clone();
        let task = tokio::spawn(async move {
            run_remote_forward(
                rule,
                assigned_port,
                forwarder,
                task_events.clone(),
                task_cancellation,
            )
            .await;
            let _ = task_events.send(PortForwardEvent::Stopped);
        });
        rules.insert(
            rule_id,
            ManagedForward {
                tunnel_id: tunnel_id.clone(),
                cancellation,
                events: events.clone(),
                task,
            },
        );
        drop(rules);
        let _ = events.send(PortForwardEvent::Active {
            address: task_bind_address.clone(),
            port: assigned_port,
        });
        Ok(PortForwardStart {
            tunnel_id,
            address: task_bind_address,
            port: assigned_port,
            events: event_receiver,
        })
    }

    pub async fn subscribe(
        &self,
        rule_id: &str,
    ) -> Result<PortForwardEventReceiver, PortForwardError> {
        self.rules
            .lock()
            .await
            .get(rule_id)
            .map(|managed| managed.events.subscribe())
            .ok_or(PortForwardError::NotFound)
    }

    pub async fn active_tunnels(&self) -> Vec<(String, String)> {
        let mut tunnels = self
            .rules
            .lock()
            .await
            .iter()
            .map(|(rule_id, managed)| (rule_id.clone(), managed.tunnel_id.clone()))
            .collect::<Vec<_>>();
        tunnels.sort_by(|left, right| left.0.cmp(&right.0));
        tunnels
    }

    pub async fn stop(&self, rule_id: &str) -> Result<(), PortForwardError> {
        let managed = self
            .rules
            .lock()
            .await
            .remove(rule_id)
            .ok_or(PortForwardError::NotFound)?;
        managed.cancellation.cancel();
        let _ = tokio::time::timeout(STOP_TIMEOUT, managed.task).await;
        Ok(())
    }

    pub async fn stop_all(&self) {
        let managed = self
            .rules
            .lock()
            .await
            .drain()
            .map(|(_, managed)| managed)
            .collect::<Vec<_>>();
        for forward in &managed {
            forward.cancellation.cancel();
        }
        for forward in managed {
            let _ = tokio::time::timeout(STOP_TIMEOUT, forward.task).await;
        }
    }
}

async fn run_remote_forward(
    rule: NormalizedPortForwardRule,
    assigned_port: u16,
    forwarder: Arc<dyn RemoteTcpipForwarder>,
    events: broadcast::Sender<PortForwardEvent>,
    cancellation: CancellationToken,
) {
    let mut connections = JoinSet::new();
    let connection_slots = Arc::new(Semaphore::new(MAX_FORWARD_CONNECTIONS_PER_RULE));
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            result = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
            accepted = forwarder.accept_remote_forward() => match accepted {
                Ok(remote) => {
                    let Ok(connection_slot) = connection_slots.clone().try_acquire_owned() else {
                        drop(remote);
                        let _ = events.send(PortForwardEvent::ConnectionError {
                            message: PortForwardError::CapacityReached.to_string(),
                        });
                        continue;
                    };
                    let Some(local_host) = rule.remote_host.clone() else {
                        break;
                    };
                    let Some(local_port) = rule.remote_port else {
                        break;
                    };
                    let connection_events = events.clone();
                    let connection_cancellation = cancellation.clone();
                    connections.spawn(async move {
                        let _connection_slot = connection_slot;
                        if let Err(error) = pipe_remote_connection(
                            remote,
                            &local_host,
                            local_port,
                            connection_cancellation,
                        ).await {
                            let _ = connection_events.send(PortForwardEvent::ConnectionError {
                                message: error.to_string(),
                            });
                        }
                    });
                }
                Err(error) => {
                    let _ = events.send(PortForwardEvent::ConnectionError {
                        message: error.to_string(),
                    });
                    break;
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let _ = forwarder
        .cancel_remote_forward(&rule.bind_address, assigned_port)
        .await;
}

async fn pipe_remote_connection(
    mut remote: ForwardedTcpipConnection,
    local_host: &str,
    local_port: u16,
    cancellation: CancellationToken,
) -> Result<(), PortForwardError> {
    let mut local = TcpStream::connect((local_host, local_port))
        .await
        .map_err(|_| PortForwardError::ChannelFailed)?;
    tokio::select! {
        () = cancellation.cancelled() => Ok(()),
        copied = tokio::io::copy_bidirectional(&mut local, &mut remote.stream) => {
            copied.map(|_| ()).map_err(|_| PortForwardError::ChannelFailed)
        }
    }
}

async fn run_listener(
    listener: TcpListener,
    rule: NormalizedPortForwardRule,
    opener: Arc<dyn DirectTcpipOpener>,
    events: broadcast::Sender<PortForwardEvent>,
    cancellation: CancellationToken,
) {
    let mut connections = JoinSet::new();
    let connection_slots = Arc::new(Semaphore::new(MAX_FORWARD_CONNECTIONS_PER_RULE));
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            result = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, originator)) => {
                    let Ok(connection_slot) = connection_slots.clone().try_acquire_owned() else {
                        drop(stream);
                        let _ = events.send(PortForwardEvent::ConnectionError {
                            message: PortForwardError::CapacityReached.to_string(),
                        });
                        continue;
                    };
                    let connection_rule = rule.clone();
                    let connection_opener = opener.clone();
                    let connection_events = events.clone();
                    let connection_cancellation = cancellation.clone();
                    connections.spawn(async move {
                        let _connection_slot = connection_slot;
                        let result = match connection_rule.kind {
                            PortForwardKind::Local => {
                                run_local_connection(stream, originator, &connection_rule, connection_opener, connection_cancellation).await
                            }
                            PortForwardKind::Dynamic => {
                                run_dynamic_connection(stream, originator, connection_opener, connection_cancellation).await
                            }
                            PortForwardKind::Remote => Err(PortForwardError::UnsupportedKind),
                        };
                        if let Err(error) = result {
                            let _ = connection_events.send(PortForwardEvent::ConnectionError {
                                message: error.to_string(),
                            });
                        }
                    });
                }
                Err(_) => {
                    let _ = events.send(PortForwardEvent::ConnectionError {
                        message: PortForwardError::BindFailed.to_string(),
                    });
                    break;
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn run_local_connection(
    mut local: TcpStream,
    originator: SocketAddr,
    rule: &NormalizedPortForwardRule,
    opener: Arc<dyn DirectTcpipOpener>,
    cancellation: CancellationToken,
) -> Result<(), PortForwardError> {
    let remote_host = rule
        .remote_host
        .as_deref()
        .ok_or(PortForwardError::InvalidRule)?;
    let remote_port = rule.remote_port.ok_or(PortForwardError::InvalidRule)?;
    let mut remote = opener
        .open_direct_tcpip(remote_host, remote_port, originator)
        .await?;
    tokio::select! {
        () = cancellation.cancelled() => Ok(()),
        copied = tokio::io::copy_bidirectional(&mut local, &mut remote) => {
            copied.map(|_| ()).map_err(|_| PortForwardError::ChannelFailed)
        }
    }
}

async fn run_dynamic_connection(
    mut local: TcpStream,
    originator: SocketAddr,
    opener: Arc<dyn DirectTcpipOpener>,
    cancellation: CancellationToken,
) -> Result<(), PortForwardError> {
    let (host, port) = accept_socks5_connect(&mut local).await?;
    let mut remote = match opener.open_direct_tcpip(&host, port, originator).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = write_socks5_reply(&mut local, 0x05).await;
            return Err(error);
        }
    };
    write_socks5_reply(&mut local, 0x00).await?;
    tokio::select! {
        () = cancellation.cancelled() => Ok(()),
        copied = tokio::io::copy_bidirectional(&mut local, &mut remote) => {
            copied.map(|_| ()).map_err(|_| PortForwardError::ChannelFailed)
        }
    }
}

async fn accept_socks5_connect(stream: &mut TcpStream) -> Result<(String, u16), PortForwardError> {
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|_| PortForwardError::SocksProtocol)?;
    if greeting[0] != 0x05 || greeting[1] == 0 {
        return Err(PortForwardError::SocksProtocol);
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| PortForwardError::SocksProtocol)?;
    if !methods.contains(&0x00) {
        stream
            .write_all(&[0x05, 0xff])
            .await
            .map_err(|_| PortForwardError::SocksProtocol)?;
        return Err(PortForwardError::SocksProtocol);
    }
    stream
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|_| PortForwardError::SocksProtocol)?;

    let mut request = [0_u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .map_err(|_| PortForwardError::SocksProtocol)?;
    if request[0] != 0x05 || request[1] != 0x01 || request[2] != 0x00 {
        let _ = write_socks5_reply(stream, 0x07).await;
        return Err(PortForwardError::SocksProtocol);
    }
    let host = match request[3] {
        0x01 => {
            let mut address = [0_u8; 4];
            stream
                .read_exact(&mut address)
                .await
                .map_err(|_| PortForwardError::SocksProtocol)?;
            IpAddr::from(address).to_string()
        }
        0x03 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| PortForwardError::SocksProtocol)?;
            if length == 0 {
                return Err(PortForwardError::SocksProtocol);
            }
            let mut address = vec![0_u8; usize::from(length)];
            stream
                .read_exact(&mut address)
                .await
                .map_err(|_| PortForwardError::SocksProtocol)?;
            String::from_utf8(address).map_err(|_| PortForwardError::SocksProtocol)?
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream
                .read_exact(&mut address)
                .await
                .map_err(|_| PortForwardError::SocksProtocol)?;
            IpAddr::from(address).to_string()
        }
        _ => {
            let _ = write_socks5_reply(stream, 0x08).await;
            return Err(PortForwardError::SocksProtocol);
        }
    };
    let port = stream
        .read_u16()
        .await
        .map_err(|_| PortForwardError::SocksProtocol)?;
    if port == 0 || host.chars().any(char::is_control) {
        return Err(PortForwardError::SocksProtocol);
    }
    Ok((host, port))
}

async fn write_socks5_reply(stream: &mut TcpStream, code: u8) -> Result<(), PortForwardError> {
    stream
        .write_all(&[0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .map_err(|_| PortForwardError::SocksProtocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct TcpOpener;

    #[async_trait]
    impl DirectTcpipOpener for TcpOpener {
        async fn open_direct_tcpip(
            &self,
            destination_host: &str,
            destination_port: u16,
            _originator: SocketAddr,
        ) -> Result<Box<dyn PortForwardStream>, PortForwardError> {
            TcpStream::connect((destination_host, destination_port))
                .await
                .map(|stream| Box::new(stream) as Box<dyn PortForwardStream>)
                .map_err(|_| PortForwardError::ChannelFailed)
        }
    }

    struct BlockingOpener;

    #[async_trait]
    impl DirectTcpipOpener for BlockingOpener {
        async fn open_direct_tcpip(
            &self,
            _destination_host: &str,
            _destination_port: u16,
            _originator: SocketAddr,
        ) -> Result<Box<dyn PortForwardStream>, PortForwardError> {
            std::future::pending().await
        }
    }

    struct FakeRemoteForwarder {
        incoming: Mutex<tokio::sync::mpsc::UnboundedReceiver<ForwardedTcpipConnection>>,
        cancelled: AtomicBool,
    }

    #[async_trait]
    impl RemoteTcpipForwarder for FakeRemoteForwarder {
        async fn request_remote_forward(
            &self,
            _bind_address: &str,
            bind_port: u16,
        ) -> Result<u16, PortForwardError> {
            Ok(bind_port)
        }

        async fn accept_remote_forward(
            &self,
        ) -> Result<ForwardedTcpipConnection, PortForwardError> {
            self.incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or(PortForwardError::ChannelFailed)
        }

        async fn cancel_remote_forward(
            &self,
            _bind_address: &str,
            _bind_port: u16,
        ) -> Result<(), PortForwardError> {
            self.cancelled.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn rule(kind: PortForwardKind, local_port: u16) -> PortForwardRule {
        PortForwardRule {
            id: "rule-1".to_owned(),
            label: "Database tunnel".to_owned(),
            kind,
            local_port,
            bind_address: "127.0.0.1".to_owned(),
            remote_host: (kind != PortForwardKind::Dynamic).then(|| "127.0.0.1".to_owned()),
            remote_port: (kind != PortForwardKind::Dynamic).then_some(22),
            host_id: "host-1".to_owned(),
            auto_start: false,
            created_at: 123,
            last_used_at: None,
            order: None,
        }
    }

    async fn unused_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn rules_match_legacy_shape_and_validate_kind_specific_fields() {
        let local = rule(PortForwardKind::Local, 15432).normalize().unwrap();
        assert_eq!(local.remote_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(local.remote_port, Some(22));

        let dynamic = rule(PortForwardKind::Dynamic, 1080).normalize().unwrap();
        assert_eq!(dynamic.remote_host, None);
        assert_eq!(dynamic.remote_port, None);

        let mut invalid = rule(PortForwardKind::Local, 15432);
        invalid.bind_address = "bad address".to_owned();
        assert!(matches!(
            invalid.normalize(),
            Err(PortForwardError::InvalidRule)
        ));
        invalid.bind_address = "localhost".to_owned();
        assert_eq!(
            invalid.normalize().unwrap().bind_address,
            "localhost".to_owned()
        );
        invalid.remote_port = None;
        assert!(matches!(
            invalid.normalize(),
            Err(PortForwardError::InvalidRule)
        ));
    }

    #[test]
    fn runtime_status_is_not_part_of_the_persisted_rule() {
        let json = serde_json::to_value(rule(PortForwardKind::Local, 15432)).unwrap();
        assert!(json.get("status").is_none());
        assert!(json.get("error").is_none());
        assert_eq!(
            json.get("type").and_then(serde_json::Value::as_str),
            Some("local")
        );
    }

    #[test]
    fn legacy_runtime_fields_are_accepted_then_discarded_during_migration() {
        let mut document = serde_json::to_value(rule(PortForwardKind::Local, 15432)).unwrap();
        let object = document.as_object_mut().unwrap();
        object.insert("status".to_owned(), serde_json::json!("active"));
        object.insert("error".to_owned(), serde_json::json!("stale runtime error"));
        let migrated: PortForwardRule = serde_json::from_value(document).unwrap();
        let persisted = serde_json::to_value(migrated).unwrap();
        assert!(persisted.get("status").is_none());
        assert!(persisted.get("error").is_none());

        let mut hostile = persisted;
        hostile
            .as_object_mut()
            .unwrap()
            .insert("password".to_owned(), serde_json::json!("must reject"));
        assert!(serde_json::from_value::<PortForwardRule>(hostile).is_err());
    }

    #[tokio::test]
    async fn local_forward_moves_bytes_and_stop_releases_the_listener() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let local_port = unused_port().await;
        let mut source = rule(PortForwardKind::Local, local_port);
        source.remote_port = Some(echo_port);
        let manager = PortForwardManager::new();
        let start = manager
            .start(source.normalize().unwrap(), Arc::new(TcpOpener))
            .await
            .unwrap();
        assert_eq!(start.port, local_port);

        let mut client = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        echo_task.await.unwrap();

        manager.stop("rule-1").await.unwrap();
        assert!(manager.active_tunnels().await.is_empty());
        assert!(TcpListener::bind(("127.0.0.1", local_port)).await.is_ok());
    }

    #[tokio::test]
    async fn dynamic_forward_negotiates_socks5_and_opens_the_requested_target() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let local_port = unused_port().await;
        let manager = PortForwardManager::new();
        manager
            .start(
                rule(PortForwardKind::Dynamic, local_port)
                    .normalize()
                    .unwrap(),
                Arc::new(TcpOpener),
            )
            .await
            .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        let [high, low] = echo_port.to_be_bytes();
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, high, low])
            .await
            .unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);
        client.write_all(b"pong").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        echo_task.await.unwrap();
        manager.stop_all().await;
    }

    #[tokio::test]
    async fn remote_forward_pipes_server_channels_to_the_configured_local_target() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::unbounded_channel();
        let forwarder = Arc::new(FakeRemoteForwarder {
            incoming: Mutex::new(incoming_receiver),
            cancelled: AtomicBool::new(false),
        });
        let mut source = rule(PortForwardKind::Remote, 22022);
        source.remote_port = Some(echo_port);
        let manager = PortForwardManager::new();
        let start = manager
            .start_remote(source.normalize().unwrap(), forwarder.clone())
            .await
            .unwrap();
        assert_eq!(start.port, 22022);

        let (mut server_peer, manager_peer) = tokio::io::duplex(1024);
        incoming_sender
            .send(ForwardedTcpipConnection {
                connected_address: "127.0.0.1".to_owned(),
                connected_port: 22022,
                originator_address: "198.51.100.2".to_owned(),
                originator_port: 54321,
                stream: Box::new(manager_peer),
            })
            .unwrap();
        server_peer.write_all(b"remote").await.unwrap();
        let mut response = [0_u8; 6];
        server_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"remote");
        echo_task.await.unwrap();

        manager.stop("rule-1").await.unwrap();
        assert!(forwarder.cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn duplicate_and_remote_starts_fail_without_replacing_the_live_rule() {
        let local_port = unused_port().await;
        let manager = PortForwardManager::new();
        let normalized = rule(PortForwardKind::Dynamic, local_port)
            .normalize()
            .unwrap();
        manager
            .start(normalized.clone(), Arc::new(TcpOpener))
            .await
            .unwrap();
        assert!(matches!(
            manager.start(normalized, Arc::new(TcpOpener)).await,
            Err(PortForwardError::BindFailed | PortForwardError::DuplicateRule)
        ));
        let remote = rule(PortForwardKind::Remote, unused_port().await)
            .normalize()
            .unwrap();
        assert!(matches!(
            manager.start(remote, Arc::new(TcpOpener)).await,
            Err(PortForwardError::UnsupportedKind)
        ));
        assert_eq!(manager.active_tunnels().await.len(), 1);
        manager.stop_all().await;
    }

    #[tokio::test]
    async fn local_forward_rejects_connections_above_the_per_rule_bound() {
        let local_port = unused_port().await;
        let manager = PortForwardManager::new();
        let mut start = manager
            .start(
                rule(PortForwardKind::Local, local_port)
                    .normalize()
                    .unwrap(),
                Arc::new(BlockingOpener),
            )
            .await
            .unwrap();
        assert!(matches!(
            start.events.recv().await.unwrap(),
            PortForwardEvent::Active { .. }
        ));

        let mut clients = Vec::new();
        for _ in 0..=MAX_FORWARD_CONNECTIONS_PER_RULE {
            clients.push(TcpStream::connect(("127.0.0.1", local_port)).await.unwrap());
        }
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), start.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            PortForwardEvent::ConnectionError {
                message: PortForwardError::CapacityReached.to_string(),
            }
        );
        drop(clients);
        manager.stop_all().await;
    }
}
