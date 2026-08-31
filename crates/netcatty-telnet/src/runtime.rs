use std::{
    collections::HashMap,
    error::Error,
    fmt, io,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio::{
    net::TcpStream,
    runtime::Handle,
    sync::{mpsc, watch},
    time::timeout,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CodecError, MAX_INPUT_BYTES, SessionError, TelnetBytes, TelnetConfig, TelnetEvent,
    TelnetSession, WindowSize,
    auto_login::{
        AutoLogin, AutoLoginAction, AutoLoginConfig, AutoLoginError, LoginValue, SecretText,
    },
    charset::{CharsetError, TelnetCharset},
};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;
pub const EVENT_CHANNEL_CAPACITY: usize = 128;
pub const MAX_HOSTNAME_BYTES: usize = 1_024;
const TERMINAL_EVENT_RESERVE: usize = 2;
const MAX_STARTUP_COMMAND_BYTES: usize = MAX_INPUT_BYTES - 1;

/// Validated, secret-safe input for one runtime session.
pub struct TelnetRuntimeConfig {
    hostname: String,
    port: u16,
    codec: TelnetConfig,
    charset: TelnetCharset,
    auto_login: AutoLoginConfig,
}

impl TelnetRuntimeConfig {
    pub fn new(
        hostname: impl Into<String>,
        port: u16,
        columns: u32,
        rows: u32,
    ) -> Result<Self, TelnetRuntimeError> {
        let hostname = hostname.into();
        validate_hostname(&hostname)?;
        if port == 0 {
            return Err(TelnetRuntimeError::InvalidPort);
        }
        let window_size = WindowSize::new(columns, rows).map_err(TelnetRuntimeError::Protocol)?;
        Ok(Self {
            hostname,
            port,
            codec: TelnetConfig::default().with_window_size(window_size),
            charset: TelnetCharset::Utf8,
            auto_login: AutoLoginConfig::default(),
        })
    }

    pub fn with_terminal_type(
        mut self,
        terminal_type: impl AsRef<str>,
    ) -> Result<Self, TelnetRuntimeError> {
        self.codec = self
            .codec
            .with_terminal_type(terminal_type)
            .map_err(TelnetRuntimeError::Protocol)?;
        Ok(self)
    }

    pub fn with_charset(mut self, charset: TelnetCharset) -> Self {
        self.charset = charset;
        self
    }

    pub fn with_username(
        mut self,
        username: impl Into<String>,
    ) -> Result<Self, TelnetRuntimeError> {
        self.auto_login.username =
            LoginValue::present(username).map_err(TelnetRuntimeError::AutoLogin)?;
        Ok(self)
    }

    pub fn with_password(
        mut self,
        password: impl Into<String>,
    ) -> Result<Self, TelnetRuntimeError> {
        self.auto_login.password =
            LoginValue::present(password).map_err(TelnetRuntimeError::AutoLogin)?;
        Ok(self)
    }

    pub fn with_login_values(mut self, username: LoginValue, password: LoginValue) -> Self {
        self.auto_login.username = username;
        self.auto_login.password = password;
        self
    }

    pub fn with_startup_command(
        mut self,
        startup_command: impl Into<String>,
    ) -> Result<Self, TelnetRuntimeError> {
        let startup_command = startup_command.into();
        if startup_command.len() > MAX_STARTUP_COMMAND_BYTES {
            return Err(TelnetRuntimeError::StartupCommandTooLarge {
                maximum_bytes: MAX_STARTUP_COMMAND_BYTES,
            });
        }
        self.auto_login.startup_command = Some(
            SecretText::startup_command(startup_command).map_err(TelnetRuntimeError::AutoLogin)?,
        );
        Ok(self)
    }

    pub fn with_auto_login_timeout(mut self, timeout: Duration) -> Self {
        self.auto_login.timeout = timeout;
        self
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn window_size(&self) -> WindowSize {
        self.codec.window_size()
    }

    pub fn terminal_type(&self) -> &str {
        self.codec.terminal_type()
    }

    pub const fn charset(&self) -> TelnetCharset {
        self.charset
    }
}

impl fmt::Debug for TelnetRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetRuntimeConfig")
            .field("hostname_bytes", &self.hostname.len())
            .field("port", &self.port)
            .field("codec", &self.codec)
            .field("charset", &self.charset)
            .field("credentials", &"<redacted>")
            .field("startup_command", &"<redacted>")
            .finish()
    }
}

/// Opaque manager-generated identifier. Callers cannot replace an existing
/// runtime by choosing the same value.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelnetSessionId(String);

impl TelnetSessionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, TelnetRuntimeError> {
        let parsed = Uuid::parse_str(value).map_err(|_| TelnetRuntimeError::InvalidSessionId)?;
        let canonical = parsed.hyphenated().to_string();
        if value != canonical {
            return Err(TelnetRuntimeError::InvalidSessionId);
        }
        Ok(Self(canonical))
    }
}

impl FromStr for TelnetSessionId {
    type Err = TelnetRuntimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for TelnetSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for TelnetSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelnetCloseReason {
    Requested,
    Cancelled,
    RemoteEof,
    Error,
}

/// Events for one receiver returned by [`TelnetRuntimeManager::start`].
pub enum TelnetRuntimeEvent {
    Connecting,
    Connected,
    Data(TelnetBytes),
    RemoteEcho { enabled: bool },
    LocalEcho { enabled: bool },
    AutoLoginCompleted,
    AutoLoginCancelled,
    AutoLoginTimedOut,
    Error(TelnetRuntimeError),
    Closed { reason: TelnetCloseReason },
}

impl fmt::Debug for TelnetRuntimeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => formatter.write_str("Connecting"),
            Self::Connected => formatter.write_str("Connected"),
            Self::Data(bytes) => formatter.debug_tuple("Data").field(bytes).finish(),
            Self::RemoteEcho { enabled } => formatter
                .debug_struct("RemoteEcho")
                .field("enabled", enabled)
                .finish(),
            Self::LocalEcho { enabled } => formatter
                .debug_struct("LocalEcho")
                .field("enabled", enabled)
                .finish(),
            Self::AutoLoginCompleted => formatter.write_str("AutoLoginCompleted"),
            Self::AutoLoginCancelled => formatter.write_str("AutoLoginCancelled"),
            Self::AutoLoginTimedOut => formatter.write_str("AutoLoginTimedOut"),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::Closed { reason } => formatter
                .debug_struct("Closed")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Runtime and queue failures with payload-free `Display` and `Debug`.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelnetRuntimeError {
    InvalidHostname { maximum_bytes: usize },
    InvalidSessionId,
    InvalidPort,
    InvalidInputEncoding,
    EncodedInputTooLarge { maximum_bytes: usize },
    StartupCommandTooLarge { maximum_bytes: usize },
    RuntimeUnavailable,
    SessionNotFound,
    SessionClosing,
    CommandQueueFull { capacity: usize },
    EventQueueFull { capacity: usize },
    ConnectionTimeout { timeout: Duration },
    ConnectionFailed { kind: io::ErrorKind },
    Protocol(CodecError),
    Session(SessionError),
    AutoLogin(AutoLoginError),
}

impl fmt::Debug for TelnetRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for TelnetRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHostname { maximum_bytes } => write!(
                formatter,
                "Telnet hostname is invalid or exceeds {maximum_bytes} bytes"
            ),
            Self::InvalidSessionId => formatter.write_str("Telnet session ID is invalid"),
            Self::InvalidPort => formatter.write_str("Telnet port must be between 1 and 65535"),
            Self::InvalidInputEncoding => {
                formatter.write_str("Telnet renderer input is not valid UTF-8")
            }
            Self::EncodedInputTooLarge { maximum_bytes } => write!(
                formatter,
                "Telnet encoded input exceeds {maximum_bytes} bytes"
            ),
            Self::StartupCommandTooLarge { maximum_bytes } => write!(
                formatter,
                "Telnet startup command exceeds {maximum_bytes} bytes"
            ),
            Self::RuntimeUnavailable => {
                formatter.write_str("Telnet runtime requires an active Tokio runtime")
            }
            Self::SessionNotFound => formatter.write_str("Telnet session was not found"),
            Self::SessionClosing => formatter.write_str("Telnet session is closing"),
            Self::CommandQueueFull { capacity } => {
                write!(
                    formatter,
                    "Telnet command queue reached its {capacity}-item limit"
                )
            }
            Self::EventQueueFull { capacity } => {
                write!(
                    formatter,
                    "Telnet event queue reached its {capacity}-item limit"
                )
            }
            Self::ConnectionTimeout { timeout } => write!(
                formatter,
                "Telnet connection timed out after {} seconds",
                timeout.as_secs()
            ),
            Self::ConnectionFailed { kind } => {
                write!(formatter, "Telnet connection failed ({kind:?})")
            }
            Self::Protocol(error) => write!(formatter, "Telnet protocol error: {error}"),
            Self::Session(error) => write!(formatter, "Telnet session error: {error}"),
            Self::AutoLogin(error) => write!(formatter, "Telnet auto-login error: {error}"),
        }
    }
}

impl Error for TelnetRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::AutoLogin(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for TelnetRuntimeError {
    fn from(error: CodecError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SessionError> for TelnetRuntimeError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<AutoLoginError> for TelnetRuntimeError {
    fn from(error: AutoLoginError) -> Self {
        Self::AutoLogin(error)
    }
}

/// Handle and bounded event receiver returned immediately by `start`.
pub struct TelnetRuntimeSession {
    session_id: TelnetSessionId,
    events: mpsc::Receiver<TelnetRuntimeEvent>,
}

impl TelnetRuntimeSession {
    pub fn session_id(&self) -> &TelnetSessionId {
        &self.session_id
    }

    pub async fn recv(&mut self) -> Option<TelnetRuntimeEvent> {
        self.events.recv().await
    }

    pub fn try_recv(&mut self) -> Result<TelnetRuntimeEvent, mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    pub fn into_parts(self) -> (TelnetSessionId, mpsc::Receiver<TelnetRuntimeEvent>) {
        (self.session_id, self.events)
    }
}

impl fmt::Debug for TelnetRuntimeSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetRuntimeSession")
            .field("session_id", &self.session_id)
            .field("queued_events", &self.events.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct TelnetRuntimeManager {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    sessions: Mutex<HashMap<TelnetSessionId, SessionEntry>>,
}

#[derive(Clone)]
struct SessionEntry {
    commands: mpsc::Sender<RuntimeCommand>,
    stop: watch::Sender<StopSignal>,
}

enum RuntimeCommand {
    Input(Zeroizing<Vec<u8>>),
    Resize(WindowSize),
}

impl fmt::Debug for RuntimeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(bytes) => formatter
                .debug_struct("Input")
                .field("bytes", &bytes.len())
                .finish(),
            Self::Resize(size) => formatter.debug_tuple("Resize").field(size).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StopSignal {
    #[default]
    Running,
    Close,
    Cancel,
}

impl TelnetRuntimeManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Register and spawn one session. Connecting happens in the background,
    /// so `cancel` can stop DNS/TCP establishment during its ten-second bound.
    pub fn start(
        &self,
        config: TelnetRuntimeConfig,
    ) -> Result<TelnetRuntimeSession, TelnetRuntimeError> {
        let handle = Handle::try_current().map_err(|_| TelnetRuntimeError::RuntimeUnavailable)?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (stop_tx, stop_rx) = watch::channel(StopSignal::Running);

        let session_id = loop {
            let candidate = TelnetSessionId(Uuid::new_v4().to_string());
            let mut sessions = lock_sessions(&self.inner);
            if !sessions.contains_key(&candidate) {
                sessions.insert(
                    candidate.clone(),
                    SessionEntry {
                        commands: command_tx.clone(),
                        stop: stop_tx.clone(),
                    },
                );
                break candidate;
            }
        };

        handle.spawn(run_session(
            self.inner.clone(),
            session_id.clone(),
            config,
            command_rx,
            event_tx,
            stop_rx,
        ));
        Ok(TelnetRuntimeSession {
            session_id,
            events: event_rx,
        })
    }

    /// Queue one bounded user input. Queue saturation is explicit and never
    /// grows memory beyond `COMMAND_CHANNEL_CAPACITY`.
    pub fn input(
        &self,
        session_id: &TelnetSessionId,
        input: &[u8],
    ) -> Result<(), TelnetRuntimeError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(TelnetRuntimeError::Protocol(CodecError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES,
            }));
        }
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        try_send_command(
            &entry.commands,
            RuntimeCommand::Input(Zeroizing::new(input.to_vec())),
        )
    }

    pub fn resize(
        &self,
        session_id: &TelnetSessionId,
        columns: u32,
        rows: u32,
    ) -> Result<(), TelnetRuntimeError> {
        let size = WindowSize::new(columns, rows).map_err(TelnetRuntimeError::Protocol)?;
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        try_send_command(&entry.commands, RuntimeCommand::Resize(size))
    }

    /// Gracefully shut down an established socket, or stop an in-flight
    /// connection attempt.
    pub fn close(&self, session_id: &TelnetSessionId) -> Result<(), TelnetRuntimeError> {
        self.request_stop(session_id, StopSignal::Close)
    }

    /// Immediately stop an established session or cancellably interrupt DNS /
    /// TCP connection establishment.
    pub fn cancel(&self, session_id: &TelnetSessionId) -> Result<(), TelnetRuntimeError> {
        self.request_stop(session_id, StopSignal::Cancel)
    }

    pub fn contains(&self, session_id: &TelnetSessionId) -> bool {
        lock_sessions(&self.inner).contains_key(session_id)
    }

    pub fn session_count(&self) -> usize {
        lock_sessions(&self.inner).len()
    }

    fn request_stop(
        &self,
        session_id: &TelnetSessionId,
        signal: StopSignal,
    ) -> Result<(), TelnetRuntimeError> {
        let entry = self.entry(session_id)?;
        let current = *entry.stop.borrow();
        if current == StopSignal::Running {
            entry.stop.send_replace(signal);
        }
        Ok(())
    }

    fn entry(&self, session_id: &TelnetSessionId) -> Result<SessionEntry, TelnetRuntimeError> {
        lock_sessions(&self.inner)
            .get(session_id)
            .cloned()
            .ok_or(TelnetRuntimeError::SessionNotFound)
    }
}

impl Default for TelnetRuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TelnetRuntimeManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetRuntimeManager")
            .field("session_count", &self.session_count())
            .finish()
    }
}

fn lock_sessions(inner: &RuntimeInner) -> MutexGuard<'_, HashMap<TelnetSessionId, SessionEntry>> {
    inner
        .sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ensure_running(entry: &SessionEntry) -> Result<(), TelnetRuntimeError> {
    if *entry.stop.borrow() == StopSignal::Running {
        Ok(())
    } else {
        Err(TelnetRuntimeError::SessionClosing)
    }
}

fn try_send_command(
    sender: &mpsc::Sender<RuntimeCommand>,
    command: RuntimeCommand,
) -> Result<(), TelnetRuntimeError> {
    match sender.try_send(command) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(TelnetRuntimeError::CommandQueueFull {
            capacity: COMMAND_CHANNEL_CAPACITY,
        }),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(TelnetRuntimeError::SessionClosing),
    }
}

fn validate_hostname(hostname: &str) -> Result<(), TelnetRuntimeError> {
    if hostname.is_empty()
        || hostname.len() > MAX_HOSTNAME_BYTES
        || hostname.trim() != hostname
        || hostname.chars().any(char::is_control)
    {
        Err(TelnetRuntimeError::InvalidHostname {
            maximum_bytes: MAX_HOSTNAME_BYTES,
        })
    } else {
        Ok(())
    }
}

struct RegistryGuard {
    inner: Arc<RuntimeInner>,
    session_id: TelnetSessionId,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        lock_sessions(&self.inner).remove(&self.session_id);
    }
}

async fn run_session(
    inner: Arc<RuntimeInner>,
    session_id: TelnetSessionId,
    config: TelnetRuntimeConfig,
    mut commands: mpsc::Receiver<RuntimeCommand>,
    events: mpsc::Sender<TelnetRuntimeEvent>,
    mut stop: watch::Receiver<StopSignal>,
) {
    let _registry_guard = RegistryGuard { inner, session_id };
    if !emit_regular(&events, TelnetRuntimeEvent::Connecting) {
        return;
    }

    let connect = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((config.hostname.as_str(), config.port)),
    );
    tokio::pin!(connect);
    let stream = tokio::select! {
        biased;
        _ = stop.changed() => {
            finish_stopped(&events, *stop.borrow());
            return;
        }
        _ = events.closed() => return,
        result = &mut connect => {
            match result {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    finish_error(
                        &events,
                        TelnetRuntimeError::ConnectionFailed { kind: error.kind() },
                    );
                    return;
                }
                Err(_) => {
                    finish_error(
                        &events,
                        TelnetRuntimeError::ConnectionTimeout { timeout: CONNECT_TIMEOUT },
                    );
                    return;
                }
            }
        }
    };

    if let Err(error) = stream.set_nodelay(true) {
        finish_error(
            &events,
            TelnetRuntimeError::ConnectionFailed { kind: error.kind() },
        );
        return;
    }
    if !emit_regular(&events, TelnetRuntimeEvent::Connected) {
        return;
    }

    let TelnetRuntimeConfig {
        codec,
        charset,
        auto_login,
        ..
    } = config;
    let mut session = TelnetSession::new(stream, codec);
    let mut auto_login = AutoLogin::new(auto_login);
    let mut text_decoder = charset.decoder();

    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => {
                let signal = *stop.borrow();
                match signal {
                    StopSignal::Running => continue,
                    StopSignal::Close => {
                        if let Err(error) = session.shutdown().await {
                            finish_error(&events, TelnetRuntimeError::Session(error));
                        } else {
                            emit_closed(&events, TelnetCloseReason::Requested);
                        }
                    }
                    StopSignal::Cancel => emit_closed(&events, TelnetCloseReason::Cancelled),
                }
                return;
            }
            _ = events.closed() => return,
            command = commands.recv() => {
                let Some(command) = command else {
                    emit_closed(&events, TelnetCloseReason::Cancelled);
                    return;
                };
                let result = match command {
                    RuntimeCommand::Input(input) => {
                        let actions = auto_login.handle_user_input();
                        if actions
                            .iter()
                            .any(|action| matches!(action, AutoLoginAction::Cancelled))
                            && !emit_regular(&events, TelnetRuntimeEvent::AutoLoginCancelled)
                        {
                            return;
                        }
                        match charset.encode_input(input.as_slice()) {
                            Ok(encoded) => session.write(encoded.as_slice()).await,
                            Err(error) => {
                                finish_error(&events, map_charset_error(error));
                                return;
                            }
                        }
                    }
                    RuntimeCommand::Resize(size) => session
                        .resize(u32::from(size.columns()), u32::from(size.rows()))
                        .await
                        .map(|_| ()),
                };
                if let Err(error) = result {
                    finish_error(&events, TelnetRuntimeError::Session(error));
                    return;
                }
            }
            read = session.read() => {
                let read = match read {
                    Ok(read) => read,
                    Err(error) => {
                        finish_error(&events, TelnetRuntimeError::Session(error));
                        return;
                    }
                };
                let (data, protocol_events, closed) = read.into_parts();
                if closed {
                    let decoded = text_decoder.decode(&[], true);
                    if !decoded.is_empty()
                        && !process_decoded_data(
                            &mut session,
                            &mut auto_login,
                            charset,
                            &events,
                            decoded,
                        )
                        .await
                    {
                        return;
                    }
                    emit_closed(&events, TelnetCloseReason::RemoteEof);
                    return;
                }
                for event in protocol_events {
                    let runtime_event = match event {
                        TelnetEvent::ProtocolActivated => continue,
                        TelnetEvent::RemoteEchoChanged { enabled } => {
                            TelnetRuntimeEvent::RemoteEcho { enabled }
                        }
                        TelnetEvent::LocalEchoChanged { enabled } => {
                            TelnetRuntimeEvent::LocalEcho { enabled }
                        }
                    };
                    if !emit_regular(&events, runtime_event) {
                        return;
                    }
                }
                if data.is_empty() {
                    continue;
                }

                let decoded = text_decoder.decode(data.as_slice(), false);
                if !decoded.is_empty()
                    && !process_decoded_data(
                        &mut session,
                        &mut auto_login,
                        charset,
                        &events,
                        decoded,
                    )
                    .await
                {
                    return;
                }
            }
        }
    }
}

async fn apply_auto_login_actions<S>(
    session: &mut TelnetSession<S>,
    charset: TelnetCharset,
    actions: Vec<AutoLoginAction>,
) -> Result<Vec<TelnetRuntimeEvent>, TelnetRuntimeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut control_events = Vec::new();
    for action in actions {
        match action {
            AutoLoginAction::SendLine(line) => {
                let encoded = charset
                    .encode_input(line.expose_bytes())
                    .map_err(map_charset_error)?;
                session.write(encoded.as_slice()).await?;
            }
            AutoLoginAction::Completed { startup_command } => {
                if let Some(command) = startup_command {
                    let mut input = Zeroizing::new(command.expose_bytes().to_vec());
                    input.push(b'\r');
                    let encoded = charset
                        .encode_input(input.as_slice())
                        .map_err(map_charset_error)?;
                    session.write(encoded.as_slice()).await?;
                }
                control_events.push(TelnetRuntimeEvent::AutoLoginCompleted);
            }
            AutoLoginAction::Cancelled => {
                control_events.push(TelnetRuntimeEvent::AutoLoginCancelled);
            }
            AutoLoginAction::TimedOut => {
                control_events.push(TelnetRuntimeEvent::AutoLoginTimedOut);
            }
        }
    }
    Ok(control_events)
}

async fn process_decoded_data<S>(
    session: &mut TelnetSession<S>,
    auto_login: &mut AutoLogin,
    charset: TelnetCharset,
    events: &mpsc::Sender<TelnetRuntimeEvent>,
    decoded: Vec<u8>,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // `encoding_rs` normally guarantees UTF-8 here. Keep the runtime total if
    // that decoder contract ever regresses: replacement characters are safe
    // for prompt matching and the original decoded bytes are still emitted.
    let text = String::from_utf8_lossy(&decoded);
    let actions = match auto_login.handle_text(text.as_ref()) {
        Ok(actions) => actions,
        Err(error) => {
            finish_error(events, TelnetRuntimeError::AutoLogin(error));
            return false;
        }
    };
    match apply_auto_login_actions(session, charset, actions).await {
        Ok(control_events) => {
            for event in control_events {
                if !emit_regular(events, event) {
                    return false;
                }
            }
        }
        Err(error) => {
            finish_error(events, error);
            return false;
        }
    }
    emit_regular(events, TelnetRuntimeEvent::Data(TelnetBytes::from(decoded)))
}

fn map_charset_error(error: CharsetError) -> TelnetRuntimeError {
    match error {
        CharsetError::InvalidUtf8Input => TelnetRuntimeError::InvalidInputEncoding,
        CharsetError::OutputTooLarge => TelnetRuntimeError::EncodedInputTooLarge {
            maximum_bytes: MAX_INPUT_BYTES,
        },
    }
}

fn emit_regular(events: &mpsc::Sender<TelnetRuntimeEvent>, event: TelnetRuntimeEvent) -> bool {
    if events.is_closed() {
        return false;
    }
    if events.capacity() <= TERMINAL_EVENT_RESERVE {
        finish_error(
            events,
            TelnetRuntimeError::EventQueueFull {
                capacity: EVENT_CHANNEL_CAPACITY,
            },
        );
        return false;
    }
    match events.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            finish_error(
                events,
                TelnetRuntimeError::EventQueueFull {
                    capacity: EVENT_CHANNEL_CAPACITY,
                },
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn finish_stopped(events: &mpsc::Sender<TelnetRuntimeEvent>, signal: StopSignal) {
    match signal {
        StopSignal::Running => {}
        StopSignal::Close => emit_closed(events, TelnetCloseReason::Requested),
        StopSignal::Cancel => emit_closed(events, TelnetCloseReason::Cancelled),
    }
}

fn finish_error(events: &mpsc::Sender<TelnetRuntimeEvent>, error: TelnetRuntimeError) {
    let _ = events.try_send(TelnetRuntimeEvent::Error(error));
    emit_closed(events, TelnetCloseReason::Error);
}

fn emit_closed(events: &mpsc::Sender<TelnetRuntimeEvent>, reason: TelnetCloseReason) {
    let _ = events.try_send(TelnetRuntimeEvent::Closed { reason });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_and_debug_hide_all_text_values() {
        let marker = "PRIVATE-CONFIG-MARKER";
        let config = TelnetRuntimeConfig::new(marker, 23, 80, 24)
            .unwrap()
            .with_terminal_type("SECRET-TERM")
            .unwrap()
            .with_username(marker)
            .unwrap()
            .with_password(marker)
            .unwrap()
            .with_startup_command(marker)
            .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(marker));
        assert!(!debug.contains("SECRET-TERM"));
        assert!(TelnetRuntimeConfig::new("", 23, 80, 24).is_err());
        assert!(TelnetRuntimeConfig::new(" host", 23, 80, 24).is_err());
        assert!(TelnetRuntimeConfig::new("host", 0, 80, 24).is_err());
    }

    #[test]
    fn utf8_decoder_preserves_split_code_points() {
        let mut decoder = TelnetCharset::Utf8.decoder();
        let bytes = "用户名: ".as_bytes();
        assert_eq!(decoder.decode(&bytes[..2], false), b"");
        assert_eq!(decoder.decode(&bytes[2..5], false), "用".as_bytes());
        assert_eq!(decoder.decode(&bytes[5..], false), "户名: ".as_bytes());
    }

    #[test]
    fn utf8_decoder_replaces_invalid_sequences_without_retaining_payload_in_debug() {
        let mut decoder = TelnetCharset::Utf8.decoder();
        assert_eq!(
            decoder.decode(&[b'a', 0xff, b'b'], false),
            "a\u{fffd}b".as_bytes()
        );
    }

    #[test]
    fn runtime_errors_do_not_include_payloads() {
        let marker = "PRIVATE-RUNTIME-MARKER";
        let error = TelnetRuntimeError::ConnectionFailed {
            kind: io::Error::new(io::ErrorKind::Other, marker).kind(),
        };
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
        let event = TelnetRuntimeEvent::Data(TelnetBytes::from(marker.as_bytes().to_vec()));
        assert!(!format!("{event:?}").contains(marker));
    }

    #[test]
    fn opaque_session_ids_round_trip_for_adapter_boundaries() {
        let value = "550e8400-e29b-41d4-a716-446655440000";
        let parsed = TelnetSessionId::parse(value).unwrap();
        assert_eq!(parsed.as_str(), value);
        assert_eq!(value.parse::<TelnetSessionId>().unwrap(), parsed);
        assert_eq!(
            TelnetSessionId::parse("550E8400-E29B-41D4-A716-446655440000"),
            Err(TelnetRuntimeError::InvalidSessionId)
        );
        assert_eq!(
            TelnetSessionId::parse("PRIVATE-ID-PAYLOAD"),
            Err(TelnetRuntimeError::InvalidSessionId)
        );
        assert!(!format!("{:?}", TelnetRuntimeError::InvalidSessionId).contains("PRIVATE"));
    }
}
