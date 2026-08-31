use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    runtime::Handle,
    sync::{mpsc, oneshot, watch},
    time::Instant,
};
use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilderExt, StopBits};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    SerialCharset, SerialCharsetError, SerialConfig, SerialConfigError, SerialDataBits,
    SerialFlowControl, SerialParity, SerialStopBits, SerialTransferKind, ZmodemSentry,
    ZmodemTransferDirection,
};

pub const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds every serial write/flush operation so hardware flow control or a
/// stalled driver cannot permanently pin a session or its raw-transfer lease.
pub const IO_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IO_WRITE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// A detected ZMODEM initiator owns raw bytes before the native picker opens.
/// If the renderer never claims it, release that ownership automatically.
pub const ZMODEM_DETECTION_TIMEOUT: Duration = Duration::from_secs(15);
const PROTOCOL_ABORT_DRAIN_IDLE: Duration = Duration::from_millis(150);
const PROTOCOL_ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;
pub const EVENT_CHANNEL_CAPACITY: usize = 128;
pub const RAW_TRANSFER_EVENT_CHANNEL_CAPACITY: usize = 64;
pub const MAX_INPUT_BYTES: usize = 64 * 1_024;
/// Worst-case ZDLE expansion for one bounded ZMODEM subpacket, plus framing.
/// YMODEM packets remain much smaller but share the same raw transport.
pub const MAX_RAW_TRANSFER_WRITE_BYTES: usize = 2 * 64 * 1_024 + 16;
pub const MAX_WINDOW_DIMENSION: u32 = u16::MAX as u32;
const READ_BUFFER_BYTES: usize = 16 * 1_024;
const MAX_EVENT_DATA_BYTES: usize = READ_BUFFER_BYTES * 4 + 2;
const TERMINAL_EVENT_RESERVE: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialWindowSize {
    columns: u16,
    rows: u16,
}

impl SerialWindowSize {
    pub fn new(columns: u32, rows: u32) -> Result<Self, SerialRuntimeError> {
        if columns == 0
            || rows == 0
            || columns > MAX_WINDOW_DIMENSION
            || rows > MAX_WINDOW_DIMENSION
        {
            return Err(SerialRuntimeError::InvalidWindowSize {
                maximum: MAX_WINDOW_DIMENSION,
            });
        }
        Ok(Self {
            columns: columns as u16,
            rows: rows as u16,
        })
    }

    pub const fn columns(self) -> u16 {
        self.columns
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }
}

/// Validated input for one runtime session. Device paths are redacted from
/// `Debug`, while typed settings remain available to thin native adapters.
#[derive(Clone)]
pub struct SerialRuntimeConfig {
    serial: SerialConfig,
    charset: SerialCharset,
    window_size: SerialWindowSize,
}

impl SerialRuntimeConfig {
    pub fn new(serial: SerialConfig, columns: u32, rows: u32) -> Result<Self, SerialRuntimeError> {
        serial
            .validate_backend_support()
            .map_err(SerialRuntimeError::Config)?;
        Ok(Self {
            serial,
            charset: SerialCharset::Utf8,
            window_size: SerialWindowSize::new(columns, rows)?,
        })
    }

    pub fn with_charset(mut self, charset: SerialCharset) -> Self {
        self.charset = charset;
        self
    }

    pub fn serial(&self) -> &SerialConfig {
        &self.serial
    }

    pub const fn charset(&self) -> SerialCharset {
        self.charset
    }

    pub const fn window_size(&self) -> SerialWindowSize {
        self.window_size
    }
}

impl fmt::Debug for SerialRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialRuntimeConfig")
            .field("serial", &self.serial)
            .field("charset", &self.charset)
            .field("window_size", &self.window_size)
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SerialSessionId(String);

impl SerialSessionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, SerialRuntimeError> {
        let parsed = Uuid::parse_str(value).map_err(|_| SerialRuntimeError::InvalidSessionId)?;
        let canonical = parsed.hyphenated().to_string();
        if value != canonical {
            return Err(SerialRuntimeError::InvalidSessionId);
        }
        Ok(Self(canonical))
    }
}

impl FromStr for SerialSessionId {
    type Err = SerialRuntimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for SerialSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for SerialSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SerialTransferId(String);

impl SerialTransferId {
    fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, SerialRuntimeError> {
        let parsed = Uuid::parse_str(value).map_err(|_| SerialRuntimeError::InvalidTransferId)?;
        let canonical = parsed.hyphenated().to_string();
        if value != canonical {
            return Err(SerialRuntimeError::InvalidTransferId);
        }
        Ok(Self(canonical))
    }
}

impl fmt::Debug for SerialTransferId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for SerialTransferId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct SerialBytes(Vec<u8>);

impl SerialBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SerialBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SerialBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialCloseReason {
    Requested,
    Cancelled,
    RemoteEof,
    Error,
}

pub enum SerialRuntimeEvent {
    Connecting,
    Connected,
    Data(SerialBytes),
    ZmodemDetected {
        transfer_id: SerialTransferId,
        direction: ZmodemTransferDirection,
    },
    Error(SerialRuntimeError),
    Closed {
        reason: SerialCloseReason,
    },
}

pub enum SerialRawTransferEvent {
    Data(SerialBytes),
    CancelRequested,
}

impl fmt::Debug for SerialRawTransferEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(bytes) => formatter.debug_tuple("Data").field(bytes).finish(),
            Self::CancelRequested => formatter.write_str("CancelRequested"),
        }
    }
}

impl fmt::Debug for SerialRuntimeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => formatter.write_str("Connecting"),
            Self::Connected => formatter.write_str("Connected"),
            Self::Data(bytes) => formatter.debug_tuple("Data").field(bytes).finish(),
            Self::ZmodemDetected {
                transfer_id,
                direction,
            } => formatter
                .debug_struct("ZmodemDetected")
                .field("transfer_id", transfer_id)
                .field("direction", direction)
                .finish(),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::Closed { reason } => formatter
                .debug_struct("Closed")
                .field("reason", reason)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialErrorKind {
    NotFound,
    Unavailable,
    AccessDeniedOrBusy,
    InvalidInput,
    TimedOut,
    Disconnected,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialIoOperation {
    Open,
    Read,
    Write,
    Flush,
    Enumerate,
}

/// Runtime failures use only typed categories and limits; backend descriptions,
/// device paths, and terminal input/output never enter `Display` or `Debug`.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SerialRuntimeError {
    Config(SerialConfigError),
    InvalidSessionId,
    InvalidTransferId,
    InvalidWindowSize {
        maximum: u32,
    },
    InputTooLarge {
        maximum_bytes: usize,
    },
    InvalidInputEncoding,
    EncodedInputTooLarge {
        maximum_bytes: usize,
    },
    EventDataTooLarge {
        maximum_bytes: usize,
    },
    RuntimeUnavailable,
    RuntimeTaskFailed {
        operation: SerialIoOperation,
    },
    SessionNotFound,
    SessionClosing,
    CommandQueueFull {
        capacity: usize,
    },
    EventQueueFull {
        capacity: usize,
    },
    TransferEventQueueFull {
        capacity: usize,
    },
    TransferActive {
        kind: SerialTransferKind,
    },
    TransferNotActive,
    TransferCancelled,
    TransferWriteTooLarge {
        maximum_bytes: usize,
    },
    OpenTimeout {
        timeout: Duration,
    },
    ConnectionFailed {
        kind: SerialErrorKind,
    },
    IoFailed {
        operation: SerialIoOperation,
        kind: SerialErrorKind,
    },
    PortInventoryTooLarge {
        maximum_entries: usize,
    },
    InvalidPortMetadata {
        maximum_bytes: usize,
    },
}

impl fmt::Debug for SerialRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SerialRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "Serial configuration error: {error}"),
            Self::InvalidSessionId => formatter.write_str("Serial session ID is invalid"),
            Self::InvalidTransferId => formatter.write_str("Serial transfer ID is invalid"),
            Self::InvalidWindowSize { maximum } => write!(
                formatter,
                "Serial terminal dimensions must be between 1 and {maximum}"
            ),
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "Serial input exceeds {maximum_bytes} bytes")
            }
            Self::InvalidInputEncoding => {
                formatter.write_str("Serial renderer input is not valid UTF-8")
            }
            Self::EncodedInputTooLarge { maximum_bytes } => write!(
                formatter,
                "Serial encoded input exceeds {maximum_bytes} bytes"
            ),
            Self::EventDataTooLarge { maximum_bytes } => write!(
                formatter,
                "Serial decoded output exceeds the {maximum_bytes}-byte event limit"
            ),
            Self::RuntimeUnavailable => {
                formatter.write_str("Serial runtime requires an active Tokio runtime")
            }
            Self::RuntimeTaskFailed { operation } => {
                write!(formatter, "Serial {operation:?} worker failed")
            }
            Self::SessionNotFound => formatter.write_str("Serial session was not found"),
            Self::SessionClosing => formatter.write_str("Serial session is closing"),
            Self::CommandQueueFull { capacity } => write!(
                formatter,
                "Serial command queue reached its {capacity}-item limit"
            ),
            Self::EventQueueFull { capacity } => write!(
                formatter,
                "Serial event queue reached its {capacity}-item limit"
            ),
            Self::TransferEventQueueFull { capacity } => write!(
                formatter,
                "Serial file-transfer queue reached its {capacity}-item limit"
            ),
            Self::TransferActive { kind } => {
                write!(
                    formatter,
                    "A Serial file transfer is already active ({kind:?})"
                )
            }
            Self::TransferNotActive => formatter.write_str("Serial file transfer is not active"),
            Self::TransferCancelled => formatter.write_str("Serial file transfer was cancelled"),
            Self::TransferWriteTooLarge { maximum_bytes } => write!(
                formatter,
                "Serial file-transfer write exceeds {maximum_bytes} bytes"
            ),
            Self::OpenTimeout { timeout } => write!(
                formatter,
                "Serial port open timed out after {} seconds",
                timeout.as_secs()
            ),
            Self::ConnectionFailed { kind } => {
                write!(formatter, "Serial port connection failed ({kind:?})")
            }
            Self::IoFailed { operation, kind } => {
                write!(formatter, "Serial {operation:?} failed ({kind:?})")
            }
            Self::PortInventoryTooLarge { maximum_entries } => write!(
                formatter,
                "Serial port inventory exceeds {maximum_entries} entries"
            ),
            Self::InvalidPortMetadata { maximum_bytes } => write!(
                formatter,
                "Serial port metadata is invalid or exceeds {maximum_bytes} bytes"
            ),
        }
    }
}

impl Error for SerialRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SerialConfigError> for SerialRuntimeError {
    fn from(error: SerialConfigError) -> Self {
        Self::Config(error)
    }
}

pub struct SerialRuntimeSession {
    session_id: SerialSessionId,
    events: mpsc::Receiver<SerialRuntimeEvent>,
}

impl SerialRuntimeSession {
    pub fn session_id(&self) -> &SerialSessionId {
        &self.session_id
    }

    pub async fn recv(&mut self) -> Option<SerialRuntimeEvent> {
        self.events.recv().await
    }

    pub fn try_recv(&mut self) -> Result<SerialRuntimeEvent, mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    pub fn into_parts(self) -> (SerialSessionId, mpsc::Receiver<SerialRuntimeEvent>) {
        (self.session_id, self.events)
    }
}

impl fmt::Debug for SerialRuntimeSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialRuntimeSession")
            .field("session_id", &self.session_id)
            .field("queued_events", &self.events.len())
            .finish()
    }
}

pub struct SerialRawTransfer {
    session_id: SerialSessionId,
    transfer_id: SerialTransferId,
    kind: SerialTransferKind,
    token: u64,
    commands: mpsc::Sender<RuntimeCommand>,
    reservation: Arc<Mutex<Option<RawTransferReservation>>>,
    events: mpsc::Receiver<SerialRawTransferEvent>,
    cancel: watch::Receiver<bool>,
    cancel_open: bool,
    cancel_delivered: bool,
    finished: bool,
}

impl SerialRawTransfer {
    pub fn session_id(&self) -> &SerialSessionId {
        &self.session_id
    }

    pub fn transfer_id(&self) -> &SerialTransferId {
        &self.transfer_id
    }

    pub const fn kind(&self) -> SerialTransferKind {
        self.kind
    }

    pub async fn recv(&mut self) -> Option<SerialRawTransferEvent> {
        loop {
            if self.take_cancel_request() {
                return Some(SerialRawTransferEvent::CancelRequested);
            }
            tokio::select! {
                biased;
                changed = self.cancel.changed(), if self.cancel_open => {
                    if changed.is_err() {
                        self.cancel_open = false;
                    }
                }
                event = self.events.recv() => return event,
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<SerialRawTransferEvent, mpsc::error::TryRecvError> {
        if self.take_cancel_request() {
            return Ok(SerialRawTransferEvent::CancelRequested);
        }
        self.events.try_recv()
    }

    fn take_cancel_request(&mut self) -> bool {
        let requested = !self.cancel_delivered && *self.cancel.borrow_and_update();
        if requested {
            self.cancel_delivered = true;
        }
        requested
    }

    pub async fn write(&self, bytes: &[u8]) -> Result<(), SerialRuntimeError> {
        if bytes.len() > MAX_RAW_TRANSFER_WRITE_BYTES {
            return Err(SerialRuntimeError::TransferWriteTooLarge {
                maximum_bytes: MAX_RAW_TRANSFER_WRITE_BYTES,
            });
        }
        if !reservation_matches(&self.reservation, self.token) {
            return Err(SerialRuntimeError::TransferNotActive);
        }
        let (acknowledge, acknowledged) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::TransferWrite {
                token: self.token,
                bytes: Zeroizing::new(bytes.to_vec()),
                acknowledge,
            })
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?;
        acknowledged
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?
    }

    /// Writes a protocol abort sequence for this exact transfer generation.
    /// Unlike a normal transfer write, this remains available after the
    /// transfer's cancel watch fires. Session stop and baud-aware I/O deadlines
    /// still interrupt it. YMODEM and ZMODEM aborts additionally arm the
    /// actor's bounded post-abort raw drain.
    pub async fn write_protocol_abort(&self, bytes: &[u8]) -> Result<(), SerialRuntimeError> {
        if bytes.len() > MAX_RAW_TRANSFER_WRITE_BYTES {
            return Err(SerialRuntimeError::TransferWriteTooLarge {
                maximum_bytes: MAX_RAW_TRANSFER_WRITE_BYTES,
            });
        }
        if !reservation_matches(&self.reservation, self.token) {
            return Err(SerialRuntimeError::TransferNotActive);
        }
        let (acknowledge, acknowledged) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::TransferAbortWrite {
                token: self.token,
                bytes: Zeroizing::new(bytes.to_vec()),
                acknowledge,
            })
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?;
        acknowledged
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?
    }

    /// Releases raw-byte ownership only after every preceding transfer write
    /// has been processed by the serial actor.
    pub async fn finish(self) -> Result<(), SerialRuntimeError> {
        self.finish_with_terminal_bytes(&[]).await
    }

    /// Releases ownership and returns only protocol-decoder bytes known to
    /// follow a successful terminal marker to the normal terminal pipeline.
    pub async fn finish_with_terminal_bytes(
        mut self,
        terminal_bytes: &[u8],
    ) -> Result<(), SerialRuntimeError> {
        if terminal_bytes.len() > MAX_EVENT_DATA_BYTES {
            return Err(SerialRuntimeError::EventDataTooLarge {
                maximum_bytes: MAX_EVENT_DATA_BYTES,
            });
        }
        let (acknowledge, acknowledged) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::EndTransfer {
                token: self.token,
                terminal_bytes: Zeroizing::new(terminal_bytes.to_vec()),
                acknowledge: Some(acknowledge),
            })
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?;
        acknowledged
            .await
            .map_err(|_| SerialRuntimeError::SessionClosing)?;
        self.finished = true;
        Ok(())
    }
}

impl fmt::Debug for SerialRawTransfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialRawTransfer")
            .field("session_id", &self.session_id)
            .field("transfer_id", &self.transfer_id)
            .field("kind", &self.kind)
            .field("queued_events", &self.events.len())
            .finish()
    }
}

impl Drop for SerialRawTransfer {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.commands.try_send(RuntimeCommand::EndTransfer {
            token: self.token,
            terminal_bytes: Zeroizing::new(Vec::new()),
            acknowledge: None,
        });
    }
}

trait AsyncSerialIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncSerialIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedSerialIo = Box<dyn AsyncSerialIo>;
type OpenFuture =
    Pin<Box<dyn Future<Output = Result<BoxedSerialIo, SerialRuntimeError>> + Send + 'static>>;

trait SerialBackend: Send + Sync {
    fn open(&self, config: SerialConfig) -> OpenFuture;
}

#[derive(Debug, Default)]
struct NativeSerialBackend;

impl SerialBackend for NativeSerialBackend {
    fn open(&self, config: SerialConfig) -> OpenFuture {
        Box::pin(async move {
            config.validate_backend_support()?;
            let builder = tokio_serial::new(config.path, config.baud_rate)
                .data_bits(map_data_bits(config.data_bits))
                .stop_bits(map_stop_bits(config.stop_bits)?)
                .parity(map_parity(config.parity)?)
                .flow_control(map_flow_control(config.flow_control));
            let result = tokio::task::spawn_blocking(move || builder.open_native_async())
                .await
                .map_err(|_| SerialRuntimeError::RuntimeTaskFailed {
                    operation: SerialIoOperation::Open,
                })?;
            let stream = result.map_err(|error| SerialRuntimeError::ConnectionFailed {
                kind: map_backend_error_kind(error.kind()),
            })?;
            Ok(Box::new(stream) as BoxedSerialIo)
        })
    }
}

#[derive(Clone)]
pub struct SerialRuntimeManager {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    sessions: Mutex<HashMap<SerialSessionId, SessionEntry>>,
    backend: Arc<dyn SerialBackend>,
    next_transfer_token: AtomicU64,
}

#[derive(Clone)]
struct SessionEntry {
    commands: mpsc::Sender<RuntimeCommand>,
    stop: watch::Sender<StopSignal>,
    charset: SerialCharset,
    window_size: Arc<Mutex<SerialWindowSize>>,
    transfer: Arc<Mutex<Option<RawTransferReservation>>>,
    detected_zmodem: Arc<Mutex<Option<DetectedZmodemTransfer>>>,
}

#[derive(Clone)]
struct RawTransferReservation {
    token: u64,
    transfer_id: SerialTransferId,
    kind: SerialTransferKind,
    events: mpsc::Sender<SerialRawTransferEvent>,
    cancel: watch::Sender<bool>,
}

struct DetectedZmodemTransfer {
    token: u64,
    transfer_id: SerialTransferId,
    direction: ZmodemTransferDirection,
    events: mpsc::Receiver<SerialRawTransferEvent>,
    cancel: watch::Receiver<bool>,
    consecutive_can: u8,
    deadline: Instant,
}

enum RuntimeCommand {
    Input(Zeroizing<Vec<u8>>),
    TransferWrite {
        token: u64,
        bytes: Zeroizing<Vec<u8>>,
        acknowledge: oneshot::Sender<Result<(), SerialRuntimeError>>,
    },
    TransferAbortWrite {
        token: u64,
        bytes: Zeroizing<Vec<u8>>,
        acknowledge: oneshot::Sender<Result<(), SerialRuntimeError>>,
    },
    EndTransfer {
        token: u64,
        terminal_bytes: Zeroizing<Vec<u8>>,
        acknowledge: Option<oneshot::Sender<()>>,
    },
    DeclineDetectedZmodem {
        token: u64,
        direction: ZmodemTransferDirection,
    },
}

impl fmt::Debug for RuntimeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(bytes) => formatter
                .debug_struct("Input")
                .field("bytes", &bytes.len())
                .finish(),
            Self::TransferWrite { bytes, .. } => formatter
                .debug_struct("TransferWrite")
                .field("bytes", &bytes.len())
                .finish(),
            Self::TransferAbortWrite { bytes, .. } => formatter
                .debug_struct("TransferAbortWrite")
                .field("bytes", &bytes.len())
                .finish(),
            Self::EndTransfer {
                terminal_bytes,
                acknowledge,
                ..
            } => formatter
                .debug_struct("EndTransfer")
                .field("terminal_bytes", &terminal_bytes.len())
                .field("acknowledge", &acknowledge.is_some())
                .finish(),
            Self::DeclineDetectedZmodem { direction, .. } => formatter
                .debug_struct("DeclineDetectedZmodem")
                .field("direction", direction)
                .finish(),
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

impl SerialRuntimeManager {
    pub fn new() -> Self {
        Self::with_backend(Arc::new(NativeSerialBackend))
    }

    fn with_backend(backend: Arc<dyn SerialBackend>) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                sessions: Mutex::new(HashMap::new()),
                backend,
                next_transfer_token: AtomicU64::new(1),
            }),
        }
    }

    /// Register one session immediately and perform the potentially blocking
    /// device open on Tokio's blocking pool. Cancellation wins independently
    /// of a stuck driver; a late open result is dropped and closes its handle.
    pub fn start(
        &self,
        config: SerialRuntimeConfig,
    ) -> Result<SerialRuntimeSession, SerialRuntimeError> {
        config.serial.validate_backend_support()?;
        let handle = Handle::try_current().map_err(|_| SerialRuntimeError::RuntimeUnavailable)?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (stop_tx, stop_rx) = watch::channel(StopSignal::Running);
        let window_size = Arc::new(Mutex::new(config.window_size));
        let transfer = Arc::new(Mutex::new(None));
        let detected_zmodem = Arc::new(Mutex::new(None));

        let session_id = loop {
            let candidate = SerialSessionId(Uuid::new_v4().to_string());
            let mut sessions = lock_sessions(&self.inner);
            if !sessions.contains_key(&candidate) {
                sessions.insert(
                    candidate.clone(),
                    SessionEntry {
                        commands: command_tx.clone(),
                        stop: stop_tx.clone(),
                        charset: config.charset,
                        window_size: window_size.clone(),
                        transfer: transfer.clone(),
                        detected_zmodem: detected_zmodem.clone(),
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
            transfer,
            detected_zmodem,
        ));
        Ok(SerialRuntimeSession {
            session_id,
            events: event_rx,
        })
    }

    pub fn input(
        &self,
        session_id: &SerialSessionId,
        input: &[u8],
    ) -> Result<(), SerialRuntimeError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(SerialRuntimeError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES,
            });
        }
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        let transfer = lock_transfer(&entry.transfer);
        if let Some(active) = transfer.as_ref() {
            if input == [0x03] {
                active.cancel.send_replace(true);
                return Ok(());
            }
            return Err(SerialRuntimeError::TransferActive { kind: active.kind });
        }
        let encoded = entry
            .charset
            .encode_input(input)
            .map_err(map_charset_error)?;
        try_send_command(&entry.commands, RuntimeCommand::Input(encoded))
    }

    /// Atomically takes raw serial-byte ownership for one file transfer. While
    /// held, device output bypasses charset decoding and ordinary terminal
    /// input is rejected. An exact Ctrl+C input becomes `CancelRequested`.
    pub fn begin_raw_transfer(
        &self,
        session_id: &SerialSessionId,
        kind: SerialTransferKind,
    ) -> Result<SerialRawTransfer, SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        let (events, receiver) = mpsc::channel(RAW_TRANSFER_EVENT_CHANNEL_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);
        let mut reservation = lock_transfer(&entry.transfer);
        if let Some(active) = reservation.as_ref() {
            return Err(SerialRuntimeError::TransferActive { kind: active.kind });
        }
        let token = self
            .inner
            .next_transfer_token
            .fetch_add(1, Ordering::Relaxed);
        let transfer_id = SerialTransferId::new();
        *reservation = Some(RawTransferReservation {
            token,
            transfer_id: transfer_id.clone(),
            kind,
            events,
            cancel,
        });
        drop(reservation);
        Ok(SerialRawTransfer {
            session_id: session_id.clone(),
            transfer_id,
            kind,
            token,
            commands: entry.commands,
            reservation: entry.transfer,
            events: receiver,
            cancel: cancel_receiver,
            cancel_open: true,
            cancel_delivered: false,
            finished: false,
        })
    }

    /// Claims the exact raw reservation created by the CRC-valid ZMODEM
    /// sentry. Detection already owns the serial stream, so no bytes can pass
    /// through charset decoding or Connection Log while the desktop opens its
    /// native picker.
    pub fn claim_detected_zmodem(
        &self,
        session_id: &SerialSessionId,
        transfer_id: &SerialTransferId,
        direction: ZmodemTransferDirection,
    ) -> Result<SerialRawTransfer, SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;

        // Keep the same lock order as the actor's reservation path.
        let reservation = lock_transfer(&entry.transfer);
        let Some(active) = reservation.as_ref() else {
            return Err(SerialRuntimeError::TransferNotActive);
        };
        if active.kind != SerialTransferKind::Zmodem {
            return Err(SerialRuntimeError::TransferActive { kind: active.kind });
        }
        if &active.transfer_id != transfer_id {
            return Err(SerialRuntimeError::TransferNotActive);
        }
        let token = active.token;
        drop(reservation);

        let mut detected = lock_detected_zmodem(&entry.detected_zmodem);
        let pending = detected
            .take()
            .ok_or(SerialRuntimeError::TransferNotActive)?;
        if pending.token != token
            || &pending.transfer_id != transfer_id
            || pending.direction != direction
        {
            *detected = Some(pending);
            return Err(SerialRuntimeError::TransferNotActive);
        }
        drop(detected);

        Ok(SerialRawTransfer {
            session_id: session_id.clone(),
            transfer_id: transfer_id.clone(),
            kind: SerialTransferKind::Zmodem,
            token,
            commands: entry.commands,
            reservation: entry.transfer,
            events: pending.events,
            cancel: pending.cancel,
            cancel_open: true,
            cancel_delivered: false,
            finished: false,
        })
    }

    /// Explicitly releases an unclaimed sentry reservation. This is used when
    /// a consumer deliberately declines a detection; an independent deadline
    /// still protects sessions whose consumer disappears without replying.
    pub fn decline_detected_zmodem(
        &self,
        session_id: &SerialSessionId,
        transfer_id: &SerialTransferId,
        direction: ZmodemTransferDirection,
    ) -> Result<(), SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        let reservation = lock_transfer(&entry.transfer);
        let Some(active) = reservation.as_ref() else {
            return Err(SerialRuntimeError::TransferNotActive);
        };
        if active.kind != SerialTransferKind::Zmodem {
            return Err(SerialRuntimeError::TransferActive { kind: active.kind });
        }
        if &active.transfer_id != transfer_id {
            return Err(SerialRuntimeError::TransferNotActive);
        }
        let token = active.token;
        drop(reservation);
        let detected = lock_detected_zmodem(&entry.detected_zmodem);
        if !detected.as_ref().is_some_and(|pending| {
            pending.token == token
                && &pending.transfer_id == transfer_id
                && pending.direction == direction
        }) {
            return Err(SerialRuntimeError::TransferNotActive);
        }
        drop(detected);
        try_send_command(
            &entry.commands,
            RuntimeCommand::DeclineDetectedZmodem { token, direction },
        )
    }

    pub fn active_transfer_kind(
        &self,
        session_id: &SerialSessionId,
    ) -> Result<Option<SerialTransferKind>, SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        Ok(lock_transfer(&entry.transfer)
            .as_ref()
            .map(|transfer| transfer.kind))
    }

    /// Signals only the exact transfer generation. Matching and signaling are
    /// performed while holding one reservation lock, so a delayed cancel for
    /// transfer A cannot cancel a later transfer B in the same serial session.
    pub fn request_transfer_cancel_exact(
        &self,
        session_id: &SerialSessionId,
        transfer_id: &SerialTransferId,
    ) -> Result<(), SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        let reservation = lock_transfer(&entry.transfer);
        let active = reservation
            .as_ref()
            .filter(|active| &active.transfer_id == transfer_id)
            .ok_or(SerialRuntimeError::TransferNotActive)?;
        active.cancel.send_replace(true);
        Ok(())
    }

    /// Serial transports have no resize protocol. Keep the latest validated
    /// dimensions as session state for UI/capture coordination without writing
    /// any bytes to the device.
    pub fn resize(
        &self,
        session_id: &SerialSessionId,
        columns: u32,
        rows: u32,
    ) -> Result<(), SerialRuntimeError> {
        let size = SerialWindowSize::new(columns, rows)?;
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        *lock_window_size(&entry.window_size) = size;
        Ok(())
    }

    pub fn window_size(
        &self,
        session_id: &SerialSessionId,
    ) -> Result<SerialWindowSize, SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        Ok(*lock_window_size(&entry.window_size))
    }

    pub fn close(&self, session_id: &SerialSessionId) -> Result<(), SerialRuntimeError> {
        self.request_stop(session_id, StopSignal::Close)
    }

    pub fn cancel(&self, session_id: &SerialSessionId) -> Result<(), SerialRuntimeError> {
        self.request_stop(session_id, StopSignal::Cancel)
    }

    pub fn contains(&self, session_id: &SerialSessionId) -> bool {
        lock_sessions(&self.inner).contains_key(session_id)
    }

    pub fn session_count(&self) -> usize {
        lock_sessions(&self.inner).len()
    }

    fn request_stop(
        &self,
        session_id: &SerialSessionId,
        signal: StopSignal,
    ) -> Result<(), SerialRuntimeError> {
        let entry = self.entry(session_id)?;
        if *entry.stop.borrow() == StopSignal::Running {
            entry.stop.send_replace(signal);
        }
        Ok(())
    }

    fn entry(&self, session_id: &SerialSessionId) -> Result<SessionEntry, SerialRuntimeError> {
        lock_sessions(&self.inner)
            .get(session_id)
            .cloned()
            .ok_or(SerialRuntimeError::SessionNotFound)
    }
}

impl Default for SerialRuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SerialRuntimeManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialRuntimeManager")
            .field("session_count", &self.session_count())
            .finish()
    }
}

fn lock_sessions(inner: &RuntimeInner) -> MutexGuard<'_, HashMap<SerialSessionId, SessionEntry>> {
    inner
        .sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_window_size(size: &Mutex<SerialWindowSize>) -> MutexGuard<'_, SerialWindowSize> {
    size.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_transfer(
    transfer: &Mutex<Option<RawTransferReservation>>,
) -> MutexGuard<'_, Option<RawTransferReservation>> {
    transfer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_detected_zmodem(
    detected: &Mutex<Option<DetectedZmodemTransfer>>,
) -> MutexGuard<'_, Option<DetectedZmodemTransfer>> {
    detected
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn reservation_matches(transfer: &Mutex<Option<RawTransferReservation>>, token: u64) -> bool {
    lock_transfer(transfer)
        .as_ref()
        .is_some_and(|active| active.token == token)
}

fn try_send_transfer_event(
    sender: &mpsc::Sender<SerialRawTransferEvent>,
    event: SerialRawTransferEvent,
) -> Result<(), SerialRuntimeError> {
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            Err(SerialRuntimeError::TransferEventQueueFull {
                capacity: RAW_TRANSFER_EVENT_CHANNEL_CAPACITY,
            })
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(SerialRuntimeError::TransferNotActive),
    }
}

fn active_transfer_events(
    transfer: &Mutex<Option<RawTransferReservation>>,
) -> Option<mpsc::Sender<SerialRawTransferEvent>> {
    let mut active = lock_transfer(transfer);
    if active
        .as_ref()
        .is_some_and(|reservation| reservation.events.is_closed())
    {
        *active = None;
        return None;
    }
    active
        .as_ref()
        .map(|reservation| reservation.events.clone())
}

enum ReserveDetectedZmodemOutcome {
    RoutedToActive,
    Detected(SerialTransferId),
    RemoteCancelled {
        drain: ProtocolAbortDrain,
        terminal_tail: Option<Vec<u8>>,
    },
}

fn reserve_detected_zmodem(
    inner: &RuntimeInner,
    transfer: &Mutex<Option<RawTransferReservation>>,
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
    direction: ZmodemTransferDirection,
    protocol_bytes: Vec<u8>,
) -> Result<ReserveDetectedZmodemOutcome, SerialRuntimeError> {
    let mut reservation = lock_transfer(transfer);
    if let Some(active) = reservation.as_ref() {
        let events = active.events.clone();
        drop(reservation);
        try_send_transfer_event(
            &events,
            SerialRawTransferEvent::Data(SerialBytes::from(protocol_bytes)),
        )?;
        return Ok(ReserveDetectedZmodemOutcome::RoutedToActive);
    }

    let token = inner.next_transfer_token.fetch_add(1, Ordering::Relaxed);
    let transfer_id = SerialTransferId::new();
    let (events, receiver) = mpsc::channel(RAW_TRANSFER_EVENT_CHANNEL_CAPACITY);
    let (cancel, cancel_receiver) = watch::channel(false);
    let now = Instant::now();
    let mut abort_drain = ProtocolAbortDrain::with_consecutive_can(token, 5, 0, now);
    let terminal_tail = abort_drain.push(&protocol_bytes, now);
    if abort_drain.marker_seen {
        *reservation = Some(RawTransferReservation {
            token,
            transfer_id,
            kind: SerialTransferKind::Zmodem,
            events,
            cancel,
        });
        drop(receiver);
        drop(cancel_receiver);
        return Ok(ReserveDetectedZmodemOutcome::RemoteCancelled {
            drain: abort_drain,
            terminal_tail,
        });
    }
    try_send_transfer_event(
        &events,
        SerialRawTransferEvent::Data(SerialBytes::from(protocol_bytes)),
    )?;
    *reservation = Some(RawTransferReservation {
        token,
        transfer_id: transfer_id.clone(),
        kind: SerialTransferKind::Zmodem,
        events,
        cancel,
    });
    let mut detected = lock_detected_zmodem(detected_zmodem);
    *detected = Some(DetectedZmodemTransfer {
        token,
        transfer_id: transfer_id.clone(),
        direction,
        events: receiver,
        cancel: cancel_receiver,
        consecutive_can: abort_drain.consecutive_can,
        deadline: now + ZMODEM_DETECTION_TIMEOUT,
    });
    Ok(ReserveDetectedZmodemOutcome::Detected(transfer_id))
}

fn record_pending_zmodem_bytes(
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
    bytes: &[u8],
    now: Instant,
) -> Option<(ProtocolAbortDrain, Option<Vec<u8>>)> {
    let mut detected = lock_detected_zmodem(detected_zmodem);
    let pending = detected.as_mut()?;
    let mut drain =
        ProtocolAbortDrain::with_consecutive_can(pending.token, 5, pending.consecutive_can, now);
    let terminal_tail = drain.push(bytes, now);
    pending.consecutive_can = drain.consecutive_can;
    if drain.marker_seen {
        *detected = None;
        Some((drain, terminal_tail))
    } else {
        None
    }
}

fn pending_zmodem_deadline(
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
) -> Option<Instant> {
    lock_detected_zmodem(detected_zmodem)
        .as_ref()
        .map(|pending| pending.deadline)
}

async fn wait_for_pending_zmodem_deadline(detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>) {
    if let Some(deadline) = pending_zmodem_deadline(detected_zmodem) {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn expire_pending_zmodem(
    transfer: &Mutex<Option<RawTransferReservation>>,
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
    now: Instant,
) -> Option<u64> {
    // Preserve the transfer -> detected lock order used by claim/reserve.
    let reservation = lock_transfer(transfer);
    let mut detected = lock_detected_zmodem(detected_zmodem);
    let Some(pending) = detected.as_ref() else {
        return None;
    };
    if pending.deadline > now
        || !reservation
            .as_ref()
            .is_some_and(|active| active.token == pending.token)
    {
        return None;
    }
    let token = pending.token;
    *detected = None;
    Some(token)
}

fn decline_pending_zmodem(
    transfer: &Mutex<Option<RawTransferReservation>>,
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
    token: u64,
    direction: ZmodemTransferDirection,
) -> bool {
    let reservation = lock_transfer(transfer);
    let mut detected = lock_detected_zmodem(detected_zmodem);
    if !reservation
        .as_ref()
        .is_some_and(|active| active.token == token)
        || !detected
            .as_ref()
            .is_some_and(|pending| pending.token == token && pending.direction == direction)
    {
        return false;
    }
    *detected = None;
    true
}

fn release_abandoned_transfer(
    transfer: &Mutex<Option<RawTransferReservation>>,
    protected_token: Option<u64>,
) -> Option<u64> {
    let mut active = lock_transfer(transfer);
    if active.as_ref().is_some_and(|reservation| {
        reservation.events.is_closed() && Some(reservation.token) != protected_token
    }) {
        let token = active.as_ref().map(|reservation| reservation.token);
        *active = None;
        token
    } else {
        None
    }
}

fn release_transfer(transfer: &Mutex<Option<RawTransferReservation>>, token: u64) -> bool {
    let mut active = lock_transfer(transfer);
    if active
        .as_ref()
        .is_some_and(|reservation| reservation.token == token)
    {
        *active = None;
        true
    } else {
        false
    }
}

fn release_detected_zmodem(detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>, token: u64) {
    let mut detected = lock_detected_zmodem(detected_zmodem);
    if detected
        .as_ref()
        .is_some_and(|pending| pending.token == token)
    {
        *detected = None;
    }
}

fn ensure_running(entry: &SessionEntry) -> Result<(), SerialRuntimeError> {
    if *entry.stop.borrow() == StopSignal::Running {
        Ok(())
    } else {
        Err(SerialRuntimeError::SessionClosing)
    }
}

fn try_send_command(
    sender: &mpsc::Sender<RuntimeCommand>,
    command: RuntimeCommand,
) -> Result<(), SerialRuntimeError> {
    match sender.try_send(command) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(SerialRuntimeError::CommandQueueFull {
            capacity: COMMAND_CHANNEL_CAPACITY,
        }),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(SerialRuntimeError::SessionClosing),
    }
}

struct RegistryGuard {
    inner: Arc<RuntimeInner>,
    session_id: SerialSessionId,
    transfer: Arc<Mutex<Option<RawTransferReservation>>>,
    detected_zmodem: Arc<Mutex<Option<DetectedZmodemTransfer>>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        *lock_transfer(&self.transfer) = None;
        *lock_detected_zmodem(&self.detected_zmodem) = None;
        lock_sessions(&self.inner).remove(&self.session_id);
    }
}

enum InterruptibleIoError {
    Runtime(SerialRuntimeError),
    Stopped(StopSignal),
    EventReceiverClosed,
}

async fn interruptible_serial_io<T, F>(
    operation: SerialIoOperation,
    future: F,
    stop: &mut watch::Receiver<StopSignal>,
    events: &mpsc::Sender<SerialRuntimeEvent>,
    timeout: Duration,
) -> Result<T, InterruptibleIoError>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::pin!(future);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    tokio::select! {
        biased;
        changed = stop.changed() => {
            let signal = if changed.is_ok() {
                *stop.borrow()
            } else {
                StopSignal::Cancel
            };
            Err(InterruptibleIoError::Stopped(signal))
        }
        _ = events.closed() => Err(InterruptibleIoError::EventReceiverClosed),
        _ = &mut deadline => Err(InterruptibleIoError::Runtime(
            SerialRuntimeError::IoFailed {
                operation,
                kind: SerialErrorKind::TimedOut,
            },
        )),
        result = &mut future => result
            .map_err(|error| InterruptibleIoError::Runtime(io_runtime_error(operation, error))),
    }
}

async fn interruptible_transfer_io<T, F>(
    operation: SerialIoOperation,
    future: F,
    stop: &mut watch::Receiver<StopSignal>,
    events: &mpsc::Sender<SerialRuntimeEvent>,
    cancel: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> Result<T, InterruptibleIoError>
where
    F: Future<Output = io::Result<T>>,
{
    if *cancel.borrow_and_update() {
        return Err(InterruptibleIoError::Runtime(
            SerialRuntimeError::TransferCancelled,
        ));
    }
    tokio::pin!(future);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    tokio::select! {
        biased;
        changed = cancel.changed() => {
            if changed.is_ok() && *cancel.borrow_and_update() {
                Err(InterruptibleIoError::Runtime(SerialRuntimeError::TransferCancelled))
            } else {
                Err(InterruptibleIoError::Runtime(SerialRuntimeError::TransferNotActive))
            }
        }
        changed = stop.changed() => {
            let signal = if changed.is_ok() {
                *stop.borrow()
            } else {
                StopSignal::Cancel
            };
            Err(InterruptibleIoError::Stopped(signal))
        }
        _ = events.closed() => Err(InterruptibleIoError::EventReceiverClosed),
        _ = &mut deadline => Err(InterruptibleIoError::Runtime(
            SerialRuntimeError::IoFailed {
                operation,
                kind: SerialErrorKind::TimedOut,
            },
        )),
        result = &mut future => result
            .map_err(|error| InterruptibleIoError::Runtime(io_runtime_error(operation, error))),
    }
}

fn serial_write_timeout(baud_rate: u32, bytes: usize) -> Duration {
    let baud_rate = u64::from(baud_rate.max(1));
    // Twelve wire bits conservatively covers start/data/parity/two-stop-bit
    // configurations. Give the estimated drain time a 2x margin plus 5s.
    let wire_millis = (bytes as u64)
        .saturating_mul(12)
        .saturating_mul(1_000)
        .div_ceil(baud_rate);
    let budget = Duration::from_millis(wire_millis.saturating_mul(2).saturating_add(5_000));
    budget.clamp(IO_WRITE_TIMEOUT, MAX_IO_WRITE_TIMEOUT)
}

async fn wait_for_optional_deadline(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

struct ProtocolAbortDrain {
    token: u64,
    required_can: u8,
    consecutive_can: u8,
    marker_seen: bool,
    idle_deadline: Instant,
    hard_deadline: Instant,
    finish_acknowledgements: Vec<oneshot::Sender<()>>,
}

impl ProtocolAbortDrain {
    fn new(token: u64, kind: SerialTransferKind, now: Instant) -> Self {
        let required_can = match kind {
            SerialTransferKind::YmodemSend | SerialTransferKind::YmodemReceive => 2,
            SerialTransferKind::Zmodem => 5,
        };
        Self::with_consecutive_can(token, required_can, 0, now)
    }

    fn with_consecutive_can(
        token: u64,
        required_can: u8,
        consecutive_can: u8,
        now: Instant,
    ) -> Self {
        Self {
            token,
            required_can,
            consecutive_can,
            marker_seen: consecutive_can >= required_can,
            idle_deadline: now + PROTOCOL_ABORT_DRAIN_IDLE,
            hard_deadline: now + PROTOCOL_ABORT_DRAIN_TIMEOUT,
            finish_acknowledgements: Vec::new(),
        }
    }

    fn deadline(&self) -> Instant {
        self.idle_deadline.min(self.hard_deadline)
    }

    fn protects(&self, token: u64) -> bool {
        self.token == token
    }

    fn attach_finish(&mut self, acknowledge: Option<oneshot::Sender<()>>) {
        if let Some(acknowledge) = acknowledge {
            self.finish_acknowledgements.push(acknowledge);
        }
    }

    /// Drops raw protocol residue until the peer's protocol-specific CAN
    /// marker. After the marker, CAN/BS and software-flow-control suffix bytes
    /// are stripped across read boundaries. The first non-control byte is
    /// definitively post-protocol and may return to the terminal. Without such
    /// a byte, an idle gap ends the drain and everything observed is dropped.
    fn push(&mut self, bytes: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.idle_deadline = (now + PROTOCOL_ABORT_DRAIN_IDLE).min(self.hard_deadline);
        for (index, &byte) in bytes.iter().enumerate() {
            if self.marker_seen {
                if is_protocol_abort_control(byte) {
                    continue;
                }
                return Some(bytes[index..].to_vec());
            }

            if byte == crate::ZMODEM_CAN {
                self.consecutive_can = self.consecutive_can.saturating_add(1);
            } else {
                self.consecutive_can = 0;
            }
            if self.consecutive_can >= self.required_can {
                self.marker_seen = true;
            }
        }
        None
    }
}

fn is_protocol_abort_control(byte: u8) -> bool {
    matches!(
        byte,
        crate::ZMODEM_CAN | crate::ZMODEM_BACKSPACE | crate::ZMODEM_XON | 0x13 | 0x91 | 0x93
    )
}

fn complete_protocol_abort_drain(
    mut drain: ProtocolAbortDrain,
    terminal_tail: Vec<u8>,
    transfer: &Mutex<Option<RawTransferReservation>>,
    detected_zmodem: &Mutex<Option<DetectedZmodemTransfer>>,
    charset: SerialCharset,
    decoder: &mut crate::SerialDecoder,
    zmodem_sentry: &mut ZmodemSentry,
    events: &mpsc::Sender<SerialRuntimeEvent>,
) -> bool {
    let _ = release_transfer(transfer, drain.token);
    release_detected_zmodem(detected_zmodem, drain.token);
    *decoder = charset.decoder();
    let _ = zmodem_sentry.reset();
    if !terminal_tail.is_empty() {
        let decoded = decoder.decode(&terminal_tail, false);
        if !decoded.is_empty() && !emit_data(events, decoded) {
            return false;
        }
    }
    for acknowledge in drain.finish_acknowledgements.drain(..) {
        let _ = acknowledge.send(());
    }
    true
}

async fn send_unclaimed_zmodem_abort<W>(
    writer: &mut W,
    stop: &mut watch::Receiver<StopSignal>,
    events: &mpsc::Sender<SerialRuntimeEvent>,
    baud_rate: u32,
) -> Result<(), InterruptibleIoError>
where
    W: AsyncWrite + Unpin,
{
    let cancel = &crate::zmodem::ZMODEM_CANCEL_SEQUENCE;
    let timeout = serial_write_timeout(baud_rate, cancel.len());
    interruptible_serial_io(
        SerialIoOperation::Write,
        writer.write_all(cancel),
        stop,
        events,
        timeout,
    )
    .await?;
    interruptible_serial_io(
        SerialIoOperation::Flush,
        writer.flush(),
        stop,
        events,
        timeout,
    )
    .await
}

fn finish_interruptible_failure(
    events: &mpsc::Sender<SerialRuntimeEvent>,
    error: InterruptibleIoError,
) {
    match error {
        InterruptibleIoError::Runtime(error) => finish_error(events, error),
        InterruptibleIoError::Stopped(signal) => finish_stopped(events, signal),
        InterruptibleIoError::EventReceiverClosed => {}
    }
}

async fn run_session(
    inner: Arc<RuntimeInner>,
    session_id: SerialSessionId,
    config: SerialRuntimeConfig,
    mut commands: mpsc::Receiver<RuntimeCommand>,
    events: mpsc::Sender<SerialRuntimeEvent>,
    mut stop: watch::Receiver<StopSignal>,
    transfer: Arc<Mutex<Option<RawTransferReservation>>>,
    detected_zmodem: Arc<Mutex<Option<DetectedZmodemTransfer>>>,
) {
    let _registry_guard = RegistryGuard {
        inner: inner.clone(),
        session_id,
        transfer: transfer.clone(),
        detected_zmodem: detected_zmodem.clone(),
    };
    if !emit_regular(&events, SerialRuntimeEvent::Connecting) {
        return;
    }

    let baud_rate = config.serial.baud_rate;
    let open = inner.backend.open(config.serial);
    tokio::pin!(open);
    let open_timeout = tokio::time::sleep(OPEN_TIMEOUT);
    tokio::pin!(open_timeout);
    let io = tokio::select! {
        biased;
        _ = stop.changed() => {
            finish_stopped(&events, *stop.borrow());
            return;
        }
        _ = events.closed() => return,
        _ = &mut open_timeout => {
            finish_error(&events, SerialRuntimeError::OpenTimeout { timeout: OPEN_TIMEOUT });
            return;
        }
        result = &mut open => {
            match result {
                Ok(io) => io,
                Err(error) => {
                    finish_error(&events, error);
                    return;
                }
            }
        }
    };

    if !emit_regular(&events, SerialRuntimeEvent::Connected) {
        return;
    }
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut decoder = config.charset.decoder();
    let mut zmodem_sentry = ZmodemSentry::default();
    let mut protocol_abort_drain: Option<ProtocolAbortDrain> = None;
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];

    loop {
        if protocol_abort_drain
            .as_ref()
            .is_some_and(|drain| drain.deadline() <= Instant::now())
        {
            let Some(drain) = protocol_abort_drain.take() else {
                continue;
            };
            if !complete_protocol_abort_drain(
                drain,
                Vec::new(),
                &transfer,
                &detected_zmodem,
                config.charset,
                &mut decoder,
                &mut zmodem_sentry,
                &events,
            ) {
                return;
            }
        }
        let protected_token = protocol_abort_drain.as_ref().map(|drain| drain.token);
        if let Some(token) = release_abandoned_transfer(&transfer, protected_token) {
            decoder = config.charset.decoder();
            release_detected_zmodem(&detected_zmodem, token);
            let buffered = zmodem_sentry.reset().into_vec();
            if !buffered.is_empty() {
                let decoded = decoder.decode(&buffered, false);
                if !decoded.is_empty() && !emit_data(&events, decoded) {
                    return;
                }
            }
        }
        tokio::select! {
            biased;
            _ = stop.changed() => {
                let signal = *stop.borrow();
                match signal {
                    StopSignal::Running => continue,
                    StopSignal::Close => {
                        let flush = tokio::time::timeout(IO_WRITE_TIMEOUT, writer.flush()).await;
                        let shutdown = match flush {
                            Ok(Ok(())) => {
                                tokio::time::timeout(IO_WRITE_TIMEOUT, writer.shutdown()).await
                            }
                            Ok(Err(error)) => {
                                finish_error(&events, io_runtime_error(SerialIoOperation::Flush, error));
                                return;
                            }
                            Err(_) => {
                                finish_error(&events, SerialRuntimeError::IoFailed {
                                    operation: SerialIoOperation::Flush,
                                    kind: SerialErrorKind::TimedOut,
                                });
                                return;
                            }
                        };
                        match shutdown {
                            Ok(Ok(())) => emit_closed(&events, SerialCloseReason::Requested),
                            Ok(Err(error)) => finish_error(
                                &events,
                                io_runtime_error(SerialIoOperation::Flush, error),
                            ),
                            Err(_) => finish_error(&events, SerialRuntimeError::IoFailed {
                                operation: SerialIoOperation::Flush,
                                kind: SerialErrorKind::TimedOut,
                            }),
                        }
                    }
                    StopSignal::Cancel => emit_closed(&events, SerialCloseReason::Cancelled),
                }
                return;
            }
            _ = events.closed() => return,
            _ = wait_for_optional_deadline(protocol_abort_drain.as_ref().map(ProtocolAbortDrain::deadline)) => {
                let Some(drain) = protocol_abort_drain.take() else {
                    continue;
                };
                if !complete_protocol_abort_drain(
                    drain,
                    Vec::new(),
                    &transfer,
                    &detected_zmodem,
                    config.charset,
                    &mut decoder,
                    &mut zmodem_sentry,
                    &events,
                ) {
                    return;
                }
            }
            _ = wait_for_pending_zmodem_deadline(&detected_zmodem) => {
                if let Some(token) = expire_pending_zmodem(
                    &transfer,
                    &detected_zmodem,
                    Instant::now(),
                ) {
                    decoder = config.charset.decoder();
                    let _ = zmodem_sentry.reset();
                    if let Err(error) = send_unclaimed_zmodem_abort(
                        &mut writer,
                        &mut stop,
                        &events,
                        baud_rate,
                    ).await {
                        finish_interruptible_failure(&events, error);
                        return;
                    }
                    protocol_abort_drain = Some(ProtocolAbortDrain::new(
                        token,
                        SerialTransferKind::Zmodem,
                        Instant::now(),
                    ));
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    emit_closed(&events, SerialCloseReason::Cancelled);
                    return;
                };
                match command {
                    RuntimeCommand::Input(input) => {
                        if lock_transfer(&transfer).is_some() {
                            // Every queued Input predates this reservation;
                            // never reinterpret a stale Ctrl+C as a cancel for
                            // a newer transfer generation.
                            continue;
                        }
                        let timeout = serial_write_timeout(baud_rate, input.len());
                        if let Err(error) = interruptible_serial_io(
                            SerialIoOperation::Write,
                            writer.write_all(input.as_slice()),
                            &mut stop,
                            &events,
                            timeout,
                        ).await {
                            finish_interruptible_failure(&events, error);
                            return;
                        }
                    }
                    RuntimeCommand::TransferWrite { token, bytes, acknowledge } => {
                        let mut transfer_cancel = lock_transfer(&transfer)
                            .as_ref()
                            .filter(|active| active.token == token)
                            .map(|active| active.cancel.subscribe());
                        let timeout = serial_write_timeout(baud_rate, bytes.len());
                        let result = if let Some(cancel) = transfer_cancel.as_mut() {
                            match interruptible_transfer_io(
                                SerialIoOperation::Write,
                                writer.write_all(bytes.as_slice()),
                                &mut stop,
                                &events,
                                cancel,
                                timeout,
                            ).await {
                                Ok(()) => match interruptible_transfer_io(
                                    SerialIoOperation::Flush,
                                    writer.flush(),
                                    &mut stop,
                                    &events,
                                    cancel,
                                    timeout,
                                ).await {
                                    Ok(()) => Ok(()),
                                    Err(InterruptibleIoError::Runtime(error)) => Err(error),
                                    Err(InterruptibleIoError::Stopped(_)
                                        | InterruptibleIoError::EventReceiverClosed) => {
                                        Err(SerialRuntimeError::SessionClosing)
                                    }
                                },
                                Err(InterruptibleIoError::Runtime(error)) => Err(error),
                                Err(InterruptibleIoError::Stopped(_)
                                    | InterruptibleIoError::EventReceiverClosed) => {
                                    Err(SerialRuntimeError::SessionClosing)
                                }
                            }
                        } else {
                            Err(SerialRuntimeError::TransferNotActive)
                        };
                        let _ = acknowledge.send(result.clone());
                        if let Err(error) = result {
                            if error == SerialRuntimeError::SessionClosing {
                                finish_stopped(&events, *stop.borrow());
                                return;
                            } else if error != SerialRuntimeError::TransferNotActive
                                && error != SerialRuntimeError::TransferCancelled
                            {
                                finish_error(&events, error);
                                return;
                            }
                        }
                    }
                    RuntimeCommand::TransferAbortWrite {
                        token,
                        bytes,
                        acknowledge,
                    } => {
                        let active_kind = lock_transfer(&transfer)
                            .as_ref()
                            .filter(|active| active.token == token)
                            .map(|active| active.kind);
                        let timeout = serial_write_timeout(baud_rate, bytes.len());
                        let result = if let Some(kind) = active_kind {
                            match interruptible_serial_io(
                                SerialIoOperation::Write,
                                writer.write_all(bytes.as_slice()),
                                &mut stop,
                                &events,
                                timeout,
                            ).await {
                                Ok(()) => {
                                    match interruptible_serial_io(
                                        SerialIoOperation::Flush,
                                        writer.flush(),
                                        &mut stop,
                                        &events,
                                        timeout,
                                    ).await {
                                        Ok(()) => {
                                            protocol_abort_drain = Some(
                                                ProtocolAbortDrain::new(
                                                    token,
                                                    kind,
                                                    Instant::now(),
                                                ),
                                            );
                                            Ok(())
                                        }
                                        Err(InterruptibleIoError::Runtime(error)) => Err(error),
                                        Err(InterruptibleIoError::Stopped(_)
                                            | InterruptibleIoError::EventReceiverClosed) => {
                                            Err(SerialRuntimeError::SessionClosing)
                                        }
                                    }
                                }
                                Err(InterruptibleIoError::Runtime(error)) => Err(error),
                                Err(InterruptibleIoError::Stopped(_)
                                    | InterruptibleIoError::EventReceiverClosed) => {
                                    Err(SerialRuntimeError::SessionClosing)
                                }
                            }
                        } else {
                            Err(SerialRuntimeError::TransferNotActive)
                        };
                        let _ = acknowledge.send(result.clone());
                        if let Err(error) = result {
                            if error == SerialRuntimeError::SessionClosing {
                                finish_stopped(&events, *stop.borrow());
                                return;
                            } else if error != SerialRuntimeError::TransferNotActive {
                                finish_error(&events, error);
                                return;
                            }
                        }
                    }
                    RuntimeCommand::EndTransfer {
                        token,
                        terminal_bytes,
                        acknowledge,
                    } => {
                        if let Some(drain) = protocol_abort_drain
                            .as_mut()
                            .filter(|drain| drain.protects(token))
                        {
                            // An abort path must never return decoder/file
                            // residue. Keep ownership and the finish waiter
                            // until the bounded drain is complete.
                            drop(terminal_bytes);
                            drain.attach_finish(acknowledge);
                            continue;
                        }
                        let released = release_transfer(&transfer, token);
                        if released {
                            release_detected_zmodem(&detected_zmodem, token);
                            decoder = config.charset.decoder();
                            let buffered = zmodem_sentry.reset().into_vec();
                            if !buffered.is_empty() {
                                let decoded = decoder.decode(&buffered, false);
                                if !decoded.is_empty() && !emit_data(&events, decoded) {
                                    return;
                                }
                            }
                            if !terminal_bytes.is_empty() {
                                let decoded = decoder.decode(terminal_bytes.as_slice(), false);
                                if !decoded.is_empty() && !emit_data(&events, decoded) {
                                    return;
                                }
                            }
                        }
                        if let Some(acknowledge) = acknowledge {
                            let _ = acknowledge.send(());
                        }
                    }
                    RuntimeCommand::DeclineDetectedZmodem { token, direction } => {
                        if decline_pending_zmodem(
                            &transfer,
                            &detected_zmodem,
                            token,
                            direction,
                        ) {
                            decoder = config.charset.decoder();
                            let _ = zmodem_sentry.reset();
                            if let Err(error) = send_unclaimed_zmodem_abort(
                                &mut writer,
                                &mut stop,
                                &events,
                                baud_rate,
                            ).await {
                                finish_interruptible_failure(&events, error);
                                return;
                            }
                            protocol_abort_drain = Some(ProtocolAbortDrain::new(
                                token,
                                SerialTransferKind::Zmodem,
                                Instant::now(),
                            ));
                        }
                    }
                }
            }
            read = reader.read(&mut buffer) => {
                match read {
                    Ok(0) => {
                        let pending = zmodem_sentry.reset().into_vec();
                        let mut decoded = decoder.decode(&pending, false);
                        decoded.extend(decoder.decode(&[], true));
                        if !decoded.is_empty() && !emit_data(&events, decoded) {
                            return;
                        }
                        emit_closed(&events, SerialCloseReason::RemoteEof);
                        return;
                    }
                    Ok(read) => {
                        if protocol_abort_drain.is_some() {
                            let terminal_tail = protocol_abort_drain
                                .as_mut()
                                .and_then(|drain| drain.push(&buffer[..read], Instant::now()));
                            if let Some(terminal_tail) = terminal_tail {
                                if let Some(drain) = protocol_abort_drain.take() {
                                    if !complete_protocol_abort_drain(
                                        drain,
                                        terminal_tail,
                                        &transfer,
                                        &detected_zmodem,
                                        config.charset,
                                        &mut decoder,
                                        &mut zmodem_sentry,
                                        &events,
                                    ) {
                                        return;
                                    }
                                }
                            }
                            continue;
                        }
                        if let Some((drain, terminal_tail)) = record_pending_zmodem_bytes(
                            &detected_zmodem,
                            &buffer[..read],
                            Instant::now(),
                        ) {
                            if let Some(terminal_tail) = terminal_tail {
                                if !complete_protocol_abort_drain(
                                    drain,
                                    terminal_tail,
                                    &transfer,
                                    &detected_zmodem,
                                    config.charset,
                                    &mut decoder,
                                    &mut zmodem_sentry,
                                    &events,
                                ) {
                                    return;
                                }
                            } else {
                                protocol_abort_drain = Some(drain);
                            }
                        } else if let Some(transfer_events) = active_transfer_events(&transfer) {
                            if let Err(error) = try_send_transfer_event(
                                &transfer_events,
                                SerialRawTransferEvent::Data(SerialBytes::from(buffer[..read].to_vec())),
                            ) {
                                finish_error(&events, error);
                                return;
                            }
                        } else {
                            let sentry_output = match zmodem_sentry.push(&buffer[..read]) {
                                Ok(output) => output,
                                Err(_) => {
                                    finish_error(
                                        &events,
                                        SerialRuntimeError::EventDataTooLarge {
                                            maximum_bytes: MAX_EVENT_DATA_BYTES,
                                        },
                                    );
                                    return;
                                }
                            };
                            if !sentry_output.passthrough.is_empty() {
                                let decoded = decoder.decode(
                                    sentry_output.passthrough.as_slice(),
                                    false,
                                );
                                if !decoded.is_empty() && !emit_data(&events, decoded) {
                                    return;
                                }
                            }
                            if let Some(detected) = sentry_output.detected {
                                let direction = detected.direction;
                                let reservation = match reserve_detected_zmodem(
                                    &inner,
                                    &transfer,
                                    &detected_zmodem,
                                    direction,
                                    detected.protocol_bytes.into_vec(),
                                ) {
                                    Ok(reserved) => reserved,
                                    Err(error) => {
                                        finish_error(&events, error);
                                        return;
                                    }
                                };
                                match reservation {
                                    ReserveDetectedZmodemOutcome::RoutedToActive => {}
                                    ReserveDetectedZmodemOutcome::Detected(transfer_id) => {
                                        if !emit_regular(
                                            &events,
                                            SerialRuntimeEvent::ZmodemDetected {
                                                transfer_id,
                                                direction,
                                            },
                                        ) {
                                            return;
                                        }
                                    }
                                    ReserveDetectedZmodemOutcome::RemoteCancelled {
                                        drain,
                                        terminal_tail,
                                    } => {
                                        if let Some(terminal_tail) = terminal_tail {
                                            if !complete_protocol_abort_drain(
                                                drain,
                                                terminal_tail,
                                                &transfer,
                                                &detected_zmodem,
                                                config.charset,
                                                &mut decoder,
                                                &mut zmodem_sentry,
                                                &events,
                                            ) {
                                                return;
                                            }
                                        } else {
                                            protocol_abort_drain = Some(drain);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        finish_error(&events, io_runtime_error(SerialIoOperation::Read, error));
                        return;
                    }
                }
            }
        }
    }
}

fn emit_data(events: &mpsc::Sender<SerialRuntimeEvent>, decoded: Vec<u8>) -> bool {
    if decoded.len() > MAX_EVENT_DATA_BYTES {
        finish_error(
            events,
            SerialRuntimeError::EventDataTooLarge {
                maximum_bytes: MAX_EVENT_DATA_BYTES,
            },
        );
        return false;
    }
    emit_regular(events, SerialRuntimeEvent::Data(SerialBytes::from(decoded)))
}

fn emit_regular(events: &mpsc::Sender<SerialRuntimeEvent>, event: SerialRuntimeEvent) -> bool {
    if events.is_closed() {
        return false;
    }
    if events.capacity() <= TERMINAL_EVENT_RESERVE {
        finish_error(
            events,
            SerialRuntimeError::EventQueueFull {
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
                SerialRuntimeError::EventQueueFull {
                    capacity: EVENT_CHANNEL_CAPACITY,
                },
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn finish_stopped(events: &mpsc::Sender<SerialRuntimeEvent>, signal: StopSignal) {
    match signal {
        StopSignal::Running => {}
        StopSignal::Close => emit_closed(events, SerialCloseReason::Requested),
        StopSignal::Cancel => emit_closed(events, SerialCloseReason::Cancelled),
    }
}

fn finish_error(events: &mpsc::Sender<SerialRuntimeEvent>, error: SerialRuntimeError) {
    let _ = events.try_send(SerialRuntimeEvent::Error(error));
    emit_closed(events, SerialCloseReason::Error);
}

fn emit_closed(events: &mpsc::Sender<SerialRuntimeEvent>, reason: SerialCloseReason) {
    let _ = events.try_send(SerialRuntimeEvent::Closed { reason });
}

fn map_charset_error(error: SerialCharsetError) -> SerialRuntimeError {
    match error {
        SerialCharsetError::InvalidUtf8Input => SerialRuntimeError::InvalidInputEncoding,
        SerialCharsetError::OutputTooLarge => SerialRuntimeError::EncodedInputTooLarge {
            maximum_bytes: MAX_INPUT_BYTES,
        },
    }
}

fn io_runtime_error(operation: SerialIoOperation, error: io::Error) -> SerialRuntimeError {
    SerialRuntimeError::IoFailed {
        operation,
        kind: map_io_error_kind(error.kind()),
    }
}

pub(crate) fn map_backend_error_kind(kind: tokio_serial::ErrorKind) -> SerialErrorKind {
    match kind {
        tokio_serial::ErrorKind::NoDevice => SerialErrorKind::Unavailable,
        tokio_serial::ErrorKind::InvalidInput => SerialErrorKind::InvalidInput,
        tokio_serial::ErrorKind::Unknown => SerialErrorKind::Other,
        tokio_serial::ErrorKind::Io(kind) => map_io_error_kind(kind),
    }
}

fn map_io_error_kind(kind: io::ErrorKind) -> SerialErrorKind {
    match kind {
        io::ErrorKind::NotFound => SerialErrorKind::NotFound,
        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse => {
            SerialErrorKind::AccessDeniedOrBusy
        }
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => SerialErrorKind::InvalidInput,
        io::ErrorKind::TimedOut => SerialErrorKind::TimedOut,
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof => SerialErrorKind::Disconnected,
        _ => SerialErrorKind::Other,
    }
}

fn map_data_bits(value: SerialDataBits) -> DataBits {
    match value {
        SerialDataBits::Five => DataBits::Five,
        SerialDataBits::Six => DataBits::Six,
        SerialDataBits::Seven => DataBits::Seven,
        SerialDataBits::Eight => DataBits::Eight,
    }
}

fn map_stop_bits(value: SerialStopBits) -> Result<StopBits, SerialConfigError> {
    match value {
        SerialStopBits::One => Ok(StopBits::One),
        SerialStopBits::Two => Ok(StopBits::Two),
        SerialStopBits::OnePointFive => {
            Err(SerialConfigError::UnsupportedStopBits { stop_bits: value })
        }
    }
}

fn map_parity(value: SerialParity) -> Result<Parity, SerialConfigError> {
    match value {
        SerialParity::None => Ok(Parity::None),
        SerialParity::Even => Ok(Parity::Even),
        SerialParity::Odd => Ok(Parity::Odd),
        SerialParity::Mark | SerialParity::Space => {
            Err(SerialConfigError::UnsupportedParity { parity: value })
        }
    }
}

fn map_flow_control(value: SerialFlowControl) -> FlowControl {
    match value {
        SerialFlowControl::None => FlowControl::None,
        SerialFlowControl::XonXoff => FlowControl::Software,
        SerialFlowControl::RtsCts => FlowControl::Hardware,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{YMODEM_ACK, YMODEM_CRC16};
    use std::sync::Mutex;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        time::{sleep, timeout},
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(3);

    struct OneShotBackend {
        io: Mutex<Option<DuplexStream>>,
    }

    impl SerialBackend for OneShotBackend {
        fn open(&self, _config: SerialConfig) -> OpenFuture {
            let io = self
                .io
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            Box::pin(async move {
                io.map(|io| Box::new(io) as BoxedSerialIo).ok_or(
                    SerialRuntimeError::ConnectionFailed {
                        kind: SerialErrorKind::Unavailable,
                    },
                )
            })
        }
    }

    struct PendingBackend;

    impl SerialBackend for PendingBackend {
        fn open(&self, _config: SerialConfig) -> OpenFuture {
            Box::pin(std::future::pending())
        }
    }

    fn test_config(charset: SerialCharset) -> SerialRuntimeConfig {
        SerialRuntimeConfig::new(SerialConfig::new("PRIVATE-DEVICE").unwrap(), 80, 24)
            .unwrap()
            .with_charset(charset)
    }

    async fn next_event(session: &mut SerialRuntimeSession) -> SerialRuntimeEvent {
        timeout(TEST_TIMEOUT, session.recv())
            .await
            .expect("serial event timed out")
            .expect("serial event stream closed early")
    }

    async fn wait_for_cleanup(manager: &SerialRuntimeManager, id: &SerialSessionId) {
        timeout(TEST_TIMEOUT, async {
            while manager.contains(id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("serial registry cleanup timed out");
    }

    #[test]
    fn config_ids_errors_and_debug_are_payload_safe() {
        let marker = "PRIVATE-SERIAL-PATH";
        let config = SerialRuntimeConfig::new(SerialConfig::new(marker).unwrap(), 80, 24).unwrap();
        assert!(!format!("{config:?}").contains(marker));
        assert_eq!(config.serial().path, marker);
        assert_eq!(config.window_size().columns(), 80);

        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            SerialSessionId::parse(canonical).unwrap().as_str(),
            canonical
        );
        assert_eq!(
            SerialSessionId::parse("550E8400-E29B-41D4-A716-446655440000"),
            Err(SerialRuntimeError::InvalidSessionId)
        );
        let backend_error = tokio_serial::Error::new(tokio_serial::ErrorKind::Unknown, marker);
        let safe = SerialRuntimeError::ConnectionFailed {
            kind: map_backend_error_kind(backend_error.kind()),
        };
        assert!(!format!("{safe:?}").contains(marker));
        assert!(!safe.to_string().contains(marker));
        let event = SerialRuntimeEvent::Data(SerialBytes::from(marker.as_bytes().to_vec()));
        assert!(!format!("{event:?}").contains(marker));
    }

    #[test]
    fn window_validation_and_platform_mapping_are_exact() {
        assert!(SerialWindowSize::new(1, 1).is_ok());
        assert!(SerialWindowSize::new(MAX_WINDOW_DIMENSION, MAX_WINDOW_DIMENSION).is_ok());
        assert!(SerialWindowSize::new(0, 1).is_err());
        assert!(SerialWindowSize::new(1, MAX_WINDOW_DIMENSION + 1).is_err());
        assert_eq!(map_data_bits(SerialDataBits::Five), DataBits::Five);
        assert_eq!(map_stop_bits(SerialStopBits::Two), Ok(StopBits::Two));
        assert_eq!(map_parity(SerialParity::Odd), Ok(Parity::Odd));
        assert_eq!(
            map_stop_bits(SerialStopBits::OnePointFive),
            Err(SerialConfigError::UnsupportedStopBits {
                stop_bits: SerialStopBits::OnePointFive,
            })
        );
        assert_eq!(
            map_parity(SerialParity::Mark),
            Err(SerialConfigError::UnsupportedParity {
                parity: SerialParity::Mark,
            })
        );
        assert_eq!(
            map_flow_control(SerialFlowControl::XonXoff),
            FlowControl::Software
        );
    }

    #[test]
    fn expired_detection_keeps_exact_reservation_for_abort_quarantine() {
        let token = 41;
        let transfer_id = SerialTransferId::new();
        let (events, receiver) = mpsc::channel(1);
        let (cancel, cancel_receiver) = watch::channel(false);
        let transfer = Mutex::new(Some(RawTransferReservation {
            token,
            transfer_id: transfer_id.clone(),
            kind: SerialTransferKind::Zmodem,
            events,
            cancel,
        }));
        let detected = Mutex::new(Some(DetectedZmodemTransfer {
            token,
            transfer_id,
            direction: ZmodemTransferDirection::Receive,
            events: receiver,
            cancel: cancel_receiver,
            consecutive_can: 0,
            deadline: Instant::now() - Duration::from_millis(1),
        }));

        assert_eq!(
            expire_pending_zmodem(&transfer, &detected, Instant::now()),
            Some(token)
        );
        assert!(lock_detected_zmodem(&detected).is_none());
        assert!(reservation_matches(&transfer, token));
        assert_eq!(release_abandoned_transfer(&transfer, Some(token)), None);
        assert!(reservation_matches(&transfer, token));
        assert!(release_transfer(&transfer, token));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_streams_charset_data_tracks_resize_and_closes_once() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let charset = SerialCharset::Gb18030;
        let mut session = manager.start(test_config(charset)).unwrap();
        let id = session.session_id().clone();
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Connecting
        ));
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Connected
        ));

        let wire = charset.encode_input("设备\n就绪\r\n".as_bytes()).unwrap();
        device.write_all(&wire[..1]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(50), session.recv())
                .await
                .is_err()
        );
        device.write_all(&wire[1..]).await.unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(data) => {
                assert_eq!(data.as_slice(), "设备\r\n就绪\r\n".as_bytes())
            }
            other => panic!("expected serial data, got {other:?}"),
        }

        manager.input(&id, "查询\r".as_bytes()).unwrap();
        let expected = charset.encode_input("查询\r".as_bytes()).unwrap();
        let mut received = vec![0_u8; expected.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected.as_slice());

        manager.resize(&id, 132, 43).unwrap();
        assert_eq!(
            manager.window_size(&id).unwrap(),
            SerialWindowSize::new(132, 43).unwrap()
        );
        let mut probe = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(60), device.read(&mut probe))
                .await
                .is_err(),
            "resize must not write serial protocol bytes"
        );

        manager.close(&id).unwrap();
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::Requested
            }
        ));
        wait_for_cleanup(&manager, &id).await;
        assert!(session.recv().await.is_none());
    }

    #[tokio::test]
    async fn pending_open_is_cancellable_and_input_queue_is_bounded() {
        let manager = SerialRuntimeManager::with_backend(Arc::new(PendingBackend));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        for _ in 0..COMMAND_CHANNEL_CAPACITY {
            manager.input(&id, b"x").unwrap();
        }
        assert_eq!(
            manager.input(&id, b"overflow"),
            Err(SerialRuntimeError::CommandQueueFull {
                capacity: COMMAND_CHANNEL_CAPACITY
            })
        );
        manager.cancel(&id).unwrap();
        assert_eq!(
            manager.input(&id, b"late"),
            Err(SerialRuntimeError::SessionClosing)
        );
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Connecting
        ));
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::Cancelled
            }
        ));
        wait_for_cleanup(&manager, &id).await;
        assert_eq!(manager.session_count(), 0);
        assert_eq!(
            manager.cancel(&id),
            Err(SerialRuntimeError::SessionNotFound)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_eof_flushes_decoder_then_emits_one_terminal_close() {
        let (client, mut device) = tokio::io::duplex(1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;
        device.write_all(&[b'a', 0xe4, 0xbd]).await.unwrap();
        drop(device);

        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(data) => assert_eq!(data.as_slice(), b"a"),
            other => panic!("expected serial data, got {other:?}"),
        }
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(data) => {
                assert_eq!(data.as_slice(), "\u{fffd}".as_bytes())
            }
            other => panic!("expected decoder flush data, got {other:?}"),
        }
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::RemoteEof
            }
        ));
        wait_for_cleanup(&manager, &id).await;
        assert!(session.recv().await.is_none());
    }

    #[tokio::test]
    async fn invalid_and_oversized_input_never_enters_the_command_queue() {
        let manager = SerialRuntimeManager::with_backend(Arc::new(PendingBackend));
        let session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        assert_eq!(
            manager.input(&id, &[0xff]),
            Err(SerialRuntimeError::InvalidInputEncoding)
        );
        assert_eq!(
            manager.input(&id, &vec![b'x'; MAX_INPUT_BYTES + 1]),
            Err(SerialRuntimeError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES
            })
        );
        manager.cancel(&id).unwrap();
    }

    #[tokio::test]
    async fn unsupported_values_are_rejected_before_registration() {
        let manager = SerialRuntimeManager::with_backend(Arc::new(PendingBackend));
        let mut config = SerialConfig::new("COM3").unwrap();
        config.parity = SerialParity::Mark;
        assert_eq!(
            SerialRuntimeConfig::new(config, 80, 24).unwrap_err(),
            SerialRuntimeError::Config(SerialConfigError::UnsupportedParity {
                parity: SerialParity::Mark
            })
        );
        assert_eq!(manager.session_count(), 0);
    }

    #[tokio::test]
    async fn event_pressure_reserves_error_and_close_slots() {
        let (sender, mut receiver) = mpsc::channel(3);
        sender.send(SerialRuntimeEvent::Connecting).await.unwrap();
        assert!(!emit_regular(&sender, SerialRuntimeEvent::Connected));
        assert!(matches!(
            receiver.recv().await,
            Some(SerialRuntimeEvent::Connecting)
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(SerialRuntimeEvent::Error(
                SerialRuntimeError::EventQueueFull {
                    capacity: EVENT_CHANNEL_CAPACITY
                }
            ))
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::Error
            })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_event_receiver_cleans_registry_and_device() {
        let (client, mut device) = tokio::io::duplex(1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        drop(session);
        wait_for_cleanup(&manager, &id).await;
        drop(manager);
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(TEST_TIMEOUT, device.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        sleep(Duration::from_millis(1)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_transfer_is_exclusive_bypasses_charset_and_ctrl_c_requests_cancel() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let mut transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemSend)
            .unwrap();
        assert_eq!(
            manager.active_transfer_kind(&id).unwrap(),
            Some(SerialTransferKind::YmodemSend)
        );
        assert_eq!(
            manager
                .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
                .unwrap_err(),
            SerialRuntimeError::TransferActive {
                kind: SerialTransferKind::YmodemSend
            }
        );
        assert_eq!(
            manager.input(&id, b"show private\r"),
            Err(SerialRuntimeError::TransferActive {
                kind: SerialTransferKind::YmodemSend
            })
        );

        transfer.write(&[YMODEM_ACK, YMODEM_CRC16]).await.unwrap();
        let mut written = [0_u8; 2];
        timeout(TEST_TIMEOUT, device.read_exact(&mut written))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written, [YMODEM_ACK, YMODEM_CRC16]);

        manager.input(&id, &[0x03]).unwrap();
        assert!(matches!(
            timeout(TEST_TIMEOUT, transfer.recv()).await.unwrap(),
            Some(SerialRawTransferEvent::CancelRequested)
        ));
        let mut probe = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(50), device.read(&mut probe))
                .await
                .is_err(),
            "Ctrl+C is a cancellation event, not a terminal byte"
        );

        device.write_all(&[0xff, 0x00, 0x80]).await.unwrap();
        match timeout(TEST_TIMEOUT, transfer.recv()).await.unwrap() {
            Some(SerialRawTransferEvent::Data(bytes)) => {
                assert_eq!(bytes.as_slice(), &[0xff, 0x00, 0x80])
            }
            other => panic!("expected raw transfer bytes, got {other:?}"),
        }
        assert!(
            timeout(Duration::from_millis(50), session.recv())
                .await
                .is_err(),
            "transfer bytes must bypass the terminal decoder"
        );

        assert_eq!(
            transfer.write(&[YMODEM_ACK]).await,
            Err(SerialRuntimeError::TransferCancelled)
        );
        transfer.finish().await.unwrap();
        assert_eq!(manager.active_transfer_kind(&id).unwrap(), None);

        manager.input(&id, b"x").unwrap();
        timeout(TEST_TIMEOUT, device.read_exact(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(probe, [b'x']);
        device.write_all(b"ready\n").await.unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => assert_eq!(bytes.as_slice(), b"ready\r\n"),
            other => panic!("expected decoded terminal bytes, got {other:?}"),
        }

        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_protocol_abort_ignores_cancel_and_returns_only_post_can_terminal_tail() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let mut transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
            .unwrap();
        let transfer_id = transfer.transfer_id().clone();
        manager
            .request_transfer_cancel_exact(&id, &transfer_id)
            .unwrap();
        assert!(matches!(
            transfer.recv().await,
            Some(SerialRawTransferEvent::CancelRequested)
        ));
        assert_eq!(
            transfer.write(b"partial-frame").await,
            Err(SerialRuntimeError::TransferCancelled)
        );

        transfer
            .write_protocol_abort(&crate::ZMODEM_CANCEL_SEQUENCE)
            .await
            .unwrap();
        let mut abort = [0_u8; crate::ZMODEM_CANCEL_SEQUENCE.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut abort))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(abort, crate::ZMODEM_CANCEL_SEQUENCE);
        device
            .write_all(&crate::ZMODEM_CANCEL_SEQUENCE[..5])
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(25), session.recv())
                .await
                .is_err(),
            "a marker ending exactly at a read boundary must keep the drain active"
        );
        let mut peer_suffix_and_prompt = crate::ZMODEM_CANCEL_SEQUENCE[5..].to_vec();
        peer_suffix_and_prompt.extend_from_slice(b"\r\nshell$ ");
        device.write_all(&peer_suffix_and_prompt).await.unwrap();
        transfer.finish().await.unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => assert_eq!(bytes.as_slice(), b"\r\nshell$ "),
            other => panic!("expected only post-CAN terminal tail, got {other:?}"),
        }
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_drain_drops_pre_idle_residue_then_restores_terminal_output() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
            .unwrap();
        transfer
            .write_protocol_abort(&crate::ZMODEM_CANCEL_SEQUENCE)
            .await
            .unwrap();
        let mut abort = [0_u8; crate::ZMODEM_CANCEL_SEQUENCE.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut abort))
            .await
            .unwrap()
            .unwrap();
        device.write_all(b"protocol-residue").await.unwrap();
        transfer.finish().await.unwrap();
        assert!(
            timeout(Duration::from_millis(50), session.recv())
                .await
                .is_err(),
            "pre-idle protocol residue must not enter terminal output"
        );
        device.write_all(b"ready\n").await.unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => assert_eq!(bytes.as_slice(), b"ready\r\n"),
            other => panic!("expected terminal output after abort idle gap, got {other:?}"),
        }
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ymodem_abort_drain_uses_two_can_marker_and_strips_split_suffix() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemReceive)
            .unwrap();
        transfer
            .write_protocol_abort(&crate::YMODEM_CANCEL_SEQUENCE)
            .await
            .unwrap();
        let mut abort = [0_u8; crate::YMODEM_CANCEL_SEQUENCE.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut abort))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(abort, crate::YMODEM_CANCEL_SEQUENCE);

        device.write_all(&[crate::YMODEM_CAN; 2]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(25), session.recv())
                .await
                .is_err(),
            "the two-CAN YMODEM marker must not expose protocol controls"
        );
        let mut suffix_and_prompt = crate::YMODEM_CANCEL_SEQUENCE[2..].to_vec();
        suffix_and_prompt.extend_from_slice(b"ymodem-shell$ ");
        device.write_all(&suffix_and_prompt).await.unwrap();
        transfer.finish().await.unwrap();

        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => {
                assert_eq!(bytes.as_slice(), b"ymodem-shell$ ")
            }
            other => panic!("expected only post-YMODEM terminal tail, got {other:?}"),
        }
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unclaimed_remote_cancel_returns_only_same_read_terminal_tail() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let initiator = crate::encode_zmodem_hex_header(crate::ZmodemHeader::new(
            crate::ZmodemFrameType::ReceiverInit,
            [0; 4],
        ));
        device.write_all(initiator.as_slice()).await.unwrap();
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::ZmodemDetected {
                direction: ZmodemTransferDirection::Send,
                ..
            }
        ));

        let mut remote_cancel_and_prompt = crate::ZMODEM_CANCEL_SEQUENCE.to_vec();
        remote_cancel_and_prompt.extend_from_slice(b"remote-shell$ ");
        device.write_all(&remote_cancel_and_prompt).await.unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => {
                assert_eq!(bytes.as_slice(), b"remote-shell$ ")
            }
            other => panic!("expected only the post-cancel terminal tail, got {other:?}"),
        }
        assert_eq!(manager.active_transfer_kind(&id).unwrap(), None);
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_read_detection_and_remote_cancel_never_expose_protocol_bytes() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let mut wire = crate::encode_zmodem_hex_header(crate::ZmodemHeader::new(
            crate::ZmodemFrameType::ReceiverInit,
            [0; 4],
        ))
        .into_vec();
        wire.extend_from_slice(&crate::ZMODEM_CANCEL_SEQUENCE);
        wire.extend_from_slice(b"same-read-shell$ ");
        device.write_all(&wire).await.unwrap();

        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => {
                assert_eq!(bytes.as_slice(), b"same-read-shell$ ")
            }
            other => panic!("expected only the same-read terminal tail, got {other:?}"),
        }
        assert_eq!(manager.active_transfer_kind(&id).unwrap(), None);
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn declined_detection_keeps_reservation_until_abort_drain_finishes() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let initiator = crate::encode_zmodem_hex_header(crate::ZmodemHeader::new(
            crate::ZmodemFrameType::RequestInit,
            [0; 4],
        ));
        device.write_all(initiator.as_slice()).await.unwrap();
        let transfer_id = match next_event(&mut session).await {
            SerialRuntimeEvent::ZmodemDetected {
                transfer_id,
                direction: ZmodemTransferDirection::Receive,
            } => transfer_id,
            other => panic!("expected receive detection, got {other:?}"),
        };
        manager
            .decline_detected_zmodem(&id, &transfer_id, ZmodemTransferDirection::Receive)
            .unwrap();
        let mut abort = [0_u8; crate::ZMODEM_CANCEL_SEQUENCE.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut abort))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(abort, crate::ZMODEM_CANCEL_SEQUENCE);
        assert_eq!(
            manager
                .begin_raw_transfer(&id, SerialTransferKind::YmodemSend)
                .unwrap_err(),
            SerialRuntimeError::TransferActive {
                kind: SerialTransferKind::Zmodem
            }
        );

        sleep(PROTOCOL_ABORT_DRAIN_IDLE + Duration::from_millis(50)).await;
        let second = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemSend)
            .unwrap();
        second.finish().await.unwrap();
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_transfer_quarantine_blocks_next_generation_until_drain_completes() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let first = manager
            .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
            .unwrap();
        first
            .write_protocol_abort(&crate::ZMODEM_CANCEL_SEQUENCE)
            .await
            .unwrap();
        let mut abort = [0_u8; crate::ZMODEM_CANCEL_SEQUENCE.len()];
        timeout(TEST_TIMEOUT, device.read_exact(&mut abort))
            .await
            .unwrap()
            .unwrap();

        let mut finish = tokio::spawn(async move { first.finish().await });
        assert!(
            timeout(Duration::from_millis(50), &mut finish)
                .await
                .is_err(),
            "finish must wait while the old generation is quarantined"
        );
        assert_eq!(
            manager
                .begin_raw_transfer(&id, SerialTransferKind::YmodemReceive)
                .unwrap_err(),
            SerialRuntimeError::TransferActive {
                kind: SerialTransferKind::Zmodem
            }
        );

        timeout(TEST_TIMEOUT, &mut finish)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut second = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemReceive)
            .unwrap();
        device.write_all(b"B-first-frame").await.unwrap();
        match timeout(TEST_TIMEOUT, second.recv()).await.unwrap() {
            Some(SerialRawTransferEvent::Data(bytes)) => {
                assert_eq!(bytes.as_slice(), b"B-first-frame")
            }
            other => panic!("expected the new generation's first raw frame, got {other:?}"),
        }
        second.finish().await.unwrap();
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_exact_cancel_cannot_reach_later_transfer_generation() {
        let (client, mut device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let first = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemSend)
            .unwrap();
        let stale_id = first.transfer_id().clone();
        first.finish().await.unwrap();

        let mut second = manager
            .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
            .unwrap();
        assert_eq!(
            manager.request_transfer_cancel_exact(&id, &stale_id),
            Err(SerialRuntimeError::TransferNotActive)
        );
        assert!(matches!(
            second.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        second.write(b"B").await.unwrap();
        let mut byte = [0_u8; 1];
        timeout(TEST_TIMEOUT, device.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(byte, [b'B']);
        second.finish().await.unwrap();
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_raw_finish_returns_bounded_terminal_remainder() {
        let (client, _device) = tokio::io::duplex(8 * 1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;

        let transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::Zmodem)
            .unwrap();
        transfer
            .finish_with_terminal_bytes(b"shell$ echo done\n")
            .await
            .unwrap();
        match next_event(&mut session).await {
            SerialRuntimeEvent::Data(bytes) => {
                assert_eq!(bytes.as_slice(), b"shell$ echo done\r\n")
            }
            other => panic!("expected successful terminal remainder, got {other:?}"),
        }
        manager.cancel(&id).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_session_releases_raw_transfer_and_wakes_its_driver() {
        let (client, _device) = tokio::io::duplex(1_024);
        let manager = SerialRuntimeManager::with_backend(Arc::new(OneShotBackend {
            io: Mutex::new(Some(client)),
        }));
        let mut session = manager.start(test_config(SerialCharset::Utf8)).unwrap();
        let id = session.session_id().clone();
        let _ = next_event(&mut session).await;
        let _ = next_event(&mut session).await;
        let mut transfer = manager
            .begin_raw_transfer(&id, SerialTransferKind::YmodemReceive)
            .unwrap();

        manager.cancel(&id).unwrap();
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::Cancelled
            }
        ));
        assert!(
            timeout(TEST_TIMEOUT, transfer.recv())
                .await
                .unwrap()
                .is_none()
        );
        wait_for_cleanup(&manager, &id).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_backend_missing_device_fails_safely_and_cleans_registry() {
        #[cfg(windows)]
        let missing_path = r"\\.\NETCATTY_PORT_THAT_DOES_NOT_EXIST";
        #[cfg(not(windows))]
        let missing_path = "/dev/netcatty-port-that-does-not-exist";

        let manager = SerialRuntimeManager::new();
        let config =
            SerialRuntimeConfig::new(SerialConfig::new(missing_path).unwrap(), 80, 24).unwrap();
        let mut session = manager.start(config).unwrap();
        let id = session.session_id().clone();
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Connecting
        ));
        match next_event(&mut session).await {
            SerialRuntimeEvent::Error(SerialRuntimeError::ConnectionFailed { .. }) => {}
            other => panic!("expected safe native open failure, got {other:?}"),
        }
        assert!(matches!(
            next_event(&mut session).await,
            SerialRuntimeEvent::Closed {
                reason: SerialCloseReason::Error
            }
        ));
        wait_for_cleanup(&manager, &id).await;
        assert!(session.recv().await.is_none());
    }
}
