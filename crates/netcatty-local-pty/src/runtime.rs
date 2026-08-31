use std::{
    collections::HashMap,
    error::Error,
    fmt,
    io::{self, Read, Write},
    str::FromStr,
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::mpsc as tokio_mpsc;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{LocalPtyConfig, LocalPtyWindowSize, ShellDiscoveryError};

pub const MAX_INPUT_BYTES: usize = 64 * 1_024;
pub const MAX_QUEUED_INPUT_BYTES: usize = 256 * 1_024;
pub const MAX_BUFFERED_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
pub const EVENT_CHANNEL_CAPACITY: usize = 136;
const INPUT_CHANNEL_CAPACITY: usize = 64;
const READ_BUFFER_BYTES: usize = 16 * 1_024;
const MAX_BUFFERED_OUTPUT_EVENTS: usize = MAX_BUFFERED_OUTPUT_BYTES.div_ceil(READ_BUFFER_BYTES);
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const FINAL_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const RUNNING: u8 = 0;
const CLOSE_REQUESTED: u8 = 1;
const CANCEL_REQUESTED: u8 = 2;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalPtySessionId(String);

impl LocalPtySessionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, LocalPtyError> {
        let parsed = Uuid::parse_str(value).map_err(|_| LocalPtyError::InvalidSessionId)?;
        let canonical = parsed.hyphenated().to_string();
        if canonical != value {
            return Err(LocalPtyError::InvalidSessionId);
        }
        Ok(Self(canonical))
    }
}

impl FromStr for LocalPtySessionId {
    type Err = LocalPtyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for LocalPtySessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for LocalPtySessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct LocalPtyBytes(Vec<u8>);

impl LocalPtyBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for LocalPtyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for LocalPtyBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalPtyBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPtyCloseReason {
    Exited,
    Requested,
    Cancelled,
    IoError,
    StartFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPtyExit {
    exit_code: Option<u32>,
    signaled: bool,
    reason: LocalPtyCloseReason,
}

impl LocalPtyExit {
    pub const fn exit_code(self) -> Option<u32> {
        self.exit_code
    }

    pub const fn signaled(self) -> bool {
        self.signaled
    }

    pub const fn reason(self) -> LocalPtyCloseReason {
        self.reason
    }
}

pub enum LocalPtyRuntimeEvent {
    Starting,
    Started { process_id: Option<u32> },
    Data(LocalPtyBytes),
    Error(LocalPtyError),
    Exited(LocalPtyExit),
}

impl fmt::Debug for LocalPtyRuntimeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => formatter.write_str("Starting"),
            Self::Started { process_id } => formatter
                .debug_struct("Started")
                .field("process_id", process_id)
                .finish(),
            Self::Data(bytes) => formatter.debug_tuple("Data").field(bytes).finish(),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::Exited(exit) => formatter.debug_tuple("Exited").field(exit).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPtyIoOperation {
    Open,
    Spawn,
    ReaderSetup,
    WriterSetup,
    Read,
    Write,
    Flush,
    Resize,
    Terminate,
    Wait,
    Drain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPtyIoErrorKind {
    NotFound,
    AccessDenied,
    BrokenPipe,
    Interrupted,
    TimedOut,
    Other,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocalPtyError {
    Config(ShellDiscoveryError),
    InvalidSessionId,
    InputTooLarge {
        maximum_bytes: usize,
    },
    InputQueueFull {
        maximum_bytes: usize,
    },
    CommandQueueFull {
        capacity: usize,
    },
    SessionNotFound,
    SessionClosing,
    RuntimeThreadUnavailable,
    BackendFailed {
        operation: LocalPtyIoOperation,
    },
    IoFailed {
        operation: LocalPtyIoOperation,
        kind: LocalPtyIoErrorKind,
    },
    FinalOutputDrainTimedOut {
        timeout: Duration,
    },
}

impl fmt::Display for LocalPtyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "Local PTY configuration error: {error}"),
            Self::InvalidSessionId => formatter.write_str("Local PTY session ID is invalid"),
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "Local PTY input exceeds {maximum_bytes} bytes")
            }
            Self::InputQueueFull { maximum_bytes } => write!(
                formatter,
                "Local PTY queued input reached its {maximum_bytes}-byte limit"
            ),
            Self::CommandQueueFull { capacity } => write!(
                formatter,
                "Local PTY command queue reached its {capacity}-item limit"
            ),
            Self::SessionNotFound => formatter.write_str("Local PTY session was not found"),
            Self::SessionClosing => formatter.write_str("Local PTY session is closing"),
            Self::RuntimeThreadUnavailable => {
                formatter.write_str("Local PTY runtime thread is unavailable")
            }
            Self::BackendFailed { operation } => {
                write!(
                    formatter,
                    "Local PTY {operation:?} backend operation failed"
                )
            }
            Self::IoFailed { operation, kind } => {
                write!(formatter, "Local PTY {operation:?} failed ({kind:?})")
            }
            Self::FinalOutputDrainTimedOut { timeout } => write!(
                formatter,
                "Local PTY final output did not drain within {} seconds",
                timeout.as_secs()
            ),
        }
    }
}

impl fmt::Debug for LocalPtyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for LocalPtyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ShellDiscoveryError> for LocalPtyError {
    fn from(error: ShellDiscoveryError) -> Self {
        Self::Config(error)
    }
}

pub struct LocalPtyRuntimeSession {
    session_id: LocalPtySessionId,
    events: tokio_mpsc::Receiver<LocalPtyRuntimeEvent>,
}

impl LocalPtyRuntimeSession {
    pub fn session_id(&self) -> &LocalPtySessionId {
        &self.session_id
    }

    pub async fn recv(&mut self) -> Option<LocalPtyRuntimeEvent> {
        self.events.recv().await
    }

    pub fn try_recv(&mut self) -> Result<LocalPtyRuntimeEvent, tokio_mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    pub fn into_parts(
        self,
    ) -> (
        LocalPtySessionId,
        tokio_mpsc::Receiver<LocalPtyRuntimeEvent>,
    ) {
        (self.session_id, self.events)
    }
}

impl fmt::Debug for LocalPtyRuntimeSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalPtyRuntimeSession")
            .field("session_id", &self.session_id)
            .field("queued_events", &self.events.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct LocalPtyManager {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    sessions: Mutex<HashMap<LocalPtySessionId, SessionEntry>>,
    backend: Arc<dyn PtyBackend>,
}

#[derive(Clone)]
struct SessionEntry {
    inputs: SyncSender<InputCommand>,
    input_budget: Arc<InputBudget>,
    close: Arc<AtomicU8>,
    window_size: Arc<Mutex<LocalPtyWindowSize>>,
    pending_resize: Arc<Mutex<Option<LocalPtyWindowSize>>>,
}

struct InputCommand {
    bytes: Zeroizing<Vec<u8>>,
    budget: Arc<InputBudget>,
}

impl Drop for InputCommand {
    fn drop(&mut self) {
        self.budget.release(self.bytes.len());
    }
}

impl fmt::Debug for InputCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputCommand")
            .field("length", &self.bytes.len())
            .finish()
    }
}

#[derive(Default)]
struct InputBudget {
    bytes: AtomicUsize,
}

impl InputBudget {
    fn reserve(&self, bytes: usize) -> bool {
        let mut current = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > MAX_QUEUED_INPUT_BYTES {
                return false;
            }
            match self.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct OutputBudget {
    queued: Mutex<OutputQueueState>,
    available: Condvar,
    closed: AtomicBool,
}

#[derive(Default)]
struct OutputQueueState {
    bytes: usize,
    events: usize,
}

impl OutputBudget {
    fn send(&self, sender: &SyncSender<LocalPtyRuntimeEvent>, bytes: Vec<u8>) -> Result<(), ()> {
        let length = bytes.len();
        let mut queued = lock(&self.queued);
        while !self.closed.load(Ordering::Acquire)
            && (queued.bytes.saturating_add(length) > MAX_BUFFERED_OUTPUT_BYTES
                || queued.events >= MAX_BUFFERED_OUTPUT_EVENTS)
        {
            let waited = self
                .available
                .wait_timeout(queued, Duration::from_millis(100))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queued = waited.0;
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(());
        }
        queued.bytes += length;
        queued.events += 1;
        drop(queued);
        if sender
            .send(LocalPtyRuntimeEvent::Data(LocalPtyBytes::new(bytes)))
            .is_err()
        {
            self.release(length);
            return Err(());
        }
        Ok(())
    }

    fn release(&self, bytes: usize) {
        let mut queued = lock(&self.queued);
        queued.bytes = queued.bytes.saturating_sub(bytes);
        queued.events = queued.events.saturating_sub(1);
        self.available.notify_all();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.available.notify_all();
    }
}

trait PtyBackend: Send + Sync {
    fn spawn(&self, config: &LocalPtyConfig) -> Result<SpawnedPty, LocalPtyError>;
}

#[derive(Debug, Default)]
struct NativePtyBackend;

struct SpawnedPty {
    master: Box<dyn MasterPty>,
    child: Box<dyn Child + Send + Sync>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

impl PtyBackend for NativePtyBackend {
    fn spawn(&self, config: &LocalPtyConfig) -> Result<SpawnedPty, LocalPtyError> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(to_native_size(config.window_size))
            .map_err(|_| LocalPtyError::BackendFailed {
                operation: LocalPtyIoOperation::Open,
            })?;
        let mut command = build_command(config);
        apply_locale_defaults(&mut command);
        let mut child =
            pair.slave
                .spawn_command(command)
                .map_err(|_| LocalPtyError::BackendFailed {
                    operation: LocalPtyIoOperation::Spawn,
                })?;
        drop(pair.slave);

        let reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(_) => {
                terminate_failed_spawn(&mut child);
                return Err(LocalPtyError::BackendFailed {
                    operation: LocalPtyIoOperation::ReaderSetup,
                });
            }
        };
        let writer = match pair.master.take_writer() {
            Ok(writer) => writer,
            Err(_) => {
                terminate_failed_spawn(&mut child);
                return Err(LocalPtyError::BackendFailed {
                    operation: LocalPtyIoOperation::WriterSetup,
                });
            }
        };
        Ok(SpawnedPty {
            master: pair.master,
            child,
            reader,
            writer,
        })
    }
}

impl LocalPtyManager {
    pub fn new() -> Self {
        Self::with_backend(Arc::new(NativePtyBackend))
    }

    fn with_backend(backend: Arc<dyn PtyBackend>) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                sessions: Mutex::new(HashMap::new()),
                backend,
            }),
        }
    }

    pub fn start(&self, config: LocalPtyConfig) -> Result<LocalPtyRuntimeSession, LocalPtyError> {
        let (input_tx, input_rx) = mpsc::sync_channel(INPUT_CHANNEL_CAPACITY);
        let (internal_event_tx, internal_event_rx) = mpsc::sync_channel(EVENT_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = tokio_mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let input_budget = Arc::new(InputBudget::default());
        let output_budget = Arc::new(OutputBudget::default());
        let close = Arc::new(AtomicU8::new(RUNNING));
        let window_size = Arc::new(Mutex::new(config.window_size));
        let pending_resize = Arc::new(Mutex::new(None));

        let session_id = loop {
            let candidate = LocalPtySessionId(Uuid::new_v4().to_string());
            let mut sessions = lock(&self.inner.sessions);
            if sessions.contains_key(&candidate) {
                continue;
            }
            sessions.insert(
                candidate.clone(),
                SessionEntry {
                    inputs: input_tx.clone(),
                    input_budget: input_budget.clone(),
                    close: close.clone(),
                    window_size: window_size.clone(),
                    pending_resize: pending_resize.clone(),
                },
            );
            break candidate;
        };

        let forward_close = close.clone();
        let forward_budget = output_budget.clone();
        thread::Builder::new()
            .name("netcatty-local-pty-events".to_owned())
            .spawn(move || {
                forward_events(internal_event_rx, event_tx, forward_close, forward_budget);
            })
            .map_err(|_| {
                lock(&self.inner.sessions).remove(&session_id);
                LocalPtyError::RuntimeThreadUnavailable
            })?;

        let inner = self.inner.clone();
        let worker_session_id = session_id.clone();
        let worker_close = close;
        let worker_budget = output_budget;
        if thread::Builder::new()
            .name("netcatty-local-pty".to_owned())
            .spawn(move || {
                run_session(
                    inner,
                    worker_session_id,
                    config,
                    input_rx,
                    internal_event_tx,
                    worker_close,
                    window_size,
                    pending_resize,
                    worker_budget,
                );
            })
            .is_err()
        {
            lock(&self.inner.sessions).remove(&session_id);
            return Err(LocalPtyError::RuntimeThreadUnavailable);
        }

        Ok(LocalPtyRuntimeSession {
            session_id,
            events: event_rx,
        })
    }

    pub fn input(&self, session_id: &LocalPtySessionId, input: &[u8]) -> Result<(), LocalPtyError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(LocalPtyError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES,
            });
        }
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        if input.is_empty() {
            return Ok(());
        }
        if !entry.input_budget.reserve(input.len()) {
            return Err(LocalPtyError::InputQueueFull {
                maximum_bytes: MAX_QUEUED_INPUT_BYTES,
            });
        }
        let command = InputCommand {
            bytes: Zeroizing::new(input.to_vec()),
            budget: entry.input_budget,
        };
        match entry.inputs.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(LocalPtyError::CommandQueueFull {
                capacity: INPUT_CHANNEL_CAPACITY,
            }),
            Err(TrySendError::Disconnected(_)) => Err(LocalPtyError::SessionClosing),
        }
    }

    pub fn resize(
        &self,
        session_id: &LocalPtySessionId,
        columns: u32,
        rows: u32,
    ) -> Result<(), LocalPtyError> {
        let size = LocalPtyWindowSize::new(columns, rows)?;
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        *lock(&entry.window_size) = size;
        *lock(&entry.pending_resize) = Some(size);
        Ok(())
    }

    pub fn window_size(
        &self,
        session_id: &LocalPtySessionId,
    ) -> Result<LocalPtyWindowSize, LocalPtyError> {
        let entry = self.entry(session_id)?;
        let size = *lock(&entry.window_size);
        Ok(size)
    }

    pub fn close(&self, session_id: &LocalPtySessionId) -> Result<(), LocalPtyError> {
        self.request_stop(session_id, CLOSE_REQUESTED)
    }

    pub fn cancel(&self, session_id: &LocalPtySessionId) -> Result<(), LocalPtyError> {
        self.request_stop(session_id, CANCEL_REQUESTED)
    }

    pub fn contains(&self, session_id: &LocalPtySessionId) -> bool {
        lock(&self.inner.sessions).contains_key(session_id)
    }

    pub fn session_count(&self) -> usize {
        lock(&self.inner.sessions).len()
    }

    fn request_stop(
        &self,
        session_id: &LocalPtySessionId,
        signal: u8,
    ) -> Result<(), LocalPtyError> {
        let entry = self.entry(session_id)?;
        let _ = entry
            .close
            .compare_exchange(RUNNING, signal, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }

    fn entry(&self, session_id: &LocalPtySessionId) -> Result<SessionEntry, LocalPtyError> {
        lock(&self.inner.sessions)
            .get(session_id)
            .cloned()
            .ok_or(LocalPtyError::SessionNotFound)
    }
}

impl Default for LocalPtyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LocalPtyManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalPtyManager")
            .field("session_count", &self.session_count())
            .finish()
    }
}

fn ensure_running(entry: &SessionEntry) -> Result<(), LocalPtyError> {
    if entry.close.load(Ordering::Acquire) == RUNNING {
        Ok(())
    } else {
        Err(LocalPtyError::SessionClosing)
    }
}

fn forward_events(
    receiver: Receiver<LocalPtyRuntimeEvent>,
    sender: tokio_mpsc::Sender<LocalPtyRuntimeEvent>,
    close: Arc<AtomicU8>,
    output_budget: Arc<OutputBudget>,
) {
    loop {
        if sender.is_closed() {
            let _ = close.compare_exchange(
                RUNNING,
                CANCEL_REQUESTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            output_budget.close();
            return;
        }
        let event = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if let LocalPtyRuntimeEvent::Data(bytes) = &event {
            output_budget.release(bytes.len());
        }
        if sender.blocking_send(event).is_err() {
            let _ = close.compare_exchange(
                RUNNING,
                CANCEL_REQUESTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            output_budget.close();
            return;
        }
    }
    output_budget.close();
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    inner: Arc<RuntimeInner>,
    session_id: LocalPtySessionId,
    config: LocalPtyConfig,
    inputs: Receiver<InputCommand>,
    events: SyncSender<LocalPtyRuntimeEvent>,
    close: Arc<AtomicU8>,
    _window_size: Arc<Mutex<LocalPtyWindowSize>>,
    pending_resize: Arc<Mutex<Option<LocalPtyWindowSize>>>,
    output_budget: Arc<OutputBudget>,
) {
    if events.send(LocalPtyRuntimeEvent::Starting).is_err() {
        finish_session(&inner, &session_id);
        return;
    }
    if close.load(Ordering::Acquire) != RUNNING {
        send_exit(&events, None, false, requested_reason(&close));
        finish_session(&inner, &session_id);
        return;
    }

    let mut spawned = match inner.backend.spawn(&config) {
        Ok(spawned) => spawned,
        Err(error) => {
            let _ = events.send(LocalPtyRuntimeEvent::Error(error));
            send_exit(&events, None, false, LocalPtyCloseReason::StartFailed);
            finish_session(&inner, &session_id);
            return;
        }
    };
    let process_id = spawned.child.process_id();
    if events
        .send(LocalPtyRuntimeEvent::Started { process_id })
        .is_err()
    {
        terminate_failed_spawn(&mut spawned.child);
        finish_session(&inner, &session_id);
        return;
    }

    let (reader_outcome_tx, reader_outcome_rx) = mpsc::sync_channel(1);
    let reader_events = events.clone();
    let reader_budget = output_budget.clone();
    let mut reader = spawned.reader;
    if thread::Builder::new()
        .name("netcatty-local-pty-reader".to_owned())
        .spawn(move || {
            read_output(
                &mut reader,
                &reader_events,
                &reader_budget,
                reader_outcome_tx,
            );
        })
        .is_err()
    {
        terminate_failed_spawn(&mut spawned.child);
        let _ = events.send(LocalPtyRuntimeEvent::Error(
            LocalPtyError::RuntimeThreadUnavailable,
        ));
        send_exit(&events, None, false, LocalPtyCloseReason::StartFailed);
        finish_session(&inner, &session_id);
        return;
    }

    let mut close_started = None;
    let mut terminal_error = None;
    let mut reader_finished = false;
    let mut resize_error_reported = false;
    let status = loop {
        let stop = close.load(Ordering::Acquire);
        if stop != RUNNING && close_started.is_none() {
            close_started = Some(Instant::now());
            if let Err(error) = spawned.child.kill() {
                terminal_error = Some(io_error(LocalPtyIoOperation::Terminate, &error));
            }
        }

        if let Some(size) = lock(&pending_resize).take()
            && spawned.master.resize(to_native_size(size)).is_err()
            && !resize_error_reported
        {
            resize_error_reported = true;
            let _ = events.send(LocalPtyRuntimeEvent::Error(LocalPtyError::BackendFailed {
                operation: LocalPtyIoOperation::Resize,
            }));
        }

        for _ in 0..INPUT_CHANNEL_CAPACITY {
            match inputs.try_recv() {
                Ok(command) => {
                    if terminal_error.is_none()
                        && let Err(error) = spawned.writer.write_all(&command.bytes)
                    {
                        terminal_error = Some(io_error(LocalPtyIoOperation::Write, &error));
                    }
                    if terminal_error.is_none()
                        && let Err(error) = spawned.writer.flush()
                    {
                        terminal_error = Some(io_error(LocalPtyIoOperation::Flush, &error));
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if !reader_finished {
            match reader_outcome_rx.try_recv() {
                Ok(ReaderOutcome::Eof) => reader_finished = true,
                Ok(ReaderOutcome::Error(kind)) => {
                    reader_finished = true;
                    terminal_error = Some(LocalPtyError::IoFailed {
                        operation: LocalPtyIoOperation::Read,
                        kind,
                    });
                }
                Err(TryRecvError::Disconnected) => reader_finished = true,
                Err(TryRecvError::Empty) => {}
            }
        }

        if terminal_error.is_some() && close_started.is_none() {
            close_started = Some(Instant::now());
            let _ = spawned.child.kill();
        }

        match spawned.child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => {
                terminal_error = Some(io_error(LocalPtyIoOperation::Wait, &error));
                break None;
            }
        }
        if close_started.is_some_and(|started| started.elapsed() >= TERMINATION_TIMEOUT) {
            terminal_error = Some(LocalPtyError::IoFailed {
                operation: LocalPtyIoOperation::Wait,
                kind: LocalPtyIoErrorKind::TimedOut,
            });
            break None;
        }
        thread::sleep(CONTROL_POLL_INTERVAL);
    };

    drop(spawned.writer);
    if let Err(error) = close_master_without_blocking_session(spawned.master) {
        terminal_error.get_or_insert(error);
    }
    if !reader_finished {
        match reader_outcome_rx.recv_timeout(FINAL_OUTPUT_DRAIN_TIMEOUT) {
            Ok(ReaderOutcome::Eof) => {}
            Ok(ReaderOutcome::Error(kind)) => {
                terminal_error.get_or_insert(LocalPtyError::IoFailed {
                    operation: LocalPtyIoOperation::Read,
                    kind,
                });
            }
            Err(_) => {
                terminal_error.get_or_insert(LocalPtyError::FinalOutputDrainTimedOut {
                    timeout: FINAL_OUTPUT_DRAIN_TIMEOUT,
                });
            }
        }
    }

    if let Some(error) = terminal_error.as_ref() {
        let _ = events.send(LocalPtyRuntimeEvent::Error(error.clone()));
    }
    let stop = close.load(Ordering::Acquire);
    let reason = if stop != RUNNING {
        requested_reason(&close)
    } else if terminal_error.is_some() {
        LocalPtyCloseReason::IoError
    } else {
        LocalPtyCloseReason::Exited
    };
    send_exit(
        &events,
        status.as_ref().map(|status| status.exit_code()),
        status.as_ref().and_then(|status| status.signal()).is_some(),
        reason,
    );
    finish_session(&inner, &session_id);
}

/// ConPTY's `ClosePseudoConsole` runs from `MasterPty::drop` and is allowed to
/// wait for its headless console host. A wedged host must not hold the session
/// worker before it publishes `Exited` and removes the exact session entry.
///
/// The holder indirection is intentional: if the OS cannot create the cleanup
/// thread, forgetting the sole remaining holder is safer than synchronously
/// dropping the master on this lifecycle-critical worker. This exceptional
/// thread-creation failure intentionally leaks the holder; it is preferable to
/// losing all future session lifecycle events to a synchronous destructor.
#[cfg(windows)]
fn close_master_without_blocking_session(master: Box<dyn MasterPty>) -> Result<(), LocalPtyError> {
    let holder = Arc::new(Mutex::new(Some(master)));
    let cleanup_holder = holder.clone();
    match thread::Builder::new()
        .name("netcatty-local-pty-master-close".to_owned())
        .spawn(move || {
            let master = lock(&cleanup_holder).take();
            drop(master);
        }) {
        Ok(_) => Ok(()),
        Err(_) => {
            // `Builder::spawn` has already dropped the closure and its Arc.
            // Keep the last holder alive forever so this error path remains
            // non-blocking even when the master destructor is the failure.
            std::mem::forget(holder);
            Err(LocalPtyError::RuntimeThreadUnavailable)
        }
    }
}

#[cfg(not(windows))]
fn close_master_without_blocking_session(master: Box<dyn MasterPty>) -> Result<(), LocalPtyError> {
    drop(master);
    Ok(())
}

fn read_output(
    reader: &mut (dyn Read + Send),
    events: &SyncSender<LocalPtyRuntimeEvent>,
    budget: &OutputBudget,
    outcome: SyncSender<ReaderOutcome>,
) {
    let mut buffer = vec![0u8; READ_BUFFER_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = outcome.send(ReaderOutcome::Eof);
                return;
            }
            Ok(length) => {
                if budget.send(events, buffer[..length].to_vec()).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = outcome.send(ReaderOutcome::Error(map_io_kind(error.kind())));
                return;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ReaderOutcome {
    Eof,
    Error(LocalPtyIoErrorKind),
}

fn finish_session(inner: &RuntimeInner, session_id: &LocalPtySessionId) {
    lock(&inner.sessions).remove(session_id);
}

fn send_exit(
    events: &SyncSender<LocalPtyRuntimeEvent>,
    exit_code: Option<u32>,
    signaled: bool,
    reason: LocalPtyCloseReason,
) {
    let _ = events.send(LocalPtyRuntimeEvent::Exited(LocalPtyExit {
        exit_code,
        signaled,
        reason,
    }));
}

fn requested_reason(close: &AtomicU8) -> LocalPtyCloseReason {
    match close.load(Ordering::Acquire) {
        CANCEL_REQUESTED => LocalPtyCloseReason::Cancelled,
        _ => LocalPtyCloseReason::Requested,
    }
}

fn build_command(config: &LocalPtyConfig) -> CommandBuilder {
    let mut command = CommandBuilder::new(&config.shell.command);
    command.args(&config.shell.args);
    command.cwd(&config.cwd);
    command.env("TERM", &config.environment.term);
    command.env("COLORTERM", &config.environment.color_term);
    command
}

fn apply_locale_defaults(command: &mut CommandBuilder) {
    let values = ["LC_ALL", "LC_CTYPE", "LANG"].map(|name| std::env::var(name).unwrap_or_default());
    if values.iter().any(|value| {
        value.to_ascii_lowercase().contains("utf-8") || value.to_ascii_lowercase().contains("utf8")
    }) {
        return;
    }
    let has_meaningful_locale = values.iter().any(|value| {
        let value = value.trim();
        !value.is_empty() && value != "C" && value != "POSIX"
    });
    if has_meaningful_locale {
        return;
    }
    for name in ["LANG", "LC_CTYPE", "LC_ALL"] {
        command.env(name, "C.UTF-8");
    }
}

fn to_native_size(size: LocalPtyWindowSize) -> PtySize {
    PtySize {
        rows: size.rows(),
        cols: size.columns(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn terminate_failed_spawn(child: &mut Box<dyn Child + Send + Sync>) {
    let _ = child.kill();
    let _ = child.wait();
}

fn io_error(operation: LocalPtyIoOperation, error: &io::Error) -> LocalPtyError {
    LocalPtyError::IoFailed {
        operation,
        kind: map_io_kind(error.kind()),
    }
}

fn map_io_kind(kind: io::ErrorKind) -> LocalPtyIoErrorKind {
    match kind {
        io::ErrorKind::NotFound => LocalPtyIoErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => LocalPtyIoErrorKind::AccessDenied,
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
            LocalPtyIoErrorKind::BrokenPipe
        }
        io::ErrorKind::Interrupted => LocalPtyIoErrorKind::Interrupted,
        io::ErrorKind::TimedOut => LocalPtyIoErrorKind::TimedOut,
        _ => LocalPtyIoErrorKind::Other,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalPtyRequest, discover_shells};
    #[cfg(windows)]
    use portable_pty::{ChildKiller, ExitStatus};
    use tokio::time::{Duration as TokioDuration, timeout};

    fn live_config() -> LocalPtyConfig {
        let catalog = discover_shells().expect("discover shells");
        let selected = if cfg!(windows) {
            catalog
                .get("cmd")
                .or_else(|| catalog.get("powershell"))
                .or_else(|| catalog.get("pwsh"))
                .unwrap_or_else(|| catalog.default_shell())
        } else {
            catalog.default_shell()
        };
        LocalPtyConfig::resolve(
            &catalog,
            LocalPtyRequest::new(Some(selected.id().to_owned()), 80, 24),
        )
        .expect("resolve live config")
    }

    #[cfg(windows)]
    #[derive(Default)]
    struct BlockingMasterDropGate {
        started: AtomicBool,
        released: AtomicBool,
        finished: AtomicBool,
        monitor: Mutex<()>,
        wake: Condvar,
    }

    #[cfg(windows)]
    impl BlockingMasterDropGate {
        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.wake.notify_all();
        }
    }

    #[cfg(windows)]
    struct ReleaseBlockedMasterOnDrop(Arc<BlockingMasterDropGate>);

    #[cfg(windows)]
    impl Drop for ReleaseBlockedMasterOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[cfg(windows)]
    struct BlockingDropMaster {
        gate: Arc<BlockingMasterDropGate>,
    }

    #[cfg(windows)]
    impl Drop for BlockingDropMaster {
        fn drop(&mut self) {
            self.gate.started.store(true, Ordering::Release);
            self.gate.wake.notify_all();
            let mut guard = lock(&self.gate.monitor);
            while !self.gate.released.load(Ordering::Acquire) {
                guard = self
                    .gate
                    .wake
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            self.gate.finished.store(true, Ordering::Release);
            self.gate.wake.notify_all();
        }
    }

    #[cfg(windows)]
    impl MasterPty for BlockingDropMaster {
        fn resize(&self, _size: PtySize) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_size(&self) -> anyhow::Result<PtySize> {
            Ok(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
        }

        fn try_clone_reader(&self) -> anyhow::Result<Box<dyn Read + Send>> {
            Ok(Box::new(io::empty()))
        }

        fn take_writer(&self) -> anyhow::Result<Box<dyn Write + Send>> {
            Ok(Box::new(io::sink()))
        }
    }

    #[cfg(windows)]
    #[derive(Clone, Debug, Default)]
    struct KillCompletesChild {
        killed: Arc<AtomicBool>,
    }

    #[cfg(windows)]
    impl ChildKiller for KillCompletesChild {
        fn kill(&mut self) -> io::Result<()> {
            self.killed.store(true, Ordering::Release);
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
            Box::new(self.clone())
        }
    }

    #[cfg(windows)]
    impl Child for KillCompletesChild {
        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            Ok(self
                .killed
                .load(Ordering::Acquire)
                .then(|| ExitStatus::with_exit_code(1)))
        }

        fn wait(&mut self) -> io::Result<ExitStatus> {
            while !self.killed.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(ExitStatus::with_exit_code(1))
        }

        fn process_id(&self) -> Option<u32> {
            Some(7)
        }

        fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            None
        }
    }

    #[cfg(windows)]
    struct BlockingMasterDropBackend {
        gate: Arc<BlockingMasterDropGate>,
    }

    #[cfg(windows)]
    impl PtyBackend for BlockingMasterDropBackend {
        fn spawn(&self, _config: &LocalPtyConfig) -> Result<SpawnedPty, LocalPtyError> {
            Ok(SpawnedPty {
                master: Box::new(BlockingDropMaster {
                    gate: self.gate.clone(),
                }),
                child: Box::new(KillCompletesChild::default()),
                reader: Box::new(io::empty()),
                writer: Box::new(io::sink()),
            })
        }
    }

    #[test]
    fn session_ids_require_canonical_uuid_text() {
        let value = Uuid::new_v4().to_string();
        assert_eq!(LocalPtySessionId::parse(&value).unwrap().as_str(), value);
        assert_eq!(
            LocalPtySessionId::parse(&value.to_ascii_uppercase()),
            Err(LocalPtyError::InvalidSessionId)
        );
    }

    #[test]
    fn byte_debug_never_contains_terminal_content() {
        let value = LocalPtyBytes::new(b"password-secret-sentinel".to_vec());
        let debug = format!("{value:?}");
        assert!(!debug.contains("password"));
        assert!(debug.contains("24"));
    }

    #[test]
    fn errors_are_typed_and_do_not_echo_native_details() {
        let error = LocalPtyError::BackendFailed {
            operation: LocalPtyIoOperation::Spawn,
        };
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("Users"));
        assert!(!rendered.contains("command"));
    }

    #[test]
    fn manager_rejects_unknown_sessions_and_oversized_input() {
        let manager = LocalPtyManager::new();
        let id = LocalPtySessionId(Uuid::new_v4().to_string());
        assert_eq!(manager.close(&id), Err(LocalPtyError::SessionNotFound));
        assert_eq!(
            manager.input(&id, &vec![0; MAX_INPUT_BYTES + 1]),
            Err(LocalPtyError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES
            })
        );
    }

    #[test]
    fn aggregate_input_budget_is_bounded_and_recoverable() {
        let budget = InputBudget::default();
        assert!(budget.reserve(MAX_QUEUED_INPUT_BYTES));
        assert!(!budget.reserve(1));
        budget.release(MAX_QUEUED_INPUT_BYTES);
        assert!(budget.reserve(MAX_INPUT_BYTES));
        budget.release(MAX_INPUT_BYTES);
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_master_drop_cannot_block_exit_or_session_removal() {
        let gate = Arc::new(BlockingMasterDropGate::default());
        let _release_on_failure = ReleaseBlockedMasterOnDrop(gate.clone());
        let manager = LocalPtyManager::with_backend(Arc::new(BlockingMasterDropBackend {
            gate: gate.clone(),
        }));
        let mut session = manager.start(live_config()).expect("start fake PTY");
        let session_id = session.session_id().clone();
        loop {
            let event = timeout(TokioDuration::from_secs(2), session.recv())
                .await
                .expect("start timeout")
                .expect("event");
            if matches!(event, LocalPtyRuntimeEvent::Started { .. }) {
                break;
            }
        }

        manager.close(&session_id).expect("close request");
        timeout(TokioDuration::from_secs(2), async {
            while !gate.started.load(Ordering::Acquire) {
                tokio::time::sleep(TokioDuration::from_millis(5)).await;
            }
        })
        .await
        .expect("master destructor did not start");
        assert!(!gate.finished.load(Ordering::Acquire));

        let exit_result = timeout(TokioDuration::from_secs(2), async {
            loop {
                if let LocalPtyRuntimeEvent::Exited(exit) = session.recv().await.expect("event") {
                    break exit;
                }
            }
        })
        .await;
        let exit = match exit_result {
            Ok(exit) => exit,
            Err(error) => {
                gate.release();
                panic!("blocking master destructor held the exit event: {error}");
            }
        };
        assert_eq!(exit.reason(), LocalPtyCloseReason::Requested);
        timeout(TokioDuration::from_secs(2), async {
            while manager.contains(&session_id) {
                tokio::time::sleep(TokioDuration::from_millis(5)).await;
            }
        })
        .await
        .expect("blocking master destructor held session removal");
        assert!(!gate.finished.load(Ordering::Acquire));

        gate.release();
        timeout(TokioDuration::from_secs(2), async {
            while !gate.finished.load(Ordering::Acquire) {
                tokio::time::sleep(TokioDuration::from_millis(5)).await;
            }
        })
        .await
        .expect("master cleanup thread did not finish after release");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_pty_streams_raw_output_resizes_and_reports_exit() {
        let config = live_config();
        let shell_id = config.shell_id().to_owned();
        let manager = LocalPtyManager::new();
        let mut session = manager.start(config).expect("start native PTY");
        let session_id = session.session_id().clone();
        let mut output = Vec::new();

        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("start timeout")
                .expect("start event");
            match event {
                LocalPtyRuntimeEvent::Started { .. } => break,
                LocalPtyRuntimeEvent::Data(bytes) => output.extend_from_slice(bytes.as_slice()),
                LocalPtyRuntimeEvent::Error(error) => panic!("PTY start failed: {error}"),
                LocalPtyRuntimeEvent::Starting | LocalPtyRuntimeEvent::Exited(_) => {}
            }
        }
        manager.resize(&session_id, 100, 30).expect("resize PTY");
        assert_eq!(
            manager.window_size(&session_id).expect("window size"),
            LocalPtyWindowSize::new(100, 30).unwrap()
        );

        let marker = "__NETCATTY_LOCAL_PTY_MARKER__";
        let command = if cfg!(windows) && shell_id == "cmd" {
            format!("echo {marker}\r\nexit\r\n")
        } else if cfg!(windows) {
            format!("Write-Output {marker}\r\nexit\r\n")
        } else {
            format!("printf '{marker}\\n'\nexit\n")
        };
        manager
            .input(&session_id, command.as_bytes())
            .expect("write command");

        let exit = loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "event timeout after output {:?}",
                        String::from_utf8_lossy(&output)
                    )
                })
                .expect("runtime event");
            match event {
                LocalPtyRuntimeEvent::Data(bytes) => output.extend_from_slice(bytes.as_slice()),
                LocalPtyRuntimeEvent::Exited(exit) => break exit,
                LocalPtyRuntimeEvent::Error(error) => panic!("PTY runtime error: {error}"),
                LocalPtyRuntimeEvent::Starting | LocalPtyRuntimeEvent::Started { .. } => {}
            }
        };
        assert_eq!(exit.reason(), LocalPtyCloseReason::Exited);
        assert!(String::from_utf8_lossy(&output).contains(marker));
        assert!(
            !output
                .windows(b"\x1b[6n".len())
                .any(|bytes| bytes == b"\x1b[6n"),
            "a fresh PTY must not request an inherited cursor position"
        );
        assert!(!manager.contains(&session_id));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requested_close_terminates_a_live_native_pty() {
        let manager = LocalPtyManager::new();
        let mut session = manager.start(live_config()).expect("start native PTY");
        let session_id = session.session_id().clone();
        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("start timeout")
                .expect("event");
            if matches!(event, LocalPtyRuntimeEvent::Started { .. }) {
                break;
            }
        }
        manager.close(&session_id).expect("close request");
        let exit = loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("close timeout")
                .expect("event");
            if let LocalPtyRuntimeEvent::Exited(exit) = event {
                break exit;
            }
        };
        assert_eq!(exit.reason(), LocalPtyCloseReason::Requested);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requested_close_terminates_the_default_live_native_pty() {
        let catalog = discover_shells().expect("discover shells");
        let config = LocalPtyConfig::resolve(
            &catalog,
            LocalPtyRequest::new(Some(catalog.default_shell().id().to_owned()), 80, 24),
        )
        .expect("resolve default shell");
        let manager = LocalPtyManager::new();
        let mut session = manager.start(config).expect("start native PTY");
        let session_id = session.session_id().clone();
        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("start timeout")
                .expect("event");
            if matches!(event, LocalPtyRuntimeEvent::Started { .. }) {
                break;
            }
        }
        manager.close(&session_id).expect("close request");
        let exit = loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("close timeout")
                .expect("event");
            if let LocalPtyRuntimeEvent::Exited(exit) = event {
                break exit;
            }
        };
        assert_eq!(exit.reason(), LocalPtyCloseReason::Requested);
        assert!(!manager.contains(&session_id));
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requested_close_terminates_a_live_conpty_process_tree() {
        let manager = LocalPtyManager::new();
        let mut session = manager.start(live_config()).expect("start native PTY");
        let session_id = session.session_id().clone();
        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("start timeout")
                .expect("event");
            if matches!(event, LocalPtyRuntimeEvent::Started { .. }) {
                break;
            }
        }
        manager
            .input(
                &session_id,
                b"cmd.exe /d /q /k echo __NETCATTY_CHILD_%COMSPEC:~0,0%READY__\r\n",
            )
            .expect("start nested console process");
        let mut output = Vec::new();
        timeout(TokioDuration::from_secs(10), async {
            while !String::from_utf8_lossy(&output).contains("__NETCATTY_CHILD_READY__") {
                match session.recv().await.expect("event") {
                    LocalPtyRuntimeEvent::Data(data) => output.extend_from_slice(data.as_slice()),
                    LocalPtyRuntimeEvent::Error(error) => panic!("PTY error: {error}"),
                    _ => {}
                }
            }
        })
        .await
        .expect("nested process start timeout");
        manager.close(&session_id).expect("close request");
        let exit = timeout(TokioDuration::from_secs(10), async {
            loop {
                if let LocalPtyRuntimeEvent::Exited(exit) = session.recv().await.expect("event") {
                    break exit;
                }
            }
        })
        .await
        .expect("process-tree close timeout");
        assert_eq!(exit.reason(), LocalPtyCloseReason::Requested);
        assert!(!manager.contains(&session_id));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_is_distinct_from_requested_close() {
        let manager = LocalPtyManager::new();
        let mut session = manager.start(live_config()).expect("start native PTY");
        let session_id = session.session_id().clone();
        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("start timeout")
                .expect("event");
            if matches!(event, LocalPtyRuntimeEvent::Started { .. }) {
                break;
            }
        }
        manager.cancel(&session_id).expect("cancel request");
        loop {
            let event = timeout(TokioDuration::from_secs(10), session.recv())
                .await
                .expect("cancel timeout")
                .expect("event");
            if let LocalPtyRuntimeEvent::Exited(exit) = event {
                assert_eq!(exit.reason(), LocalPtyCloseReason::Cancelled);
                break;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_event_receiver_cancels_an_idle_session() {
        let manager = LocalPtyManager::new();
        let session = manager.start(live_config()).expect("start native PTY");
        let session_id = session.session_id().clone();
        drop(session);
        timeout(TokioDuration::from_secs(10), async {
            while manager.contains(&session_id) {
                tokio::time::sleep(TokioDuration::from_millis(25)).await;
            }
        })
        .await
        .expect("dropped receiver cleanup timeout");
    }
}
