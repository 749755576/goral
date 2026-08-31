use std::{
    collections::HashMap,
    error::Error,
    fmt,
    io::{self, Read, Write},
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::mpsc as tokio_mpsc;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{EtConfigError, EtLaunchSpec, EtSessionConfig, EtWindowSize};

pub const MAX_INPUT_BYTES: usize = 64 * 1_024;
pub const MAX_QUEUED_INPUT_BYTES: usize = 256 * 1_024;
pub const MAX_BUFFERED_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
const READ_BUFFER_BYTES: usize = 16 * 1_024;
/// Together with the active reader buffer this keeps terminal output at or
/// below `MAX_BUFFERED_OUTPUT_BYTES` while the renderer is back-pressured.
pub const EVENT_CHANNEL_CAPACITY: usize = MAX_BUFFERED_OUTPUT_BYTES / READ_BUFFER_BYTES - 1;
const INPUT_CHANNEL_CAPACITY: usize = 64;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const FINAL_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const RUNNING: u8 = 0;
const CLOSE_REQUESTED: u8 = 1;
const CANCEL_REQUESTED: u8 = 2;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EtSessionId(String);

impl EtSessionId {
    pub fn parse(value: &str) -> Result<Self, EtRuntimeError> {
        let parsed = Uuid::parse_str(value).map_err(|_| EtRuntimeError::InvalidSessionId)?;
        let canonical = parsed.hyphenated().to_string();
        if canonical != value {
            return Err(EtRuntimeError::InvalidSessionId);
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EtSessionId {
    type Err = EtRuntimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for EtSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for EtSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct EtBytes(Vec<u8>);

impl EtBytes {
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

impl Drop for EtBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for EtBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtCloseReason {
    Exited,
    Requested,
    Cancelled,
    IoError,
    StartFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EtExit {
    exit_code: Option<u32>,
    signaled: bool,
    reason: EtCloseReason,
}

impl EtExit {
    pub const fn exit_code(self) -> Option<u32> {
        self.exit_code
    }

    pub const fn signaled(self) -> bool {
        self.signaled
    }

    pub const fn reason(self) -> EtCloseReason {
        self.reason
    }
}

pub enum EtRuntimeEvent {
    Starting,
    Started { process_id: Option<u32> },
    Data(EtBytes),
    Error(EtRuntimeError),
    Exited(EtExit),
}

impl fmt::Debug for EtRuntimeEvent {
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
pub enum EtIoOperation {
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
pub enum EtIoErrorKind {
    NotFound,
    AccessDenied,
    BrokenPipe,
    Interrupted,
    TimedOut,
    Other,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum EtRuntimeError {
    Config(EtConfigError),
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
        operation: EtIoOperation,
    },
    IoFailed {
        operation: EtIoOperation,
        kind: EtIoErrorKind,
    },
    FinalOutputDrainTimedOut {
        timeout: Duration,
    },
}

impl fmt::Display for EtRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => {
                write!(formatter, "Eternal Terminal configuration error: {error}")
            }
            Self::InvalidSessionId => formatter.write_str("Eternal Terminal session ID is invalid"),
            Self::InputTooLarge { maximum_bytes } => write!(
                formatter,
                "Eternal Terminal input exceeds {maximum_bytes} bytes"
            ),
            Self::InputQueueFull { maximum_bytes } => write!(
                formatter,
                "Eternal Terminal queued input reached its {maximum_bytes}-byte limit"
            ),
            Self::CommandQueueFull { capacity } => write!(
                formatter,
                "Eternal Terminal command queue reached its {capacity}-item limit"
            ),
            Self::SessionNotFound => formatter.write_str("Eternal Terminal session was not found"),
            Self::SessionClosing => formatter.write_str("Eternal Terminal session is closing"),
            Self::RuntimeThreadUnavailable => {
                formatter.write_str("Eternal Terminal runtime thread is unavailable")
            }
            Self::BackendFailed { operation } => write!(
                formatter,
                "Eternal Terminal {operation:?} backend operation failed"
            ),
            Self::IoFailed { operation, kind } => {
                write!(
                    formatter,
                    "Eternal Terminal {operation:?} failed ({kind:?})"
                )
            }
            Self::FinalOutputDrainTimedOut { timeout } => write!(
                formatter,
                "Eternal Terminal final output did not drain within {} seconds",
                timeout.as_secs()
            ),
        }
    }
}

impl fmt::Debug for EtRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for EtRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EtConfigError> for EtRuntimeError {
    fn from(error: EtConfigError) -> Self {
        Self::Config(error)
    }
}

pub struct EtRuntimeSession {
    session_id: EtSessionId,
    events: tokio_mpsc::Receiver<EtRuntimeEvent>,
}

impl EtRuntimeSession {
    pub fn session_id(&self) -> &EtSessionId {
        &self.session_id
    }

    pub async fn recv(&mut self) -> Option<EtRuntimeEvent> {
        self.events.recv().await
    }

    pub fn try_recv(&mut self) -> Result<EtRuntimeEvent, tokio_mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    pub fn into_parts(self) -> (EtSessionId, tokio_mpsc::Receiver<EtRuntimeEvent>) {
        (self.session_id, self.events)
    }
}

impl fmt::Debug for EtRuntimeSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtRuntimeSession")
            .field("session_id", &self.session_id)
            .field("queued_events", &self.events.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct EtSessionManager {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    sessions: Mutex<HashMap<EtSessionId, SessionEntry>>,
    backend: Arc<dyn PtyBackend>,
}

#[derive(Clone)]
struct SessionEntry {
    inputs: SyncSender<InputCommand>,
    input_budget: Arc<InputBudget>,
    stop: Arc<AtomicU8>,
    window_size: Arc<Mutex<EtWindowSize>>,
    pending_resize: Arc<Mutex<Option<EtWindowSize>>>,
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

trait PtyBackend: Send + Sync {
    fn spawn(&self, spec: &EtLaunchSpec) -> Result<SpawnedPty, EtRuntimeError>;
}

trait ProcessControl: Send {
    fn resize(&mut self, size: EtWindowSize) -> io::Result<()>;
}

trait ProcessChild: Send {
    fn process_id(&self) -> Option<u32>;
    fn kill(&mut self) -> io::Result<()>;
    fn try_wait(&mut self) -> io::Result<Option<ProcessExit>>;
}

#[derive(Clone, Copy)]
struct ProcessExit {
    exit_code: Option<u32>,
    signaled: bool,
}

struct SpawnedPty {
    control: Box<dyn ProcessControl>,
    child: Box<dyn ProcessChild>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

#[derive(Debug, Default)]
struct NativePtyBackend;

struct NativeControl(Box<dyn MasterPty + Send>);

impl ProcessControl for NativeControl {
    fn resize(&mut self, size: EtWindowSize) -> io::Result<()> {
        self.0
            .resize(to_native_size(size))
            .map_err(|_| io::Error::other("native PTY resize failed"))
    }
}

struct NativeChild(Box<dyn Child + Send + Sync>);

impl ProcessChild for NativeChild {
    fn process_id(&self) -> Option<u32> {
        self.0.process_id()
    }

    fn kill(&mut self) -> io::Result<()> {
        self.0.kill()
    }

    fn try_wait(&mut self) -> io::Result<Option<ProcessExit>> {
        self.0.try_wait().map(|status| {
            status.map(|status| ProcessExit {
                exit_code: Some(status.exit_code()),
                signaled: status.signal().is_some(),
            })
        })
    }
}

impl PtyBackend for NativePtyBackend {
    fn spawn(&self, spec: &EtLaunchSpec) -> Result<SpawnedPty, EtRuntimeError> {
        let pair = native_pty_system()
            .openpty(to_native_size(spec.window_size()))
            .map_err(|_| EtRuntimeError::BackendFailed {
                operation: EtIoOperation::Open,
            })?;
        let mut command = CommandBuilder::new(spec.executable());
        command.args(spec.arguments());
        command.cwd(spec.cwd());
        for (name, value) in spec.environment() {
            command.env(name, value);
        }
        let mut child =
            pair.slave
                .spawn_command(command)
                .map_err(|_| EtRuntimeError::BackendFailed {
                    operation: EtIoOperation::Spawn,
                })?;
        drop(pair.slave);
        let reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(_) => {
                terminate_native_child(&mut child);
                return Err(EtRuntimeError::BackendFailed {
                    operation: EtIoOperation::ReaderSetup,
                });
            }
        };
        let writer = match pair.master.take_writer() {
            Ok(writer) => writer,
            Err(_) => {
                terminate_native_child(&mut child);
                return Err(EtRuntimeError::BackendFailed {
                    operation: EtIoOperation::WriterSetup,
                });
            }
        };
        Ok(SpawnedPty {
            control: Box::new(NativeControl(pair.master)),
            child: Box::new(NativeChild(child)),
            reader,
            writer,
        })
    }
}

impl EtSessionManager {
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

    pub fn start(&self, config: EtSessionConfig) -> Result<EtRuntimeSession, EtRuntimeError> {
        let spec = config.into_launch_spec();
        let (input_tx, input_rx) = mpsc::sync_channel(INPUT_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = tokio_mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let input_budget = Arc::new(InputBudget::default());
        let stop = Arc::new(AtomicU8::new(RUNNING));
        let window_size = Arc::new(Mutex::new(spec.window_size()));
        let pending_resize = Arc::new(Mutex::new(None));

        let session_id = loop {
            let candidate = EtSessionId(Uuid::new_v4().to_string());
            let mut sessions = lock(&self.inner.sessions);
            if sessions.contains_key(&candidate) {
                continue;
            }
            sessions.insert(
                candidate.clone(),
                SessionEntry {
                    inputs: input_tx.clone(),
                    input_budget: input_budget.clone(),
                    stop: stop.clone(),
                    window_size: window_size.clone(),
                    pending_resize: pending_resize.clone(),
                },
            );
            break candidate;
        };

        let inner = self.inner.clone();
        let worker_session_id = session_id.clone();
        if thread::Builder::new()
            .name("netcatty-et".to_owned())
            .spawn(move || {
                run_session(
                    inner,
                    worker_session_id,
                    spec,
                    input_rx,
                    event_tx,
                    stop,
                    pending_resize,
                );
            })
            .is_err()
        {
            lock(&self.inner.sessions).remove(&session_id);
            return Err(EtRuntimeError::RuntimeThreadUnavailable);
        }

        Ok(EtRuntimeSession {
            session_id,
            events: event_rx,
        })
    }

    pub fn input(&self, session_id: &EtSessionId, input: &[u8]) -> Result<(), EtRuntimeError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(EtRuntimeError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES,
            });
        }
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        if input.is_empty() {
            return Ok(());
        }
        if !entry.input_budget.reserve(input.len()) {
            return Err(EtRuntimeError::InputQueueFull {
                maximum_bytes: MAX_QUEUED_INPUT_BYTES,
            });
        }
        let command = InputCommand {
            bytes: Zeroizing::new(input.to_vec()),
            budget: entry.input_budget,
        };
        match entry.inputs.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(EtRuntimeError::CommandQueueFull {
                capacity: INPUT_CHANNEL_CAPACITY,
            }),
            Err(TrySendError::Disconnected(_)) => Err(EtRuntimeError::SessionClosing),
        }
    }

    pub fn resize(
        &self,
        session_id: &EtSessionId,
        columns: u32,
        rows: u32,
    ) -> Result<(), EtRuntimeError> {
        let size = EtWindowSize::new(columns, rows)?;
        let entry = self.entry(session_id)?;
        ensure_running(&entry)?;
        *lock(&entry.window_size) = size;
        *lock(&entry.pending_resize) = Some(size);
        Ok(())
    }

    pub fn window_size(&self, session_id: &EtSessionId) -> Result<EtWindowSize, EtRuntimeError> {
        let entry = self.entry(session_id)?;
        Ok(*lock(&entry.window_size))
    }

    pub fn close(&self, session_id: &EtSessionId) -> Result<(), EtRuntimeError> {
        self.request_stop(session_id, CLOSE_REQUESTED)
    }

    pub fn cancel(&self, session_id: &EtSessionId) -> Result<(), EtRuntimeError> {
        self.request_stop(session_id, CANCEL_REQUESTED)
    }

    pub fn contains(&self, session_id: &EtSessionId) -> bool {
        lock(&self.inner.sessions).contains_key(session_id)
    }

    pub fn session_count(&self) -> usize {
        lock(&self.inner.sessions).len()
    }

    fn request_stop(&self, session_id: &EtSessionId, signal: u8) -> Result<(), EtRuntimeError> {
        let entry = self.entry(session_id)?;
        let _ = entry
            .stop
            .compare_exchange(RUNNING, signal, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }

    fn entry(&self, session_id: &EtSessionId) -> Result<SessionEntry, EtRuntimeError> {
        lock(&self.inner.sessions)
            .get(session_id)
            .cloned()
            .ok_or(EtRuntimeError::SessionNotFound)
    }
}

impl Default for EtSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EtSessionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtSessionManager")
            .field("session_count", &self.session_count())
            .finish()
    }
}

fn ensure_running(entry: &SessionEntry) -> Result<(), EtRuntimeError> {
    if entry.stop.load(Ordering::Acquire) == RUNNING {
        Ok(())
    } else {
        Err(EtRuntimeError::SessionClosing)
    }
}

fn send_event(
    sender: &tokio_mpsc::Sender<EtRuntimeEvent>,
    event: EtRuntimeEvent,
    stop: &AtomicU8,
) -> bool {
    if sender.blocking_send(event).is_ok() {
        true
    } else {
        let _ = stop.compare_exchange(
            RUNNING,
            CANCEL_REQUESTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        false
    }
}

fn run_session(
    inner: Arc<RuntimeInner>,
    session_id: EtSessionId,
    spec: EtLaunchSpec,
    inputs: Receiver<InputCommand>,
    events: tokio_mpsc::Sender<EtRuntimeEvent>,
    stop: Arc<AtomicU8>,
    pending_resize: Arc<Mutex<Option<EtWindowSize>>>,
) {
    if !send_event(&events, EtRuntimeEvent::Starting, &stop) {
        finish_session(&inner, &session_id);
        return;
    }
    if stop.load(Ordering::Acquire) != RUNNING {
        send_exit(&events, None, false, requested_reason(&stop), &stop);
        finish_session(&inner, &session_id);
        return;
    }

    let mut spawned = match inner.backend.spawn(&spec) {
        Ok(spawned) => spawned,
        Err(error) => {
            let _ = send_event(&events, EtRuntimeEvent::Error(error), &stop);
            send_exit(&events, None, false, EtCloseReason::StartFailed, &stop);
            finish_session(&inner, &session_id);
            return;
        }
    };
    if !send_event(
        &events,
        EtRuntimeEvent::Started {
            process_id: spawned.child.process_id(),
        },
        &stop,
    ) {
        let _ = spawned.child.kill();
        finish_session(&inner, &session_id);
        return;
    }

    let (reader_outcome_tx, reader_outcome_rx) = mpsc::sync_channel(1);
    let reader_events = events.clone();
    let reader_stop = stop.clone();
    let mut reader = spawned.reader;
    if thread::Builder::new()
        .name("netcatty-et-reader".to_owned())
        .spawn(move || read_output(&mut reader, &reader_events, &reader_stop, reader_outcome_tx))
        .is_err()
    {
        let _ = spawned.child.kill();
        let _ = send_event(
            &events,
            EtRuntimeEvent::Error(EtRuntimeError::RuntimeThreadUnavailable),
            &stop,
        );
        send_exit(&events, None, false, EtCloseReason::StartFailed, &stop);
        finish_session(&inner, &session_id);
        return;
    }

    let mut close_started = None;
    let mut terminal_error = None;
    let mut reader_finished = false;
    let mut resize_error_reported = false;
    let status = loop {
        let requested = stop.load(Ordering::Acquire);
        if requested != RUNNING && close_started.is_none() {
            close_started = Some(Instant::now());
            if let Err(error) = spawned.child.kill() {
                terminal_error = Some(io_error(EtIoOperation::Terminate, &error));
            }
        }

        if let Some(size) = lock(&pending_resize).take()
            && spawned.control.resize(size).is_err()
            && !resize_error_reported
        {
            resize_error_reported = true;
            let _ = send_event(
                &events,
                EtRuntimeEvent::Error(EtRuntimeError::BackendFailed {
                    operation: EtIoOperation::Resize,
                }),
                &stop,
            );
        }

        for _ in 0..INPUT_CHANNEL_CAPACITY {
            match inputs.try_recv() {
                Ok(command) => {
                    if terminal_error.is_none()
                        && let Err(error) = spawned.writer.write_all(&command.bytes)
                    {
                        terminal_error = Some(io_error(EtIoOperation::Write, &error));
                    }
                    if terminal_error.is_none()
                        && let Err(error) = spawned.writer.flush()
                    {
                        terminal_error = Some(io_error(EtIoOperation::Flush, &error));
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
                    terminal_error = Some(EtRuntimeError::IoFailed {
                        operation: EtIoOperation::Read,
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
                terminal_error = Some(io_error(EtIoOperation::Wait, &error));
                break None;
            }
        }
        if close_started.is_some_and(|started| started.elapsed() >= TERMINATION_TIMEOUT) {
            terminal_error = Some(EtRuntimeError::IoFailed {
                operation: EtIoOperation::Wait,
                kind: EtIoErrorKind::TimedOut,
            });
            break None;
        }
        thread::sleep(CONTROL_POLL_INTERVAL);
    };

    drop(spawned.writer);
    drop(spawned.control);
    if !reader_finished {
        match reader_outcome_rx.recv_timeout(FINAL_OUTPUT_DRAIN_TIMEOUT) {
            Ok(ReaderOutcome::Eof) => {}
            Ok(ReaderOutcome::Error(kind)) => {
                terminal_error.get_or_insert(EtRuntimeError::IoFailed {
                    operation: EtIoOperation::Read,
                    kind,
                });
            }
            Err(_) => {
                terminal_error.get_or_insert(EtRuntimeError::FinalOutputDrainTimedOut {
                    timeout: FINAL_OUTPUT_DRAIN_TIMEOUT,
                });
            }
        }
    }

    if let Some(error) = terminal_error.as_ref() {
        let _ = send_event(&events, EtRuntimeEvent::Error(error.clone()), &stop);
    }
    let requested = stop.load(Ordering::Acquire);
    let reason = if requested != RUNNING {
        requested_reason(&stop)
    } else if terminal_error.is_some() {
        EtCloseReason::IoError
    } else {
        EtCloseReason::Exited
    };
    send_exit(
        &events,
        status.map(|status| status.exit_code).flatten(),
        status.is_some_and(|status| status.signaled),
        reason,
        &stop,
    );
    finish_session(&inner, &session_id);
}

fn read_output(
    reader: &mut (dyn Read + Send),
    events: &tokio_mpsc::Sender<EtRuntimeEvent>,
    stop: &AtomicU8,
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
                if !send_event(
                    events,
                    EtRuntimeEvent::Data(EtBytes::new(buffer[..length].to_vec())),
                    stop,
                ) {
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
    Error(EtIoErrorKind),
}

fn send_exit(
    events: &tokio_mpsc::Sender<EtRuntimeEvent>,
    exit_code: Option<u32>,
    signaled: bool,
    reason: EtCloseReason,
    stop: &AtomicU8,
) {
    let _ = send_event(
        events,
        EtRuntimeEvent::Exited(EtExit {
            exit_code,
            signaled,
            reason,
        }),
        stop,
    );
}

fn requested_reason(stop: &AtomicU8) -> EtCloseReason {
    match stop.load(Ordering::Acquire) {
        CANCEL_REQUESTED => EtCloseReason::Cancelled,
        _ => EtCloseReason::Requested,
    }
}

fn finish_session(inner: &RuntimeInner, session_id: &EtSessionId) {
    lock(&inner.sessions).remove(session_id);
}

fn to_native_size(size: EtWindowSize) -> PtySize {
    PtySize {
        rows: size.rows(),
        cols: size.columns(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn terminate_native_child(child: &mut Box<dyn Child + Send + Sync>) {
    let _ = child.kill();
    let _ = child.wait();
}

fn io_error(operation: EtIoOperation, error: &io::Error) -> EtRuntimeError {
    EtRuntimeError::IoFailed {
        operation,
        kind: map_io_kind(error.kind()),
    }
}

fn map_io_kind(kind: io::ErrorKind) -> EtIoErrorKind {
    match kind {
        io::ErrorKind::NotFound => EtIoErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => EtIoErrorKind::AccessDenied,
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => EtIoErrorKind::BrokenPipe,
        io::ErrorKind::Interrupted => EtIoErrorKind::Interrupted,
        io::ErrorKind::TimedOut => EtIoErrorKind::TimedOut,
        _ => EtIoErrorKind::Other,
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
    use crate::{
        EtArchitecture, EtClientResolver, EtEndpoint, EtNativeEnvironment, EtPlatform,
        EtStartRequest, EtTarget, NativePath,
    };
    use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
    use tokio::time::{Duration as TokioDuration, timeout};

    struct FakeBackend {
        killed: Arc<AtomicBool>,
        written: Arc<Mutex<Vec<u8>>>,
        resized: Arc<Mutex<Vec<EtWindowSize>>>,
    }

    struct FakeControl(Arc<Mutex<Vec<EtWindowSize>>>);

    impl ProcessControl for FakeControl {
        fn resize(&mut self, size: EtWindowSize) -> io::Result<()> {
            lock(&self.0).push(size);
            Ok(())
        }
    }

    struct FakeChild(Arc<AtomicBool>);

    impl ProcessChild for FakeChild {
        fn process_id(&self) -> Option<u32> {
            Some(42)
        }

        fn kill(&mut self) -> io::Result<()> {
            self.0.store(true, Ordering::Release);
            Ok(())
        }

        fn try_wait(&mut self) -> io::Result<Option<ProcessExit>> {
            Ok(self.0.load(Ordering::Acquire).then_some(ProcessExit {
                exit_code: Some(0),
                signaled: false,
            }))
        }
    }

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            lock(&self.0).extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PtyBackend for FakeBackend {
        fn spawn(&self, _spec: &EtLaunchSpec) -> Result<SpawnedPty, EtRuntimeError> {
            Ok(SpawnedPty {
                control: Box::new(FakeControl(self.resized.clone())),
                child: Box::new(FakeChild(self.killed.clone())),
                reader: Box::new(io::empty()),
                writer: Box::new(SharedWriter(self.written.clone())),
            })
        }
    }

    fn config() -> (EtSessionConfig, PathBuf) {
        let root = std::env::temp_dir().join(format!("netcatty-et-runtime-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("et")).unwrap();
        let platform = EtPlatform::current().unwrap();
        let client_path = root.join("et").join(if platform == EtPlatform::Windows {
            "et.exe"
        } else {
            "et"
        });
        fs::write(&client_path, b"test").unwrap();
        #[cfg(unix)]
        if platform != EtPlatform::Windows {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&client_path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let client = EtClientResolver::new(root.clone())
            .resolve_for(platform, EtArchitecture::X86_64)
            .unwrap();
        let target = EtTarget::new(
            "host-1".into(),
            EtEndpoint::new("target".into(), "alice".into(), 22, 2022).unwrap(),
            vec![],
        )
        .unwrap();
        let config = EtSessionConfig::resolve(
            EtStartRequest::new("host-1".into(), 80, 24),
            target,
            client,
            NativePath::existing_directory(root.clone()).unwrap(),
            vec![],
            EtNativeEnvironment::new(),
            None,
        )
        .unwrap();
        (config, root)
    }

    #[test]
    fn session_ids_require_canonical_uuid_text() {
        let value = Uuid::new_v4().to_string();
        assert_eq!(EtSessionId::parse(&value).unwrap().as_str(), value);
        assert_eq!(
            EtSessionId::parse(&value.to_ascii_uppercase()),
            Err(EtRuntimeError::InvalidSessionId)
        );
    }

    #[test]
    fn byte_and_error_debug_are_redacted() {
        let bytes = EtBytes::new(b"password-secret-sentinel".to_vec());
        let error = EtRuntimeError::BackendFailed {
            operation: EtIoOperation::Spawn,
        };
        let rendered = format!("{bytes:?} {error:?}");
        assert!(!rendered.contains("password-secret"));
        assert!(!rendered.contains("Users\\"));
    }

    #[test]
    fn input_budget_is_strictly_byte_bounded() {
        let budget = InputBudget::default();
        assert!(budget.reserve(MAX_QUEUED_INPUT_BYTES));
        assert!(!budget.reserve(1));
        budget.release(MAX_QUEUED_INPUT_BYTES);
        assert!(budget.reserve(1));
    }

    #[tokio::test]
    async fn manager_writes_resizes_and_closes_one_exact_session() {
        let killed = Arc::new(AtomicBool::new(false));
        let written = Arc::new(Mutex::new(Vec::new()));
        let resized = Arc::new(Mutex::new(Vec::new()));
        let manager = EtSessionManager::with_backend(Arc::new(FakeBackend {
            killed: killed.clone(),
            written: written.clone(),
            resized: resized.clone(),
        }));
        let (config, root) = config();
        let mut session = manager.start(config).unwrap();
        let id = session.session_id().clone();

        assert!(matches!(
            session.recv().await,
            Some(EtRuntimeEvent::Starting)
        ));
        assert!(matches!(
            session.recv().await,
            Some(EtRuntimeEvent::Started {
                process_id: Some(42)
            })
        ));
        manager.input(&id, b"echo bounded\r").unwrap();
        manager.resize(&id, 132, 40).unwrap();
        manager.close(&id).unwrap();

        let exit = timeout(TokioDuration::from_secs(2), async {
            loop {
                if let Some(EtRuntimeEvent::Exited(exit)) = session.recv().await {
                    break exit;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(exit.reason(), EtCloseReason::Requested);
        assert!(killed.load(Ordering::Acquire));
        assert_eq!(&*lock(&written), b"echo bounded\r");
        assert_eq!(&*lock(&resized), &[EtWindowSize::new(132, 40).unwrap()]);
        assert!(!manager.contains(&id));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_input_is_rejected_before_session_lookup() {
        let manager = EtSessionManager::new();
        let id = EtSessionId(Uuid::new_v4().to_string());
        assert_eq!(
            manager.input(&id, &vec![0; MAX_INPUT_BYTES + 1]),
            Err(EtRuntimeError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES
            })
        );
    }
}
