use std::{collections::VecDeque, error::Error, fmt};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    MoshClientLaunch, MoshConfigError, MoshConnect, MoshConnectSniffer, MoshParserError,
    MoshSessionConfig, MoshWindowSize,
};

pub const MAX_INPUT_FRAME_BYTES: usize = 64 * 1_024;
pub const MAX_QUEUED_INPUT_BYTES: usize = 512 * 1_024;
pub const MAX_PENDING_INPUT_FRAMES: usize = 64;
pub const MAX_CLIENT_OUTPUT_CHUNK_BYTES: usize = 256 * 1_024;
pub const MAX_QUEUED_OUTPUT_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_ACTION_QUEUE_ENTRIES: usize = 128;
pub const MAX_EVENT_QUEUE_ENTRIES: usize = 256;

#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MoshSessionId(String);

impl MoshSessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, MoshError> {
        let parsed = Uuid::parse_str(value).map_err(|_| MoshError::InvalidSessionId)?;
        if parsed.to_string() != value {
            return Err(MoshError::InvalidSessionId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MoshSessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MoshSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MoshBytes(Vec<u8>);

impl MoshBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

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

impl fmt::Debug for MoshBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{} terminal bytes redacted]", self.0.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MoshPhase {
    SshHandshake,
    WaitingForHandshakeExit,
    ClientStarting,
    Running,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoshIoTarget {
    SshHandshake,
    MoshClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoshCloseReason {
    Exited,
    Requested,
    Cancelled,
    StartFailed,
    ProtocolError,
    ClientError,
    BackendError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoshExit {
    exit_code: Option<i32>,
    signaled: bool,
    reason: MoshCloseReason,
}

impl MoshExit {
    pub const fn exit_code(self) -> Option<i32> {
        self.exit_code
    }

    pub const fn signaled(self) -> bool {
        self.signaled
    }

    pub const fn reason(self) -> MoshCloseReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoshBackendOperation {
    StartSshHandshake,
    Write,
    Resize,
    StartClient,
    Terminate,
    Wait,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MoshError {
    InvalidSessionId,
    InvalidConfiguration(MoshConfigError),
    Parser(MoshParserError),
    InvalidTransition,
    SessionNotReady,
    SessionClosing,
    SessionClosed,
    InputTooLarge { maximum_bytes: usize },
    InputQueueFull { maximum_bytes: usize },
    TooManyPendingInputs { maximum_entries: usize },
    ActionQueueFull { maximum_entries: usize },
    EventQueueFull { maximum_entries: usize },
    OutputTooLarge { maximum_bytes: usize },
    OutputQueueFull { maximum_bytes: usize },
    MissingConnect,
    ClientStartFailed,
    BackendFailed { operation: MoshBackendOperation },
}

impl fmt::Display for MoshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSessionId => formatter.write_str("The Mosh session ID is invalid"),
            Self::InvalidConfiguration(error) => fmt::Display::fmt(error, formatter),
            Self::Parser(error) => fmt::Display::fmt(error, formatter),
            Self::InvalidTransition => {
                formatter.write_str("The Mosh session transition is invalid")
            }
            Self::SessionNotReady => formatter.write_str("The Mosh session is not ready for input"),
            Self::SessionClosing => formatter.write_str("The Mosh session is closing"),
            Self::SessionClosed => formatter.write_str("The Mosh session is closed"),
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "Mosh input exceeds {maximum_bytes} bytes")
            }
            Self::InputQueueFull { maximum_bytes } => {
                write!(formatter, "Mosh queued input exceeds {maximum_bytes} bytes")
            }
            Self::TooManyPendingInputs { maximum_entries } => write!(
                formatter,
                "Mosh pending input exceeds {maximum_entries} frames"
            ),
            Self::ActionQueueFull { maximum_entries } => write!(
                formatter,
                "Mosh native action queue exceeds {maximum_entries} entries"
            ),
            Self::EventQueueFull { maximum_entries } => write!(
                formatter,
                "Mosh event queue exceeds {maximum_entries} entries"
            ),
            Self::OutputTooLarge { maximum_bytes } => {
                write!(formatter, "Mosh output chunk exceeds {maximum_bytes} bytes")
            }
            Self::OutputQueueFull { maximum_bytes } => write!(
                formatter,
                "Mosh queued output exceeds {maximum_bytes} bytes"
            ),
            Self::MissingConnect => {
                formatter.write_str("Mosh SSH startup ended without a valid MOSH CONNECT marker")
            }
            Self::ClientStartFailed => {
                formatter.write_str("The bundled Mosh client could not be started")
            }
            Self::BackendFailed { operation } => {
                write!(
                    formatter,
                    "The native Mosh backend failed during {operation:?}"
                )
            }
        }
    }
}

impl fmt::Debug for MoshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for MoshError {}

impl From<MoshConfigError> for MoshError {
    fn from(value: MoshConfigError) -> Self {
        Self::InvalidConfiguration(value)
    }
}

impl From<MoshParserError> for MoshError {
    fn from(value: MoshParserError) -> Self {
        Self::Parser(value)
    }
}

pub enum MoshAction {
    StartClient(MoshClientLaunch),
    Write {
        target: MoshIoTarget,
        bytes: MoshBytes,
    },
    Resize {
        target: MoshIoTarget,
        size: MoshWindowSize,
    },
    Terminate {
        target: MoshIoTarget,
        reason: MoshCloseReason,
    },
}

impl fmt::Debug for MoshAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartClient(launch) => {
                formatter.debug_tuple("StartClient").field(launch).finish()
            }
            Self::Write { target, bytes } => formatter
                .debug_struct("Write")
                .field("target", target)
                .field("bytes", bytes)
                .finish(),
            Self::Resize { target, size } => formatter
                .debug_struct("Resize")
                .field("target", target)
                .field("size", size)
                .finish(),
            Self::Terminate { target, reason } => formatter
                .debug_struct("Terminate")
                .field("target", target)
                .field("reason", reason)
                .finish(),
        }
    }
}

pub enum MoshEvent {
    PhaseChanged(MoshPhase),
    Output(MoshBytes),
    HandshakeAccepted { port: u16, has_host_override: bool },
    Ready,
    Error(MoshError),
    Exited(MoshExit),
}

impl fmt::Debug for MoshEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PhaseChanged(phase) => {
                formatter.debug_tuple("PhaseChanged").field(phase).finish()
            }
            Self::Output(bytes) => formatter.debug_tuple("Output").field(bytes).finish(),
            Self::HandshakeAccepted {
                port,
                has_host_override,
            } => formatter
                .debug_struct("HandshakeAccepted")
                .field("port", port)
                .field("has_host_override", has_host_override)
                .finish(),
            Self::Ready => formatter.write_str("Ready"),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::Exited(exit) => formatter.debug_tuple("Exited").field(exit).finish(),
        }
    }
}

pub struct MoshSessionCore {
    session_id: MoshSessionId,
    config: Option<MoshSessionConfig>,
    phase: MoshPhase,
    sniffer: MoshConnectSniffer,
    connect: Option<MoshConnect>,
    actions: VecDeque<MoshAction>,
    events: VecDeque<MoshEvent>,
    deferred_client_input: VecDeque<MoshBytes>,
    queued_input_bytes: usize,
    queued_output_bytes: usize,
    window_size: MoshWindowSize,
    requested_close: Option<MoshCloseReason>,
}

impl MoshSessionCore {
    pub fn new(config: MoshSessionConfig) -> Self {
        let window_size = config.window_size();
        let mut events = VecDeque::new();
        events.push_back(MoshEvent::PhaseChanged(MoshPhase::SshHandshake));
        Self {
            session_id: MoshSessionId::new(),
            config: Some(config),
            phase: MoshPhase::SshHandshake,
            sniffer: MoshConnectSniffer::new(),
            connect: None,
            actions: VecDeque::new(),
            events,
            deferred_client_input: VecDeque::new(),
            queued_input_bytes: 0,
            queued_output_bytes: 0,
            window_size,
            requested_close: None,
        }
    }

    pub fn session_id(&self) -> &MoshSessionId {
        &self.session_id
    }

    pub const fn phase(&self) -> MoshPhase {
        self.phase
    }

    pub const fn window_size(&self) -> MoshWindowSize {
        self.window_size
    }

    pub fn queued_input_bytes(&self) -> usize {
        self.queued_input_bytes
    }

    pub fn queued_output_bytes(&self) -> usize {
        self.queued_output_bytes
    }

    pub fn pop_action(&mut self) -> Option<MoshAction> {
        let action = self.actions.pop_front()?;
        if let MoshAction::Write { bytes, .. } = &action {
            self.queued_input_bytes = self.queued_input_bytes.saturating_sub(bytes.len());
        }
        Some(action)
    }

    pub fn pop_event(&mut self) -> Option<MoshEvent> {
        let event = self.events.pop_front()?;
        if let MoshEvent::Output(bytes) = &event {
            self.queued_output_bytes = self.queued_output_bytes.saturating_sub(bytes.len());
        }
        Some(event)
    }

    pub fn on_handshake_output(&mut self, chunk: &[u8]) -> Result<(), MoshError> {
        match self.phase {
            MoshPhase::SshHandshake => {}
            MoshPhase::WaitingForHandshakeExit => {
                // Once the secret-bearing marker was accepted, discard any
                // late SSH bytes until exit rather than risk a duplicate marker.
                return Ok(());
            }
            MoshPhase::Closing => return Err(MoshError::SessionClosing),
            MoshPhase::Closed => return Err(MoshError::SessionClosed),
            _ => return Err(MoshError::InvalidTransition),
        }

        let mut sniffed = match self.sniffer.feed(chunk) {
            Ok(sniffed) => sniffed,
            Err(error) => {
                let error = MoshError::Parser(error);
                self.fail_closed(error.clone(), MoshCloseReason::ProtocolError);
                return Err(error);
            }
        };
        if !sniffed.visible().is_empty()
            && let Err(error) = self.queue_output(sniffed.visible().to_vec())
        {
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        }
        if let Some(connect) = sniffed.take_connect() {
            let port = connect.port();
            let has_host_override = connect.announced_host().is_some();
            if let Err(error) = self.ensure_event_capacity(2) {
                self.fail_closed(error.clone(), MoshCloseReason::BackendError);
                return Err(error);
            }
            self.connect = Some(connect);
            self.phase = MoshPhase::WaitingForHandshakeExit;
            self.events.push_back(MoshEvent::HandshakeAccepted {
                port,
                has_host_override,
            });
            self.events.push_back(MoshEvent::PhaseChanged(self.phase));
        }
        Ok(())
    }

    pub fn on_handshake_exit(
        &mut self,
        exit_code: Option<i32>,
        signaled: bool,
    ) -> Result<(), MoshError> {
        if self.phase == MoshPhase::Closing {
            self.finish_closed(exit_code, signaled, self.requested_reason());
            return Ok(());
        }
        if self.phase == MoshPhase::Closed {
            return Err(MoshError::SessionClosed);
        }
        if !matches!(
            self.phase,
            MoshPhase::SshHandshake | MoshPhase::WaitingForHandshakeExit
        ) {
            return Err(MoshError::InvalidTransition);
        }

        if self.connect.is_none() {
            let mut sniffed = match self.sniffer.finish() {
                Ok(sniffed) => sniffed,
                Err(error) => {
                    let error = MoshError::Parser(error);
                    self.fail_closed(error.clone(), MoshCloseReason::ProtocolError);
                    return Err(error);
                }
            };
            if !sniffed.visible().is_empty()
                && let Err(error) = self.queue_output(sniffed.visible().to_vec())
            {
                self.fail_closed(error.clone(), MoshCloseReason::BackendError);
                return Err(error);
            }
            self.connect = sniffed.take_connect();
        }

        let Some(connect) = self.connect.take() else {
            let error = MoshError::MissingConnect;
            self.fail_closed(error.clone(), MoshCloseReason::StartFailed);
            return Err(error);
        };
        let Some(config) = self.config.take() else {
            let error = MoshError::InvalidTransition;
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        };
        if self.actions.len() >= MAX_ACTION_QUEUE_ENTRIES {
            let error = MoshError::ActionQueueFull {
                maximum_entries: MAX_ACTION_QUEUE_ENTRIES,
            };
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        }
        let launch = config.launch(connect);
        self.actions.push_back(MoshAction::StartClient(launch));
        self.phase = MoshPhase::ClientStarting;
        self.push_critical_event(MoshEvent::PhaseChanged(self.phase));
        Ok(())
    }

    pub fn on_client_started(&mut self) -> Result<(), MoshError> {
        if self.phase == MoshPhase::Closing {
            return Err(MoshError::SessionClosing);
        }
        if self.phase == MoshPhase::Closed {
            return Err(MoshError::SessionClosed);
        }
        if self.phase != MoshPhase::ClientStarting {
            return Err(MoshError::InvalidTransition);
        }
        let required_actions = 1usize.saturating_add(self.deferred_client_input.len());
        if self.actions.len().saturating_add(required_actions) > MAX_ACTION_QUEUE_ENTRIES {
            let error = MoshError::ActionQueueFull {
                maximum_entries: MAX_ACTION_QUEUE_ENTRIES,
            };
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        }
        self.remove_resize(MoshIoTarget::MoshClient);
        self.actions.push_back(MoshAction::Resize {
            target: MoshIoTarget::MoshClient,
            size: self.window_size,
        });
        while let Some(bytes) = self.deferred_client_input.pop_front() {
            self.actions.push_back(MoshAction::Write {
                target: MoshIoTarget::MoshClient,
                bytes,
            });
        }
        self.phase = MoshPhase::Running;
        self.push_critical_event(MoshEvent::PhaseChanged(self.phase));
        self.push_critical_event(MoshEvent::Ready);
        Ok(())
    }

    pub fn on_client_spawn_failed(&mut self) -> Result<(), MoshError> {
        if self.phase != MoshPhase::ClientStarting {
            return Err(if self.phase == MoshPhase::Closed {
                MoshError::SessionClosed
            } else if self.phase == MoshPhase::Closing {
                MoshError::SessionClosing
            } else {
                MoshError::InvalidTransition
            });
        }
        let error = MoshError::ClientStartFailed;
        self.fail_closed(error.clone(), MoshCloseReason::StartFailed);
        Err(error)
    }

    pub fn on_client_output(&mut self, chunk: &[u8]) -> Result<(), MoshError> {
        if chunk.len() > MAX_CLIENT_OUTPUT_CHUNK_BYTES {
            let error = MoshError::OutputTooLarge {
                maximum_bytes: MAX_CLIENT_OUTPUT_CHUNK_BYTES,
            };
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        }
        if self.phase != MoshPhase::Running && self.phase != MoshPhase::Closing {
            return Err(if self.phase == MoshPhase::Closed {
                MoshError::SessionClosed
            } else {
                MoshError::InvalidTransition
            });
        }
        if chunk.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.queue_output(chunk.to_vec()) {
            self.fail_closed(error.clone(), MoshCloseReason::BackendError);
            return Err(error);
        }
        Ok(())
    }

    pub fn on_client_exit(
        &mut self,
        exit_code: Option<i32>,
        signaled: bool,
    ) -> Result<(), MoshError> {
        if self.phase == MoshPhase::Closed {
            return Err(MoshError::SessionClosed);
        }
        if !matches!(
            self.phase,
            MoshPhase::Running | MoshPhase::ClientStarting | MoshPhase::Closing
        ) {
            return Err(MoshError::InvalidTransition);
        }
        let reason = if self.phase == MoshPhase::Closing {
            self.requested_reason()
        } else if exit_code.is_some_and(|code| code != 0) || signaled {
            MoshCloseReason::ClientError
        } else {
            MoshCloseReason::Exited
        };
        self.finish_closed(exit_code, signaled, reason);
        Ok(())
    }

    pub fn input(&mut self, bytes: &[u8]) -> Result<(), MoshError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.len() > MAX_INPUT_FRAME_BYTES {
            return Err(MoshError::InputTooLarge {
                maximum_bytes: MAX_INPUT_FRAME_BYTES,
            });
        }
        if self.queued_input_bytes.saturating_add(bytes.len()) > MAX_QUEUED_INPUT_BYTES {
            return Err(MoshError::InputQueueFull {
                maximum_bytes: MAX_QUEUED_INPUT_BYTES,
            });
        }
        if self.input_frame_count() >= MAX_PENDING_INPUT_FRAMES {
            return Err(MoshError::TooManyPendingInputs {
                maximum_entries: MAX_PENDING_INPUT_FRAMES,
            });
        }

        let bytes = MoshBytes::new(bytes.to_vec());
        match self.phase {
            MoshPhase::SshHandshake => {
                self.push_action(MoshAction::Write {
                    target: MoshIoTarget::SshHandshake,
                    bytes,
                })?;
                self.queued_input_bytes += bytes_len_of_last(&self.actions);
            }
            MoshPhase::WaitingForHandshakeExit => return Err(MoshError::SessionNotReady),
            MoshPhase::ClientStarting => {
                self.queued_input_bytes += bytes.len();
                self.deferred_client_input.push_back(bytes);
            }
            MoshPhase::Running => {
                self.push_action(MoshAction::Write {
                    target: MoshIoTarget::MoshClient,
                    bytes,
                })?;
                self.queued_input_bytes += bytes_len_of_last(&self.actions);
            }
            MoshPhase::Closing => return Err(MoshError::SessionClosing),
            MoshPhase::Closed => return Err(MoshError::SessionClosed),
        }
        Ok(())
    }

    pub fn resize(&mut self, columns: u32, rows: u32) -> Result<(), MoshError> {
        let size = MoshWindowSize::new(columns, rows)?;
        match self.phase {
            MoshPhase::SshHandshake => {
                self.window_size = size;
                self.queue_resize(MoshIoTarget::SshHandshake, size)
            }
            MoshPhase::WaitingForHandshakeExit | MoshPhase::ClientStarting => {
                self.window_size = size;
                Ok(())
            }
            MoshPhase::Running => {
                self.window_size = size;
                self.queue_resize(MoshIoTarget::MoshClient, size)
            }
            MoshPhase::Closing => Err(MoshError::SessionClosing),
            MoshPhase::Closed => Err(MoshError::SessionClosed),
        }
    }

    pub fn close(&mut self) -> Result<(), MoshError> {
        self.request_close(MoshCloseReason::Requested)
    }

    pub fn cancel(&mut self) -> Result<(), MoshError> {
        self.request_close(MoshCloseReason::Cancelled)
    }

    pub fn backend_failed(&mut self, operation: MoshBackendOperation) -> MoshError {
        let error = MoshError::BackendFailed { operation };
        self.fail_closed(error.clone(), MoshCloseReason::BackendError);
        error
    }

    fn queue_output(&mut self, bytes: Vec<u8>) -> Result<(), MoshError> {
        if bytes.len() > MAX_CLIENT_OUTPUT_CHUNK_BYTES {
            return Err(MoshError::OutputTooLarge {
                maximum_bytes: MAX_CLIENT_OUTPUT_CHUNK_BYTES,
            });
        }
        if self.queued_output_bytes.saturating_add(bytes.len()) > MAX_QUEUED_OUTPUT_BYTES {
            return Err(MoshError::OutputQueueFull {
                maximum_bytes: MAX_QUEUED_OUTPUT_BYTES,
            });
        }
        self.ensure_event_capacity(1)?;
        self.queued_output_bytes += bytes.len();
        self.events
            .push_back(MoshEvent::Output(MoshBytes::new(bytes)));
        Ok(())
    }

    fn ensure_event_capacity(&self, additional: usize) -> Result<(), MoshError> {
        if self.events.len().saturating_add(additional) > MAX_EVENT_QUEUE_ENTRIES {
            return Err(MoshError::EventQueueFull {
                maximum_entries: MAX_EVENT_QUEUE_ENTRIES,
            });
        }
        Ok(())
    }

    fn push_action(&mut self, action: MoshAction) -> Result<(), MoshError> {
        if self.actions.len() >= MAX_ACTION_QUEUE_ENTRIES {
            return Err(MoshError::ActionQueueFull {
                maximum_entries: MAX_ACTION_QUEUE_ENTRIES,
            });
        }
        self.actions.push_back(action);
        Ok(())
    }

    fn queue_resize(
        &mut self,
        target: MoshIoTarget,
        size: MoshWindowSize,
    ) -> Result<(), MoshError> {
        self.remove_resize(target);
        self.push_action(MoshAction::Resize { target, size })
    }

    fn remove_resize(&mut self, target: MoshIoTarget) {
        self.actions.retain(
            |action| !matches!(action, MoshAction::Resize { target: queued, .. } if *queued == target),
        );
    }

    fn input_frame_count(&self) -> usize {
        self.deferred_client_input.len()
            + self
                .actions
                .iter()
                .filter(|action| matches!(action, MoshAction::Write { .. }))
                .count()
    }

    fn request_close(&mut self, reason: MoshCloseReason) -> Result<(), MoshError> {
        if self.phase == MoshPhase::Closed {
            return Err(MoshError::SessionClosed);
        }
        if self.phase == MoshPhase::Closing {
            return Ok(());
        }
        let target = match self.phase {
            MoshPhase::SshHandshake | MoshPhase::WaitingForHandshakeExit => {
                MoshIoTarget::SshHandshake
            }
            MoshPhase::ClientStarting | MoshPhase::Running => MoshIoTarget::MoshClient,
            MoshPhase::Closing => return Ok(()),
            MoshPhase::Closed => return Err(MoshError::SessionClosed),
        };
        self.actions.clear();
        self.deferred_client_input.clear();
        self.queued_input_bytes = 0;
        self.connect = None;
        self.config = None;
        self.requested_close = Some(reason);
        self.phase = MoshPhase::Closing;
        self.actions
            .push_back(MoshAction::Terminate { target, reason });
        self.push_critical_event(MoshEvent::PhaseChanged(self.phase));
        Ok(())
    }

    fn requested_reason(&self) -> MoshCloseReason {
        self.requested_close.unwrap_or(MoshCloseReason::Requested)
    }

    fn fail_closed(&mut self, error: MoshError, reason: MoshCloseReason) {
        self.actions.clear();
        self.deferred_client_input.clear();
        self.queued_input_bytes = 0;
        self.connect = None;
        self.config = None;
        self.phase = MoshPhase::Closed;
        self.make_critical_event_room(3);
        self.events.push_back(MoshEvent::Error(error));
        self.events.push_back(MoshEvent::PhaseChanged(self.phase));
        self.events.push_back(MoshEvent::Exited(MoshExit {
            exit_code: None,
            signaled: false,
            reason,
        }));
    }

    fn finish_closed(&mut self, exit_code: Option<i32>, signaled: bool, reason: MoshCloseReason) {
        self.actions.clear();
        self.deferred_client_input.clear();
        self.queued_input_bytes = 0;
        self.connect = None;
        self.config = None;
        self.phase = MoshPhase::Closed;
        self.make_critical_event_room(2);
        self.events.push_back(MoshEvent::PhaseChanged(self.phase));
        self.events.push_back(MoshEvent::Exited(MoshExit {
            exit_code,
            signaled,
            reason,
        }));
    }

    fn push_critical_event(&mut self, event: MoshEvent) {
        self.make_critical_event_room(1);
        self.events.push_back(event);
    }

    fn make_critical_event_room(&mut self, needed: usize) {
        while self.events.len().saturating_add(needed) > MAX_EVENT_QUEUE_ENTRIES {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            if let MoshEvent::Output(bytes) = event {
                self.queued_output_bytes = self.queued_output_bytes.saturating_sub(bytes.len());
            }
        }
    }
}

impl fmt::Debug for MoshSessionCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshSessionCore")
            .field("session_id", &self.session_id)
            .field("phase", &self.phase)
            .field("has_config", &self.config.is_some())
            .field("has_connect_secret", &self.connect.is_some())
            .field("queued_actions", &self.actions.len())
            .field("queued_events", &self.events.len())
            .field("queued_input_bytes", &self.queued_input_bytes)
            .field("queued_output_bytes", &self.queued_output_bytes)
            .field("window_size", &self.window_size)
            .finish()
    }
}

fn bytes_len_of_last(actions: &VecDeque<MoshAction>) -> usize {
    match actions.back() {
        Some(MoshAction::Write { bytes, .. }) => bytes.len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{MoshStartRequest, TrustedMoshClient};

    const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUV==";

    fn config() -> MoshSessionConfig {
        let path = if cfg!(windows) {
            PathBuf::from(r"D:\Netcatty\resources\mosh-client.exe")
        } else {
            PathBuf::from("/opt/netcatty/resources/mosh-client")
        };
        MoshSessionConfig::resolve(
            TrustedMoshClient::from_native_path(path).unwrap(),
            MoshStartRequest::new("origin.example".to_owned(), 80, 24),
        )
        .unwrap()
    }

    fn start_client(core: &mut MoshSessionCore, with_ip: bool) -> MoshClientLaunch {
        let marker = if with_ip {
            format!("MOSH IP 203.0.113.8\r\nMOSH CONNECT 60002 {KEY}\r\n")
        } else {
            format!("MOSH CONNECT 60002 {KEY}\r\n")
        };
        core.on_handshake_output(marker.as_bytes()).unwrap();
        core.on_handshake_exit(Some(0), false).unwrap();
        loop {
            match core.pop_action().expect("start action") {
                MoshAction::StartClient(launch) => return launch,
                _ => continue,
            }
        }
    }

    fn take_exit(core: &mut MoshSessionCore) -> MoshExit {
        while let Some(event) = core.pop_event() {
            if let MoshEvent::Exited(exit) = event {
                return exit;
            }
        }
        panic!("missing exit event")
    }

    #[test]
    fn session_ids_are_native_canonical_uuids() {
        let id = MoshSessionId::new();
        assert_eq!(MoshSessionId::parse(id.as_str()).unwrap(), id);
        assert_eq!(
            MoshSessionId::parse(&id.as_str().to_ascii_uppercase()),
            Err(MoshError::InvalidSessionId)
        );
    }

    #[test]
    fn handshake_redacts_marker_and_authorizes_one_trusted_launch() {
        let mut core = MoshSessionCore::new(config());
        core.on_handshake_output(b"login banner\r\n").unwrap();
        let launch = start_client(&mut core, true);
        assert_eq!(core.phase(), MoshPhase::ClientStarting);
        assert_eq!(launch.host(), "203.0.113.8");
        assert_eq!(launch.fallback_host(), Some("origin.example"));
        assert_eq!(launch.port(), 60002);
        let parts = launch.into_parts();
        assert_eq!(parts.key.expose_secret(), KEY);

        let mut visible = Vec::new();
        while let Some(event) = core.pop_event() {
            if let MoshEvent::Output(bytes) = event {
                visible.extend_from_slice(bytes.as_slice());
            }
        }
        assert!(visible.windows(12).all(|window| window != b"MOSH CONNECT"));
        assert!(
            visible
                .windows(KEY.len())
                .all(|window| window != KEY.as_bytes())
        );
    }

    #[test]
    fn handshake_eof_without_marker_fails_closed() {
        let mut core = MoshSessionCore::new(config());
        core.on_handshake_output(b"remote command failed\r\n")
            .unwrap();
        assert_eq!(
            core.on_handshake_exit(Some(127), false),
            Err(MoshError::MissingConnect)
        );
        assert_eq!(core.phase(), MoshPhase::Closed);
        assert_eq!(take_exit(&mut core).reason(), MoshCloseReason::StartFailed);
    }

    #[test]
    fn invalid_protocol_fails_closed_without_secret_debug() {
        let mut core = MoshSessionCore::new(config());
        let sentinel = "SUPERSECRETABCDEFGHIJKLMNOP";
        let result =
            core.on_handshake_output(format!("MOSH CONNECT 99999 {sentinel}\r\n").as_bytes());
        assert_eq!(
            result,
            Err(MoshError::Parser(MoshParserError::InvalidConnectLine))
        );
        assert_eq!(core.phase(), MoshPhase::Closed);
        assert!(!format!("{core:?}").contains(sentinel));
    }

    #[test]
    fn input_routes_to_the_active_process_and_defers_during_client_start() {
        let mut core = MoshSessionCore::new(config());
        core.input(b"ssh-password\r").unwrap();
        match core.pop_action().unwrap() {
            MoshAction::Write { target, bytes } => {
                assert_eq!(target, MoshIoTarget::SshHandshake);
                assert_eq!(bytes.as_slice(), b"ssh-password\r");
            }
            other => panic!("unexpected action: {other:?}"),
        }

        let _launch = start_client(&mut core, false);
        core.input(b"deferred-key").unwrap();
        assert_eq!(core.queued_input_bytes(), b"deferred-key".len());
        core.on_client_started().unwrap();
        let actions: Vec<_> = std::iter::from_fn(|| core.pop_action()).collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            MoshAction::Write { target: MoshIoTarget::MoshClient, bytes }
                if bytes.as_slice() == b"deferred-key"
        )));
        assert_eq!(core.queued_input_bytes(), 0);
    }

    #[test]
    fn resize_is_coalesced_and_reapplied_after_handoff() {
        let mut core = MoshSessionCore::new(config());
        core.resize(100, 30).unwrap();
        core.resize(120, 40).unwrap();
        let actions: Vec<_> = std::iter::from_fn(|| core.pop_action()).collect();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            MoshAction::Resize {
                target: MoshIoTarget::SshHandshake,
                size
            } if size == MoshWindowSize::new(120, 40).unwrap()
        ));

        let _launch = start_client(&mut core, false);
        core.resize(140, 50).unwrap();
        core.on_client_started().unwrap();
        assert!(
            std::iter::from_fn(|| core.pop_action()).any(|action| matches!(
                action,
                MoshAction::Resize {
                    target: MoshIoTarget::MoshClient,
                    size
                } if size == MoshWindowSize::new(140, 50).unwrap()
            ))
        );
    }

    #[test]
    fn input_frames_and_aggregate_queue_are_bounded() {
        let mut core = MoshSessionCore::new(config());
        assert_eq!(
            core.input(&vec![0; MAX_INPUT_FRAME_BYTES + 1]),
            Err(MoshError::InputTooLarge {
                maximum_bytes: MAX_INPUT_FRAME_BYTES
            })
        );
        for _ in 0..MAX_PENDING_INPUT_FRAMES {
            core.input(b"x").unwrap();
        }
        assert_eq!(
            core.input(b"x"),
            Err(MoshError::TooManyPendingInputs {
                maximum_entries: MAX_PENDING_INPUT_FRAMES
            })
        );
        while core.pop_action().is_some() {}
        assert_eq!(core.queued_input_bytes(), 0);

        for _ in 0..(MAX_QUEUED_INPUT_BYTES / MAX_INPUT_FRAME_BYTES) {
            core.input(&vec![0; MAX_INPUT_FRAME_BYTES]).unwrap();
        }
        assert_eq!(
            core.input(b"x"),
            Err(MoshError::InputQueueFull {
                maximum_bytes: MAX_QUEUED_INPUT_BYTES
            })
        );
    }

    #[test]
    fn close_and_cancel_are_distinct_and_drop_pending_launch_authority() {
        for (cancel, expected) in [
            (false, MoshCloseReason::Requested),
            (true, MoshCloseReason::Cancelled),
        ] {
            let mut core = MoshSessionCore::new(config());
            let _launch = start_client(&mut core, false);
            core.input(b"queued").unwrap();
            if cancel {
                core.cancel().unwrap();
            } else {
                core.close().unwrap();
            }
            assert_eq!(core.queued_input_bytes(), 0);
            assert!(matches!(
                core.pop_action(),
                Some(MoshAction::Terminate {
                    target: MoshIoTarget::MoshClient,
                    reason
                }) if reason == expected
            ));
            core.on_client_exit(None, true).unwrap();
            assert_eq!(take_exit(&mut core).reason(), expected);
        }
    }

    #[test]
    fn client_ready_output_and_exit_lifecycle_is_explicit() {
        let mut core = MoshSessionCore::new(config());
        let _launch = start_client(&mut core, false);
        core.on_client_started().unwrap();
        assert_eq!(core.phase(), MoshPhase::Running);
        core.on_client_output(b"terminal-data").unwrap();
        core.on_client_exit(Some(1), false).unwrap();
        assert_eq!(core.phase(), MoshPhase::Closed);
        assert_eq!(take_exit(&mut core).reason(), MoshCloseReason::ClientError);
    }

    #[test]
    fn client_spawn_failure_is_redacted_and_terminal() {
        let mut core = MoshSessionCore::new(config());
        let _launch = start_client(&mut core, false);
        assert_eq!(
            core.on_client_spawn_failed(),
            Err(MoshError::ClientStartFailed)
        );
        assert_eq!(core.phase(), MoshPhase::Closed);
        assert_eq!(take_exit(&mut core).reason(), MoshCloseReason::StartFailed);
    }

    #[test]
    fn output_memory_is_bounded_and_terminal_bytes_are_redacted() {
        let mut core = MoshSessionCore::new(config());
        let _launch = start_client(&mut core, false);
        core.on_client_started().unwrap();
        while core.pop_event().is_some() {}

        let frame = vec![b'x'; MAX_CLIENT_OUTPUT_CHUNK_BYTES];
        for _ in 0..(MAX_QUEUED_OUTPUT_BYTES / MAX_CLIENT_OUTPUT_CHUNK_BYTES) {
            core.on_client_output(&frame).unwrap();
        }
        let error = core.on_client_output(b"overflow").unwrap_err();
        assert_eq!(
            error,
            MoshError::OutputQueueFull {
                maximum_bytes: MAX_QUEUED_OUTPUT_BYTES
            }
        );
        assert_eq!(core.phase(), MoshPhase::Closed);
        let debug = format!("{:?}", MoshBytes::new(b"password-sentinel".to_vec()));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn errors_never_echo_backend_paths_hosts_or_secrets() {
        let values = [
            MoshError::MissingConnect,
            MoshError::ClientStartFailed,
            MoshError::BackendFailed {
                operation: MoshBackendOperation::StartClient,
            },
        ];
        for value in values {
            let rendered = format!("{value:?}");
            assert!(!rendered.contains("origin.example"));
            assert!(!rendered.contains("mosh-client.exe"));
            assert!(!rendered.contains(KEY));
        }
    }
}
