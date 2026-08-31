use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::SerialSessionId;

pub const YMODEM_SOH: u8 = 0x01;
pub const YMODEM_STX: u8 = 0x02;
pub const YMODEM_EOT: u8 = 0x04;
pub const YMODEM_ACK: u8 = 0x06;
pub const YMODEM_BACKSPACE: u8 = 0x08;
pub const YMODEM_NAK: u8 = 0x15;
pub const YMODEM_CAN: u8 = 0x18;
pub const YMODEM_CRC16: u8 = 0x43;
pub const YMODEM_PACKET_SIZE_128: usize = 128;
pub const YMODEM_PACKET_SIZE_1024: usize = 1024;
pub const DEFAULT_YMODEM_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_YMODEM_RETRY_LIMIT: u32 = 10;
pub const MAX_YMODEM_RETRY_LIMIT: u32 = 100;
pub const MAX_YMODEM_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_YMODEM_FILENAME_BYTES: usize = 255;
/// JavaScript's largest exactly representable integer, matching the reliable
/// size boundary of the legacy implementation while keeping all I/O streamed.
pub const MAX_YMODEM_FILE_BYTES: u64 = (1_u64 << 53) - 1;
pub const YMODEM_CANCEL_SEQUENCE: [u8; 10] = [
    YMODEM_CAN,
    YMODEM_CAN,
    YMODEM_CAN,
    YMODEM_CAN,
    YMODEM_CAN,
    YMODEM_BACKSPACE,
    YMODEM_BACKSPACE,
    YMODEM_BACKSPACE,
    YMODEM_BACKSPACE,
    YMODEM_BACKSPACE,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YmodemPacketSize {
    Bytes128,
    Bytes1024,
}

impl YmodemPacketSize {
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::Bytes128 => YMODEM_PACKET_SIZE_128,
            Self::Bytes1024 => YMODEM_PACKET_SIZE_1024,
        }
    }

    const fn header(self) -> u8 {
        match self {
            Self::Bytes128 => YMODEM_SOH,
            Self::Bytes1024 => YMODEM_STX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YmodemConfig {
    timeout: Duration,
    retry_limit: u32,
}

impl YmodemConfig {
    pub fn new(timeout: Duration, retry_limit: u32) -> Result<Self, YmodemError> {
        if timeout.is_zero() {
            return Err(YmodemError::InvalidTimeout);
        }
        if retry_limit == 0 || retry_limit > MAX_YMODEM_RETRY_LIMIT {
            return Err(YmodemError::InvalidRetryLimit {
                maximum: MAX_YMODEM_RETRY_LIMIT,
            });
        }
        Ok(Self {
            timeout,
            retry_limit,
        })
    }

    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    pub const fn retry_limit(self) -> u32 {
        self.retry_limit
    }
}

impl Default for YmodemConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_YMODEM_TIMEOUT,
            retry_limit: DEFAULT_YMODEM_RETRY_LIMIT,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum YmodemError {
    InvalidTimeout,
    InvalidRetryLimit { maximum: u32 },
    InputTooLarge { maximum_bytes: usize },
    FilenameTooLong { maximum_bytes: usize },
    MetadataTooLarge { maximum_bytes: usize },
    FileTooLarge { maximum_bytes: u64 },
    InvalidFileSize,
    InvalidPacketPayload { expected: usize, actual: usize },
    InvalidSourceChunk { expected: usize, actual: usize },
    SourceLengthMismatch,
    IncompleteFile,
    UnexpectedByte { byte: u8 },
    UnexpectedFrame,
    EndOfFileExpected,
    RetryLimit,
    TimedOut,
    Cancelled,
    RemoteCancelled,
    TransferBusy,
    InvalidState,
}

impl YmodemError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTimeout => "YMODEM_INVALID_TIMEOUT",
            Self::InvalidRetryLimit { .. } => "YMODEM_INVALID_RETRY_LIMIT",
            Self::InputTooLarge { .. } => "YMODEM_INPUT_TOO_LARGE",
            Self::FilenameTooLong { .. } => "YMODEM_FILENAME_TOO_LONG",
            Self::MetadataTooLarge { .. } => "YMODEM_METADATA_TOO_LARGE",
            Self::FileTooLarge { .. } => "YMODEM_FILE_TOO_LARGE",
            Self::InvalidFileSize => "YMODEM_INVALID_SIZE",
            Self::InvalidPacketPayload { .. } => "YMODEM_INVALID_PACKET",
            Self::InvalidSourceChunk { .. } | Self::SourceLengthMismatch => {
                "YMODEM_SOURCE_LENGTH_MISMATCH"
            }
            Self::IncompleteFile => "YMODEM_INCOMPLETE_FILE",
            Self::UnexpectedByte { .. } | Self::UnexpectedFrame => "YMODEM_TRANSFER_ERROR",
            Self::EndOfFileExpected => "YMODEM_EOT_EXPECTED",
            Self::RetryLimit => "YMODEM_RETRY_LIMIT",
            Self::TimedOut => "YMODEM_TIMEOUT",
            Self::Cancelled => "YMODEM_CANCELLED",
            Self::RemoteCancelled => "YMODEM_REMOTE_CANCELLED",
            Self::TransferBusy => "YMODEM_TRANSFER_BUSY",
            Self::InvalidState => "YMODEM_INVALID_STATE",
        }
    }
}

impl fmt::Debug for YmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for YmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => formatter.write_str("YMODEM timeout must be positive"),
            Self::InvalidRetryLimit { maximum } => {
                write!(
                    formatter,
                    "YMODEM retry limit must be between 1 and {maximum}"
                )
            }
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "YMODEM input exceeds {maximum_bytes} bytes")
            }
            Self::FilenameTooLong { maximum_bytes } => {
                write!(formatter, "YMODEM file name exceeds {maximum_bytes} bytes")
            }
            Self::MetadataTooLarge { maximum_bytes } => {
                write!(formatter, "YMODEM metadata exceeds {maximum_bytes} bytes")
            }
            Self::FileTooLarge { maximum_bytes } => {
                write!(formatter, "YMODEM file exceeds {maximum_bytes} bytes")
            }
            Self::InvalidFileSize => formatter.write_str("YMODEM file header has an invalid size"),
            Self::InvalidPacketPayload { expected, actual } => write!(
                formatter,
                "YMODEM packet payload length is invalid (expected {expected}, got {actual})"
            ),
            Self::InvalidSourceChunk { expected, actual } => write!(
                formatter,
                "YMODEM source chunk length is invalid (expected {expected}, got {actual})"
            ),
            Self::SourceLengthMismatch => {
                formatter.write_str("YMODEM source length does not match its metadata")
            }
            Self::IncompleteFile => formatter.write_str("YMODEM received an incomplete file"),
            Self::UnexpectedByte { byte } => {
                write!(formatter, "Unexpected YMODEM control byte: 0x{byte:02x}")
            }
            Self::UnexpectedFrame => formatter.write_str("Unexpected YMODEM frame"),
            Self::EndOfFileExpected => {
                formatter.write_str("YMODEM sender did not confirm end of file")
            }
            Self::RetryLimit => formatter.write_str("YMODEM retry limit reached"),
            Self::TimedOut => formatter.write_str("Timed out waiting for YMODEM peer"),
            Self::Cancelled => formatter.write_str("YMODEM transfer cancelled"),
            Self::RemoteCancelled => {
                formatter.write_str("YMODEM transfer cancelled by the remote peer")
            }
            Self::TransferBusy => {
                formatter.write_str("Another serial file transfer is already in progress")
            }
            Self::InvalidState => formatter.write_str("YMODEM state transition is invalid"),
        }
    }
}

impl Error for YmodemError {}

#[derive(Clone, Eq, PartialEq)]
pub struct YmodemBytes(Vec<u8>);

impl YmodemBytes {
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

impl From<Vec<u8>> for YmodemBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for YmodemBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemBytes")
            .field("length", &self.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct YmodemFileMetadata {
    file_name: String,
    total_bytes: u64,
    modified_time: u64,
    mode: u32,
}

impl YmodemFileMetadata {
    pub fn new(
        file_name: impl AsRef<str>,
        total_bytes: u64,
        modified_time: u64,
        mode: u32,
    ) -> Result<Self, YmodemError> {
        if total_bytes > MAX_YMODEM_FILE_BYTES {
            return Err(YmodemError::FileTooLarge {
                maximum_bytes: MAX_YMODEM_FILE_BYTES,
            });
        }
        Ok(Self {
            file_name: sanitize_ymodem_filename(file_name.as_ref())?,
            total_bytes,
            modified_time,
            mode,
        })
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub const fn modified_time(&self) -> u64 {
        self.modified_time
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

impl fmt::Debug for YmodemFileMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemFileMetadata")
            .field("file_name_bytes", &self.file_name.len())
            .field("total_bytes", &self.total_bytes)
            .field("modified_time", &self.modified_time)
            .field("mode", &format_args!("{:#o}", self.mode))
            .finish()
    }
}

pub fn sanitize_ymodem_filename(value: &str) -> Result<String, YmodemError> {
    let normalized = value.replace('\\', "/");
    let base_name = normalized.rsplit('/').next().unwrap_or("");
    let sanitized: String = base_name
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    let sanitized = if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "ymodem-received.bin".to_owned()
    } else {
        sanitized
    };
    if sanitized.len() > MAX_YMODEM_FILENAME_BYTES {
        return Err(YmodemError::FilenameTooLong {
            maximum_bytes: MAX_YMODEM_FILENAME_BYTES,
        });
    }
    Ok(sanitized)
}

pub fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in bytes {
        let mut code = ((crc >> 8) as u8) ^ byte;
        code ^= code >> 4;
        crc = (crc << 8) ^ ((code as u16) << 12) ^ ((code as u16) << 5) ^ code as u16;
    }
    crc
}

pub fn encode_ymodem_packet(
    packet_size: YmodemPacketSize,
    block_number: u8,
    payload: &[u8],
) -> Result<YmodemBytes, YmodemError> {
    let expected = packet_size.payload_bytes();
    if payload.len() != expected {
        return Err(YmodemError::InvalidPacketPayload {
            expected,
            actual: payload.len(),
        });
    }
    let mut packet = Vec::with_capacity(3 + expected + 2);
    packet.extend_from_slice(&[packet_size.header(), block_number, 0xff - block_number]);
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&crc16_xmodem(payload).to_be_bytes());
    Ok(packet.into())
}

pub fn create_ymodem_file_header(
    metadata: &YmodemFileMetadata,
) -> Result<YmodemBytes, YmodemError> {
    let text = format!(
        "{}\0{} {:o} {:o}",
        metadata.file_name, metadata.total_bytes, metadata.modified_time, metadata.mode
    );
    let bytes = text.as_bytes();
    if bytes.len() > YMODEM_PACKET_SIZE_1024 {
        return Err(YmodemError::MetadataTooLarge {
            maximum_bytes: YMODEM_PACKET_SIZE_1024,
        });
    }
    let packet_size = if bytes.len() >= YMODEM_PACKET_SIZE_128 {
        YmodemPacketSize::Bytes1024
    } else {
        YmodemPacketSize::Bytes128
    };
    let mut payload = vec![0_u8; packet_size.payload_bytes()];
    payload[..bytes.len()].copy_from_slice(bytes);
    encode_ymodem_packet(packet_size, 0, &payload)
}

pub fn create_ymodem_data_packet(
    block_number: u8,
    data: &[u8],
) -> Result<YmodemBytes, YmodemError> {
    if data.len() > YMODEM_PACKET_SIZE_1024 {
        return Err(YmodemError::InvalidPacketPayload {
            expected: YMODEM_PACKET_SIZE_1024,
            actual: data.len(),
        });
    }
    let mut payload = vec![0x1a; YMODEM_PACKET_SIZE_1024];
    payload[..data.len()].copy_from_slice(data);
    encode_ymodem_packet(YmodemPacketSize::Bytes1024, block_number, &payload)
}

pub fn create_ymodem_end_session_packet() -> YmodemBytes {
    encode_ymodem_packet(YmodemPacketSize::Bytes128, 0, &[0; YMODEM_PACKET_SIZE_128])
        .expect("fixed YMODEM end packet has the required payload length")
}

pub fn parse_ymodem_file_header(payload: &[u8]) -> Result<Option<YmodemFileMetadata>, YmodemError> {
    if payload.len() != YMODEM_PACKET_SIZE_128 && payload.len() != YMODEM_PACKET_SIZE_1024 {
        return Err(YmodemError::InvalidPacketPayload {
            expected: YMODEM_PACKET_SIZE_128,
            actual: payload.len(),
        });
    }
    let separator = payload.iter().position(|byte| *byte == 0);
    let raw_name = &payload[..separator.unwrap_or(payload.len())];
    if raw_name.is_empty() {
        return Ok(None);
    }
    let raw_name = String::from_utf8_lossy(raw_name);
    let file_name = sanitize_ymodem_filename(&raw_name)?;
    let metadata = separator
        .map(|index| &payload[index + 1..])
        .unwrap_or_default();
    let metadata_end = metadata
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(metadata.len());
    let metadata = &metadata[..metadata_end];
    let size_end = metadata
        .iter()
        .position(|byte| byte.is_ascii_whitespace())
        .unwrap_or(metadata.len());
    let size_text = &metadata[..size_end];
    if size_text.is_empty() || !size_text.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(YmodemError::InvalidFileSize);
    }
    let size_text = std::str::from_utf8(size_text).map_err(|_| YmodemError::InvalidFileSize)?;
    let total_bytes = size_text
        .parse::<u64>()
        .map_err(|_| YmodemError::InvalidFileSize)?;
    if total_bytes > MAX_YMODEM_FILE_BYTES {
        return Err(YmodemError::FileTooLarge {
            maximum_bytes: MAX_YMODEM_FILE_BYTES,
        });
    }
    Ok(Some(YmodemFileMetadata {
        file_name,
        total_bytes,
        modified_time: 0,
        mode: 0,
    }))
}

#[derive(Clone, Eq, PartialEq)]
pub enum YmodemWireEvent {
    Control(u8),
    Packet {
        block_number: u8,
        payload: YmodemBytes,
        valid: bool,
    },
    EndOfFile,
    RemoteCancel,
    Unexpected(u8),
}

impl fmt::Debug for YmodemWireEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(byte) => formatter.debug_tuple("Control").field(byte).finish(),
            Self::Packet {
                block_number,
                payload,
                valid,
            } => formatter
                .debug_struct("Packet")
                .field("block_number", block_number)
                .field("payload_bytes", &payload.len())
                .field("valid", valid)
                .finish(),
            Self::EndOfFile => formatter.write_str("EndOfFile"),
            Self::RemoteCancel => formatter.write_str("RemoteCancel"),
            Self::Unexpected(byte) => formatter.debug_tuple("Unexpected").field(byte).finish(),
        }
    }
}

#[derive(Default)]
pub struct YmodemWireDecoder {
    packet: Vec<u8>,
    expected_packet_bytes: usize,
    pending_cancel: bool,
}

impl fmt::Debug for YmodemWireDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemWireDecoder")
            .field("buffered_bytes", &self.packet.len())
            .field("expected_packet_bytes", &self.expected_packet_bytes)
            .field("pending_cancel", &self.pending_cancel)
            .finish()
    }
}

impl YmodemWireDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<YmodemWireEvent>, YmodemError> {
        if bytes.len() > MAX_YMODEM_INPUT_BYTES {
            return Err(YmodemError::InputTooLarge {
                maximum_bytes: MAX_YMODEM_INPUT_BYTES,
            });
        }
        let mut events = Vec::new();
        for &byte in bytes {
            if let Some(event) = self.push_byte(byte) {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn reset(&mut self) {
        self.packet.clear();
        self.expected_packet_bytes = 0;
        self.pending_cancel = false;
    }

    pub fn has_partial_frame(&self) -> bool {
        !self.packet.is_empty() || self.pending_cancel
    }

    fn push_byte(&mut self, byte: u8) -> Option<YmodemWireEvent> {
        if self.expected_packet_bytes != 0 {
            self.packet.push(byte);
            if self.packet.len() == self.expected_packet_bytes {
                let block_number = self.packet[1];
                let complement = self.packet[2];
                let payload_end = self.packet.len() - 2;
                let payload = self.packet[3..payload_end].to_vec();
                let sent_crc =
                    u16::from_be_bytes([self.packet[payload_end], self.packet[payload_end + 1]]);
                let valid = complement == 0xff - block_number && sent_crc == crc16_xmodem(&payload);
                let event = YmodemWireEvent::Packet {
                    block_number,
                    payload: payload.into(),
                    valid,
                };
                self.packet.clear();
                self.expected_packet_bytes = 0;
                return Some(event);
            }
            return None;
        }

        if self.pending_cancel {
            self.pending_cancel = false;
            if byte == YMODEM_CAN {
                return Some(YmodemWireEvent::RemoteCancel);
            }
        }

        match byte {
            YMODEM_CAN => {
                self.pending_cancel = true;
                None
            }
            YMODEM_SOH => {
                self.begin_packet(byte, YMODEM_PACKET_SIZE_128);
                None
            }
            YMODEM_STX => {
                self.begin_packet(byte, YMODEM_PACKET_SIZE_1024);
                None
            }
            YMODEM_EOT => Some(YmodemWireEvent::EndOfFile),
            YMODEM_ACK | YMODEM_NAK | YMODEM_CRC16 => Some(YmodemWireEvent::Control(byte)),
            other => Some(YmodemWireEvent::Unexpected(other)),
        }
    }

    fn begin_packet(&mut self, header: u8, payload_bytes: usize) {
        self.packet.clear();
        self.packet.push(header);
        self.expected_packet_bytes = 3 + payload_bytes + 2;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YmodemProgressStage {
    Header,
    Data,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YmodemProgress {
    pub transferred_bytes: u64,
    pub total_bytes: u64,
    pub stage: YmodemProgressStage,
}

#[derive(Clone, Eq, PartialEq)]
pub struct YmodemSendSummary {
    file_name: String,
    pub total_bytes: u64,
    pub written_bytes: u64,
    pub packets_sent: u64,
}

impl YmodemSendSummary {
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

impl fmt::Debug for YmodemSendSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemSendSummary")
            .field("file_name_bytes", &self.file_name.len())
            .field("total_bytes", &self.total_bytes)
            .field("written_bytes", &self.written_bytes)
            .field("packets_sent", &self.packets_sent)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum YmodemSenderAction {
    Write(YmodemBytes),
    ReadSource {
        exact_bytes: usize,
    },
    Progress(YmodemProgress),
    Completed {
        summary: YmodemSendSummary,
        terminal_bytes: YmodemBytes,
    },
    Failed(YmodemError),
}

impl fmt::Debug for YmodemSenderAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(bytes) => formatter.debug_tuple("Write").field(bytes).finish(),
            Self::ReadSource { exact_bytes } => formatter
                .debug_struct("ReadSource")
                .field("exact_bytes", exact_bytes)
                .finish(),
            Self::Progress(progress) => formatter.debug_tuple("Progress").field(progress).finish(),
            Self::Completed {
                summary,
                terminal_bytes,
            } => formatter
                .debug_struct("Completed")
                .field("summary", summary)
                .field("terminal_bytes", &terminal_bytes.len())
                .finish(),
            Self::Failed(error) => formatter.debug_tuple("Failed").field(error).finish(),
        }
    }
}

enum SenderState {
    AwaitInitialRequest,
    AwaitHeaderAck {
        attempts: u32,
    },
    AwaitDataRequest {
        retries: u32,
    },
    AwaitRepeatedHeaderAck {
        attempts: u32,
        request_retries: u32,
    },
    AwaitSource {
        exact_bytes: usize,
    },
    AwaitDataAck {
        packet: YmodemBytes,
        data_bytes: usize,
        attempts: u32,
    },
    AwaitFirstEot {
        attempts: u32,
    },
    AwaitSecondEotAck {
        attempts: u32,
    },
    AwaitEndRequest {
        attempts: u32,
    },
    AwaitEndAck {
        attempts: u32,
    },
    Terminal,
}

pub struct YmodemSender {
    config: YmodemConfig,
    metadata: YmodemFileMetadata,
    header_packet: YmodemBytes,
    decoder: YmodemWireDecoder,
    state: SenderState,
    actions: VecDeque<YmodemSenderAction>,
    transferred_bytes: u64,
    next_block_number: u8,
    packets_sent: u64,
}

impl YmodemSender {
    pub fn new(metadata: YmodemFileMetadata, config: YmodemConfig) -> Result<Self, YmodemError> {
        let header_packet = create_ymodem_file_header(&metadata)?;
        Ok(Self {
            config,
            metadata,
            header_packet,
            decoder: YmodemWireDecoder::default(),
            state: SenderState::AwaitInitialRequest,
            actions: VecDeque::new(),
            transferred_bytes: 0,
            next_block_number: 1,
            packets_sent: 0,
        })
    }

    pub fn next_action(&mut self) -> Option<YmodemSenderAction> {
        self.actions.pop_front()
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self.state {
            SenderState::AwaitInitialRequest
            | SenderState::AwaitHeaderAck { .. }
            | SenderState::AwaitDataRequest { .. }
            | SenderState::AwaitRepeatedHeaderAck { .. }
            | SenderState::AwaitDataAck { .. }
            | SenderState::AwaitFirstEot { .. }
            | SenderState::AwaitSecondEotAck { .. }
            | SenderState::AwaitEndRequest { .. }
            | SenderState::AwaitEndAck { .. } => Some(self.config.timeout),
            SenderState::AwaitSource { .. } | SenderState::Terminal => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, SenderState::Terminal)
    }

    pub fn push_serial_bytes(&mut self, bytes: &[u8]) -> Result<(), YmodemError> {
        if self.is_terminal() {
            return Err(YmodemError::InvalidState);
        }
        if bytes.len() > MAX_YMODEM_INPUT_BYTES {
            return Err(YmodemError::InputTooLarge {
                maximum_bytes: MAX_YMODEM_INPUT_BYTES,
            });
        }
        for (index, &byte) in bytes.iter().enumerate() {
            let Some(event) = self.decoder.push_byte(byte) else {
                continue;
            };
            if self.is_terminal() {
                break;
            }
            self.handle_event(event);
            if self.is_terminal() {
                if let Some(YmodemSenderAction::Completed { terminal_bytes, .. }) =
                    self.actions.back_mut()
                {
                    *terminal_bytes = bytes[index + 1..].to_vec().into();
                }
                break;
            }
        }
        Ok(())
    }

    pub fn provide_source_chunk(&mut self, bytes: &[u8]) -> Result<(), YmodemError> {
        let exact_bytes = match self.state {
            SenderState::AwaitSource { exact_bytes } => exact_bytes,
            _ => return Err(YmodemError::InvalidState),
        };
        if bytes.len() != exact_bytes {
            return Err(YmodemError::InvalidSourceChunk {
                expected: exact_bytes,
                actual: bytes.len(),
            });
        }
        let packet = create_ymodem_data_packet(self.next_block_number, bytes)?;
        self.next_block_number = self.next_block_number.wrapping_add(1);
        self.packets_sent += 1;
        self.actions
            .push_back(YmodemSenderAction::Write(packet.clone()));
        self.state = SenderState::AwaitDataAck {
            packet,
            data_bytes: bytes.len(),
            attempts: 1,
        };
        Ok(())
    }

    pub fn on_timeout(&mut self) -> Result<(), YmodemError> {
        if self.is_terminal() {
            return Err(YmodemError::InvalidState);
        }
        self.decoder.reset();
        match std::mem::replace(&mut self.state, SenderState::Terminal) {
            SenderState::AwaitInitialRequest => self.fail(YmodemError::TimedOut),
            SenderState::AwaitHeaderAck { attempts } => {
                self.retry_header(attempts, SenderRetryTarget::InitialHeader)
            }
            SenderState::AwaitDataRequest { retries } => self.retry_data_request(retries),
            SenderState::AwaitRepeatedHeaderAck {
                attempts,
                request_retries,
            } => self.retry_header(
                attempts,
                SenderRetryTarget::RepeatedHeader { request_retries },
            ),
            SenderState::AwaitDataAck {
                packet,
                data_bytes,
                attempts,
            } => self.retry_data_packet(packet, data_bytes, attempts),
            SenderState::AwaitFirstEot { attempts } => {
                self.retry_control(YMODEM_EOT, attempts, SenderControlTarget::FirstEot)
            }
            SenderState::AwaitSecondEotAck { attempts } => {
                self.retry_control(YMODEM_EOT, attempts, SenderControlTarget::SecondEot)
            }
            SenderState::AwaitEndRequest { attempts } => {
                self.retry_control(YMODEM_EOT, attempts, SenderControlTarget::EndRequest)
            }
            SenderState::AwaitEndAck { attempts } => self.retry_end_packet(attempts),
            SenderState::AwaitSource { exact_bytes } => {
                self.state = SenderState::AwaitSource { exact_bytes };
                return Err(YmodemError::InvalidState);
            }
            SenderState::Terminal => return Err(YmodemError::InvalidState),
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        if !self.is_terminal() {
            self.actions.push_back(YmodemSenderAction::Write(
                YMODEM_CANCEL_SEQUENCE.to_vec().into(),
            ));
            self.fail(YmodemError::Cancelled);
        }
    }

    fn handle_event(&mut self, event: YmodemWireEvent) {
        if matches!(event, YmodemWireEvent::RemoteCancel) {
            self.fail(YmodemError::RemoteCancelled);
            return;
        }
        match std::mem::replace(&mut self.state, SenderState::Terminal) {
            SenderState::AwaitInitialRequest => match event {
                YmodemWireEvent::Control(YMODEM_CRC16) => self.send_header(),
                other => {
                    self.restore_or_fail(SenderState::AwaitInitialRequest, other, &[YMODEM_CRC16])
                }
            },
            SenderState::AwaitHeaderAck { attempts } => match event {
                YmodemWireEvent::Control(YMODEM_ACK) => {
                    self.state = SenderState::AwaitDataRequest { retries: 0 }
                }
                YmodemWireEvent::Control(YMODEM_NAK) => {
                    self.retry_header(attempts, SenderRetryTarget::InitialHeader)
                }
                other => self.restore_or_fail(
                    SenderState::AwaitHeaderAck { attempts },
                    other,
                    &[YMODEM_ACK, YMODEM_NAK],
                ),
            },
            SenderState::AwaitDataRequest { retries } => match event {
                YmodemWireEvent::Control(YMODEM_CRC16) => self.request_next_source_or_eot(),
                YmodemWireEvent::Control(YMODEM_NAK) => self.retry_data_request(retries),
                other => self.restore_or_fail(
                    SenderState::AwaitDataRequest { retries },
                    other,
                    &[YMODEM_CRC16, YMODEM_NAK],
                ),
            },
            SenderState::AwaitRepeatedHeaderAck {
                attempts,
                request_retries,
            } => match event {
                YmodemWireEvent::Control(YMODEM_ACK) => {
                    self.state = SenderState::AwaitDataRequest {
                        retries: request_retries,
                    }
                }
                YmodemWireEvent::Control(YMODEM_NAK) => self.retry_header(
                    attempts,
                    SenderRetryTarget::RepeatedHeader { request_retries },
                ),
                other => self.restore_or_fail(
                    SenderState::AwaitRepeatedHeaderAck {
                        attempts,
                        request_retries,
                    },
                    other,
                    &[YMODEM_ACK, YMODEM_NAK],
                ),
            },
            SenderState::AwaitDataAck {
                packet,
                data_bytes,
                attempts,
            } => match event {
                YmodemWireEvent::Control(YMODEM_ACK) => {
                    self.transferred_bytes += data_bytes as u64;
                    self.actions
                        .push_back(YmodemSenderAction::Progress(YmodemProgress {
                            transferred_bytes: self.transferred_bytes,
                            total_bytes: self.metadata.total_bytes,
                            stage: YmodemProgressStage::Data,
                        }));
                    self.request_next_source_or_eot();
                }
                YmodemWireEvent::Control(YMODEM_NAK) => {
                    self.retry_data_packet(packet, data_bytes, attempts)
                }
                other => self.restore_or_fail(
                    SenderState::AwaitDataAck {
                        packet,
                        data_bytes,
                        attempts,
                    },
                    other,
                    &[YMODEM_ACK, YMODEM_NAK],
                ),
            },
            SenderState::AwaitFirstEot { attempts } => match event {
                YmodemWireEvent::Control(YMODEM_NAK) => {
                    self.actions
                        .push_back(YmodemSenderAction::Write(vec![YMODEM_EOT].into()));
                    self.state = SenderState::AwaitSecondEotAck { attempts: 1 };
                }
                YmodemWireEvent::Control(YMODEM_ACK) => {
                    self.state = SenderState::AwaitEndRequest { attempts: 1 }
                }
                other => self.restore_or_fail(
                    SenderState::AwaitFirstEot { attempts },
                    other,
                    &[YMODEM_NAK, YMODEM_ACK],
                ),
            },
            SenderState::AwaitSecondEotAck { attempts } => match event {
                YmodemWireEvent::Control(YMODEM_ACK) => {
                    self.state = SenderState::AwaitEndRequest { attempts: 1 }
                }
                YmodemWireEvent::Control(YMODEM_NAK) => {
                    self.retry_control(YMODEM_EOT, attempts, SenderControlTarget::SecondEot)
                }
                other => self.restore_or_fail(
                    SenderState::AwaitSecondEotAck { attempts },
                    other,
                    &[YMODEM_ACK],
                ),
            },
            SenderState::AwaitEndRequest { attempts } => match event {
                YmodemWireEvent::Control(YMODEM_CRC16) => self.send_end_packet(),
                other => self.restore_or_fail(
                    SenderState::AwaitEndRequest { attempts },
                    other,
                    &[YMODEM_CRC16],
                ),
            },
            SenderState::AwaitEndAck { attempts } => match event {
                YmodemWireEvent::Control(YMODEM_ACK) => self.complete(),
                YmodemWireEvent::Control(YMODEM_NAK) => self.retry_end_packet(attempts),
                other => self.restore_or_fail(
                    SenderState::AwaitEndAck { attempts },
                    other,
                    &[YMODEM_ACK, YMODEM_NAK],
                ),
            },
            state @ SenderState::AwaitSource { .. } => self.restore_or_fail(state, event, &[]),
            SenderState::Terminal => self.state = SenderState::Terminal,
        }
    }

    fn restore_or_fail(&mut self, state: SenderState, event: YmodemWireEvent, expected: &[u8]) {
        match event {
            YmodemWireEvent::Control(byte)
                if [YMODEM_CRC16, YMODEM_ACK, YMODEM_NAK].contains(&byte)
                    && !expected.contains(&byte) =>
            {
                self.state = state;
            }
            YmodemWireEvent::Unexpected(byte) => self.fail(YmodemError::UnexpectedByte { byte }),
            _ => self.fail(YmodemError::UnexpectedFrame),
        }
    }

    fn send_header(&mut self) {
        self.packets_sent += 1;
        self.actions
            .push_back(YmodemSenderAction::Write(self.header_packet.clone()));
        self.actions
            .push_back(YmodemSenderAction::Progress(YmodemProgress {
                transferred_bytes: 0,
                total_bytes: self.metadata.total_bytes,
                stage: YmodemProgressStage::Header,
            }));
        self.state = SenderState::AwaitHeaderAck { attempts: 1 };
    }

    fn retry_header(&mut self, attempts: u32, target: SenderRetryTarget) {
        if attempts >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
            return;
        }
        self.packets_sent += 1;
        self.actions
            .push_back(YmodemSenderAction::Write(self.header_packet.clone()));
        self.actions
            .push_back(YmodemSenderAction::Progress(YmodemProgress {
                transferred_bytes: 0,
                total_bytes: self.metadata.total_bytes,
                stage: YmodemProgressStage::Header,
            }));
        self.state = match target {
            SenderRetryTarget::InitialHeader => SenderState::AwaitHeaderAck {
                attempts: attempts + 1,
            },
            SenderRetryTarget::RepeatedHeader { request_retries } => {
                SenderState::AwaitRepeatedHeaderAck {
                    attempts: attempts + 1,
                    request_retries,
                }
            }
        };
    }

    fn retry_data_request(&mut self, retries: u32) {
        if retries >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
            return;
        }
        self.packets_sent += 1;
        self.actions
            .push_back(YmodemSenderAction::Write(self.header_packet.clone()));
        self.actions
            .push_back(YmodemSenderAction::Progress(YmodemProgress {
                transferred_bytes: 0,
                total_bytes: self.metadata.total_bytes,
                stage: YmodemProgressStage::Header,
            }));
        self.state = SenderState::AwaitRepeatedHeaderAck {
            attempts: 1,
            request_retries: retries + 1,
        };
    }

    fn request_next_source_or_eot(&mut self) {
        if self.transferred_bytes == self.metadata.total_bytes {
            self.actions
                .push_back(YmodemSenderAction::Write(vec![YMODEM_EOT].into()));
            self.state = SenderState::AwaitFirstEot { attempts: 1 };
        } else if self.transferred_bytes > self.metadata.total_bytes {
            self.fail(YmodemError::SourceLengthMismatch);
        } else {
            let exact_bytes = usize::try_from(
                (self.metadata.total_bytes - self.transferred_bytes)
                    .min(YMODEM_PACKET_SIZE_1024 as u64),
            )
            .expect("bounded YMODEM chunk fits usize");
            self.actions
                .push_back(YmodemSenderAction::ReadSource { exact_bytes });
            self.state = SenderState::AwaitSource { exact_bytes };
        }
    }

    fn retry_data_packet(&mut self, packet: YmodemBytes, data_bytes: usize, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
            return;
        }
        self.packets_sent += 1;
        self.actions
            .push_back(YmodemSenderAction::Write(packet.clone()));
        self.state = SenderState::AwaitDataAck {
            packet,
            data_bytes,
            attempts: attempts + 1,
        };
    }

    fn retry_control(&mut self, byte: u8, attempts: u32, target: SenderControlTarget) {
        if attempts >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
            return;
        }
        self.actions
            .push_back(YmodemSenderAction::Write(vec![byte].into()));
        self.state = match target {
            SenderControlTarget::FirstEot => SenderState::AwaitFirstEot {
                attempts: attempts + 1,
            },
            SenderControlTarget::SecondEot => SenderState::AwaitSecondEotAck {
                attempts: attempts + 1,
            },
            SenderControlTarget::EndRequest => SenderState::AwaitEndRequest {
                attempts: attempts + 1,
            },
        };
    }

    fn send_end_packet(&mut self) {
        self.actions
            .push_back(YmodemSenderAction::Write(create_ymodem_end_session_packet()));
        self.state = SenderState::AwaitEndAck { attempts: 1 };
    }

    fn retry_end_packet(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
            return;
        }
        self.actions
            .push_back(YmodemSenderAction::Write(create_ymodem_end_session_packet()));
        self.state = SenderState::AwaitEndAck {
            attempts: attempts + 1,
        };
    }

    fn complete(&mut self) {
        self.actions
            .push_back(YmodemSenderAction::Progress(YmodemProgress {
                transferred_bytes: self.metadata.total_bytes,
                total_bytes: self.metadata.total_bytes,
                stage: YmodemProgressStage::Complete,
            }));
        self.actions.push_back(YmodemSenderAction::Completed {
            summary: YmodemSendSummary {
                file_name: self.metadata.file_name.clone(),
                total_bytes: self.metadata.total_bytes,
                written_bytes: self.metadata.total_bytes,
                packets_sent: self.packets_sent,
            },
            terminal_bytes: Vec::new().into(),
        });
        self.state = SenderState::Terminal;
    }

    fn fail(&mut self, error: YmodemError) {
        self.actions.push_back(YmodemSenderAction::Failed(error));
        self.state = SenderState::Terminal;
    }
}

impl fmt::Debug for YmodemSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemSender")
            .field("phase", &sender_phase(&self.state))
            .field("total_bytes", &self.metadata.total_bytes)
            .field("transferred_bytes", &self.transferred_bytes)
            .field("queued_actions", &self.actions.len())
            .finish()
    }
}

enum SenderRetryTarget {
    InitialHeader,
    RepeatedHeader { request_retries: u32 },
}

enum SenderControlTarget {
    FirstEot,
    SecondEot,
    EndRequest,
}

fn sender_phase(state: &SenderState) -> &'static str {
    match state {
        SenderState::AwaitInitialRequest => "await-initial-request",
        SenderState::AwaitHeaderAck { .. } => "await-header-ack",
        SenderState::AwaitDataRequest { .. } => "await-data-request",
        SenderState::AwaitRepeatedHeaderAck { .. } => "await-repeated-header-ack",
        SenderState::AwaitSource { .. } => "await-source",
        SenderState::AwaitDataAck { .. } => "await-data-ack",
        SenderState::AwaitFirstEot { .. } => "await-first-eot-response",
        SenderState::AwaitSecondEotAck { .. } => "await-second-eot-ack",
        SenderState::AwaitEndRequest { .. } => "await-end-request",
        SenderState::AwaitEndAck { .. } => "await-end-ack",
        SenderState::Terminal => "terminal",
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct YmodemReceiveFileSummary {
    file_name: String,
    pub total_bytes: u64,
    pub written_bytes: u64,
}

impl YmodemReceiveFileSummary {
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

impl fmt::Debug for YmodemReceiveFileSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemReceiveFileSummary")
            .field("file_name_bytes", &self.file_name.len())
            .field("total_bytes", &self.total_bytes)
            .field("written_bytes", &self.written_bytes)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum YmodemReceiverAction {
    Write(YmodemBytes),
    BeginFile(YmodemFileMetadata),
    WriteFile(YmodemBytes),
    Progress(YmodemProgress),
    FileCompleted(YmodemReceiveFileSummary),
    BatchCompleted {
        file_count: u64,
        total_bytes: u64,
        terminal_bytes: YmodemBytes,
    },
    Failed(YmodemError),
}

impl fmt::Debug for YmodemReceiverAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(bytes) => formatter.debug_tuple("Write").field(bytes).finish(),
            Self::BeginFile(metadata) => {
                formatter.debug_tuple("BeginFile").field(metadata).finish()
            }
            Self::WriteFile(bytes) => formatter.debug_tuple("WriteFile").field(bytes).finish(),
            Self::Progress(progress) => formatter.debug_tuple("Progress").field(progress).finish(),
            Self::FileCompleted(summary) => formatter
                .debug_tuple("FileCompleted")
                .field(summary)
                .finish(),
            Self::BatchCompleted {
                file_count,
                total_bytes,
                terminal_bytes,
            } => formatter
                .debug_struct("BatchCompleted")
                .field("file_count", file_count)
                .field("total_bytes", total_bytes)
                .field("terminal_bytes", &terminal_bytes.len())
                .finish(),
            Self::Failed(error) => formatter.debug_tuple("Failed").field(error).finish(),
        }
    }
}

enum ReceiverState {
    AwaitHeader {
        rejected: u32,
    },
    AwaitFileAcceptance,
    AwaitData {
        expected_block: u8,
        rejected: u32,
    },
    AwaitFileWrite {
        expected_block: u8,
        written_bytes: usize,
    },
    AwaitSecondEot {
        retries: u32,
    },
    Terminal,
}

pub struct YmodemReceiver {
    config: YmodemConfig,
    decoder: YmodemWireDecoder,
    state: ReceiverState,
    actions: VecDeque<YmodemReceiverAction>,
    current_file: Option<YmodemFileMetadata>,
    current_written: u64,
    completed_files: u64,
    completed_bytes: u64,
}

impl YmodemReceiver {
    pub fn new(config: YmodemConfig) -> Self {
        let mut actions = VecDeque::new();
        actions.push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
        Self {
            config,
            decoder: YmodemWireDecoder::default(),
            state: ReceiverState::AwaitHeader { rejected: 0 },
            actions,
            current_file: None,
            current_written: 0,
            completed_files: 0,
            completed_bytes: 0,
        }
    }

    pub fn next_action(&mut self) -> Option<YmodemReceiverAction> {
        self.actions.pop_front()
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self.state {
            ReceiverState::AwaitHeader { .. }
            | ReceiverState::AwaitData { .. }
            | ReceiverState::AwaitSecondEot { .. } => Some(self.config.timeout),
            ReceiverState::AwaitFileAcceptance
            | ReceiverState::AwaitFileWrite { .. }
            | ReceiverState::Terminal => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, ReceiverState::Terminal)
    }

    pub fn push_serial_bytes(&mut self, bytes: &[u8]) -> Result<(), YmodemError> {
        if self.is_terminal() {
            return Err(YmodemError::InvalidState);
        }
        if bytes.len() > MAX_YMODEM_INPUT_BYTES {
            return Err(YmodemError::InputTooLarge {
                maximum_bytes: MAX_YMODEM_INPUT_BYTES,
            });
        }
        for (index, &byte) in bytes.iter().enumerate() {
            let Some(event) = self.decoder.push_byte(byte) else {
                continue;
            };
            if self.is_terminal() {
                break;
            }
            self.handle_event(event);
            if self.is_terminal() {
                if let Some(YmodemReceiverAction::BatchCompleted { terminal_bytes, .. }) =
                    self.actions.back_mut()
                {
                    *terminal_bytes = bytes[index + 1..].to_vec().into();
                }
                break;
            }
        }
        Ok(())
    }

    /// Confirms that the native adapter opened a unique no-overwrite sink for
    /// the preceding `BeginFile` action.
    pub fn accept_file(&mut self) -> Result<(), YmodemError> {
        if !matches!(self.state, ReceiverState::AwaitFileAcceptance) {
            return Err(YmodemError::InvalidState);
        }
        let metadata = self
            .current_file
            .as_ref()
            .ok_or(YmodemError::InvalidState)?;
        self.actions
            .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
        self.actions
            .push_back(YmodemReceiverAction::Progress(YmodemProgress {
                transferred_bytes: 0,
                total_bytes: metadata.total_bytes,
                stage: YmodemProgressStage::Header,
            }));
        self.state = ReceiverState::AwaitData {
            expected_block: 1,
            rejected: 0,
        };
        Ok(())
    }

    /// Confirms that the adapter durably consumed the preceding bounded
    /// `WriteFile` chunk. ACK is deliberately withheld until this call.
    pub fn confirm_file_write(&mut self) -> Result<(), YmodemError> {
        let (expected_block, written_bytes) = match self.state {
            ReceiverState::AwaitFileWrite {
                expected_block,
                written_bytes,
            } => (expected_block, written_bytes),
            _ => return Err(YmodemError::InvalidState),
        };
        self.current_written += written_bytes as u64;
        let total_bytes = self
            .current_file
            .as_ref()
            .ok_or(YmodemError::InvalidState)?
            .total_bytes;
        self.actions
            .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
        self.actions
            .push_back(YmodemReceiverAction::Progress(YmodemProgress {
                transferred_bytes: self.current_written,
                total_bytes,
                stage: YmodemProgressStage::Data,
            }));
        self.state = ReceiverState::AwaitData {
            expected_block: expected_block.wrapping_add(1),
            rejected: 0,
        };
        Ok(())
    }

    pub fn on_timeout(&mut self) -> Result<(), YmodemError> {
        if self.is_terminal() {
            return Err(YmodemError::InvalidState);
        }
        self.decoder.reset();
        match self.state {
            ReceiverState::AwaitHeader { rejected } => {
                let rejected = rejected + 1;
                if rejected >= self.config.retry_limit {
                    self.fail(YmodemError::RetryLimit);
                } else {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
                    self.state = ReceiverState::AwaitHeader { rejected };
                }
            }
            ReceiverState::AwaitData {
                expected_block,
                rejected,
            } => {
                let rejected = rejected + 1;
                if rejected > self.config.retry_limit {
                    self.fail(YmodemError::RetryLimit);
                } else {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_NAK].into()));
                    self.state = ReceiverState::AwaitData {
                        expected_block,
                        rejected,
                    };
                }
            }
            ReceiverState::AwaitSecondEot { retries } => {
                let retries = retries + 1;
                if retries > self.config.retry_limit {
                    self.fail(YmodemError::RetryLimit);
                } else {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_NAK].into()));
                    self.state = ReceiverState::AwaitSecondEot { retries };
                }
            }
            ReceiverState::AwaitFileAcceptance | ReceiverState::AwaitFileWrite { .. } => {
                return Err(YmodemError::InvalidState);
            }
            ReceiverState::Terminal => return Err(YmodemError::InvalidState),
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        if !self.is_terminal() {
            self.actions.push_back(YmodemReceiverAction::Write(
                YMODEM_CANCEL_SEQUENCE.to_vec().into(),
            ));
            self.fail(YmodemError::Cancelled);
        }
    }

    fn handle_event(&mut self, event: YmodemWireEvent) {
        if matches!(event, YmodemWireEvent::RemoteCancel) {
            self.fail(YmodemError::RemoteCancelled);
            return;
        }
        match self.state {
            ReceiverState::AwaitHeader { rejected } => self.handle_header(event, rejected),
            ReceiverState::AwaitData {
                expected_block,
                rejected,
            } => self.handle_data(event, expected_block, rejected),
            ReceiverState::AwaitSecondEot { .. } => match event {
                YmodemWireEvent::EndOfFile => self.finish_current_file(),
                _ => self.fail(YmodemError::EndOfFileExpected),
            },
            ReceiverState::AwaitFileAcceptance | ReceiverState::AwaitFileWrite { .. } => {
                self.fail(YmodemError::UnexpectedFrame)
            }
            ReceiverState::Terminal => {}
        }
    }

    fn handle_header(&mut self, event: YmodemWireEvent, rejected: u32) {
        match event {
            YmodemWireEvent::Packet {
                block_number: 0,
                payload,
                valid: true,
            } => match parse_ymodem_file_header(payload.as_slice()) {
                Ok(Some(metadata)) => {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                    self.actions
                        .push_back(YmodemReceiverAction::BeginFile(metadata.clone()));
                    self.current_file = Some(metadata);
                    self.current_written = 0;
                    self.state = ReceiverState::AwaitFileAcceptance;
                }
                Ok(None) => {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                    self.actions
                        .push_back(YmodemReceiverAction::BatchCompleted {
                            file_count: self.completed_files,
                            total_bytes: self.completed_bytes,
                            terminal_bytes: Vec::new().into(),
                        });
                    self.state = ReceiverState::Terminal;
                }
                Err(error) => self.fail(error),
            },
            YmodemWireEvent::Packet {
                block_number: 255,
                valid: true,
                ..
            } => {
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
            }
            YmodemWireEvent::EndOfFile => {
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
            }
            YmodemWireEvent::Unexpected(byte) => self.fail(YmodemError::UnexpectedByte { byte }),
            YmodemWireEvent::Control(_) => {}
            _ => self.reject_header(rejected),
        }
    }

    fn reject_header(&mut self, rejected: u32) {
        let rejected = rejected + 1;
        if rejected >= self.config.retry_limit {
            self.fail(YmodemError::RetryLimit);
        } else {
            self.actions
                .push_back(YmodemReceiverAction::Write(vec![YMODEM_NAK].into()));
            self.actions
                .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
            self.state = ReceiverState::AwaitHeader { rejected };
        }
    }

    fn handle_data(&mut self, event: YmodemWireEvent, expected_block: u8, rejected: u32) {
        match event {
            YmodemWireEvent::EndOfFile => {
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_NAK].into()));
                self.state = ReceiverState::AwaitSecondEot { retries: 0 };
            }
            YmodemWireEvent::Packet {
                block_number,
                payload,
                valid,
            } if valid && block_number == expected_block => {
                let remaining = self
                    .current_file
                    .as_ref()
                    .map(|file| file.total_bytes.saturating_sub(self.current_written))
                    .unwrap_or(0);
                let written_bytes = usize::try_from(remaining.min(payload.len() as u64))
                    .expect("bounded YMODEM payload fits usize");
                if written_bytes == 0 {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                    self.state = ReceiverState::AwaitData {
                        expected_block: expected_block.wrapping_add(1),
                        rejected: 0,
                    };
                } else {
                    self.actions.push_back(YmodemReceiverAction::WriteFile(
                        payload.as_slice()[..written_bytes].to_vec().into(),
                    ));
                    self.state = ReceiverState::AwaitFileWrite {
                        expected_block,
                        written_bytes,
                    };
                }
            }
            YmodemWireEvent::Packet {
                block_number,
                valid: true,
                ..
            } if block_number == expected_block.wrapping_sub(1) => {
                self.actions
                    .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
                self.state = ReceiverState::AwaitData {
                    expected_block,
                    rejected,
                };
            }
            YmodemWireEvent::Unexpected(byte) => self.fail(YmodemError::UnexpectedByte { byte }),
            YmodemWireEvent::Control(_) => {
                self.state = ReceiverState::AwaitData {
                    expected_block,
                    rejected,
                };
            }
            _ => {
                let rejected = rejected + 1;
                if rejected > self.config.retry_limit {
                    self.fail(YmodemError::RetryLimit);
                } else {
                    self.actions
                        .push_back(YmodemReceiverAction::Write(vec![YMODEM_NAK].into()));
                    self.state = ReceiverState::AwaitData {
                        expected_block,
                        rejected,
                    };
                }
            }
        }
    }

    fn finish_current_file(&mut self) {
        self.actions
            .push_back(YmodemReceiverAction::Write(vec![YMODEM_ACK].into()));
        let Some(metadata) = self.current_file.take() else {
            self.fail(YmodemError::InvalidState);
            return;
        };
        if self.current_written != metadata.total_bytes {
            self.fail(YmodemError::IncompleteFile);
            return;
        }
        self.completed_files += 1;
        self.completed_bytes += self.current_written;
        self.actions.push_back(YmodemReceiverAction::FileCompleted(
            YmodemReceiveFileSummary {
                file_name: metadata.file_name,
                total_bytes: metadata.total_bytes,
                written_bytes: self.current_written,
            },
        ));
        self.actions
            .push_back(YmodemReceiverAction::Write(vec![YMODEM_CRC16].into()));
        self.state = ReceiverState::AwaitHeader { rejected: 0 };
    }

    fn fail(&mut self, error: YmodemError) {
        self.actions.push_back(YmodemReceiverAction::Failed(error));
        self.state = ReceiverState::Terminal;
    }
}

impl fmt::Debug for YmodemReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YmodemReceiver")
            .field("phase", &receiver_phase(&self.state))
            .field("current_written", &self.current_written)
            .field("completed_files", &self.completed_files)
            .field("queued_actions", &self.actions.len())
            .finish()
    }
}

fn receiver_phase(state: &ReceiverState) -> &'static str {
    match state {
        ReceiverState::AwaitHeader { .. } => "await-header",
        ReceiverState::AwaitFileAcceptance => "await-file-acceptance",
        ReceiverState::AwaitData { .. } => "await-data",
        ReceiverState::AwaitFileWrite { .. } => "await-file-write",
        ReceiverState::AwaitSecondEot { .. } => "await-second-eot",
        ReceiverState::Terminal => "terminal",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialTransferKind {
    YmodemSend,
    YmodemReceive,
    Zmodem,
}

#[derive(Clone, Default)]
pub struct SerialTransferRegistry {
    inner: Arc<TransferRegistryInner>,
}

#[derive(Default)]
struct TransferRegistryInner {
    owners: Mutex<HashMap<SerialSessionId, TransferOwner>>,
    next_token: AtomicU64,
}

#[derive(Clone, Copy)]
struct TransferOwner {
    kind: SerialTransferKind,
    token: u64,
}

impl SerialTransferRegistry {
    pub fn try_acquire(
        &self,
        session_id: &SerialSessionId,
        kind: SerialTransferKind,
    ) -> Result<SerialTransferLease, YmodemError> {
        let mut owners = lock_transfer_owners(&self.inner);
        if owners.contains_key(session_id) {
            return Err(YmodemError::TransferBusy);
        }
        let token = self.inner.next_token.fetch_add(1, Ordering::Relaxed);
        owners.insert(session_id.clone(), TransferOwner { kind, token });
        Ok(SerialTransferLease {
            inner: self.inner.clone(),
            session_id: Some(session_id.clone()),
            token,
        })
    }

    pub fn owner(&self, session_id: &SerialSessionId) -> Option<SerialTransferKind> {
        lock_transfer_owners(&self.inner)
            .get(session_id)
            .map(|owner| owner.kind)
    }

    pub fn is_owned(&self, session_id: &SerialSessionId) -> bool {
        self.owner(session_id).is_some()
    }

    pub fn active_count(&self) -> usize {
        lock_transfer_owners(&self.inner).len()
    }
}

impl fmt::Debug for SerialTransferRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialTransferRegistry")
            .field("active_count", &self.active_count())
            .finish()
    }
}

pub struct SerialTransferLease {
    inner: Arc<TransferRegistryInner>,
    session_id: Option<SerialSessionId>,
    token: u64,
}

impl SerialTransferLease {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        let Some(session_id) = self.session_id.take() else {
            return;
        };
        let mut owners = lock_transfer_owners(&self.inner);
        if owners.get(&session_id).map(|owner| owner.token) == Some(self.token) {
            owners.remove(&session_id);
        }
    }
}

impl fmt::Debug for SerialTransferLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialTransferLease")
            .field("active", &self.session_id.is_some())
            .finish()
    }
}

impl Drop for SerialTransferLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

fn lock_transfer_owners(
    inner: &TransferRegistryInner,
) -> MutexGuard<'_, HashMap<SerialSessionId, TransferOwner>> {
    inner
        .owners
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(name: &str, total_bytes: u64) -> YmodemFileMetadata {
        YmodemFileMetadata::new(name, total_bytes, 0o123456, 0o100644).unwrap()
    }

    fn drain_sender(sender: &mut YmodemSender) -> Vec<YmodemSenderAction> {
        std::iter::from_fn(|| sender.next_action()).collect()
    }

    fn drain_receiver(receiver: &mut YmodemReceiver) -> Vec<YmodemReceiverAction> {
        std::iter::from_fn(|| receiver.next_action()).collect()
    }

    fn sender_write(actions: &[YmodemSenderAction]) -> YmodemBytes {
        actions
            .iter()
            .find_map(|action| match action {
                YmodemSenderAction::Write(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("sender write action")
    }

    fn receiver_write(actions: &[YmodemReceiverAction]) -> YmodemBytes {
        actions
            .iter()
            .find_map(|action| match action {
                YmodemReceiverAction::Write(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("receiver write action")
    }

    #[test]
    fn crc_and_both_packet_sizes_match_legacy_vectors() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
        let short = encode_ymodem_packet(YmodemPacketSize::Bytes128, 7, &[0x55; 128]).unwrap();
        assert_eq!(short.len(), 133);
        assert_eq!(&short.as_slice()[..3], &[YMODEM_SOH, 7, 248]);
        assert_eq!(
            &short.as_slice()[131..],
            &crc16_xmodem(&[0x55; 128]).to_be_bytes()
        );
        let long = create_ymodem_data_packet(255, &[1, 2, 3]).unwrap();
        assert_eq!(long.len(), 1029);
        assert_eq!(&long.as_slice()[..3], &[YMODEM_STX, 255, 0]);
        assert_eq!(&long.as_slice()[3..6], &[1, 2, 3]);
        assert!(long.as_slice()[6..1027].iter().all(|byte| *byte == 0x1a));
    }

    #[test]
    fn filename_and_metadata_are_traversal_safe_and_bounded() {
        assert_eq!(
            sanitize_ymodem_filename(r"..\secret:<a>?.bin").unwrap(),
            "secret__a__.bin"
        );
        assert_eq!(
            sanitize_ymodem_filename("../..").unwrap(),
            "ymodem-received.bin"
        );
        assert_eq!(
            sanitize_ymodem_filename(&"x".repeat(MAX_YMODEM_FILENAME_BYTES + 1)),
            Err(YmodemError::FilenameTooLong {
                maximum_bytes: MAX_YMODEM_FILENAME_BYTES
            })
        );
        assert_eq!(
            YmodemFileMetadata::new("safe", MAX_YMODEM_FILE_BYTES + 1, 0, 0),
            Err(YmodemError::FileTooLarge {
                maximum_bytes: MAX_YMODEM_FILE_BYTES
            })
        );

        let info = metadata("folder/private.bin", 1234);
        let packet = create_ymodem_file_header(&info).unwrap();
        assert_eq!(packet.as_slice()[0], YMODEM_SOH);
        let decoded = parse_ymodem_file_header(&packet.as_slice()[3..131])
            .unwrap()
            .unwrap();
        assert_eq!(decoded.file_name(), "private.bin");
        assert_eq!(decoded.total_bytes(), 1234);
        assert!(parse_ymodem_file_header(&[0; 128]).unwrap().is_none());
    }

    #[test]
    fn decoder_is_incremental_checks_crc_and_recognizes_remote_cancel() {
        let packet = create_ymodem_data_packet(3, b"secret").unwrap();
        let mut decoder = YmodemWireDecoder::default();
        assert!(decoder.push(&packet.as_slice()[..5]).unwrap().is_empty());
        assert!(decoder.has_partial_frame());
        let events = decoder.push(&packet.as_slice()[5..]).unwrap();
        assert!(matches!(
            events.as_slice(),
            [YmodemWireEvent::Packet {
                block_number: 3,
                valid: true,
                ..
            }]
        ));

        let mut corrupt = packet.into_vec();
        corrupt[50] ^= 1;
        assert!(matches!(
            decoder.push(&corrupt).unwrap().as_slice(),
            [YmodemWireEvent::Packet { valid: false, .. }]
        ));
        assert!(decoder.push(&[YMODEM_CAN]).unwrap().is_empty());
        assert_eq!(
            decoder.push(&[YMODEM_CAN]).unwrap(),
            vec![YmodemWireEvent::RemoteCancel]
        );
    }

    #[test]
    fn sender_streams_one_packet_at_a_time_and_preserves_coalesced_terminal_prompt() {
        let content = vec![0x5a; 1030];
        let mut sender = YmodemSender::new(
            metadata("private.bin", content.len() as u64),
            YmodemConfig::default(),
        )
        .unwrap();
        sender.push_serial_bytes(&[YMODEM_CRC16]).unwrap();
        let header_actions = drain_sender(&mut sender);
        assert!(matches!(
            header_actions.as_slice(),
            [
                YmodemSenderAction::Write(_),
                YmodemSenderAction::Progress(YmodemProgress {
                    stage: YmodemProgressStage::Header,
                    ..
                })
            ]
        ));
        sender
            .push_serial_bytes(&[YMODEM_ACK, YMODEM_CRC16])
            .unwrap();
        assert_eq!(
            drain_sender(&mut sender),
            vec![YmodemSenderAction::ReadSource { exact_bytes: 1024 }]
        );
        sender.provide_source_chunk(&content[..1024]).unwrap();
        assert_eq!(sender_write(&drain_sender(&mut sender)).len(), 1029);
        sender.push_serial_bytes(&[YMODEM_ACK]).unwrap();
        let actions = drain_sender(&mut sender);
        assert!(actions.contains(&YmodemSenderAction::ReadSource { exact_bytes: 6 }));
        sender.provide_source_chunk(&content[1024..]).unwrap();
        let _ = drain_sender(&mut sender);
        sender.push_serial_bytes(&[YMODEM_ACK]).unwrap();
        assert_eq!(
            receiver_control_from_sender(&drain_sender(&mut sender)),
            YMODEM_EOT
        );
        sender.push_serial_bytes(&[YMODEM_NAK]).unwrap();
        assert_eq!(
            receiver_control_from_sender(&drain_sender(&mut sender)),
            YMODEM_EOT
        );
        sender
            .push_serial_bytes(&[YMODEM_ACK, YMODEM_CRC16])
            .unwrap();
        let end = sender_write(&drain_sender(&mut sender));
        assert_eq!(end.len(), 133);
        let terminal_prompt = b"\r\nreceiver-shell$ ";
        let mut final_ack = vec![YMODEM_ACK];
        final_ack.extend_from_slice(terminal_prompt);
        sender.push_serial_bytes(&final_ack).unwrap();
        let actions = drain_sender(&mut sender);
        assert!(matches!(
            actions.last(),
            Some(YmodemSenderAction::Completed {
                summary,
                terminal_bytes,
            }) if summary.written_bytes == 1030
                && summary.packets_sent == 3
                && terminal_bytes.as_slice() == terminal_prompt
        ));
        assert!(sender.is_terminal());
    }

    fn receiver_control_from_sender(actions: &[YmodemSenderAction]) -> u8 {
        sender_write(actions).as_slice()[0]
    }

    #[test]
    fn sender_retries_nak_timeout_rejects_bad_source_and_honors_cancel() {
        let config = YmodemConfig::new(Duration::from_secs(1), 2).unwrap();
        let mut sender = YmodemSender::new(metadata("secret.bin", 1), config).unwrap();
        sender.push_serial_bytes(&[YMODEM_CRC16]).unwrap();
        let first = sender_write(&drain_sender(&mut sender));
        sender.push_serial_bytes(&[YMODEM_NAK]).unwrap();
        let second = sender_write(&drain_sender(&mut sender));
        assert_eq!(first, second);
        sender.on_timeout().unwrap();
        assert!(matches!(
            drain_sender(&mut sender).last(),
            Some(YmodemSenderAction::Failed(YmodemError::RetryLimit))
        ));

        let mut sender = YmodemSender::new(metadata("secret.bin", 2), config).unwrap();
        sender
            .push_serial_bytes(&[YMODEM_CRC16, YMODEM_ACK, YMODEM_CRC16])
            .unwrap();
        let _ = drain_sender(&mut sender);
        assert_eq!(
            sender.provide_source_chunk(&[1]),
            Err(YmodemError::InvalidSourceChunk {
                expected: 2,
                actual: 1
            })
        );
        sender.cancel();
        let actions = drain_sender(&mut sender);
        assert!(
            matches!(&actions[0], YmodemSenderAction::Write(bytes) if bytes.as_slice() == YMODEM_CANCEL_SEQUENCE)
        );
        assert!(matches!(
            &actions[1],
            YmodemSenderAction::Failed(YmodemError::Cancelled)
        ));
    }

    #[test]
    fn receiver_streams_writes_and_preserves_coalesced_terminal_prompt() {
        let mut receiver = YmodemReceiver::new(YmodemConfig::default());
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_CRC16]
        );
        let header = create_ymodem_file_header(&metadata("../private.bin", 3)).unwrap();
        receiver.push_serial_bytes(header.as_slice()).unwrap();
        let actions = drain_receiver(&mut receiver);
        assert!(
            matches!(&actions[0], YmodemReceiverAction::Write(bytes) if bytes.as_slice() == [YMODEM_ACK])
        );
        assert!(
            matches!(&actions[1], YmodemReceiverAction::BeginFile(info) if info.file_name() == "private.bin")
        );
        receiver.accept_file().unwrap();
        let _ = drain_receiver(&mut receiver);

        let out_of_order = create_ymodem_data_packet(2, b"bad").unwrap();
        receiver.push_serial_bytes(out_of_order.as_slice()).unwrap();
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_NAK]
        );
        let packet = create_ymodem_data_packet(1, b"abc").unwrap();
        receiver.push_serial_bytes(packet.as_slice()).unwrap();
        let actions = drain_receiver(&mut receiver);
        assert!(
            matches!(&actions[0], YmodemReceiverAction::WriteFile(bytes) if bytes.as_slice() == b"abc")
        );
        receiver.confirm_file_write().unwrap();
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_ACK]
        );
        receiver.push_serial_bytes(packet.as_slice()).unwrap();
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_ACK]
        );

        receiver.push_serial_bytes(&[YMODEM_EOT]).unwrap();
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_NAK]
        );
        receiver.push_serial_bytes(&[YMODEM_EOT]).unwrap();
        let actions = drain_receiver(&mut receiver);
        assert!(
            matches!(&actions[0], YmodemReceiverAction::Write(bytes) if bytes.as_slice() == [YMODEM_ACK])
        );
        assert!(actions.iter().any(|action| matches!(action, YmodemReceiverAction::FileCompleted(summary) if summary.written_bytes == 3)));
        assert!(
            matches!(actions.last(), Some(YmodemReceiverAction::Write(bytes)) if bytes.as_slice() == [YMODEM_CRC16])
        );

        let terminal_prompt = b"\r\nsender-shell$ ";
        let mut final_header = create_ymodem_end_session_packet().into_vec();
        final_header.extend_from_slice(terminal_prompt);
        receiver.push_serial_bytes(&final_header).unwrap();
        let actions = drain_receiver(&mut receiver);
        assert!(matches!(
            actions.last(),
            Some(YmodemReceiverAction::BatchCompleted {
                file_count: 1,
                total_bytes: 3,
                terminal_bytes,
            }) if terminal_bytes.as_slice() == terminal_prompt
        ));
        assert!(receiver.is_terminal());
    }

    #[test]
    fn receiver_rejects_crc_truncation_remote_cancel_and_incomplete_file() {
        let config = YmodemConfig::new(Duration::from_secs(1), 2).unwrap();
        let mut receiver = YmodemReceiver::new(config);
        let _ = drain_receiver(&mut receiver);
        receiver.push_serial_bytes(&[YMODEM_SOH, 0, 255]).unwrap();
        assert!(receiver.timeout().is_some());
        receiver.on_timeout().unwrap();
        assert_eq!(
            receiver_write(&drain_receiver(&mut receiver)).as_slice(),
            &[YMODEM_CRC16]
        );
        receiver
            .push_serial_bytes(&[YMODEM_CAN, YMODEM_CAN])
            .unwrap();
        assert!(matches!(
            drain_receiver(&mut receiver).last(),
            Some(YmodemReceiverAction::Failed(YmodemError::RemoteCancelled))
        ));

        let mut receiver = YmodemReceiver::new(config);
        let _ = drain_receiver(&mut receiver);
        let header = create_ymodem_file_header(&metadata("private.bin", 1)).unwrap();
        receiver.push_serial_bytes(header.as_slice()).unwrap();
        let _ = drain_receiver(&mut receiver);
        receiver.accept_file().unwrap();
        let _ = drain_receiver(&mut receiver);
        receiver
            .push_serial_bytes(&[YMODEM_EOT, YMODEM_EOT])
            .unwrap();
        let actions = drain_receiver(&mut receiver);
        assert!(actions.iter().any(|action| matches!(
            action,
            YmodemReceiverAction::Failed(YmodemError::IncompleteFile)
        )));
    }

    #[test]
    fn failure_and_cancel_paths_never_expose_coalesced_bytes_as_terminal_remainder() {
        let terminal_like_bytes = b"PRIVATE-PROTOCOL-BODY\r\nshell$ ";

        let mut sender =
            YmodemSender::new(metadata("secret.bin", 1), YmodemConfig::default()).unwrap();
        let mut invalid_sender_input = vec![b'!'];
        invalid_sender_input.extend_from_slice(terminal_like_bytes);
        sender.push_serial_bytes(&invalid_sender_input).unwrap();
        let sender_actions = drain_sender(&mut sender);
        assert!(matches!(
            sender_actions.as_slice(),
            [YmodemSenderAction::Failed(YmodemError::UnexpectedByte {
                byte: b'!'
            })]
        ));
        assert!(
            !sender_actions
                .iter()
                .any(|action| matches!(action, YmodemSenderAction::Completed { .. }))
        );

        let mut receiver = YmodemReceiver::new(YmodemConfig::default());
        let _ = drain_receiver(&mut receiver);
        let mut canceled_receiver_input = vec![YMODEM_CAN, YMODEM_CAN];
        canceled_receiver_input.extend_from_slice(terminal_like_bytes);
        receiver
            .push_serial_bytes(&canceled_receiver_input)
            .unwrap();
        let receiver_actions = drain_receiver(&mut receiver);
        assert!(matches!(
            receiver_actions.as_slice(),
            [YmodemReceiverAction::Failed(YmodemError::RemoteCancelled)]
        ));
        assert!(
            !receiver_actions
                .iter()
                .any(|action| matches!(action, YmodemReceiverAction::BatchCompleted { .. }))
        );
    }

    #[test]
    fn debug_output_redacts_names_and_payloads() {
        let marker = "PRIVATE-YMODEM-NAME";
        let metadata = metadata(marker, 6);
        assert!(!format!("{metadata:?}").contains(marker));
        let bytes = YmodemBytes::from(b"PRIVATE-YMODEM-DATA".to_vec());
        assert!(!format!("{bytes:?}").contains("PRIVATE-YMODEM-DATA"));
        let sender = YmodemSender::new(metadata, YmodemConfig::default()).unwrap();
        assert!(!format!("{sender:?}").contains(marker));
        assert!(!format!("{:?}", YmodemSenderAction::Write(bytes)).contains("PRIVATE-YMODEM-DATA"));
    }

    #[test]
    fn one_transfer_lease_owns_a_session_and_drop_releases_it() {
        let registry = SerialTransferRegistry::default();
        let session_id = SerialSessionId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let lease = registry
            .try_acquire(&session_id, SerialTransferKind::YmodemSend)
            .unwrap();
        assert_eq!(
            registry.owner(&session_id),
            Some(SerialTransferKind::YmodemSend)
        );
        assert_eq!(
            registry
                .try_acquire(&session_id, SerialTransferKind::Zmodem)
                .unwrap_err(),
            YmodemError::TransferBusy
        );
        assert!(!format!("{lease:?}").contains(session_id.as_str()));
        drop(lease);
        let receive = registry
            .try_acquire(&session_id, SerialTransferKind::YmodemReceive)
            .unwrap();
        assert_eq!(registry.active_count(), 1);
        receive.release();
        assert!(!registry.is_owned(&session_id));
    }
}
