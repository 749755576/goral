use std::{collections::VecDeque, error::Error, fmt, time::Duration};

pub const ZMODEM_ZPAD: u8 = b'*';
pub const ZMODEM_ZDLE: u8 = 0x18;
pub const ZMODEM_ZBIN: u8 = b'A';
pub const ZMODEM_ZHEX: u8 = b'B';
pub const ZMODEM_ZBIN32: u8 = b'C';
pub const ZMODEM_XON: u8 = 0x11;
pub const ZMODEM_CAN: u8 = 0x18;
pub const ZMODEM_BACKSPACE: u8 = 0x08;
pub const ZMODEM_ZCRCE: u8 = b'h';
pub const ZMODEM_ZCRCG: u8 = b'i';
pub const ZMODEM_ZCRCQ: u8 = b'j';
pub const ZMODEM_ZCRCW: u8 = b'k';
pub const ZMODEM_OVER_AND_OUT: [u8; 2] = *b"OO";
pub const ZMODEM_CANCEL_SEQUENCE: [u8; 10] = [
    ZMODEM_CAN,
    ZMODEM_CAN,
    ZMODEM_CAN,
    ZMODEM_CAN,
    ZMODEM_CAN,
    ZMODEM_BACKSPACE,
    ZMODEM_BACKSPACE,
    ZMODEM_BACKSPACE,
    ZMODEM_BACKSPACE,
    ZMODEM_BACKSPACE,
];

pub const DEFAULT_ZMODEM_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_ZMODEM_RETRY_LIMIT: u32 = 10;
pub const MAX_ZMODEM_RETRY_LIMIT: u32 = 100;
pub const DEFAULT_ZMODEM_CHUNK_BYTES: usize = 64 * 1024;
/// `zmodem.js` accepts a 64-KiB source read but emits at most 8 KiB per
/// protocol subpacket for lrzsz compatibility.
pub const ZMODEM_WIRE_SUBPACKET_BYTES: usize = 8 * 1024;
pub const MAX_ZMODEM_SUBPACKET_BYTES: usize = 64 * 1024;
pub const MAX_ZMODEM_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_ZMODEM_FILENAME_BYTES: usize = 255;
pub const MAX_ZMODEM_METADATA_BYTES: usize = 1024;
pub const MAX_ZMODEM_BATCH_FILES: usize = 1024;
pub const MAX_ZMODEM_PENDING_ACTIONS: usize = 512;
/// Classic ZMODEM carries file offsets in four little-endian bytes.
pub const MAX_ZMODEM_FILE_BYTES: u64 = u32::MAX as u64;

const HEX_HEADER_PREFIX: [u8; 4] = [ZMODEM_ZPAD, ZMODEM_ZPAD, ZMODEM_ZDLE, ZMODEM_ZHEX];
const BINARY16_HEADER_PREFIX: [u8; 3] = [ZMODEM_ZPAD, ZMODEM_ZDLE, ZMODEM_ZBIN];
const BINARY32_HEADER_PREFIX: [u8; 3] = [ZMODEM_ZPAD, ZMODEM_ZDLE, ZMODEM_ZBIN32];
const ZRINIT_CANFDX: u8 = 0x01;
const ZRINIT_CANOVIO: u8 = 0x02;
const ZRINIT_CANFC32: u8 = 0x20;
const ZRINIT_ESCCTL: u8 = 0x40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemConfig {
    timeout: Duration,
    retry_limit: u32,
    chunk_bytes: usize,
    escape_control_bytes: bool,
}

impl ZmodemConfig {
    pub fn new(
        timeout: Duration,
        retry_limit: u32,
        chunk_bytes: usize,
        escape_control_bytes: bool,
    ) -> Result<Self, ZmodemError> {
        if timeout.is_zero() {
            return Err(ZmodemError::InvalidTimeout);
        }
        if retry_limit == 0 || retry_limit > MAX_ZMODEM_RETRY_LIMIT {
            return Err(ZmodemError::InvalidRetryLimit {
                maximum: MAX_ZMODEM_RETRY_LIMIT,
            });
        }
        if chunk_bytes == 0 || chunk_bytes > MAX_ZMODEM_SUBPACKET_BYTES {
            return Err(ZmodemError::InvalidChunkSize {
                maximum_bytes: MAX_ZMODEM_SUBPACKET_BYTES,
            });
        }
        Ok(Self {
            timeout,
            retry_limit,
            chunk_bytes,
            escape_control_bytes,
        })
    }

    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    pub const fn retry_limit(self) -> u32 {
        self.retry_limit
    }

    pub const fn chunk_bytes(self) -> usize {
        self.chunk_bytes
    }

    pub const fn escape_control_bytes(self) -> bool {
        self.escape_control_bytes
    }
}

impl Default for ZmodemConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_ZMODEM_TIMEOUT,
            retry_limit: DEFAULT_ZMODEM_RETRY_LIMIT,
            chunk_bytes: DEFAULT_ZMODEM_CHUNK_BYTES,
            escape_control_bytes: true,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ZmodemError {
    InvalidTimeout,
    InvalidRetryLimit { maximum: u32 },
    InvalidChunkSize { maximum_bytes: usize },
    InputTooLarge { maximum_bytes: usize },
    SubpacketTooLarge { maximum_bytes: usize },
    FilenameTooLong { maximum_bytes: usize },
    MetadataTooLarge { maximum_bytes: usize },
    InvalidMetadata,
    InvalidBatch { maximum_files: usize },
    FileTooLarge { maximum_bytes: u64 },
    BatchSizeOverflow,
    InvalidHeader,
    UnsupportedFrame,
    UnsupportedPeerCapabilities,
    InvalidEscape,
    CrcMismatch,
    UnexpectedFrame,
    InvalidSourceChunk { maximum_bytes: usize, actual: usize },
    SourceLengthMismatch,
    SinkLengthMismatch { expected: usize, actual: usize },
    IncompleteFile,
    RetryLimit,
    TimedOut,
    Cancelled,
    RemoteCancelled,
    RemoteAborted,
    ActionQueueFull { maximum: usize },
    InvalidState,
}

impl ZmodemError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTimeout => "ZMODEM_INVALID_TIMEOUT",
            Self::InvalidRetryLimit { .. } => "ZMODEM_INVALID_RETRY_LIMIT",
            Self::InvalidChunkSize { .. } => "ZMODEM_INVALID_CHUNK_SIZE",
            Self::InputTooLarge { .. } => "ZMODEM_INPUT_TOO_LARGE",
            Self::SubpacketTooLarge { .. } => "ZMODEM_SUBPACKET_TOO_LARGE",
            Self::FilenameTooLong { .. } => "ZMODEM_FILENAME_TOO_LONG",
            Self::MetadataTooLarge { .. } | Self::InvalidMetadata => "ZMODEM_INVALID_METADATA",
            Self::InvalidBatch { .. } | Self::BatchSizeOverflow => "ZMODEM_INVALID_BATCH",
            Self::FileTooLarge { .. } => "ZMODEM_FILE_TOO_LARGE",
            Self::InvalidHeader | Self::UnsupportedFrame => "ZMODEM_INVALID_HEADER",
            Self::UnsupportedPeerCapabilities => "ZMODEM_UNSUPPORTED_PEER",
            Self::InvalidEscape => "ZMODEM_INVALID_ESCAPE",
            Self::CrcMismatch => "ZMODEM_CRC_MISMATCH",
            Self::UnexpectedFrame => "ZMODEM_TRANSFER_ERROR",
            Self::InvalidSourceChunk { .. } | Self::SourceLengthMismatch => {
                "ZMODEM_SOURCE_LENGTH_MISMATCH"
            }
            Self::SinkLengthMismatch { .. } => "ZMODEM_SINK_LENGTH_MISMATCH",
            Self::IncompleteFile => "ZMODEM_INCOMPLETE_FILE",
            Self::RetryLimit => "ZMODEM_RETRY_LIMIT",
            Self::TimedOut => "ZMODEM_TIMEOUT",
            Self::Cancelled => "ZMODEM_CANCELLED",
            Self::RemoteCancelled => "ZMODEM_REMOTE_CANCELLED",
            Self::RemoteAborted => "ZMODEM_REMOTE_ABORTED",
            Self::ActionQueueFull { .. } => "ZMODEM_BACKPRESSURE",
            Self::InvalidState => "ZMODEM_INVALID_STATE",
        }
    }
}

impl fmt::Debug for ZmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for ZmodemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => formatter.write_str("ZMODEM timeout must be positive"),
            Self::InvalidRetryLimit { maximum } => write!(
                formatter,
                "ZMODEM retry limit must be between 1 and {maximum}"
            ),
            Self::InvalidChunkSize { maximum_bytes } => write!(
                formatter,
                "ZMODEM chunk size must be between 1 and {maximum_bytes} bytes"
            ),
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "ZMODEM input exceeds {maximum_bytes} bytes")
            }
            Self::SubpacketTooLarge { maximum_bytes } => write!(
                formatter,
                "ZMODEM data subpacket exceeds {maximum_bytes} bytes"
            ),
            Self::FilenameTooLong { maximum_bytes } => {
                write!(formatter, "ZMODEM file name exceeds {maximum_bytes} bytes")
            }
            Self::MetadataTooLarge { maximum_bytes } => {
                write!(formatter, "ZMODEM metadata exceeds {maximum_bytes} bytes")
            }
            Self::InvalidMetadata => formatter.write_str("ZMODEM file metadata is invalid"),
            Self::InvalidBatch { maximum_files } => write!(
                formatter,
                "ZMODEM batch must contain between 1 and {maximum_files} files"
            ),
            Self::FileTooLarge { maximum_bytes } => {
                write!(formatter, "ZMODEM file exceeds {maximum_bytes} bytes")
            }
            Self::BatchSizeOverflow => formatter.write_str("ZMODEM batch byte total overflowed"),
            Self::InvalidHeader => formatter.write_str("ZMODEM header is invalid"),
            Self::UnsupportedFrame => formatter.write_str("ZMODEM frame type is unsupported"),
            Self::UnsupportedPeerCapabilities => {
                formatter.write_str("ZMODEM peer capabilities are unsupported")
            }
            Self::InvalidEscape => formatter.write_str("ZMODEM escape sequence is invalid"),
            Self::CrcMismatch => formatter.write_str("ZMODEM frame checksum did not match"),
            Self::UnexpectedFrame => formatter.write_str("Unexpected ZMODEM frame"),
            Self::InvalidSourceChunk {
                maximum_bytes,
                actual,
            } => write!(
                formatter,
                "ZMODEM source chunk is invalid (maximum {maximum_bytes}, got {actual})"
            ),
            Self::SourceLengthMismatch => {
                formatter.write_str("ZMODEM source length does not match its metadata")
            }
            Self::SinkLengthMismatch { expected, actual } => write!(
                formatter,
                "ZMODEM sink length is invalid (expected {expected}, got {actual})"
            ),
            Self::IncompleteFile => formatter.write_str("ZMODEM received an incomplete file"),
            Self::RetryLimit => formatter.write_str("ZMODEM retry limit reached"),
            Self::TimedOut => formatter.write_str("Timed out waiting for ZMODEM peer"),
            Self::Cancelled => formatter.write_str("ZMODEM transfer cancelled"),
            Self::RemoteCancelled => {
                formatter.write_str("ZMODEM transfer cancelled by the remote peer")
            }
            Self::RemoteAborted => formatter.write_str("ZMODEM peer aborted the transfer"),
            Self::ActionQueueFull { maximum } => write!(
                formatter,
                "ZMODEM action queue reached its {maximum}-item limit"
            ),
            Self::InvalidState => formatter.write_str("ZMODEM state transition is invalid"),
        }
    }
}

impl Error for ZmodemError {}

#[derive(Clone, Eq, PartialEq)]
pub struct ZmodemBytes(Vec<u8>);

impl ZmodemBytes {
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

impl From<Vec<u8>> for ZmodemBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ZmodemBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemBytes")
            .field("length", &self.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ZmodemFrameType {
    RequestInit = 0,
    ReceiverInit = 1,
    SenderInit = 2,
    Ack = 3,
    File = 4,
    Skip = 5,
    Nak = 6,
    Abort = 7,
    Finish = 8,
    ReceiverPosition = 9,
    Data = 10,
    EndOfFile = 11,
    FileError = 12,
    Crc = 13,
    Challenge = 14,
    Complete = 15,
    Cancel = 16,
    FreeCount = 17,
    Command = 18,
    StandardError = 19,
}

impl TryFrom<u8> for ZmodemFrameType {
    type Error = ZmodemError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RequestInit),
            1 => Ok(Self::ReceiverInit),
            2 => Ok(Self::SenderInit),
            3 => Ok(Self::Ack),
            4 => Ok(Self::File),
            5 => Ok(Self::Skip),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Abort),
            8 => Ok(Self::Finish),
            9 => Ok(Self::ReceiverPosition),
            10 => Ok(Self::Data),
            11 => Ok(Self::EndOfFile),
            12 => Ok(Self::FileError),
            13 => Ok(Self::Crc),
            14 => Ok(Self::Challenge),
            15 => Ok(Self::Complete),
            16 => Ok(Self::Cancel),
            17 => Ok(Self::FreeCount),
            18 => Ok(Self::Command),
            19 => Ok(Self::StandardError),
            _ => Err(ZmodemError::UnsupportedFrame),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZmodemChecksum {
    Crc16,
    Crc32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemHeader {
    pub frame_type: ZmodemFrameType,
    pub parameters: [u8; 4],
}

impl ZmodemHeader {
    pub const fn new(frame_type: ZmodemFrameType, parameters: [u8; 4]) -> Self {
        Self {
            frame_type,
            parameters,
        }
    }

    pub fn with_offset(frame_type: ZmodemFrameType, offset: u32) -> Self {
        Self::new(frame_type, offset.to_le_bytes())
    }

    pub const fn offset(self) -> u32 {
        u32::from_le_bytes(self.parameters)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemDecodedHeader {
    pub header: ZmodemHeader,
    pub checksum: ZmodemChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZmodemFrameEnd {
    EndNoAck,
    ContinueNoAck,
    ContinueAck,
    EndAck,
}

impl ZmodemFrameEnd {
    const fn byte(self) -> u8 {
        match self {
            Self::EndNoAck => ZMODEM_ZCRCE,
            Self::ContinueNoAck => ZMODEM_ZCRCG,
            Self::ContinueAck => ZMODEM_ZCRCQ,
            Self::EndAck => ZMODEM_ZCRCW,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            ZMODEM_ZCRCE => Some(Self::EndNoAck),
            ZMODEM_ZCRCG => Some(Self::ContinueNoAck),
            ZMODEM_ZCRCQ => Some(Self::ContinueAck),
            ZMODEM_ZCRCW => Some(Self::EndAck),
            _ => None,
        }
    }

    pub const fn ends_frame(self) -> bool {
        matches!(self, Self::EndNoAck | Self::EndAck)
    }

    pub const fn expects_ack(self) -> bool {
        matches!(self, Self::ContinueAck | Self::EndAck)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ZmodemSubpacket {
    pub payload: ZmodemBytes,
    pub frame_end: ZmodemFrameEnd,
}

impl fmt::Debug for ZmodemSubpacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemSubpacket")
            .field("payload_bytes", &self.payload.len())
            .field("frame_end", &self.frame_end)
            .finish()
    }
}

pub fn crc16_zmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in bytes {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub fn crc32_zmodem(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn header_crc_bytes(header: ZmodemHeader) -> [u8; 5] {
    [
        header.frame_type as u8,
        header.parameters[0],
        header.parameters[1],
        header.parameters[2],
        header.parameters[3],
    ]
}

pub fn encode_zmodem_hex_header(header: ZmodemHeader) -> ZmodemBytes {
    let data = header_crc_bytes(header);
    let crc = crc16_zmodem(&data).to_be_bytes();
    let mut bytes = Vec::with_capacity(21);
    bytes.extend_from_slice(&HEX_HEADER_PREFIX);
    for byte in data.into_iter().chain(crc) {
        bytes.push(to_hex(byte >> 4));
        bytes.push(to_hex(byte & 0x0f));
    }
    bytes.extend_from_slice(b"\r\n");
    if !matches!(
        header.frame_type,
        ZmodemFrameType::Finish | ZmodemFrameType::Ack
    ) {
        bytes.push(ZMODEM_XON);
    }
    bytes.into()
}

pub fn encode_zmodem_binary_header(
    header: ZmodemHeader,
    checksum: ZmodemChecksum,
    escape_control_bytes: bool,
) -> ZmodemBytes {
    let data = header_crc_bytes(header);
    let mut body = data.to_vec();
    let prefix = match checksum {
        ZmodemChecksum::Crc16 => {
            body.extend_from_slice(&crc16_zmodem(&data).to_be_bytes());
            &BINARY16_HEADER_PREFIX[..]
        }
        ZmodemChecksum::Crc32 => {
            body.extend_from_slice(&crc32_zmodem(&data).to_le_bytes());
            &BINARY32_HEADER_PREFIX[..]
        }
    };
    let mut bytes = Vec::with_capacity(prefix.len() + body.len() * 2);
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&encode_zdle(&body, escape_control_bytes));
    bytes.into()
}

pub fn encode_zmodem_subpacket(
    payload: &[u8],
    frame_end: ZmodemFrameEnd,
    checksum: ZmodemChecksum,
    escape_control_bytes: bool,
) -> Result<ZmodemBytes, ZmodemError> {
    if payload.len() > MAX_ZMODEM_SUBPACKET_BYTES {
        return Err(ZmodemError::SubpacketTooLarge {
            maximum_bytes: MAX_ZMODEM_SUBPACKET_BYTES,
        });
    }
    let end = frame_end.byte();
    let mut bytes = encode_zdle(payload, escape_control_bytes);
    bytes.extend_from_slice(&[ZMODEM_ZDLE, end]);
    let mut crc_input = Vec::with_capacity(payload.len() + 1);
    crc_input.extend_from_slice(payload);
    crc_input.push(end);
    let crc = match checksum {
        ZmodemChecksum::Crc16 => crc16_zmodem(&crc_input).to_be_bytes().to_vec(),
        ZmodemChecksum::Crc32 => crc32_zmodem(&crc_input).to_le_bytes().to_vec(),
    };
    bytes.extend_from_slice(&encode_zdle(&crc, escape_control_bytes));
    Ok(bytes.into())
}

fn to_hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

fn from_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_zdle(bytes: &[u8], escape_control_bytes: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    let mut previous = None;
    for &byte in bytes {
        let mandatory = matches!(byte, ZMODEM_ZDLE | 0x10 | 0x90 | 0x11 | 0x91 | 0x13 | 0x93);
        let control = byte & 0x60 == 0;
        let telnet_cr =
            matches!(byte, 0x0d | 0x8d) && previous.is_some_and(|prior: u8| prior & 0x7f == b'@');
        if mandatory || (escape_control_bytes && control) || telnet_cr {
            encoded.push(ZMODEM_ZDLE);
            encoded.push(byte ^ 0x40);
        } else {
            encoded.push(byte);
        }
        previous = Some(byte);
    }
    encoded
}

fn decode_zdle_byte(encoded: u8) -> Result<u8, ZmodemError> {
    match encoded {
        b'l' => Ok(0x7f),
        b'm' => Ok(0xff),
        ZMODEM_ZCRCE | ZMODEM_ZCRCG | ZMODEM_ZCRCQ | ZMODEM_ZCRCW => {
            Err(ZmodemError::InvalidEscape)
        }
        value => Ok(value ^ 0x40),
    }
}

#[derive(Default)]
pub struct ZmodemWireDecoder {
    input: Vec<u8>,
    consecutive_can: usize,
    remote_cancelled: bool,
}

/// Direction of an automatically detected transfer from the local desktop's
/// point of view. A peer `ZRINIT` asks Netcatty to send, while a peer
/// `ZRQINIT` asks Netcatty to receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZmodemTransferDirection {
    Send,
    Receive,
}

/// One CRC-validated automatic-transfer detection. The protocol bytes retain
/// the exact wire representation, including bytes following the initiating
/// header in the same serial read, so the selected state machine sees the
/// complete stream.
#[derive(Clone, Eq, PartialEq)]
pub struct ZmodemDetection {
    pub direction: ZmodemTransferDirection,
    pub protocol_bytes: ZmodemBytes,
}

impl fmt::Debug for ZmodemDetection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemDetection")
            .field("direction", &self.direction)
            .field("protocol_bytes", &self.protocol_bytes.len())
            .finish()
    }
}

/// Output from the raw-byte sentry. `passthrough` is safe to route through the
/// configured charset decoder and Connection Log. Bytes in `detected` must be
/// routed only to the ZMODEM driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmodemSentryOutput {
    pub passthrough: ZmodemBytes,
    pub detected: Option<ZmodemDetection>,
}

/// Incremental ZMODEM initiator sentry used in front of charset decoding.
///
/// The sentry retains only a possible fragmented header. Invalid CRCs,
/// unrelated ZMODEM headers, ordinary `*`/ZDLE text, and every byte preceding a
/// valid initiator are returned unchanged as terminal passthrough.
#[derive(Default)]
pub struct ZmodemSentry {
    input: Vec<u8>,
}

impl ZmodemSentry {
    pub fn push(&mut self, bytes: &[u8]) -> Result<ZmodemSentryOutput, ZmodemError> {
        if bytes.len() > MAX_ZMODEM_INPUT_BYTES
            || self.input.len().saturating_add(bytes.len()) > MAX_ZMODEM_INPUT_BYTES
        {
            self.input.clear();
            return Err(ZmodemError::InputTooLarge {
                maximum_bytes: MAX_ZMODEM_INPUT_BYTES,
            });
        }
        self.input.extend_from_slice(bytes);
        let mut passthrough = Vec::new();

        loop {
            let Some(candidate) = find_header_candidate(&self.input) else {
                passthrough.append(&mut self.input);
                return Ok(ZmodemSentryOutput {
                    passthrough: passthrough.into(),
                    detected: None,
                });
            };
            if candidate > 0 {
                passthrough.extend(self.input.drain(..candidate));
            }

            match parse_header_at_start(&self.input) {
                Ok(Some((decoded, _consumed))) => {
                    let direction = match decoded.header.frame_type {
                        ZmodemFrameType::ReceiverInit => Some(ZmodemTransferDirection::Send),
                        ZmodemFrameType::RequestInit => Some(ZmodemTransferDirection::Receive),
                        _ => None,
                    };
                    if let Some(direction) = direction {
                        let protocol_bytes = std::mem::take(&mut self.input).into();
                        return Ok(ZmodemSentryOutput {
                            passthrough: passthrough.into(),
                            detected: Some(ZmodemDetection {
                                direction,
                                protocol_bytes,
                            }),
                        });
                    }
                    // A valid but unrelated frame is terminal data until a
                    // transfer is owned. Advance one exact byte and rescan so
                    // a later initiator in the same read is still detected.
                    passthrough.push(self.input.remove(0));
                }
                Ok(None) => {
                    return Ok(ZmodemSentryOutput {
                        passthrough: passthrough.into(),
                        detected: None,
                    });
                }
                Err(_) => {
                    // A malformed candidate is ordinary terminal data. Never
                    // suppress it merely because it resembles a header.
                    passthrough.push(self.input.remove(0));
                }
            }
        }
    }

    pub fn reset(&mut self) -> ZmodemBytes {
        std::mem::take(&mut self.input).into()
    }

    pub fn buffered_len(&self) -> usize {
        self.input.len()
    }
}

impl fmt::Debug for ZmodemSentry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemSentry")
            .field("buffered_bytes", &self.input.len())
            .finish()
    }
}

impl ZmodemWireDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ZmodemError> {
        if bytes.len() > MAX_ZMODEM_INPUT_BYTES
            || self.input.len().saturating_add(bytes.len()) > MAX_ZMODEM_INPUT_BYTES
        {
            return Err(ZmodemError::InputTooLarge {
                maximum_bytes: MAX_ZMODEM_INPUT_BYTES,
            });
        }
        for &byte in bytes {
            if byte == ZMODEM_CAN {
                self.consecutive_can = self.consecutive_can.saturating_add(1);
                if self.consecutive_can >= 5 {
                    self.remote_cancelled = true;
                }
            } else {
                self.consecutive_can = 0;
            }
            if matches!(byte, 0x11 | 0x13 | 0x91 | 0x93) {
                continue;
            }
            self.input.push(byte);
        }
        Ok(())
    }

    pub fn buffered_len(&self) -> usize {
        self.input.len()
    }

    pub fn reset(&mut self) {
        self.input.clear();
        self.consecutive_can = 0;
        self.remote_cancelled = false;
    }

    /// Takes bytes received after the protocol's terminal marker. Callers must
    /// expose this only after a successful batch completion; error and cancel
    /// paths may still contain protocol or file-body bytes.
    fn take_success_remainder(&mut self) -> ZmodemBytes {
        self.consecutive_can = 0;
        self.remote_cancelled = false;
        std::mem::take(&mut self.input).into()
    }

    pub fn next_header(&mut self) -> Result<Option<ZmodemDecodedHeader>, ZmodemError> {
        loop {
            if self.remote_cancelled || contains_remote_cancel(&self.input) {
                self.input.clear();
                self.remote_cancelled = false;
                self.consecutive_can = 0;
                return Err(ZmodemError::RemoteCancelled);
            }
            let Some(candidate) = find_header_candidate(&self.input) else {
                retain_possible_header_prefix(&mut self.input);
                return Ok(None);
            };
            if candidate > 0 {
                self.input.drain(..candidate);
            }
            match parse_header_at_start(&self.input) {
                Ok(Some((header, consumed))) => {
                    self.input.drain(..consumed);
                    return Ok(Some(header));
                }
                Ok(None) => return Ok(None),
                Err(error) => {
                    self.input.remove(0);
                    return Err(error);
                }
            }
        }
    }

    pub fn next_subpacket(
        &mut self,
        checksum: ZmodemChecksum,
    ) -> Result<Option<ZmodemSubpacket>, ZmodemError> {
        if self.remote_cancelled || contains_remote_cancel(&self.input) {
            self.input.clear();
            self.remote_cancelled = false;
            self.consecutive_can = 0;
            return Err(ZmodemError::RemoteCancelled);
        }
        let crc_bytes = match checksum {
            ZmodemChecksum::Crc16 => 2,
            ZmodemChecksum::Crc32 => 4,
        };
        let mut decoded_payload = Vec::new();
        let mut cursor = 0;
        let frame_end;
        loop {
            if cursor >= self.input.len() {
                if decoded_payload.len() > MAX_ZMODEM_SUBPACKET_BYTES {
                    self.input.clear();
                    return Err(ZmodemError::SubpacketTooLarge {
                        maximum_bytes: MAX_ZMODEM_SUBPACKET_BYTES,
                    });
                }
                return Ok(None);
            }
            let byte = self.input[cursor];
            if byte != ZMODEM_ZDLE {
                decoded_payload.push(byte);
                cursor += 1;
                continue;
            }
            let Some(&after) = self.input.get(cursor + 1) else {
                return Ok(None);
            };
            if let Some(end) = ZmodemFrameEnd::from_byte(after) {
                frame_end = end;
                cursor += 2;
                break;
            }
            decoded_payload.push(decode_zdle_byte(after)?);
            cursor += 2;
            if decoded_payload.len() > MAX_ZMODEM_SUBPACKET_BYTES {
                self.input.clear();
                return Err(ZmodemError::SubpacketTooLarge {
                    maximum_bytes: MAX_ZMODEM_SUBPACKET_BYTES,
                });
            }
        }

        let Some((got_crc, crc_consumed)) = decode_exact_zdle(&self.input[cursor..], crc_bytes)?
        else {
            return Ok(None);
        };
        let mut crc_input = decoded_payload.clone();
        crc_input.push(frame_end.byte());
        let crc_matches = match checksum {
            ZmodemChecksum::Crc16 => got_crc.as_slice() == crc16_zmodem(&crc_input).to_be_bytes(),
            ZmodemChecksum::Crc32 => got_crc.as_slice() == crc32_zmodem(&crc_input).to_le_bytes(),
        };
        self.input.drain(..cursor + crc_consumed);
        if !crc_matches {
            return Err(ZmodemError::CrcMismatch);
        }
        Ok(Some(ZmodemSubpacket {
            payload: decoded_payload.into(),
            frame_end,
        }))
    }

    pub fn next_over_and_out(&mut self) -> Result<bool, ZmodemError> {
        if self.remote_cancelled || contains_remote_cancel(&self.input) {
            self.input.clear();
            self.remote_cancelled = false;
            self.consecutive_can = 0;
            return Err(ZmodemError::RemoteCancelled);
        }
        if let Some(position) = self
            .input
            .windows(ZMODEM_OVER_AND_OUT.len())
            .position(|window| window == ZMODEM_OVER_AND_OUT)
        {
            self.input.drain(..position + ZMODEM_OVER_AND_OUT.len());
            return Ok(true);
        }
        if self.input.len() > 1 {
            let retain = usize::from(self.input.last() == Some(&b'O'));
            let discard = self.input.len() - retain;
            self.input.drain(..discard);
        }
        Ok(false)
    }
}

impl fmt::Debug for ZmodemWireDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemWireDecoder")
            .field("buffered_bytes", &self.input.len())
            .finish()
    }
}

fn parse_header_at_start(
    input: &[u8],
) -> Result<Option<(ZmodemDecodedHeader, usize)>, ZmodemError> {
    if input.starts_with(&HEX_HEADER_PREFIX) {
        return parse_hex_header(input);
    }
    if input.starts_with(&BINARY16_HEADER_PREFIX) {
        return parse_binary_header(input, ZmodemChecksum::Crc16);
    }
    if input.starts_with(&BINARY32_HEADER_PREFIX) {
        return parse_binary_header(input, ZmodemChecksum::Crc32);
    }
    Ok(None)
}

fn parse_hex_header(input: &[u8]) -> Result<Option<(ZmodemDecodedHeader, usize)>, ZmodemError> {
    const HEX_BODY_BYTES: usize = 14;
    let body_start = HEX_HEADER_PREFIX.len();
    let body_end = body_start + HEX_BODY_BYTES;
    if input.len() < body_end + 1 {
        return Ok(None);
    }
    let mut decoded = [0_u8; 7];
    for (index, pair) in input[body_start..body_end].chunks_exact(2).enumerate() {
        let Some(high) = from_hex(pair[0]) else {
            return Err(ZmodemError::InvalidHeader);
        };
        let Some(low) = from_hex(pair[1]) else {
            return Err(ZmodemError::InvalidHeader);
        };
        decoded[index] = (high << 4) | low;
    }
    let mut consumed = body_end;
    match input.get(consumed) {
        Some(0x0d | 0x8d) => {
            consumed += 1;
            match input.get(consumed) {
                Some(0x0a | 0x8a) => consumed += 1,
                None => return Ok(None),
                _ => return Err(ZmodemError::InvalidHeader),
            }
        }
        Some(0x0a | 0x8a) => consumed += 1,
        Some(_) => return Err(ZmodemError::InvalidHeader),
        None => return Ok(None),
    }
    if input.get(consumed) == Some(&ZMODEM_XON) {
        consumed += 1;
    }
    let header = decode_header_body(&decoded[..5], &decoded[5..], ZmodemChecksum::Crc16)?;
    Ok(Some((header, consumed)))
}

fn parse_binary_header(
    input: &[u8],
    checksum: ZmodemChecksum,
) -> Result<Option<(ZmodemDecodedHeader, usize)>, ZmodemError> {
    let prefix_len = 3;
    let decoded_bytes = match checksum {
        ZmodemChecksum::Crc16 => 7,
        ZmodemChecksum::Crc32 => 9,
    };
    let Some((decoded, consumed)) = decode_exact_zdle(&input[prefix_len..], decoded_bytes)? else {
        return Ok(None);
    };
    let header = decode_header_body(&decoded[..5], &decoded[5..], checksum)?;
    Ok(Some((header, prefix_len + consumed)))
}

fn decode_header_body(
    data: &[u8],
    got_crc: &[u8],
    checksum: ZmodemChecksum,
) -> Result<ZmodemDecodedHeader, ZmodemError> {
    if data.len() != 5 {
        return Err(ZmodemError::InvalidHeader);
    }
    let expected_matches = match checksum {
        ZmodemChecksum::Crc16 => got_crc == crc16_zmodem(data).to_be_bytes(),
        ZmodemChecksum::Crc32 => got_crc == crc32_zmodem(data).to_le_bytes(),
    };
    if !expected_matches {
        return Err(ZmodemError::CrcMismatch);
    }
    Ok(ZmodemDecodedHeader {
        header: ZmodemHeader::new(
            ZmodemFrameType::try_from(data[0])?,
            [data[1], data[2], data[3], data[4]],
        ),
        checksum,
    })
}

fn decode_exact_zdle(
    input: &[u8],
    decoded_bytes: usize,
) -> Result<Option<(Vec<u8>, usize)>, ZmodemError> {
    let mut decoded = Vec::with_capacity(decoded_bytes);
    let mut cursor = 0;
    while decoded.len() < decoded_bytes {
        let Some(&byte) = input.get(cursor) else {
            return Ok(None);
        };
        if byte != ZMODEM_ZDLE {
            decoded.push(byte);
            cursor += 1;
            continue;
        }
        let Some(&after) = input.get(cursor + 1) else {
            return Ok(None);
        };
        decoded.push(decode_zdle_byte(after)?);
        cursor += 2;
    }
    Ok(Some((decoded, cursor)))
}

fn find_header_candidate(input: &[u8]) -> Option<usize> {
    (0..input.len()).find(|&index| {
        input[index..].starts_with(&HEX_HEADER_PREFIX)
            || input[index..].starts_with(&BINARY16_HEADER_PREFIX)
            || input[index..].starts_with(&BINARY32_HEADER_PREFIX)
            || is_partial_header_prefix(&input[index..])
    })
}

fn is_partial_header_prefix(input: &[u8]) -> bool {
    [
        &HEX_HEADER_PREFIX[..],
        &BINARY16_HEADER_PREFIX[..],
        &BINARY32_HEADER_PREFIX[..],
    ]
    .iter()
    .any(|prefix| input.len() < prefix.len() && prefix.starts_with(input))
}

fn retain_possible_header_prefix(input: &mut Vec<u8>) {
    let retain = (1..=input.len().min(HEX_HEADER_PREFIX.len() - 1))
        .rev()
        .find(|&length| is_partial_header_prefix(&input[input.len() - length..]))
        .unwrap_or(0);
    if input.len() > retain {
        input.drain(..input.len() - retain);
    }
}

fn contains_remote_cancel(input: &[u8]) -> bool {
    input
        .windows(5)
        .any(|window| window.iter().all(|byte| *byte == ZMODEM_CAN))
}

#[derive(Clone, Eq, PartialEq)]
pub struct ZmodemFileMetadata {
    file_name: String,
    total_bytes: u64,
    modified_time: u64,
    mode: u32,
    files_remaining: Option<u64>,
    bytes_remaining: Option<u64>,
}

impl ZmodemFileMetadata {
    pub fn new(
        file_name: impl AsRef<str>,
        total_bytes: u64,
        modified_time: u64,
        mode: u32,
    ) -> Result<Self, ZmodemError> {
        if total_bytes > MAX_ZMODEM_FILE_BYTES {
            return Err(ZmodemError::FileTooLarge {
                maximum_bytes: MAX_ZMODEM_FILE_BYTES,
            });
        }
        Ok(Self {
            file_name: sanitize_zmodem_filename(file_name.as_ref())?,
            total_bytes,
            modified_time,
            mode,
            files_remaining: None,
            bytes_remaining: None,
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

    pub const fn files_remaining(&self) -> Option<u64> {
        self.files_remaining
    }

    pub const fn bytes_remaining(&self) -> Option<u64> {
        self.bytes_remaining
    }
}

impl fmt::Debug for ZmodemFileMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemFileMetadata")
            .field("file_name_bytes", &self.file_name.len())
            .field("total_bytes", &self.total_bytes)
            .field("modified_time", &self.modified_time)
            .field("mode", &format_args!("{:#o}", self.mode))
            .field("files_remaining", &self.files_remaining)
            .field("bytes_remaining", &self.bytes_remaining)
            .finish()
    }
}

pub fn sanitize_zmodem_filename(value: &str) -> Result<String, ZmodemError> {
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
        "zmodem-received.bin".to_owned()
    } else {
        sanitized
    };
    if sanitized.len() > MAX_ZMODEM_FILENAME_BYTES {
        return Err(ZmodemError::FilenameTooLong {
            maximum_bytes: MAX_ZMODEM_FILENAME_BYTES,
        });
    }
    Ok(sanitized)
}

pub fn encode_zmodem_file_metadata(
    metadata: &ZmodemFileMetadata,
    files_remaining: u64,
    bytes_remaining: u64,
) -> Result<ZmodemBytes, ZmodemError> {
    let mode = 0o100000 | (metadata.mode & 0o7777);
    let value = format!(
        "{}\0{} {:o} {:o} 0 {} {}\0",
        metadata.file_name,
        metadata.total_bytes,
        metadata.modified_time,
        mode,
        files_remaining,
        bytes_remaining
    );
    if value.len() > MAX_ZMODEM_METADATA_BYTES {
        return Err(ZmodemError::MetadataTooLarge {
            maximum_bytes: MAX_ZMODEM_METADATA_BYTES,
        });
    }
    Ok(value.into_bytes().into())
}

pub fn parse_zmodem_file_metadata(bytes: &[u8]) -> Result<ZmodemFileMetadata, ZmodemError> {
    if bytes.len() > MAX_ZMODEM_METADATA_BYTES {
        return Err(ZmodemError::MetadataTooLarge {
            maximum_bytes: MAX_ZMODEM_METADATA_BYTES,
        });
    }
    let Some(name_end) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(ZmodemError::InvalidMetadata);
    };
    let name = std::str::from_utf8(&bytes[..name_end]).map_err(|_| ZmodemError::InvalidMetadata)?;
    let fields_end = bytes[name_end + 1..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| name_end + 1 + offset)
        .unwrap_or(bytes.len());
    let fields = std::str::from_utf8(&bytes[name_end + 1..fields_end])
        .map_err(|_| ZmodemError::InvalidMetadata)?;
    let mut parts = fields.split_ascii_whitespace();
    let total_bytes = parts
        .next()
        .ok_or(ZmodemError::InvalidMetadata)?
        .parse::<u64>()
        .map_err(|_| ZmodemError::InvalidMetadata)?;
    let modified_time = parse_optional_radix(parts.next(), 8)?;
    let mode = u32::try_from(parse_optional_radix(parts.next(), 8)?)
        .map_err(|_| ZmodemError::InvalidMetadata)?;
    let _serial = parts.next();
    let files_remaining = parse_optional_decimal(parts.next())?;
    let bytes_remaining = parse_optional_decimal(parts.next())?;
    if files_remaining.is_some_and(|count| count > MAX_ZMODEM_BATCH_FILES as u64) {
        return Err(ZmodemError::InvalidBatch {
            maximum_files: MAX_ZMODEM_BATCH_FILES,
        });
    }
    if bytes_remaining.is_some_and(|bytes| {
        bytes > MAX_ZMODEM_FILE_BYTES.saturating_mul(MAX_ZMODEM_BATCH_FILES as u64)
    }) {
        return Err(ZmodemError::BatchSizeOverflow);
    }
    let mut metadata = ZmodemFileMetadata::new(name, total_bytes, modified_time, mode)?;
    metadata.files_remaining = files_remaining;
    metadata.bytes_remaining = bytes_remaining;
    Ok(metadata)
}

fn parse_optional_radix(value: Option<&str>, radix: u32) -> Result<u64, ZmodemError> {
    match value {
        Some(value) if !value.is_empty() => {
            u64::from_str_radix(value, radix).map_err(|_| ZmodemError::InvalidMetadata)
        }
        _ => Ok(0),
    }
}

fn parse_optional_decimal(value: Option<&str>) -> Result<Option<u64>, ZmodemError> {
    value
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| ZmodemError::InvalidMetadata)
        })
        .transpose()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZmodemProgressStage {
    Header,
    Data,
    Finalizing,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemProgress {
    pub file_index: usize,
    pub file_count: usize,
    pub transferred_bytes: u64,
    pub total_bytes: u64,
    pub stage: ZmodemProgressStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemFileSummary {
    pub file_index: usize,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZmodemBatchSummary {
    pub file_count: usize,
    pub completed_files: usize,
    pub skipped_files: usize,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ZmodemSenderAction {
    Write(ZmodemBytes),
    ReadSource {
        file_index: usize,
        offset: u64,
        maximum_bytes: usize,
    },
    Progress(ZmodemProgress),
    FileCompleted(ZmodemFileSummary),
    FileSkipped {
        file_index: usize,
    },
    BatchCompleted {
        summary: ZmodemBatchSummary,
        terminal_bytes: ZmodemBytes,
    },
    Failed(ZmodemError),
}

impl fmt::Debug for ZmodemSenderAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(bytes) => formatter.debug_tuple("Write").field(bytes).finish(),
            Self::ReadSource {
                file_index,
                offset,
                maximum_bytes,
            } => formatter
                .debug_struct("ReadSource")
                .field("file_index", file_index)
                .field("offset", offset)
                .field("maximum_bytes", maximum_bytes)
                .finish(),
            Self::Progress(progress) => formatter.debug_tuple("Progress").field(progress).finish(),
            Self::FileCompleted(summary) => formatter
                .debug_tuple("FileCompleted")
                .field(summary)
                .finish(),
            Self::FileSkipped { file_index } => formatter
                .debug_struct("FileSkipped")
                .field("file_index", file_index)
                .finish(),
            Self::BatchCompleted {
                summary,
                terminal_bytes,
            } => formatter
                .debug_struct("BatchCompleted")
                .field("summary", summary)
                .field("terminal_bytes", &terminal_bytes.len())
                .finish(),
            Self::Failed(error) => formatter.debug_tuple("Failed").field(error).finish(),
        }
    }
}

enum SenderState {
    AwaitReceiverInit { attempts: u32 },
    AwaitSenderInitAck { attempts: u32 },
    AwaitOfferResponse { attempts: u32 },
    AwaitSource { attempts: u32 },
    AwaitReceiverInitAfterFile { attempts: u32 },
    AwaitFinish { attempts: u32 },
    Terminal,
}

pub struct ZmodemSender {
    config: ZmodemConfig,
    files: Vec<ZmodemFileMetadata>,
    wire: ZmodemWireDecoder,
    state: SenderState,
    actions: VecDeque<ZmodemSenderAction>,
    file_index: usize,
    offset: u64,
    checksum: ZmodemChecksum,
    completed_files: usize,
    skipped_files: usize,
    transferred_bytes: u64,
    batch_total_bytes: u64,
}

impl ZmodemSender {
    pub fn new(files: Vec<ZmodemFileMetadata>, config: ZmodemConfig) -> Result<Self, ZmodemError> {
        if files.is_empty() || files.len() > MAX_ZMODEM_BATCH_FILES {
            return Err(ZmodemError::InvalidBatch {
                maximum_files: MAX_ZMODEM_BATCH_FILES,
            });
        }
        let batch_total_bytes = files.iter().try_fold(0_u64, |total, file| {
            total
                .checked_add(file.total_bytes)
                .ok_or(ZmodemError::BatchSizeOverflow)
        })?;
        Ok(Self {
            config,
            files,
            wire: ZmodemWireDecoder::default(),
            state: SenderState::AwaitReceiverInit { attempts: 1 },
            actions: VecDeque::new(),
            file_index: 0,
            offset: 0,
            checksum: ZmodemChecksum::Crc16,
            completed_files: 0,
            skipped_files: 0,
            transferred_bytes: 0,
            batch_total_bytes,
        })
    }

    pub fn next_action(&mut self) -> Option<ZmodemSenderAction> {
        self.actions.pop_front()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, SenderState::Terminal)
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self.state {
            SenderState::AwaitReceiverInit { .. }
            | SenderState::AwaitSenderInitAck { .. }
            | SenderState::AwaitOfferResponse { .. }
            | SenderState::AwaitReceiverInitAfterFile { .. }
            | SenderState::AwaitFinish { .. } => Some(self.config.timeout),
            SenderState::AwaitSource { .. } | SenderState::Terminal => None,
        }
    }

    pub fn push_serial_bytes(&mut self, bytes: &[u8]) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.wire.push(bytes)?;
        self.pump_headers();
        Ok(())
    }

    pub fn provide_source_chunk(&mut self, bytes: &[u8]) -> Result<(), ZmodemError> {
        let source_attempts = match self.state {
            SenderState::AwaitSource { attempts } => attempts,
            _ => return Err(ZmodemError::InvalidState),
        };
        let total_bytes = self.files[self.file_index].total_bytes;
        let remaining = total_bytes
            .checked_sub(self.offset)
            .ok_or(ZmodemError::SourceLengthMismatch)?;
        let maximum = usize::try_from(remaining.min(self.config.chunk_bytes as u64))
            .expect("bounded ZMODEM chunk fits usize");
        if bytes.len() > maximum || (bytes.is_empty() && remaining > 0) {
            return Err(ZmodemError::InvalidSourceChunk {
                maximum_bytes: maximum,
                actual: bytes.len(),
            });
        }
        let final_chunk = bytes.len() as u64 == remaining;
        if bytes.is_empty() {
            let packet = encode_zmodem_subpacket(
                bytes,
                ZmodemFrameEnd::EndNoAck,
                self.checksum,
                self.config.escape_control_bytes,
            )?;
            if !self.queue_sender_action(ZmodemSenderAction::Write(packet)) {
                return Ok(());
            }
        } else {
            let chunk_count = bytes.len().div_ceil(ZMODEM_WIRE_SUBPACKET_BYTES);
            for (chunk_index, chunk) in bytes.chunks(ZMODEM_WIRE_SUBPACKET_BYTES).enumerate() {
                let is_last_wire_chunk = chunk_index + 1 == chunk_count;
                let frame_end = if final_chunk && is_last_wire_chunk {
                    ZmodemFrameEnd::EndNoAck
                } else {
                    ZmodemFrameEnd::ContinueNoAck
                };
                let packet = encode_zmodem_subpacket(
                    chunk,
                    frame_end,
                    self.checksum,
                    self.config.escape_control_bytes,
                )?;
                if !self.queue_sender_action(ZmodemSenderAction::Write(packet)) {
                    return Ok(());
                }
            }
        }
        self.offset += bytes.len() as u64;
        self.queue_sender_action(ZmodemSenderAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: self.files.len(),
            transferred_bytes: self.offset,
            total_bytes,
            stage: if final_chunk {
                ZmodemProgressStage::Finalizing
            } else {
                ZmodemProgressStage::Data
            },
        }));
        if final_chunk {
            self.send_end_of_file(1);
        } else {
            self.request_source(source_attempts);
        }
        Ok(())
    }

    pub fn on_timeout(&mut self) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.wire.reset();
        match self.state {
            SenderState::AwaitReceiverInit { attempts } => {
                if attempts >= self.config.retry_limit {
                    self.fail(ZmodemError::TimedOut);
                } else {
                    self.state = SenderState::AwaitReceiverInit {
                        attempts: attempts + 1,
                    };
                }
            }
            SenderState::AwaitOfferResponse { attempts } => self.retry_offer(attempts),
            SenderState::AwaitSenderInitAck { attempts } => self.retry_sender_init(attempts),
            SenderState::AwaitReceiverInitAfterFile { attempts } => {
                self.retry_end_of_file(attempts)
            }
            SenderState::AwaitFinish { attempts } => self.retry_finish(attempts),
            SenderState::AwaitSource { .. } => return Err(ZmodemError::InvalidState),
            SenderState::Terminal => return Err(ZmodemError::InvalidState),
        }
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.queue_sender_action(ZmodemSenderAction::Write(
            ZMODEM_CANCEL_SEQUENCE.to_vec().into(),
        ));
        self.fail(ZmodemError::Cancelled);
        Ok(())
    }

    fn pump_headers(&mut self) {
        while !self.is_terminal() && self.actions.len() < MAX_ZMODEM_PENDING_ACTIONS {
            match self.wire.next_header() {
                Ok(Some(decoded)) => self.handle_header(decoded),
                Ok(None) => break,
                Err(ZmodemError::RemoteCancelled) => {
                    self.fail(ZmodemError::RemoteCancelled);
                    break;
                }
                Err(ZmodemError::CrcMismatch | ZmodemError::InvalidHeader) => break,
                Err(error) => {
                    self.fail(error);
                    break;
                }
            }
        }
    }

    fn handle_header(&mut self, decoded: ZmodemDecodedHeader) {
        let header = decoded.header;
        if matches!(
            header.frame_type,
            ZmodemFrameType::Abort | ZmodemFrameType::FileError
        ) {
            self.fail(ZmodemError::RemoteAborted);
            return;
        }
        if matches!(header.frame_type, ZmodemFrameType::Cancel) {
            self.fail(ZmodemError::RemoteCancelled);
            return;
        }
        match self.state {
            SenderState::AwaitReceiverInit { attempts } => match header.frame_type {
                ZmodemFrameType::ReceiverInit => {
                    self.checksum = ZmodemChecksum::Crc16;
                    self.handle_receiver_init(header);
                }
                ZmodemFrameType::Challenge => {
                    self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_hex_header(
                        ZmodemHeader::new(ZmodemFrameType::Ack, header.parameters),
                    )));
                }
                ZmodemFrameType::RequestInit => {
                    self.state = SenderState::AwaitReceiverInit { attempts }
                }
                _ => self.state = SenderState::AwaitReceiverInit { attempts },
            },
            SenderState::AwaitSenderInitAck { attempts } => match header.frame_type {
                ZmodemFrameType::Ack => self.send_offer(1),
                ZmodemFrameType::ReceiverInit | ZmodemFrameType::Nak => {
                    self.retry_sender_init(attempts)
                }
                _ => self.state = SenderState::AwaitSenderInitAck { attempts },
            },
            SenderState::AwaitOfferResponse { attempts } => match header.frame_type {
                ZmodemFrameType::ReceiverPosition => {
                    self.begin_or_resume_source(header.offset() as u64, attempts)
                }
                ZmodemFrameType::Skip => self.skip_current_file(),
                ZmodemFrameType::ReceiverInit | ZmodemFrameType::Nak => self.retry_offer(attempts),
                _ => self.state = SenderState::AwaitOfferResponse { attempts },
            },
            SenderState::AwaitSource { attempts } => match header.frame_type {
                ZmodemFrameType::ReceiverPosition => {
                    self.begin_or_resume_source(header.offset() as u64, attempts + 1)
                }
                _ => self.state = SenderState::AwaitSource { attempts },
            },
            SenderState::AwaitReceiverInitAfterFile { attempts } => match header.frame_type {
                ZmodemFrameType::ReceiverInit => self.complete_current_file(),
                ZmodemFrameType::ReceiverPosition => {
                    self.begin_or_resume_source(header.offset() as u64, attempts)
                }
                ZmodemFrameType::Skip => self.skip_current_file(),
                ZmodemFrameType::Nak => self.retry_end_of_file(attempts),
                _ => self.state = SenderState::AwaitReceiverInitAfterFile { attempts },
            },
            SenderState::AwaitFinish { attempts } => match header.frame_type {
                ZmodemFrameType::Finish => self.complete_batch(),
                ZmodemFrameType::ReceiverInit | ZmodemFrameType::Nak => self.retry_finish(attempts),
                _ => self.state = SenderState::AwaitFinish { attempts },
            },
            SenderState::Terminal => {}
        }
    }

    fn send_offer(&mut self, attempts: u32) {
        let files_remaining = (self.files.len() - self.file_index) as u64;
        let bytes_remaining = self.files[self.file_index..]
            .iter()
            .map(|file| file.total_bytes)
            .sum();
        let metadata = match encode_zmodem_file_metadata(
            &self.files[self.file_index],
            files_remaining,
            bytes_remaining,
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        let header = ZmodemHeader::new(ZmodemFrameType::File, [0, 0, 0, 1]);
        self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_binary_header(
            header,
            self.checksum,
            self.config.escape_control_bytes,
        )));
        match encode_zmodem_subpacket(
            metadata.as_slice(),
            ZmodemFrameEnd::EndAck,
            self.checksum,
            self.config.escape_control_bytes,
        ) {
            Ok(packet) => self.queue_sender_action(ZmodemSenderAction::Write(packet)),
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        self.queue_sender_action(ZmodemSenderAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: self.files.len(),
            transferred_bytes: 0,
            total_bytes: self.files[self.file_index].total_bytes,
            stage: ZmodemProgressStage::Header,
        }));
        self.state = SenderState::AwaitOfferResponse { attempts };
    }

    fn handle_receiver_init(&mut self, header: ZmodemHeader) {
        let flags = header.parameters[3];
        let has_required_capabilities = flags & ZRINIT_CANFDX != 0
            && flags & ZRINIT_CANOVIO != 0
            && flags & 0x80 == 0
            && header.parameters[0] == 0
            && header.parameters[1] == 0;
        if !has_required_capabilities {
            self.fail(ZmodemError::UnsupportedPeerCapabilities);
            return;
        }
        if flags & ZRINIT_ESCCTL == 0 {
            self.send_sender_init(1);
        } else {
            self.send_offer(1);
        }
    }

    fn send_sender_init(&mut self, attempts: u32) {
        self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::new(ZmodemFrameType::SenderInit, [0, 0, 0, ZRINIT_ESCCTL]),
        )));
        match encode_zmodem_subpacket(
            &[0],
            ZmodemFrameEnd::EndAck,
            ZmodemChecksum::Crc16,
            self.config.escape_control_bytes,
        ) {
            Ok(packet) => self.queue_sender_action(ZmodemSenderAction::Write(packet)),
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        self.state = SenderState::AwaitSenderInitAck { attempts };
    }

    fn retry_sender_init(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
        } else {
            self.send_sender_init(attempts + 1);
        }
    }

    fn retry_offer(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
        } else {
            self.send_offer(attempts + 1);
        }
    }

    fn begin_or_resume_source(&mut self, offset: u64, attempts: u32) {
        if offset > self.files[self.file_index].total_bytes {
            self.fail(ZmodemError::SourceLengthMismatch);
            return;
        }
        if attempts > self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
            return;
        }
        self.offset = offset;
        self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_binary_header(
            ZmodemHeader::with_offset(ZmodemFrameType::Data, offset as u32),
            self.checksum,
            self.config.escape_control_bytes,
        )));
        self.state = SenderState::AwaitSource { attempts };
        if self.offset == self.files[self.file_index].total_bytes {
            let empty = encode_zmodem_subpacket(
                &[],
                ZmodemFrameEnd::EndNoAck,
                self.checksum,
                self.config.escape_control_bytes,
            );
            match empty {
                Ok(packet) => {
                    self.queue_sender_action(ZmodemSenderAction::Write(packet));
                    self.send_end_of_file(1);
                }
                Err(error) => self.fail(error),
            }
        } else {
            self.request_source(attempts);
        }
    }

    fn request_source(&mut self, attempts: u32) {
        let remaining = self.files[self.file_index].total_bytes - self.offset;
        let maximum_bytes = usize::try_from(remaining.min(self.config.chunk_bytes as u64))
            .expect("bounded ZMODEM chunk fits usize");
        self.queue_sender_action(ZmodemSenderAction::ReadSource {
            file_index: self.file_index,
            offset: self.offset,
            maximum_bytes,
        });
        self.state = SenderState::AwaitSource { attempts };
    }

    fn send_end_of_file(&mut self, attempts: u32) {
        let offset = self.offset as u32;
        self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::with_offset(ZmodemFrameType::EndOfFile, offset),
        )));
        self.state = SenderState::AwaitReceiverInitAfterFile { attempts };
    }

    fn retry_end_of_file(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
        } else {
            self.send_end_of_file(attempts + 1);
        }
    }

    fn complete_current_file(&mut self) {
        let total_bytes = self.files[self.file_index].total_bytes;
        self.completed_files += 1;
        self.transferred_bytes = self.transferred_bytes.saturating_add(total_bytes);
        self.queue_sender_action(ZmodemSenderAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: self.files.len(),
            transferred_bytes: total_bytes,
            total_bytes,
            stage: ZmodemProgressStage::Complete,
        }));
        self.queue_sender_action(ZmodemSenderAction::FileCompleted(ZmodemFileSummary {
            file_index: self.file_index,
            total_bytes,
            transferred_bytes: total_bytes,
        }));
        self.file_index += 1;
        self.offset = 0;
        if self.file_index == self.files.len() {
            self.send_finish(1);
        } else {
            self.send_offer(1);
        }
    }

    fn skip_current_file(&mut self) {
        self.queue_sender_action(ZmodemSenderAction::FileSkipped {
            file_index: self.file_index,
        });
        self.skipped_files += 1;
        self.file_index += 1;
        self.offset = 0;
        if self.file_index == self.files.len() {
            self.send_finish(1);
        } else {
            self.send_offer(1);
        }
    }

    fn send_finish(&mut self, attempts: u32) {
        self.queue_sender_action(ZmodemSenderAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::new(ZmodemFrameType::Finish, [0; 4]),
        )));
        self.state = SenderState::AwaitFinish { attempts };
    }

    fn retry_finish(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
        } else {
            self.send_finish(attempts + 1);
        }
    }

    fn complete_batch(&mut self) {
        self.queue_sender_action(ZmodemSenderAction::Write(
            ZMODEM_OVER_AND_OUT.to_vec().into(),
        ));
        let terminal_bytes = self.wire.take_success_remainder();
        self.queue_sender_action(ZmodemSenderAction::BatchCompleted {
            summary: ZmodemBatchSummary {
                file_count: self.files.len(),
                completed_files: self.completed_files,
                skipped_files: self.skipped_files,
                total_bytes: self.batch_total_bytes,
                transferred_bytes: self.transferred_bytes,
            },
            terminal_bytes,
        });
        self.state = SenderState::Terminal;
    }

    fn queue_sender_action(&mut self, action: ZmodemSenderAction) -> bool {
        if self.actions.len() >= MAX_ZMODEM_PENDING_ACTIONS {
            self.actions.clear();
            self.actions
                .push_back(ZmodemSenderAction::Failed(ZmodemError::ActionQueueFull {
                    maximum: MAX_ZMODEM_PENDING_ACTIONS,
                }));
            self.state = SenderState::Terminal;
            false
        } else {
            self.actions.push_back(action);
            true
        }
    }

    fn fail(&mut self, error: ZmodemError) {
        self.queue_sender_action(ZmodemSenderAction::Failed(error));
        self.state = SenderState::Terminal;
    }
}

impl fmt::Debug for ZmodemSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemSender")
            .field("phase", &sender_phase(&self.state))
            .field("file_count", &self.files.len())
            .field("file_index", &self.file_index)
            .field("offset", &self.offset)
            .field("queued_actions", &self.actions.len())
            .finish()
    }
}

fn sender_phase(state: &SenderState) -> &'static str {
    match state {
        SenderState::AwaitReceiverInit { .. } => "await-receiver-init",
        SenderState::AwaitSenderInitAck { .. } => "await-sender-init-ack",
        SenderState::AwaitOfferResponse { .. } => "await-offer-response",
        SenderState::AwaitSource { .. } => "await-source",
        SenderState::AwaitReceiverInitAfterFile { .. } => "await-post-file-init",
        SenderState::AwaitFinish { .. } => "await-finish",
        SenderState::Terminal => "terminal",
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ZmodemReceiverAction {
    Write(ZmodemBytes),
    OfferFile {
        file_index: usize,
        metadata: ZmodemFileMetadata,
    },
    BeginFile {
        file_index: usize,
        metadata: ZmodemFileMetadata,
    },
    WriteFile {
        file_index: usize,
        offset: u64,
        bytes: ZmodemBytes,
    },
    Progress(ZmodemProgress),
    FileCompleted(ZmodemFileSummary),
    BatchCompleted {
        summary: ZmodemBatchSummary,
        terminal_bytes: ZmodemBytes,
    },
    Failed(ZmodemError),
}

impl fmt::Debug for ZmodemReceiverAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(bytes) => formatter.debug_tuple("Write").field(bytes).finish(),
            Self::OfferFile {
                file_index,
                metadata,
            } => formatter
                .debug_struct("OfferFile")
                .field("file_index", file_index)
                .field("metadata", metadata)
                .finish(),
            Self::BeginFile {
                file_index,
                metadata,
            } => formatter
                .debug_struct("BeginFile")
                .field("file_index", file_index)
                .field("metadata", metadata)
                .finish(),
            Self::WriteFile {
                file_index,
                offset,
                bytes,
            } => formatter
                .debug_struct("WriteFile")
                .field("file_index", file_index)
                .field("offset", offset)
                .field("bytes", bytes)
                .finish(),
            Self::Progress(progress) => formatter.debug_tuple("Progress").field(progress).finish(),
            Self::FileCompleted(summary) => formatter
                .debug_tuple("FileCompleted")
                .field(summary)
                .finish(),
            Self::BatchCompleted {
                summary,
                terminal_bytes,
            } => formatter
                .debug_struct("BatchCompleted")
                .field("summary", summary)
                .field("terminal_bytes", &terminal_bytes.len())
                .finish(),
            Self::Failed(error) => formatter.debug_tuple("Failed").field(error).finish(),
        }
    }
}

enum ReceiverState {
    AwaitHeader {
        attempts: u32,
    },
    AwaitSenderInitData {
        checksum: ZmodemChecksum,
        attempts: u32,
    },
    AwaitMetadata {
        checksum: ZmodemChecksum,
        attempts: u32,
    },
    AwaitAcceptance,
    AwaitDataHeader {
        attempts: u32,
    },
    AwaitData {
        checksum: ZmodemChecksum,
        attempts: u32,
    },
    AwaitSink {
        exact_bytes: usize,
        frame_end: ZmodemFrameEnd,
        checksum: ZmodemChecksum,
        attempts: u32,
    },
    AwaitEndOfFile {
        attempts: u32,
    },
    AwaitOverAndOut {
        attempts: u32,
    },
    Terminal,
}

pub struct ZmodemReceiver {
    config: ZmodemConfig,
    wire: ZmodemWireDecoder,
    state: ReceiverState,
    actions: VecDeque<ZmodemReceiverAction>,
    current: Option<ZmodemFileMetadata>,
    file_index: usize,
    written: u64,
    completed_files: usize,
    skipped_files: usize,
    transferred_bytes: u64,
    advertised_total_bytes: u64,
}

impl ZmodemReceiver {
    pub fn new(config: ZmodemConfig) -> Self {
        let mut receiver = Self {
            config,
            wire: ZmodemWireDecoder::default(),
            state: ReceiverState::AwaitHeader { attempts: 1 },
            actions: VecDeque::new(),
            current: None,
            file_index: 0,
            written: 0,
            completed_files: 0,
            skipped_files: 0,
            transferred_bytes: 0,
            advertised_total_bytes: 0,
        };
        receiver.send_receiver_init(1);
        receiver
    }

    pub fn next_action(&mut self) -> Option<ZmodemReceiverAction> {
        self.actions.pop_front()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, ReceiverState::Terminal)
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self.state {
            ReceiverState::AwaitAcceptance
            | ReceiverState::AwaitSink { .. }
            | ReceiverState::Terminal => None,
            _ => Some(self.config.timeout),
        }
    }

    pub fn push_serial_bytes(&mut self, bytes: &[u8]) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.wire.push(bytes)?;
        self.pump();
        Ok(())
    }

    pub fn accept_file(&mut self) -> Result<(), ZmodemError> {
        if !matches!(self.state, ReceiverState::AwaitAcceptance) {
            return Err(ZmodemError::InvalidState);
        }
        let Some(metadata) = self.current.clone() else {
            return Err(ZmodemError::InvalidState);
        };
        self.written = 0;
        self.queue_receiver_action(ZmodemReceiverAction::BeginFile {
            file_index: self.file_index,
            metadata: metadata.clone(),
        });
        self.queue_receiver_action(ZmodemReceiverAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: usize::try_from(metadata.files_remaining.unwrap_or(0)).unwrap_or(0),
            transferred_bytes: 0,
            total_bytes: metadata.total_bytes,
            stage: ZmodemProgressStage::Header,
        }));
        self.send_receiver_position(1);
        self.pump();
        Ok(())
    }

    pub fn skip_file(&mut self) -> Result<(), ZmodemError> {
        if !matches!(self.state, ReceiverState::AwaitAcceptance) {
            return Err(ZmodemError::InvalidState);
        }
        self.queue_receiver_action(ZmodemReceiverAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::new(ZmodemFrameType::Skip, [0; 4]),
        )));
        self.current = None;
        self.skipped_files += 1;
        self.file_index += 1;
        self.send_receiver_init(1);
        self.pump();
        Ok(())
    }

    pub fn confirm_file_write(&mut self, written_bytes: usize) -> Result<(), ZmodemError> {
        let (exact_bytes, frame_end, checksum, attempts) = match self.state {
            ReceiverState::AwaitSink {
                exact_bytes,
                frame_end,
                checksum,
                attempts,
            } => (exact_bytes, frame_end, checksum, attempts),
            _ => return Err(ZmodemError::InvalidState),
        };
        if written_bytes != exact_bytes {
            let error = ZmodemError::SinkLengthMismatch {
                expected: exact_bytes,
                actual: written_bytes,
            };
            self.fail(error.clone());
            return Err(error);
        }
        self.written += written_bytes as u64;
        let total_bytes = self
            .current
            .as_ref()
            .map(|metadata| metadata.total_bytes)
            .ok_or(ZmodemError::InvalidState)?;
        if self.written > total_bytes {
            self.fail(ZmodemError::IncompleteFile);
            return Ok(());
        }
        self.queue_receiver_action(ZmodemReceiverAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: self.current_file_count_hint(),
            transferred_bytes: self.written,
            total_bytes,
            stage: if frame_end.ends_frame() {
                ZmodemProgressStage::Finalizing
            } else {
                ZmodemProgressStage::Data
            },
        }));
        if frame_end.expects_ack() {
            self.queue_receiver_action(ZmodemReceiverAction::Write(encode_zmodem_hex_header(
                ZmodemHeader::with_offset(
                    ZmodemFrameType::Ack,
                    u32::try_from(self.written).unwrap_or(u32::MAX),
                ),
            )));
        }
        self.state = if frame_end.ends_frame() {
            ReceiverState::AwaitEndOfFile { attempts }
        } else {
            ReceiverState::AwaitData { checksum, attempts }
        };
        self.pump();
        Ok(())
    }

    pub fn on_timeout(&mut self) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.wire.reset();
        match self.state {
            ReceiverState::AwaitHeader { attempts } => self.retry_receiver_init(attempts),
            ReceiverState::AwaitSenderInitData { attempts, .. }
            | ReceiverState::AwaitMetadata { attempts, .. } => {
                if attempts >= self.config.retry_limit {
                    self.fail(ZmodemError::RetryLimit);
                } else {
                    self.queue_receiver_action(ZmodemReceiverAction::Write(
                        encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::Nak, [0; 4])),
                    ));
                    self.state = ReceiverState::AwaitHeader {
                        attempts: attempts + 1,
                    };
                }
            }
            ReceiverState::AwaitDataHeader { attempts }
            | ReceiverState::AwaitData { attempts, .. }
            | ReceiverState::AwaitEndOfFile { attempts } => self.retry_receiver_position(attempts),
            ReceiverState::AwaitOverAndOut { attempts } => self.retry_finish(attempts),
            ReceiverState::AwaitAcceptance | ReceiverState::AwaitSink { .. } => {
                return Err(ZmodemError::InvalidState);
            }
            ReceiverState::Terminal => return Err(ZmodemError::InvalidState),
        }
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), ZmodemError> {
        if self.is_terminal() {
            return Err(ZmodemError::InvalidState);
        }
        self.queue_receiver_action(ZmodemReceiverAction::Write(
            ZMODEM_CANCEL_SEQUENCE.to_vec().into(),
        ));
        self.fail(ZmodemError::Cancelled);
        Ok(())
    }

    fn pump(&mut self) {
        loop {
            if self.is_terminal() || self.actions.len() >= MAX_ZMODEM_PENDING_ACTIONS {
                break;
            }
            let progressed = match self.state {
                ReceiverState::AwaitHeader { .. }
                | ReceiverState::AwaitDataHeader { .. }
                | ReceiverState::AwaitEndOfFile { .. } => self.pump_header(),
                ReceiverState::AwaitSenderInitData { checksum, .. }
                | ReceiverState::AwaitMetadata { checksum, .. }
                | ReceiverState::AwaitData { checksum, .. } => self.pump_subpacket(checksum),
                ReceiverState::AwaitOverAndOut { .. } => self.pump_over_and_out(),
                ReceiverState::AwaitAcceptance
                | ReceiverState::AwaitSink { .. }
                | ReceiverState::Terminal => false,
            };
            if !progressed {
                break;
            }
        }
    }

    fn pump_header(&mut self) -> bool {
        match self.wire.next_header() {
            Ok(Some(decoded)) => {
                self.handle_receiver_header(decoded);
                true
            }
            Ok(None) => false,
            Err(ZmodemError::RemoteCancelled) => {
                self.fail(ZmodemError::RemoteCancelled);
                false
            }
            Err(ZmodemError::CrcMismatch | ZmodemError::InvalidHeader) => {
                self.recover_corrupt_input();
                false
            }
            Err(error) => {
                self.fail(error);
                false
            }
        }
    }

    fn pump_subpacket(&mut self, checksum: ZmodemChecksum) -> bool {
        match self.wire.next_subpacket(checksum) {
            Ok(Some(packet)) => {
                self.handle_receiver_subpacket(packet, checksum);
                true
            }
            Ok(None) => false,
            Err(ZmodemError::CrcMismatch | ZmodemError::InvalidEscape) => {
                self.recover_corrupt_input();
                false
            }
            Err(ZmodemError::RemoteCancelled) => {
                self.fail(ZmodemError::RemoteCancelled);
                false
            }
            Err(error) => {
                self.fail(error);
                false
            }
        }
    }

    fn pump_over_and_out(&mut self) -> bool {
        match self.wire.next_over_and_out() {
            Ok(true) => {
                self.complete_batch();
                true
            }
            Ok(false) => false,
            Err(error) => {
                self.fail(error);
                false
            }
        }
    }

    fn handle_receiver_header(&mut self, decoded: ZmodemDecodedHeader) {
        let header = decoded.header;
        if matches!(
            header.frame_type,
            ZmodemFrameType::Abort | ZmodemFrameType::FileError
        ) {
            self.fail(ZmodemError::RemoteAborted);
            return;
        }
        match self.state {
            ReceiverState::AwaitHeader { attempts } => match header.frame_type {
                ZmodemFrameType::RequestInit => self.send_receiver_init(attempts),
                ZmodemFrameType::SenderInit => {
                    self.state = ReceiverState::AwaitSenderInitData {
                        checksum: decoded.checksum,
                        attempts,
                    }
                }
                ZmodemFrameType::File => {
                    self.state = ReceiverState::AwaitMetadata {
                        checksum: decoded.checksum,
                        attempts,
                    }
                }
                ZmodemFrameType::Finish => self.send_finish(1),
                ZmodemFrameType::Challenge => {
                    self.queue_receiver_action(ZmodemReceiverAction::Write(
                        encode_zmodem_hex_header(ZmodemHeader::new(
                            ZmodemFrameType::Ack,
                            header.parameters,
                        )),
                    ));
                }
                _ => self.state = ReceiverState::AwaitHeader { attempts },
            },
            ReceiverState::AwaitDataHeader { attempts } => match header.frame_type {
                ZmodemFrameType::Data if header.offset() as u64 == self.written => {
                    self.state = ReceiverState::AwaitData {
                        checksum: decoded.checksum,
                        attempts,
                    }
                }
                ZmodemFrameType::EndOfFile => self.handle_end_of_file(header.offset() as u64),
                ZmodemFrameType::Data => self.retry_receiver_position(attempts),
                _ => self.state = ReceiverState::AwaitDataHeader { attempts },
            },
            ReceiverState::AwaitEndOfFile { attempts } => match header.frame_type {
                ZmodemFrameType::EndOfFile => self.handle_end_of_file(header.offset() as u64),
                ZmodemFrameType::Data if header.offset() as u64 == self.written => {
                    self.state = ReceiverState::AwaitData {
                        checksum: decoded.checksum,
                        attempts,
                    }
                }
                _ => self.state = ReceiverState::AwaitEndOfFile { attempts },
            },
            _ => self.fail(ZmodemError::UnexpectedFrame),
        }
    }

    fn handle_receiver_subpacket(&mut self, packet: ZmodemSubpacket, checksum: ZmodemChecksum) {
        match self.state {
            ReceiverState::AwaitSenderInitData { attempts, .. } => {
                if packet.frame_end.expects_ack() {
                    self.queue_receiver_action(ZmodemReceiverAction::Write(
                        encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::Ack, [0; 4])),
                    ));
                }
                self.state = ReceiverState::AwaitHeader { attempts };
            }
            ReceiverState::AwaitMetadata { .. } => {
                if !packet.frame_end.ends_frame() {
                    self.fail(ZmodemError::InvalidMetadata);
                    return;
                }
                match parse_zmodem_file_metadata(packet.payload.as_slice()) {
                    Ok(metadata) => {
                        if self.file_index >= MAX_ZMODEM_BATCH_FILES {
                            self.fail(ZmodemError::InvalidBatch {
                                maximum_files: MAX_ZMODEM_BATCH_FILES,
                            });
                            return;
                        }
                        self.advertised_total_bytes = self
                            .advertised_total_bytes
                            .saturating_add(metadata.total_bytes);
                        self.current = Some(metadata.clone());
                        self.queue_receiver_action(ZmodemReceiverAction::OfferFile {
                            file_index: self.file_index,
                            metadata,
                        });
                        self.state = ReceiverState::AwaitAcceptance;
                    }
                    Err(error) => self.fail(error),
                }
            }
            ReceiverState::AwaitData { attempts, .. } => {
                let total_bytes = match self.current.as_ref() {
                    Some(metadata) => metadata.total_bytes,
                    None => {
                        self.fail(ZmodemError::InvalidState);
                        return;
                    }
                };
                if self.written.saturating_add(packet.payload.len() as u64) > total_bytes {
                    self.fail(ZmodemError::IncompleteFile);
                    return;
                }
                let exact_bytes = packet.payload.len();
                let frame_end = packet.frame_end;
                self.queue_receiver_action(ZmodemReceiverAction::WriteFile {
                    file_index: self.file_index,
                    offset: self.written,
                    bytes: packet.payload,
                });
                self.state = ReceiverState::AwaitSink {
                    exact_bytes,
                    frame_end,
                    checksum,
                    attempts,
                };
            }
            _ => self.fail(ZmodemError::UnexpectedFrame),
        }
    }

    fn send_receiver_init(&mut self, attempts: u32) {
        let flags = ZRINIT_CANFDX | ZRINIT_CANOVIO | ZRINIT_CANFC32 | ZRINIT_ESCCTL;
        self.queue_receiver_action(ZmodemReceiverAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::new(ZmodemFrameType::ReceiverInit, [0, 0, 0, flags]),
        )));
        self.state = ReceiverState::AwaitHeader { attempts };
    }

    fn retry_receiver_init(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::TimedOut);
        } else {
            self.send_receiver_init(attempts + 1);
        }
    }

    fn send_receiver_position(&mut self, attempts: u32) {
        let Some(offset) = u32::try_from(self.written).ok() else {
            self.fail(ZmodemError::FileTooLarge {
                maximum_bytes: u32::MAX as u64,
            });
            return;
        };
        self.queue_receiver_action(ZmodemReceiverAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::with_offset(ZmodemFrameType::ReceiverPosition, offset),
        )));
        self.state = ReceiverState::AwaitDataHeader { attempts };
    }

    fn retry_receiver_position(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::RetryLimit);
        } else {
            self.send_receiver_position(attempts + 1);
        }
    }

    fn recover_corrupt_input(&mut self) {
        self.wire.reset();
        match self.state {
            ReceiverState::AwaitDataHeader { attempts }
            | ReceiverState::AwaitData { attempts, .. }
            | ReceiverState::AwaitEndOfFile { attempts } => self.retry_receiver_position(attempts),
            ReceiverState::AwaitHeader { attempts }
            | ReceiverState::AwaitSenderInitData { attempts, .. }
            | ReceiverState::AwaitMetadata { attempts, .. } => {
                if attempts >= self.config.retry_limit {
                    self.fail(ZmodemError::RetryLimit);
                } else {
                    self.send_receiver_init(attempts + 1);
                }
            }
            _ => self.fail(ZmodemError::CrcMismatch),
        }
    }

    fn handle_end_of_file(&mut self, offset: u64) {
        let Some(metadata) = self.current.take() else {
            self.fail(ZmodemError::InvalidState);
            return;
        };
        if offset != self.written || self.written != metadata.total_bytes {
            self.current = Some(metadata);
            self.retry_receiver_position(1);
            return;
        }
        self.completed_files += 1;
        self.transferred_bytes = self.transferred_bytes.saturating_add(self.written);
        self.queue_receiver_action(ZmodemReceiverAction::Progress(ZmodemProgress {
            file_index: self.file_index,
            file_count: self.current_file_count_hint_from(&metadata),
            transferred_bytes: self.written,
            total_bytes: metadata.total_bytes,
            stage: ZmodemProgressStage::Complete,
        }));
        self.queue_receiver_action(ZmodemReceiverAction::FileCompleted(ZmodemFileSummary {
            file_index: self.file_index,
            total_bytes: metadata.total_bytes,
            transferred_bytes: self.written,
        }));
        self.file_index += 1;
        self.written = 0;
        self.send_receiver_init(1);
    }

    fn send_finish(&mut self, attempts: u32) {
        self.queue_receiver_action(ZmodemReceiverAction::Write(encode_zmodem_hex_header(
            ZmodemHeader::new(ZmodemFrameType::Finish, [0; 4]),
        )));
        self.state = ReceiverState::AwaitOverAndOut { attempts };
    }

    fn retry_finish(&mut self, attempts: u32) {
        if attempts >= self.config.retry_limit {
            self.fail(ZmodemError::TimedOut);
        } else {
            self.send_finish(attempts + 1);
        }
    }

    fn complete_batch(&mut self) {
        let terminal_bytes = self.wire.take_success_remainder();
        self.queue_receiver_action(ZmodemReceiverAction::BatchCompleted {
            summary: ZmodemBatchSummary {
                file_count: self.file_index,
                completed_files: self.completed_files,
                skipped_files: self.skipped_files,
                total_bytes: self.advertised_total_bytes,
                transferred_bytes: self.transferred_bytes,
            },
            terminal_bytes,
        });
        self.state = ReceiverState::Terminal;
    }

    fn current_file_count_hint(&self) -> usize {
        self.current
            .as_ref()
            .map(|metadata| self.current_file_count_hint_from(metadata))
            .unwrap_or(0)
    }

    fn current_file_count_hint_from(&self, metadata: &ZmodemFileMetadata) -> usize {
        metadata
            .files_remaining
            .and_then(|remaining| usize::try_from(remaining).ok())
            .map(|remaining| self.file_index.saturating_add(remaining))
            .unwrap_or(0)
    }

    fn queue_receiver_action(&mut self, action: ZmodemReceiverAction) -> bool {
        if self.actions.len() >= MAX_ZMODEM_PENDING_ACTIONS {
            self.actions.clear();
            self.actions
                .push_back(ZmodemReceiverAction::Failed(ZmodemError::ActionQueueFull {
                    maximum: MAX_ZMODEM_PENDING_ACTIONS,
                }));
            self.state = ReceiverState::Terminal;
            false
        } else {
            self.actions.push_back(action);
            true
        }
    }

    fn fail(&mut self, error: ZmodemError) {
        self.queue_receiver_action(ZmodemReceiverAction::Failed(error));
        self.state = ReceiverState::Terminal;
    }
}

impl fmt::Debug for ZmodemReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZmodemReceiver")
            .field("phase", &receiver_phase(&self.state))
            .field("file_index", &self.file_index)
            .field("written", &self.written)
            .field("queued_actions", &self.actions.len())
            .finish()
    }
}

fn receiver_phase(state: &ReceiverState) -> &'static str {
    match state {
        ReceiverState::AwaitHeader { .. } => "await-header",
        ReceiverState::AwaitSenderInitData { .. } => "await-sender-init-data",
        ReceiverState::AwaitMetadata { .. } => "await-metadata",
        ReceiverState::AwaitAcceptance => "await-acceptance",
        ReceiverState::AwaitDataHeader { .. } => "await-data-header",
        ReceiverState::AwaitData { .. } => "await-data",
        ReceiverState::AwaitSink { .. } => "await-sink",
        ReceiverState::AwaitEndOfFile { .. } => "await-end-of-file",
        ReceiverState::AwaitOverAndOut { .. } => "await-over-and-out",
        ReceiverState::Terminal => "terminal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(name: &str, total_bytes: u64) -> ZmodemFileMetadata {
        ZmodemFileMetadata::new(name, total_bytes, 0o123456, 0o644).unwrap()
    }

    fn drain_sender(sender: &mut ZmodemSender) -> Vec<ZmodemSenderAction> {
        std::iter::from_fn(|| sender.next_action()).collect()
    }

    fn drain_receiver(receiver: &mut ZmodemReceiver) -> Vec<ZmodemReceiverAction> {
        std::iter::from_fn(|| receiver.next_action()).collect()
    }

    fn sender_writes(actions: &[ZmodemSenderAction]) -> Vec<ZmodemBytes> {
        actions
            .iter()
            .filter_map(|action| match action {
                ZmodemSenderAction::Write(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    fn receiver_writes(actions: &[ZmodemReceiverAction]) -> Vec<ZmodemBytes> {
        actions
            .iter()
            .filter_map(|action| match action {
                ZmodemReceiverAction::Write(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    fn deliver_sender_writes(receiver: &mut ZmodemReceiver, actions: &[ZmodemSenderAction]) {
        for bytes in sender_writes(actions) {
            receiver.push_serial_bytes(bytes.as_slice()).unwrap();
        }
    }

    fn deliver_receiver_writes(sender: &mut ZmodemSender, actions: &[ZmodemReceiverAction]) {
        for bytes in receiver_writes(actions) {
            sender.push_serial_bytes(bytes.as_slice()).unwrap();
        }
    }

    #[test]
    fn crc_vectors_match_zmodem_variants() {
        assert_eq!(crc16_zmodem(b"123456789"), 0x31c3);
        assert_eq!(crc32_zmodem(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc16_zmodem(&[0; 5]), 0);
    }

    #[test]
    fn hex_and_binary_headers_decode_across_every_split() {
        let header = ZmodemHeader::with_offset(ZmodemFrameType::ReceiverPosition, 0x1122_3344);
        let encodings = [
            encode_zmodem_hex_header(header),
            encode_zmodem_binary_header(header, ZmodemChecksum::Crc16, true),
            encode_zmodem_binary_header(header, ZmodemChecksum::Crc32, true),
        ];

        for encoding in encodings {
            for split in 0..=encoding.len() {
                let expected_checksum = if encoding.as_slice().starts_with(&BINARY32_HEADER_PREFIX)
                {
                    ZmodemChecksum::Crc32
                } else {
                    ZmodemChecksum::Crc16
                };
                let mut decoder = ZmodemWireDecoder::default();
                decoder.push(&encoding.as_slice()[..split]).unwrap();
                let first = decoder.next_header().unwrap();
                if split < encoding.len() {
                    decoder.push(&encoding.as_slice()[split..]).unwrap();
                }
                assert_eq!(
                    first.or(decoder.next_header().unwrap()),
                    Some(ZmodemDecodedHeader {
                        header,
                        checksum: expected_checksum,
                    }),
                    "split {split}"
                );
                let _ = decoder.next_header().unwrap();
                assert_eq!(decoder.buffered_len(), 0);
            }
        }
    }

    #[test]
    fn header_decoder_ignores_leading_terminal_text_and_rejects_bad_crc() {
        let header =
            encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::RequestInit, [0; 4]));
        let mut wire = b"shell output\r\n".to_vec();
        wire.extend_from_slice(header.as_slice());
        let mut decoder = ZmodemWireDecoder::default();
        decoder.push(&wire).unwrap();
        assert_eq!(
            decoder.next_header().unwrap().unwrap().header.frame_type,
            ZmodemFrameType::RequestInit
        );

        let mut corrupt = header.into_vec();
        corrupt[5] = if corrupt[5] == b'0' { b'1' } else { b'0' };
        decoder.push(&corrupt).unwrap();
        assert_eq!(decoder.next_header(), Err(ZmodemError::CrcMismatch));
    }

    #[test]
    fn sentry_preserves_prefix_and_detects_crc_valid_directions_across_splits() {
        for (frame_type, direction) in [
            (ZmodemFrameType::ReceiverInit, ZmodemTransferDirection::Send),
            (
                ZmodemFrameType::RequestInit,
                ZmodemTransferDirection::Receive,
            ),
        ] {
            let header = encode_zmodem_hex_header(ZmodemHeader::new(frame_type, [0; 4]));
            for split in 0..header.len() {
                let mut sentry = ZmodemSentry::default();
                let mut first = b"ordinary terminal\r\n".to_vec();
                first.extend_from_slice(&header.as_slice()[..split]);
                let first_output = sentry.push(&first).unwrap();
                assert_eq!(
                    first_output.passthrough.as_slice(),
                    b"ordinary terminal\r\n"
                );
                if let Some(detected) = first_output.detected {
                    assert_eq!(detected.direction, direction);
                    assert_eq!(
                        detected.protocol_bytes.as_slice(),
                        &header.as_slice()[..split]
                    );
                    continue;
                }

                let mut second = header.as_slice()[split..].to_vec();
                second.extend_from_slice(b"following-protocol-bytes");
                let detected = sentry.push(&second).unwrap().detected.unwrap();
                assert_eq!(detected.direction, direction);
                let mut expected = header.as_slice().to_vec();
                expected.extend_from_slice(b"following-protocol-bytes");
                assert_eq!(detected.protocol_bytes.as_slice(), expected);
                assert_eq!(sentry.buffered_len(), 0);
            }
        }
    }

    #[test]
    fn sentry_never_suppresses_bad_crc_or_unrelated_headers() {
        let unrelated =
            encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::Ack, [1, 2, 3, 4]));
        let mut bad =
            encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::ReceiverInit, [0; 4]))
                .into_vec();
        bad[8] = if bad[8] == b'0' { b'1' } else { b'0' };
        let mut wire = unrelated.into_vec();
        wire.extend_from_slice(&bad);
        wire.extend_from_slice(b"tail");

        let mut sentry = ZmodemSentry::default();
        let output = sentry.push(&wire).unwrap();
        assert!(output.detected.is_none());
        assert_eq!(output.passthrough.as_slice(), wire);
        assert_eq!(sentry.buffered_len(), 0);
    }

    #[test]
    fn sentry_debug_redacts_protocol_and_reset_returns_fragment() {
        let mut sentry = ZmodemSentry::default();
        let output = sentry.push(b"secret terminal *").unwrap();
        assert_eq!(output.passthrough.as_slice(), b"secret terminal ");
        assert_eq!(sentry.buffered_len(), 1);
        assert!(!format!("{sentry:?}").contains("secret"));
        assert_eq!(sentry.reset().as_slice(), b"*");
    }

    #[test]
    fn subpacket_round_trips_all_control_bytes_with_crc16_and_crc32() {
        let payload: Vec<u8> = (0..=255).collect();
        for checksum in [ZmodemChecksum::Crc16, ZmodemChecksum::Crc32] {
            for frame_end in [
                ZmodemFrameEnd::EndNoAck,
                ZmodemFrameEnd::ContinueNoAck,
                ZmodemFrameEnd::ContinueAck,
                ZmodemFrameEnd::EndAck,
            ] {
                let encoded = encode_zmodem_subpacket(&payload, frame_end, checksum, true).unwrap();
                let mut decoder = ZmodemWireDecoder::default();
                for chunk in encoded.as_slice().chunks(7) {
                    decoder.push(chunk).unwrap();
                }
                assert_eq!(
                    decoder.next_subpacket(checksum).unwrap(),
                    Some(ZmodemSubpacket {
                        payload: payload.clone().into(),
                        frame_end,
                    })
                );
                assert_eq!(decoder.buffered_len(), 0);
            }
        }
    }

    #[test]
    fn unescaped_transport_flow_control_bytes_are_ignored() {
        let header = encode_zmodem_binary_header(
            ZmodemHeader::with_offset(ZmodemFrameType::Data, 7),
            ZmodemChecksum::Crc16,
            true,
        );
        let mut noisy_header = header.into_vec();
        noisy_header.insert(4, 0x13);
        noisy_header.insert(7, 0x91);
        let mut decoder = ZmodemWireDecoder::default();
        decoder.push(&noisy_header).unwrap();
        assert_eq!(decoder.next_header().unwrap().unwrap().header.offset(), 7);

        let packet = encode_zmodem_subpacket(
            b"payload",
            ZmodemFrameEnd::EndNoAck,
            ZmodemChecksum::Crc16,
            true,
        );
        let mut noisy_packet = packet.unwrap().into_vec();
        noisy_packet.insert(2, 0x11);
        noisy_packet.insert(5, 0x93);
        decoder.push(&noisy_packet).unwrap();
        assert_eq!(
            decoder
                .next_subpacket(ZmodemChecksum::Crc16)
                .unwrap()
                .unwrap()
                .payload
                .as_slice(),
            b"payload"
        );
    }

    #[test]
    fn corrupt_subpacket_is_consumed_and_reported_without_payload_disclosure() {
        let mut encoded = encode_zmodem_subpacket(
            b"secret body",
            ZmodemFrameEnd::EndNoAck,
            ZmodemChecksum::Crc16,
            true,
        )
        .unwrap()
        .into_vec();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let mut decoder = ZmodemWireDecoder::default();
        decoder.push(&encoded).unwrap();
        assert_eq!(
            decoder.next_subpacket(ZmodemChecksum::Crc16),
            Err(ZmodemError::CrcMismatch)
        );
        assert_eq!(decoder.buffered_len(), 0);
        assert!(!format!("{:?}", ZmodemError::CrcMismatch).contains("secret"));
    }

    #[test]
    fn metadata_is_bounded_sanitized_and_round_trips_batch_hints() {
        let source = metadata("../../private\\report?.txt", 1234);
        assert_eq!(source.file_name(), "report_.txt");
        let encoded = encode_zmodem_file_metadata(&source, 3, 5678).unwrap();
        let decoded = parse_zmodem_file_metadata(encoded.as_slice()).unwrap();
        assert_eq!(decoded.file_name(), "report_.txt");
        assert_eq!(decoded.total_bytes(), 1234);
        assert_eq!(decoded.modified_time(), 0o123456);
        assert_eq!(decoded.mode() & 0o7777, 0o644);
        assert_eq!(decoded.files_remaining(), Some(3));
        assert_eq!(decoded.bytes_remaining(), Some(5678));
        assert!(!format!("{decoded:?}").contains("report"));

        let long_name = "x".repeat(MAX_ZMODEM_FILENAME_BYTES + 1);
        assert_eq!(
            ZmodemFileMetadata::new(long_name, 0, 0, 0),
            Err(ZmodemError::FilenameTooLong {
                maximum_bytes: MAX_ZMODEM_FILENAME_BYTES,
            })
        );
        assert_eq!(
            ZmodemFileMetadata::new("large", MAX_ZMODEM_FILE_BYTES + 1, 0, 0),
            Err(ZmodemError::FileTooLarge {
                maximum_bytes: MAX_ZMODEM_FILE_BYTES,
            })
        );
        assert_eq!(
            parse_zmodem_file_metadata(b"file\000 0 0 0 1025 0\0"),
            Err(ZmodemError::InvalidBatch {
                maximum_files: MAX_ZMODEM_BATCH_FILES,
            })
        );
    }

    #[test]
    fn input_and_subpacket_memory_are_bounded() {
        let mut decoder = ZmodemWireDecoder::default();
        assert_eq!(
            decoder.push(&vec![0; MAX_ZMODEM_INPUT_BYTES + 1]),
            Err(ZmodemError::InputTooLarge {
                maximum_bytes: MAX_ZMODEM_INPUT_BYTES,
            })
        );
        assert_eq!(decoder.buffered_len(), 0);
        assert_eq!(
            encode_zmodem_subpacket(
                &vec![0; MAX_ZMODEM_SUBPACKET_BYTES + 1],
                ZmodemFrameEnd::EndNoAck,
                ZmodemChecksum::Crc16,
                true,
            ),
            Err(ZmodemError::SubpacketTooLarge {
                maximum_bytes: MAX_ZMODEM_SUBPACKET_BYTES,
            })
        );
    }

    #[test]
    fn one_file_streams_end_to_end_without_paths_or_whole_file_actions() {
        let body = b"hello \x00\x11\x18 zmodem".to_vec();
        let mut sender = ZmodemSender::new(
            vec![metadata("hello.bin", body.len() as u64)],
            ZmodemConfig::default(),
        )
        .unwrap();
        let mut receiver = ZmodemReceiver::new(ZmodemConfig::default());

        let receiver_start = drain_receiver(&mut receiver);
        deliver_receiver_writes(&mut sender, &receiver_start);
        let offer = drain_sender(&mut sender);
        assert!(offer.iter().any(|action| matches!(
            action,
            ZmodemSenderAction::Progress(ZmodemProgress {
                stage: ZmodemProgressStage::Header,
                ..
            })
        )));
        deliver_sender_writes(&mut receiver, &offer);
        let offered = drain_receiver(&mut receiver);
        assert!(offered.iter().any(|action| matches!(
            action,
            ZmodemReceiverAction::OfferFile { file_index: 0, metadata }
                if metadata.file_name() == "hello.bin"
        )));

        receiver.accept_file().unwrap();
        let accepted = drain_receiver(&mut receiver);
        deliver_receiver_writes(&mut sender, &accepted);
        let request = drain_sender(&mut sender);
        assert!(request.iter().any(|action| matches!(
            action,
            ZmodemSenderAction::ReadSource {
                file_index: 0,
                offset: 0,
                maximum_bytes,
            } if *maximum_bytes == body.len()
        )));
        deliver_sender_writes(&mut receiver, &request);

        sender.provide_source_chunk(&body).unwrap();
        let sent = drain_sender(&mut sender);
        deliver_sender_writes(&mut receiver, &sent);
        let write = drain_receiver(&mut receiver);
        let received = write.iter().find_map(|action| match action {
            ZmodemReceiverAction::WriteFile { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        });
        assert_eq!(received, Some(body.as_slice()));
        receiver.confirm_file_write(body.len()).unwrap();
        let file_done = drain_receiver(&mut receiver);
        assert!(file_done.iter().any(|action| matches!(
            action,
            ZmodemReceiverAction::FileCompleted(ZmodemFileSummary {
                file_index: 0,
                transferred_bytes,
                ..
            }) if *transferred_bytes == body.len() as u64
        )));

        deliver_receiver_writes(&mut sender, &file_done);
        let sender_finish = drain_sender(&mut sender);
        assert!(
            sender_finish
                .iter()
                .any(|action| matches!(action, ZmodemSenderAction::FileCompleted(_)))
        );
        deliver_sender_writes(&mut receiver, &sender_finish);
        let receiver_finish = drain_receiver(&mut receiver);
        let sender_prompt = b"\r\nreceiver-shell$ ";
        for bytes in receiver_writes(&receiver_finish) {
            let mut wire = bytes.into_vec();
            wire.extend_from_slice(sender_prompt);
            sender.push_serial_bytes(&wire).unwrap();
        }
        let sender_complete = drain_sender(&mut sender);
        assert!(sender_complete.iter().any(|action| matches!(
            action,
            ZmodemSenderAction::BatchCompleted {
                summary: ZmodemBatchSummary {
                    completed_files: 1,
                    skipped_files: 0,
                    ..
                },
                ..
            }
        )));
        assert!(sender_complete.iter().any(|action| matches!(
            action,
            ZmodemSenderAction::BatchCompleted { terminal_bytes, .. }
                if terminal_bytes.as_slice() == sender_prompt
        )));
        let receiver_prompt = b"\r\nsender-shell$ ";
        for bytes in sender_writes(&sender_complete) {
            let mut wire = bytes.into_vec();
            wire.extend_from_slice(receiver_prompt);
            receiver.push_serial_bytes(&wire).unwrap();
        }
        let receiver_complete = drain_receiver(&mut receiver);
        assert!(receiver_complete.iter().any(|action| matches!(
            action,
            ZmodemReceiverAction::BatchCompleted {
                summary: ZmodemBatchSummary {
                    completed_files: 1,
                    skipped_files: 0,
                    ..
                },
                ..
            }
        )));
        assert!(receiver_complete.iter().any(|action| matches!(
            action,
            ZmodemReceiverAction::BatchCompleted { terminal_bytes, .. }
                if terminal_bytes.as_slice() == receiver_prompt
        )));
        assert!(sender.is_terminal());
        assert!(receiver.is_terminal());
    }

    #[test]
    fn multi_file_sender_preserves_batch_metadata_and_remote_skip() {
        let mut sender = ZmodemSender::new(
            vec![metadata("first", 1), metadata("second", 2)],
            ZmodemConfig::default(),
        )
        .unwrap();
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(
                    ZmodemFrameType::ReceiverInit,
                    [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO | ZRINIT_ESCCTL],
                ))
                .as_slice(),
            )
            .unwrap();
        let first_offer = drain_sender(&mut sender);
        let first_metadata_packet = sender_writes(&first_offer).pop().unwrap();
        let mut decoder = ZmodemWireDecoder::default();
        decoder.push(first_metadata_packet.as_slice()).unwrap();
        let packet = decoder
            .next_subpacket(ZmodemChecksum::Crc16)
            .unwrap()
            .unwrap();
        let first_metadata = parse_zmodem_file_metadata(packet.payload.as_slice()).unwrap();
        assert_eq!(first_metadata.files_remaining(), Some(2));
        assert_eq!(first_metadata.bytes_remaining(), Some(3));

        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::Skip, [0; 4]))
                    .as_slice(),
            )
            .unwrap();
        let second_offer = drain_sender(&mut sender);
        assert!(
            second_offer
                .iter()
                .any(|action| matches!(action, ZmodemSenderAction::FileSkipped { file_index: 0 }))
        );
        let second_metadata_packet = sender_writes(&second_offer).pop().unwrap();
        decoder.push(second_metadata_packet.as_slice()).unwrap();
        let packet = decoder
            .next_subpacket(ZmodemChecksum::Crc16)
            .unwrap()
            .unwrap();
        let second_metadata = parse_zmodem_file_metadata(packet.payload.as_slice()).unwrap();
        assert_eq!(second_metadata.files_remaining(), Some(1));
        assert_eq!(second_metadata.bytes_remaining(), Some(2));
    }

    #[test]
    fn sender_negotiates_control_escaping_and_rejects_unsafe_peer_modes() {
        let mut sender =
            ZmodemSender::new(vec![metadata("file", 1)], ZmodemConfig::default()).unwrap();
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(
                    ZmodemFrameType::ReceiverInit,
                    [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO],
                ))
                .as_slice(),
            )
            .unwrap();
        let sender_init = drain_sender(&mut sender);
        assert_eq!(sender_phase(&sender.state), "await-sender-init-ack");
        assert_eq!(sender_writes(&sender_init).len(), 2);
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(ZmodemFrameType::Ack, [0; 4]))
                    .as_slice(),
            )
            .unwrap();
        assert!(drain_sender(&mut sender).iter().any(|action| matches!(
            action,
            ZmodemSenderAction::Progress(ZmodemProgress {
                stage: ZmodemProgressStage::Header,
                ..
            })
        )));

        for parameters in [
            [0, 0, 0, ZRINIT_CANOVIO],
            [0, 0, 0, ZRINIT_CANFDX],
            [1, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO],
            [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO | 0x80],
        ] {
            let mut sender =
                ZmodemSender::new(vec![metadata("file", 1)], ZmodemConfig::default()).unwrap();
            sender
                .push_serial_bytes(
                    encode_zmodem_hex_header(ZmodemHeader::new(
                        ZmodemFrameType::ReceiverInit,
                        parameters,
                    ))
                    .as_slice(),
                )
                .unwrap();
            assert_eq!(
                drain_sender(&mut sender),
                vec![ZmodemSenderAction::Failed(
                    ZmodemError::UnsupportedPeerCapabilities
                )]
            );
        }
    }

    #[test]
    fn receiver_requests_last_committed_offset_after_corrupt_data() {
        let mut receiver = ZmodemReceiver::new(ZmodemConfig::default());
        drain_receiver(&mut receiver);
        let file_header = encode_zmodem_binary_header(
            ZmodemHeader::new(ZmodemFrameType::File, [0, 0, 0, 1]),
            ZmodemChecksum::Crc16,
            true,
        );
        let metadata_packet = encode_zmodem_subpacket(
            encode_zmodem_file_metadata(&metadata("file", 4), 1, 4)
                .unwrap()
                .as_slice(),
            ZmodemFrameEnd::EndAck,
            ZmodemChecksum::Crc16,
            true,
        )
        .unwrap();
        receiver.push_serial_bytes(file_header.as_slice()).unwrap();
        receiver
            .push_serial_bytes(metadata_packet.as_slice())
            .unwrap();
        drain_receiver(&mut receiver);
        receiver.accept_file().unwrap();
        drain_receiver(&mut receiver);
        receiver
            .push_serial_bytes(
                encode_zmodem_binary_header(
                    ZmodemHeader::with_offset(ZmodemFrameType::Data, 0),
                    ZmodemChecksum::Crc16,
                    true,
                )
                .as_slice(),
            )
            .unwrap();
        let mut corrupt = encode_zmodem_subpacket(
            b"data",
            ZmodemFrameEnd::EndNoAck,
            ZmodemChecksum::Crc16,
            true,
        )
        .unwrap()
        .into_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        receiver.push_serial_bytes(&corrupt).unwrap();
        let retry = drain_receiver(&mut receiver);
        let write = receiver_writes(&retry).pop().expect("ZRPOS retry");
        let mut decoder = ZmodemWireDecoder::default();
        decoder.push(write.as_slice()).unwrap();
        let header = decoder.next_header().unwrap().unwrap().header;
        assert_eq!(header.frame_type, ZmodemFrameType::ReceiverPosition);
        assert_eq!(header.offset(), 0);
    }

    #[test]
    fn sender_resumes_from_receiver_position_without_buffering_prior_data() {
        let mut sender =
            ZmodemSender::new(vec![metadata("large", 100)], ZmodemConfig::default()).unwrap();
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(
                    ZmodemFrameType::ReceiverInit,
                    [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO | ZRINIT_ESCCTL],
                ))
                .as_slice(),
            )
            .unwrap();
        drain_sender(&mut sender);
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::with_offset(
                    ZmodemFrameType::ReceiverPosition,
                    40,
                ))
                .as_slice(),
            )
            .unwrap();
        let actions = drain_sender(&mut sender);
        assert!(actions.iter().any(|action| matches!(
            action,
            ZmodemSenderAction::ReadSource {
                offset: 40,
                maximum_bytes: 60,
                ..
            }
        )));
    }

    #[test]
    fn sixty_four_kib_source_reads_are_split_into_legacy_eight_kib_subpackets() {
        let body = vec![0xa5; DEFAULT_ZMODEM_CHUNK_BYTES];
        let mut sender = ZmodemSender::new(
            vec![metadata("large", body.len() as u64)],
            ZmodemConfig::default(),
        )
        .unwrap();
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(
                    ZmodemFrameType::ReceiverInit,
                    [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO | ZRINIT_ESCCTL],
                ))
                .as_slice(),
            )
            .unwrap();
        drain_sender(&mut sender);
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::with_offset(
                    ZmodemFrameType::ReceiverPosition,
                    0,
                ))
                .as_slice(),
            )
            .unwrap();
        drain_sender(&mut sender);
        sender.provide_source_chunk(&body).unwrap();
        let actions = drain_sender(&mut sender);
        let writes = sender_writes(&actions);
        let packet_count = body.len().div_ceil(ZMODEM_WIRE_SUBPACKET_BYTES);
        assert_eq!(writes.len(), packet_count + 1, "data packets plus ZEOF");

        for (index, packet) in writes[..packet_count].iter().enumerate() {
            let mut decoder = ZmodemWireDecoder::default();
            decoder.push(packet.as_slice()).unwrap();
            let decoded = decoder
                .next_subpacket(ZmodemChecksum::Crc16)
                .unwrap()
                .unwrap();
            assert_eq!(decoded.payload.len(), ZMODEM_WIRE_SUBPACKET_BYTES);
            assert_eq!(
                decoded.frame_end,
                if index + 1 == packet_count {
                    ZmodemFrameEnd::EndNoAck
                } else {
                    ZmodemFrameEnd::ContinueNoAck
                }
            );
        }
    }

    #[test]
    fn handshake_timeouts_retry_then_fail_deterministically() {
        let config = ZmodemConfig::new(Duration::from_millis(1), 2, 1024, true).unwrap();
        let mut receiver = ZmodemReceiver::new(config);
        drain_receiver(&mut receiver);
        receiver.on_timeout().unwrap();
        assert!(matches!(
            drain_receiver(&mut receiver).as_slice(),
            [ZmodemReceiverAction::Write(_)]
        ));
        receiver.on_timeout().unwrap();
        assert_eq!(
            drain_receiver(&mut receiver),
            vec![ZmodemReceiverAction::Failed(ZmodemError::TimedOut)]
        );
        assert!(receiver.is_terminal());

        let mut sender = ZmodemSender::new(vec![metadata("file", 1)], config).unwrap();
        sender.on_timeout().unwrap();
        assert!(drain_sender(&mut sender).is_empty());
        sender.on_timeout().unwrap();
        assert_eq!(
            drain_sender(&mut sender),
            vec![ZmodemSenderAction::Failed(ZmodemError::TimedOut)]
        );
    }

    #[test]
    fn local_and_remote_cancel_are_terminal_and_payload_safe() {
        let mut sender =
            ZmodemSender::new(vec![metadata("secret-name", 1)], ZmodemConfig::default()).unwrap();
        sender.cancel().unwrap();
        let actions = drain_sender(&mut sender);
        assert_eq!(
            actions,
            vec![
                ZmodemSenderAction::Write(ZMODEM_CANCEL_SEQUENCE.to_vec().into()),
                ZmodemSenderAction::Failed(ZmodemError::Cancelled),
            ]
        );
        assert!(!format!("{sender:?}").contains("secret-name"));

        let mut receiver = ZmodemReceiver::new(ZmodemConfig::default());
        drain_receiver(&mut receiver);
        receiver
            .push_serial_bytes(&[ZMODEM_CAN, ZMODEM_CAN, ZMODEM_CAN])
            .unwrap();
        receiver
            .push_serial_bytes(&[ZMODEM_CAN, ZMODEM_CAN])
            .unwrap();
        assert_eq!(
            drain_receiver(&mut receiver),
            vec![ZmodemReceiverAction::Failed(ZmodemError::RemoteCancelled)]
        );
        assert!(receiver.is_terminal());
    }

    #[test]
    fn empty_file_uses_empty_final_subpacket_and_completes() {
        let mut sender =
            ZmodemSender::new(vec![metadata("empty", 0)], ZmodemConfig::default()).unwrap();
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::new(
                    ZmodemFrameType::ReceiverInit,
                    [0, 0, 0, ZRINIT_CANFDX | ZRINIT_CANOVIO | ZRINIT_ESCCTL],
                ))
                .as_slice(),
            )
            .unwrap();
        drain_sender(&mut sender);
        sender
            .push_serial_bytes(
                encode_zmodem_hex_header(ZmodemHeader::with_offset(
                    ZmodemFrameType::ReceiverPosition,
                    0,
                ))
                .as_slice(),
            )
            .unwrap();
        let actions = drain_sender(&mut sender);
        assert_eq!(sender_phase(&sender.state), "await-post-file-init");
        assert_eq!(sender_writes(&actions).len(), 3);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, ZmodemSenderAction::ReadSource { .. }))
        );
    }
}
