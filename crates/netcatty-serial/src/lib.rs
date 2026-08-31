//! Electron-free, Tauri-independent serial-port core for Netcatty.
//!
//! The crate owns legacy-compatible serial settings, bounded port discovery,
//! character-set conversion, a bounded Tokio session runtime, and pure YMODEM
//! and ZMODEM protocol state machines. It does not own persistence, native file
//! selection, filesystem publication, desktop events, or terminal
//! local-echo/line-editing policy.

mod charset;
mod config;
mod ports;
mod runtime;
mod ymodem;
mod zmodem;

pub use charset::{SerialCharset, SerialCharsetError, SerialDecoder};
pub use config::{
    DEFAULT_BAUD_RATE, MAX_SERIAL_PATH_BYTES, SerialBackspaceBehavior, SerialConfig,
    SerialConfigError, SerialDataBits, SerialFlowControl, SerialParity, SerialStopBits,
};
pub use ports::{
    MAX_PORT_INVENTORY_ENTRIES, MAX_PORT_METADATA_BYTES, SerialPortInfo, SerialPortKind,
    list_serial_ports, list_serial_ports_async,
};
pub use runtime::{
    COMMAND_CHANNEL_CAPACITY, EVENT_CHANNEL_CAPACITY, IO_WRITE_TIMEOUT, MAX_INPUT_BYTES,
    MAX_RAW_TRANSFER_WRITE_BYTES, MAX_WINDOW_DIMENSION, OPEN_TIMEOUT,
    RAW_TRANSFER_EVENT_CHANNEL_CAPACITY, SerialBytes, SerialCloseReason, SerialErrorKind,
    SerialIoOperation, SerialRawTransfer, SerialRawTransferEvent, SerialRuntimeConfig,
    SerialRuntimeError, SerialRuntimeEvent, SerialRuntimeManager, SerialRuntimeSession,
    SerialSessionId, SerialTransferId, SerialWindowSize, ZMODEM_DETECTION_TIMEOUT,
};
pub use ymodem::{
    DEFAULT_YMODEM_RETRY_LIMIT, DEFAULT_YMODEM_TIMEOUT, MAX_YMODEM_FILE_BYTES,
    MAX_YMODEM_FILENAME_BYTES, MAX_YMODEM_INPUT_BYTES, MAX_YMODEM_RETRY_LIMIT, SerialTransferKind,
    SerialTransferLease, SerialTransferRegistry, YMODEM_ACK, YMODEM_BACKSPACE, YMODEM_CAN,
    YMODEM_CANCEL_SEQUENCE, YMODEM_CRC16, YMODEM_EOT, YMODEM_NAK, YMODEM_PACKET_SIZE_128,
    YMODEM_PACKET_SIZE_1024, YMODEM_SOH, YMODEM_STX, YmodemBytes, YmodemConfig, YmodemError,
    YmodemFileMetadata, YmodemPacketSize, YmodemProgress, YmodemProgressStage,
    YmodemReceiveFileSummary, YmodemReceiver, YmodemReceiverAction, YmodemSendSummary,
    YmodemSender, YmodemSenderAction, YmodemWireDecoder, YmodemWireEvent, crc16_xmodem,
    create_ymodem_data_packet, create_ymodem_end_session_packet, create_ymodem_file_header,
    encode_ymodem_packet, parse_ymodem_file_header, sanitize_ymodem_filename,
};
pub use zmodem::{
    DEFAULT_ZMODEM_CHUNK_BYTES, DEFAULT_ZMODEM_RETRY_LIMIT, DEFAULT_ZMODEM_TIMEOUT,
    MAX_ZMODEM_BATCH_FILES, MAX_ZMODEM_FILE_BYTES, MAX_ZMODEM_FILENAME_BYTES,
    MAX_ZMODEM_INPUT_BYTES, MAX_ZMODEM_METADATA_BYTES, MAX_ZMODEM_PENDING_ACTIONS,
    MAX_ZMODEM_RETRY_LIMIT, MAX_ZMODEM_SUBPACKET_BYTES, ZMODEM_BACKSPACE, ZMODEM_CAN,
    ZMODEM_CANCEL_SEQUENCE, ZMODEM_OVER_AND_OUT, ZMODEM_WIRE_SUBPACKET_BYTES, ZMODEM_XON,
    ZMODEM_ZBIN, ZMODEM_ZBIN32, ZMODEM_ZCRCE, ZMODEM_ZCRCG, ZMODEM_ZCRCQ, ZMODEM_ZCRCW,
    ZMODEM_ZDLE, ZMODEM_ZHEX, ZMODEM_ZPAD, ZmodemBatchSummary, ZmodemBytes, ZmodemChecksum,
    ZmodemConfig, ZmodemDecodedHeader, ZmodemDetection, ZmodemError, ZmodemFileMetadata,
    ZmodemFileSummary, ZmodemFrameEnd, ZmodemFrameType, ZmodemHeader, ZmodemProgress,
    ZmodemProgressStage, ZmodemReceiver, ZmodemReceiverAction, ZmodemSender, ZmodemSenderAction,
    ZmodemSentry, ZmodemSentryOutput, ZmodemSubpacket, ZmodemTransferDirection, ZmodemWireDecoder,
    crc16_zmodem, crc32_zmodem, encode_zmodem_binary_header, encode_zmodem_file_metadata,
    encode_zmodem_hex_header, encode_zmodem_subpacket, parse_zmodem_file_metadata,
    sanitize_zmodem_filename,
};
