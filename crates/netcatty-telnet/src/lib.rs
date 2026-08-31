//! Electron-free, Tauri-independent Telnet protocol core for Netcatty.
//!
//! The crate intentionally separates a synchronous, bounded RFC 854 codec
//! from its small Tokio transport wrapper. It does not own credentials,
//! persistence, desktop events, or UI behavior.

pub mod auto_login;
pub mod charset;
pub mod codec;
pub mod protocol;
pub mod runtime;
pub mod session;

pub use charset::TelnetCharset;
pub use codec::{
    CodecError, DEFAULT_TERMINAL_TYPE, DecodeResult, MAX_INPUT_BYTES, MAX_SUBNEGOTIATION_BYTES,
    MAX_WINDOW_DIMENSION, TelnetBytes, TelnetCodec, TelnetConfig, TelnetEvent, WindowSize,
};
pub use protocol::{command, option, suboption};
pub use runtime::{
    COMMAND_CHANNEL_CAPACITY, CONNECT_TIMEOUT, EVENT_CHANNEL_CAPACITY, MAX_HOSTNAME_BYTES,
    TelnetCloseReason, TelnetRuntimeConfig, TelnetRuntimeError, TelnetRuntimeEvent,
    TelnetRuntimeManager, TelnetRuntimeSession, TelnetSessionId,
};
pub use session::{IoOperation, SessionError, SessionRead, TelnetSession};
