//! Electron-free Mosh protocol and session primitives.
//!
//! This crate deliberately does not spawn SSH or Mosh processes itself and
//! does not depend on Tauri. A desktop adapter owns the SSH transport and the
//! native PTY, while [`MoshSessionCore`] provides the bounded, testable state
//! machine that redacts the SSH bootstrap protocol and authorizes a single
//! trusted MoshCatty launch.
//!
//! Renderer payloads may deserialize only [`MoshStartRequest`]. The external
//! executable enters through [`TrustedMoshClient`], which has no Serde
//! implementation, and `MOSH_KEY` is created only by [`MoshConnectSniffer`].

mod model;
mod parser;
mod session;

pub use model::{
    MAX_HOST_BYTES, MAX_NATIVE_PATH_BYTES, MAX_WINDOW_DIMENSION, MoshClientLaunch,
    MoshClientLaunchParts, MoshConfigError, MoshSessionConfig, MoshStartRequest, MoshWindowSize,
    TrustedMoshClient,
};
pub use parser::{
    MAX_HANDSHAKE_CHUNK_BYTES, MAX_PENDING_HANDSHAKE_BYTES, MAX_PROTOCOL_LINE_BYTES, MoshConnect,
    MoshConnectSniffer, MoshKey, MoshParserError, SniffedHandshake,
};
pub use session::{
    MAX_ACTION_QUEUE_ENTRIES, MAX_CLIENT_OUTPUT_CHUNK_BYTES, MAX_EVENT_QUEUE_ENTRIES,
    MAX_INPUT_FRAME_BYTES, MAX_PENDING_INPUT_FRAMES, MAX_QUEUED_INPUT_BYTES,
    MAX_QUEUED_OUTPUT_BYTES, MoshAction, MoshBackendOperation, MoshBytes, MoshCloseReason,
    MoshError, MoshEvent, MoshExit, MoshIoTarget, MoshPhase, MoshSessionCore, MoshSessionId,
};
