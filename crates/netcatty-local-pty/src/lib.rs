//! Cross-platform shell discovery and a bounded local pseudo-terminal runtime.
//!
//! The crate is intentionally independent from Tauri. Native adapters expose
//! [`DiscoveredShell`] values to the renderer, accept only an opaque shell ID
//! back, resolve it against a native [`ShellCatalog`], and then pass the
//! resulting [`LocalPtyConfig`] to [`LocalPtyManager`]. Executable paths and
//! arguments are therefore never renderer-authored launch authority.

mod discovery;
mod model;
mod runtime;

pub use discovery::discover_shells;
pub use model::{
    CustomShellRegistration, DiscoveredShell, LocalPtyConfig, LocalPtyRequest, LocalPtyWindowSize,
    ShellCatalog, ShellDiscoveryError, ShellField, TerminalEnvironmentRequest,
};
pub use runtime::{
    EVENT_CHANNEL_CAPACITY, LocalPtyBytes, LocalPtyCloseReason, LocalPtyError, LocalPtyExit,
    LocalPtyIoErrorKind, LocalPtyIoOperation, LocalPtyManager, LocalPtyRuntimeEvent,
    LocalPtyRuntimeSession, LocalPtySessionId, MAX_BUFFERED_OUTPUT_BYTES, MAX_INPUT_BYTES,
    MAX_QUEUED_INPUT_BYTES,
};
