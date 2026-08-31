//! Electron-free Eternal Terminal (`et`) client planning and PTY runtime.
//!
//! Renderer input is deliberately limited to an opaque native target ID and
//! terminal dimensions. The executable, endpoint, SSH argv/environment and
//! authentication artifacts are supplied by native code through types that
//! do not implement `Deserialize`.

mod askpass;
mod launch;
mod model;
mod resource;
mod runtime;

pub use askpass::{
    ET_ASKPASS_HELPER_ENV, ET_ASKPASS_MAP_ENV, EtAskpassError, EtAskpassKind, EtAskpassMap,
    run_askpass_helper_if_requested,
};
pub use launch::{
    EtHostKeyChecking, EtLaunchSpec, EtNativeEnvironment, EtSessionConfig, EtSshOption, NativePath,
};
pub use model::{
    EtConfigError, EtConfigField, EtEndpoint, EtJumpHost, EtStartRequest, EtTarget, EtWindowSize,
    MAX_ENVIRONMENT_VALUE_BYTES, MAX_HOST_BYTES, MAX_NATIVE_PATH_BYTES,
    MAX_RENDERER_TARGET_ID_BYTES, MAX_SSH_OPTION_BYTES, MAX_SSH_OPTION_TOTAL_BYTES,
    MAX_SSH_OPTIONS, MAX_USERNAME_BYTES, MAX_WINDOW_DIMENSION,
};
pub use resource::{
    EtArchitecture, EtClientDescriptor, EtClientError, EtClientResolver, EtPlatform,
    TrustedEtClient,
};
pub use runtime::{
    EVENT_CHANNEL_CAPACITY, EtBytes, EtCloseReason, EtExit, EtIoErrorKind, EtIoOperation,
    EtRuntimeError, EtRuntimeEvent, EtRuntimeSession, EtSessionId, EtSessionManager,
    MAX_BUFFERED_OUTPUT_BYTES, MAX_INPUT_BYTES, MAX_QUEUED_INPUT_BYTES,
};
