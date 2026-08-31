//! Remote system management over an established session.
//!
//! Everything here is deliberately transport-free: this crate builds command
//! strings and parses their output, and knows nothing about SSH. That keeps
//! the parsing and the escalation policy unit-testable without a network, and
//! keeps the crate reusable for any session type that can run a command and
//! hand back stdout, stderr and an exit status.
//!
//! The caller supplies execution. See [`docker`] for the shape.

pub mod docker;
pub mod gpu;
pub mod inventory;
pub mod overview;
pub mod tmux;

/// What one command produced, as far as this crate needs to care.
///
/// Mirrors the transport's own output type rather than depending on it, so a
/// core crate never has to pull in SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<i32>,
    pub timed_out: bool,
}

impl ExecResult {
    /// True only for an explicit zero exit status.
    ///
    /// A remote that closes the channel without reporting a status has not
    /// told us the command worked, and output from an unconfirmed command
    /// must never be parsed as authoritative.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.exit_status == Some(0)
    }

    /// The most useful message for a human, preferring stderr.
    #[must_use]
    pub fn failure_message(&self, fallback: &str) -> String {
        let stderr = self.stderr.trim();
        if !stderr.is_empty() {
            return stderr.to_owned();
        }
        let stdout = self.stdout.trim();
        if !stdout.is_empty() {
            return stdout.to_owned();
        }
        fallback.to_owned()
    }
}
