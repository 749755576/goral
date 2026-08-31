use std::fmt;

/// Stable, secret-free failure categories for SSH secret envelopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretEnvelopeErrorCode {
    InvalidInput,
    TooLarge,
    InvalidEnvelope,
    UnsupportedVersion,
    UnsupportedCipher,
    RandomnessUnavailable,
    CryptographicFailure,
}

impl SecretEnvelopeErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "SSH secret envelope input is invalid",
            Self::TooLarge => "SSH secret envelope input exceeds its size limit",
            Self::InvalidEnvelope => "SSH secret envelope is invalid or corrupt",
            Self::UnsupportedVersion => "SSH secret envelope version is unsupported",
            Self::UnsupportedCipher => "SSH secret envelope cipher is unsupported",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::CryptographicFailure => "SSH secret envelope cryptographic operation failed",
        }
    }
}

/// An error that retains only a fixed code and fixed message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretEnvelopeError {
    code: SecretEnvelopeErrorCode,
}

impl SecretEnvelopeError {
    #[must_use]
    pub const fn new(code: SecretEnvelopeErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> SecretEnvelopeErrorCode {
        self.code
    }
}

impl From<SecretEnvelopeErrorCode> for SecretEnvelopeError {
    fn from(code: SecretEnvelopeErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for SecretEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

// Debug must be just as safe as Display. In particular, no wrapped source
// error is retained because platform or parser diagnostics can contain data.
impl fmt::Debug for SecretEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvelopeError")
            .field("code", &self.code)
            .finish()
    }
}

impl std::error::Error for SecretEnvelopeError {}
