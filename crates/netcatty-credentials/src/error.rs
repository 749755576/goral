use std::fmt;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialErrorCode {
    InvalidReference,
    NotFound,
    Expired,
    OwnerMismatch,
    InvalidSecret,
    TooLarge,
    CapacityExceeded,
    InvalidUtf8,
    KindMismatch,
    CorruptRecord,
    StorageUnavailable,
    Conflict,
    BackendFailure,
}

impl CredentialErrorCode {
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidReference => "Credential reference is invalid",
            Self::NotFound => "Credential is unavailable",
            Self::Expired => "Staged credential has expired",
            Self::OwnerMismatch => "Staged credential is unavailable for this window",
            Self::InvalidSecret => "Credential value is invalid",
            Self::TooLarge => "Credential value exceeds the supported size",
            Self::CapacityExceeded => "Staged credential storage capacity is exhausted",
            Self::InvalidUtf8 => "Credential value is not valid UTF-8",
            Self::KindMismatch => "Credential type does not match the requested use",
            Self::CorruptRecord => "Stored credential is invalid",
            Self::StorageUnavailable => "Credential storage is unavailable",
            Self::Conflict => "Credential storage contains conflicting entries",
            Self::BackendFailure => "Credential storage operation failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialError {
    code: CredentialErrorCode,
    message: &'static str,
}

impl CredentialError {
    #[must_use]
    pub const fn new(code: CredentialErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> CredentialErrorCode {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CredentialError {}

impl From<CredentialErrorCode> for CredentialError {
    fn from(code: CredentialErrorCode) -> Self {
        Self::new(code)
    }
}
