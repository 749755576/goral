use std::fmt;

/// Stable, secret-free failures from the local custody file layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretFileStoreErrorCode {
    InvalidRoot,
    InvalidOwner,
    InvalidKeyset,
    BothKeysetSlotsCorrupt,
    ArtifactConflict,
    NotInitialized,
    InvalidInput,
    GenerationOverflow,
    LockUnavailable,
    LockPoisoned,
    StorageUnavailable,
    ObjectUnavailable,
    DurabilityUnconfirmed,
    GarbageCollectionUncertain,
    MasterKeyRotationUncertain,
}

impl SecretFileStoreErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidRoot => "secret custody root is invalid",
            Self::InvalidOwner => "secret custody owner marker is invalid",
            Self::InvalidKeyset => "secret custody keyset is invalid",
            Self::BothKeysetSlotsCorrupt => {
                "secret custody keyset recovery slots are unavailable or corrupt"
            }
            Self::ArtifactConflict => "secret custody storage contains an unowned artifact",
            Self::NotInitialized => "secret custody storage is not initialized",
            Self::InvalidInput => "secret custody storage input is invalid",
            Self::GenerationOverflow => "secret custody generation overflowed",
            Self::LockUnavailable => "secret custody transaction lock is unavailable",
            Self::LockPoisoned => "secret custody process lock is unavailable",
            Self::StorageUnavailable => "secret custody storage is unavailable",
            Self::ObjectUnavailable => "secret custody object is unavailable or corrupt",
            Self::DurabilityUnconfirmed => "secret custody durability could not be confirmed",
            Self::GarbageCollectionUncertain => {
                "secret custody garbage collection could not be determined safely"
            }
            Self::MasterKeyRotationUncertain => {
                "secret custody master-key rotation could not be determined safely"
            }
        }
    }
}

/// An error retaining only a fixed code and fixed message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretFileStoreError {
    code: SecretFileStoreErrorCode,
}

impl SecretFileStoreError {
    #[must_use]
    pub const fn new(code: SecretFileStoreErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> SecretFileStoreErrorCode {
        self.code
    }
}

impl From<SecretFileStoreErrorCode> for SecretFileStoreError {
    fn from(code: SecretFileStoreErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for SecretFileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl fmt::Debug for SecretFileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFileStoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl std::error::Error for SecretFileStoreError {}
