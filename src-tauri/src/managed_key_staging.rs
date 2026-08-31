use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

use netcatty_secret_store::{
    MAX_BUNDLE_PLAINTEXT_BYTES, MAX_CERTIFICATE_BYTES, MAX_PASSPHRASE_BYTES, MAX_PRIVATE_KEY_BYTES,
    MAX_PUBLIC_KEY_BYTES, SshSecretBundle,
};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{Mutex, oneshot};
use tokio::time::Instant;
use uuid::{Uuid, Version};

const STAGING_MAGIC: &[u8; 8] = b"NCTMKRAW";
const STAGING_VERSION: u8 = 1;
const STAGING_HEADER_BYTES: usize = 28;
const HAS_PUBLIC_KEY: u8 = 1 << 0;
const HAS_CERTIFICATE: u8 = 1 << 1;
const HAS_PASSPHRASE: u8 = 1 << 2;
const KNOWN_FLAGS: u8 = HAS_PUBLIC_KEY | HAS_CERTIFICATE | HAS_PASSPHRASE;
const STAGING_REFERENCE_PREFIX: &str = "keymem:v1:";
const MAX_STAGED_BUNDLES: usize = 32;
const MAX_STAGED_BUNDLES_PER_OWNER: usize = 8;
const MAX_STAGED_SECRET_BYTES: usize = 32 * 1_024 * 1_024;
const MAX_OWNER_BYTES: usize = 256;
pub(crate) const DEFAULT_MANAGED_KEY_STAGING_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedKeyStagingErrorCode {
    InvalidEnvelope,
    UnsupportedVersion,
    TooLarge,
    CapacityExceeded,
    InvalidReference,
    NotFound,
    Expired,
    OwnerMismatch,
}

impl ManagedKeyStagingErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "Managed SSH key staging envelope is invalid",
            Self::UnsupportedVersion => "Managed SSH key staging envelope version is unsupported",
            Self::TooLarge => "Managed SSH key staging envelope exceeds its size limit",
            Self::CapacityExceeded => "Managed SSH key staging capacity is exhausted",
            Self::InvalidReference => "Managed SSH key staging reference is invalid",
            Self::NotFound => "Managed SSH key staging reference was not found",
            Self::Expired => "Managed SSH key staging reference has expired",
            Self::OwnerMismatch => "Managed SSH key staging reference belongs to another window",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManagedKeyStagingError {
    code: ManagedKeyStagingErrorCode,
}

impl ManagedKeyStagingError {
    const fn new(code: ManagedKeyStagingErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    const fn code(self) -> ManagedKeyStagingErrorCode {
        self.code
    }
}

impl From<ManagedKeyStagingErrorCode> for ManagedKeyStagingError {
    fn from(code: ManagedKeyStagingErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for ManagedKeyStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl fmt::Debug for ManagedKeyStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedKeyStagingError")
            .field("code", &self.code)
            .finish()
    }
}

impl std::error::Error for ManagedKeyStagingError {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ManagedKeyStagingReference(Uuid);

impl ManagedKeyStagingReference {
    fn new() -> Self {
        Self(Uuid::new_v4())
    }

    fn parse(value: &str) -> Result<Self, ManagedKeyStagingError> {
        let suffix = value
            .strip_prefix(STAGING_REFERENCE_PREFIX)
            .ok_or(ManagedKeyStagingErrorCode::InvalidReference)?;
        let id = Uuid::parse_str(suffix).map_err(|_| {
            ManagedKeyStagingError::new(ManagedKeyStagingErrorCode::InvalidReference)
        })?;
        if id.get_version() != Some(Version::Random) || id.hyphenated().to_string() != suffix {
            return Err(ManagedKeyStagingErrorCode::InvalidReference.into());
        }
        Ok(Self(id))
    }
}

impl fmt::Display for ManagedKeyStagingReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{STAGING_REFERENCE_PREFIX}{}",
            self.0.hyphenated()
        )
    }
}

impl fmt::Debug for ManagedKeyStagingReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedKeyStagingReference([redacted])")
    }
}

impl Serialize for ManagedKeyStagingReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ManagedKeyStagingReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .map_err(|_| D::Error::custom("invalid managed SSH key staging reference"))
    }
}

struct StagedManagedKeyEntry {
    owner: String,
    expires_at: Instant,
    generation: u64,
    secret_bytes: usize,
    _expiry_cancel: oneshot::Sender<()>,
    bundle: SshSecretBundle,
}

struct ManagedKeyStagingState {
    entries: HashMap<ManagedKeyStagingReference, StagedManagedKeyEntry>,
    next_generation: u64,
}

impl ManagedKeyStagingState {
    fn purge_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    fn remove_expired_generation(
        &mut self,
        reference: ManagedKeyStagingReference,
        generation: u64,
        now: Instant,
    ) {
        if self
            .entries
            .get(&reference)
            .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now)
        {
            self.entries.remove(&reference);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ManagedKeyStagingStore {
    state: Arc<Mutex<ManagedKeyStagingState>>,
    ttl: Duration,
}

impl ManagedKeyStagingStore {
    #[cfg(test)]
    fn new(ttl: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManagedKeyStagingState {
                entries: HashMap::new(),
                next_generation: 0,
            })),
            ttl,
        }
    }

    pub(crate) async fn insert(
        &self,
        owner: impl Into<String>,
        bundle: SshSecretBundle,
    ) -> Result<ManagedKeyStagingReference, ManagedKeyStagingError> {
        let owner = owner.into();
        if owner.is_empty() || owner.len() > MAX_OWNER_BYTES {
            return Err(ManagedKeyStagingErrorCode::OwnerMismatch.into());
        }
        let secret_bytes = bundle_secret_bytes(&bundle)?;
        let now = Instant::now();
        let expires_at = now + self.ttl;
        let mut state = self.state.lock().await;
        state.purge_expired(now);

        let owner_entries = state
            .entries
            .values()
            .filter(|entry| entry.owner == owner)
            .count();
        let total_bytes = state
            .entries
            .values()
            .try_fold(0_usize, |total, entry| {
                total.checked_add(entry.secret_bytes)
            })
            .ok_or(ManagedKeyStagingErrorCode::CapacityExceeded)?;
        if state.entries.len() >= MAX_STAGED_BUNDLES
            || owner_entries >= MAX_STAGED_BUNDLES_PER_OWNER
            || total_bytes
                .checked_add(secret_bytes)
                .is_none_or(|total| total > MAX_STAGED_SECRET_BYTES)
        {
            return Err(ManagedKeyStagingErrorCode::CapacityExceeded.into());
        }

        let reference = loop {
            let candidate = ManagedKeyStagingReference::new();
            if !state.entries.contains_key(&candidate) {
                break candidate;
            }
        };
        state.next_generation = state.next_generation.wrapping_add(1);
        let generation = state.next_generation;
        let (expiry_cancel, expiry_cancelled) = oneshot::channel();
        state.entries.insert(
            reference,
            StagedManagedKeyEntry {
                owner,
                expires_at,
                generation,
                secret_bytes,
                _expiry_cancel: expiry_cancel,
                bundle,
            },
        );
        drop(state);
        Self::schedule_expiry(
            Arc::downgrade(&self.state),
            reference,
            generation,
            expires_at,
            expiry_cancelled,
        );
        Ok(reference)
    }

    pub(crate) async fn take(
        &self,
        owner: &str,
        reference: &ManagedKeyStagingReference,
    ) -> Result<SshSecretBundle, ManagedKeyStagingError> {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let Some(entry) = state.entries.get(reference) else {
            return Err(ManagedKeyStagingErrorCode::NotFound.into());
        };
        if now >= entry.expires_at {
            state.entries.remove(reference);
            return Err(ManagedKeyStagingErrorCode::Expired.into());
        }
        if entry.owner != owner {
            return Err(ManagedKeyStagingErrorCode::OwnerMismatch.into());
        }
        Ok(state
            .entries
            .remove(reference)
            .expect("entry was checked while holding the same lock")
            .bundle)
    }

    pub(crate) async fn purge_owner(&self, owner: &str) -> usize {
        let mut state = self.state.lock().await;
        let before = state.entries.len();
        state.entries.retain(|_, entry| entry.owner != owner);
        before - state.entries.len()
    }

    fn schedule_expiry(
        state: Weak<Mutex<ManagedKeyStagingState>>,
        reference: ManagedKeyStagingReference,
        generation: u64,
        expires_at: Instant,
        expiry_cancelled: oneshot::Receiver<()>,
    ) {
        tokio::spawn(async move {
            if tokio::time::timeout_at(expires_at, expiry_cancelled)
                .await
                .is_ok()
            {
                return;
            }
            let Some(state) = state.upgrade() else {
                return;
            };
            state
                .lock()
                .await
                .remove_expired_generation(reference, generation, Instant::now());
        });
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.state.lock().await.entries.len()
    }
}

impl Default for ManagedKeyStagingStore {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(ManagedKeyStagingState {
                entries: HashMap::new(),
                next_generation: 0,
            })),
            ttl: DEFAULT_MANAGED_KEY_STAGING_TTL,
        }
    }
}

pub(crate) fn parse_managed_key_staging_envelope(
    bytes: &[u8],
) -> Result<SshSecretBundle, ManagedKeyStagingError> {
    if bytes.len() < STAGING_HEADER_BYTES || bytes.get(..8) != Some(STAGING_MAGIC.as_slice()) {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }
    if bytes[8] != STAGING_VERSION {
        return Err(ManagedKeyStagingErrorCode::UnsupportedVersion.into());
    }
    let flags = bytes[9];
    if flags & !KNOWN_FLAGS != 0 || read_u16(bytes, 10)? != 0 {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }

    let private_len = read_u32(bytes, 12)?;
    let public_len = read_u32(bytes, 16)?;
    let certificate_len = read_u32(bytes, 20)?;
    let passphrase_len = read_u32(bytes, 24)?;
    validate_required_len(private_len, MAX_PRIVATE_KEY_BYTES)?;
    validate_optional_len(public_len, MAX_PUBLIC_KEY_BYTES)?;
    validate_optional_len(certificate_len, MAX_CERTIFICATE_BYTES)?;
    validate_optional_len(passphrase_len, MAX_PASSPHRASE_BYTES)?;
    if (public_len != 0) != (flags & HAS_PUBLIC_KEY != 0)
        || (certificate_len != 0) != (flags & HAS_CERTIFICATE != 0)
        || (passphrase_len != 0) != (flags & HAS_PASSPHRASE != 0)
    {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }

    let expected_len = [private_len, public_len, certificate_len, passphrase_len]
        .into_iter()
        .try_fold(STAGING_HEADER_BYTES, |total, length| {
            total.checked_add(length)
        })
        .ok_or(ManagedKeyStagingErrorCode::TooLarge)?;
    if expected_len != bytes.len() {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }
    if expected_len > MAX_BUNDLE_PLAINTEXT_BYTES {
        return Err(ManagedKeyStagingErrorCode::TooLarge.into());
    }

    let mut cursor = STAGING_HEADER_BYTES;
    let private_key = take_field(bytes, &mut cursor, private_len)?.to_vec();
    let public_key = take_optional_field(bytes, &mut cursor, public_len)?;
    let certificate = take_optional_field(bytes, &mut cursor, certificate_len)?;
    let passphrase = take_optional_field(bytes, &mut cursor, passphrase_len)?;
    if cursor != bytes.len() {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }
    SshSecretBundle::new(private_key, public_key, certificate, passphrase).map_err(|error| {
        match error.code() {
            netcatty_secret_store::SecretEnvelopeErrorCode::TooLarge => {
                ManagedKeyStagingErrorCode::TooLarge.into()
            }
            _ => ManagedKeyStagingErrorCode::InvalidEnvelope.into(),
        }
    })
}

fn bundle_secret_bytes(bundle: &SshSecretBundle) -> Result<usize, ManagedKeyStagingError> {
    [
        bundle.private_key().len(),
        bundle.public_key().map_or(0, <[u8]>::len),
        bundle.certificate().map_or(0, <[u8]>::len),
        bundle.passphrase().map_or(0, <[u8]>::len),
    ]
    .into_iter()
    .try_fold(0_usize, |total, length| total.checked_add(length))
    .ok_or_else(|| ManagedKeyStagingErrorCode::TooLarge.into())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ManagedKeyStagingError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(ManagedKeyStagingErrorCode::InvalidEnvelope)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<usize, ManagedKeyStagingError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(ManagedKeyStagingErrorCode::InvalidEnvelope)?;
    usize::try_from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
        .map_err(|_| ManagedKeyStagingErrorCode::TooLarge.into())
}

fn validate_required_len(length: usize, maximum: usize) -> Result<(), ManagedKeyStagingError> {
    if length == 0 {
        return Err(ManagedKeyStagingErrorCode::InvalidEnvelope.into());
    }
    validate_optional_len(length, maximum)
}

fn validate_optional_len(length: usize, maximum: usize) -> Result<(), ManagedKeyStagingError> {
    if length > maximum {
        return Err(ManagedKeyStagingErrorCode::TooLarge.into());
    }
    Ok(())
}

fn take_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ManagedKeyStagingError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ManagedKeyStagingErrorCode::TooLarge)?;
    let field = bytes
        .get(*cursor..end)
        .ok_or(ManagedKeyStagingErrorCode::InvalidEnvelope)?;
    *cursor = end;
    Ok(field)
}

fn take_optional_field(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
) -> Result<Option<Vec<u8>>, ManagedKeyStagingError> {
    if length == 0 {
        return Ok(None);
    }
    Ok(Some(take_field(bytes, cursor, length)?.to_vec()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;

    use super::{
        ManagedKeyStagingErrorCode, ManagedKeyStagingReference, ManagedKeyStagingStore,
        STAGING_HEADER_BYTES, STAGING_MAGIC, STAGING_VERSION, parse_managed_key_staging_envelope,
    };

    fn envelope(private_key: &[u8], certificate: &[u8], passphrase: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            STAGING_HEADER_BYTES + private_key.len() + certificate.len() + passphrase.len(),
        );
        encoded.extend_from_slice(STAGING_MAGIC);
        encoded.push(STAGING_VERSION);
        let mut flags = 0_u8;
        if !certificate.is_empty() {
            flags |= super::HAS_CERTIFICATE;
        }
        if !passphrase.is_empty() {
            flags |= super::HAS_PASSPHRASE;
        }
        encoded.push(flags);
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&(private_key.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&0_u32.to_be_bytes());
        encoded.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(passphrase.len() as u32).to_be_bytes());
        encoded.extend_from_slice(private_key);
        encoded.extend_from_slice(certificate);
        encoded.extend_from_slice(passphrase);
        encoded
    }

    #[test]
    fn raw_envelope_is_strict_bounded_and_secret_safe() {
        let private_key = b"private-key-sentinel";
        let certificate = b"certificate-sentinel";
        let passphrase = b"passphrase-sentinel";
        let encoded = envelope(private_key, certificate, passphrase);
        let bundle = parse_managed_key_staging_envelope(&encoded).expect("valid envelope");
        assert_eq!(bundle.private_key(), private_key);
        assert_eq!(bundle.certificate(), Some(certificate.as_slice()));
        assert_eq!(bundle.passphrase(), Some(passphrase.as_slice()));

        for mutation in [
            Vec::new(),
            encoded[..encoded.len() - 1].to_vec(),
            {
                let mut value = encoded.clone();
                value.extend_from_slice(b"trailing");
                value
            },
            {
                let mut value = encoded.clone();
                value[10] = 1;
                value
            },
        ] {
            let error =
                parse_managed_key_staging_envelope(&mutation).expect_err("invalid envelope");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("private-key-sentinel"));
            assert!(!rendered.contains("certificate-sentinel"));
            assert!(!rendered.contains("passphrase-sentinel"));
        }
    }

    #[test]
    fn staging_reference_parser_is_canonical_and_debug_is_redacted() {
        let reference = ManagedKeyStagingReference::new();
        let encoded = reference.to_string();
        assert_eq!(ManagedKeyStagingReference::parse(&encoded), Ok(reference));
        assert_eq!(
            format!("{reference:?}"),
            "ManagedKeyStagingReference([redacted])"
        );
        assert_eq!(
            ManagedKeyStagingReference::parse("mem:v1:00000000-0000-4000-8000-000000000000")
                .expect_err("wrong prefix")
                .code(),
            ManagedKeyStagingErrorCode::InvalidReference
        );
    }

    #[tokio::test]
    async fn bundles_are_owner_bound_one_shot_and_expire() {
        let store = ManagedKeyStagingStore::new(Duration::from_millis(20));
        let first = store
            .insert(
                "main",
                parse_managed_key_staging_envelope(&envelope(b"first", b"", b""))
                    .expect("first bundle"),
            )
            .await
            .expect("stage first");
        assert_eq!(
            store
                .take("other", &first)
                .await
                .expect_err("owner mismatch")
                .code(),
            ManagedKeyStagingErrorCode::OwnerMismatch
        );
        let resolved = store.take("main", &first).await.expect("take first");
        assert_eq!(resolved.private_key(), b"first");
        assert_eq!(
            store
                .take("main", &first)
                .await
                .expect_err("one shot")
                .code(),
            ManagedKeyStagingErrorCode::NotFound
        );

        let expiring = store
            .insert(
                "main",
                parse_managed_key_staging_envelope(&envelope(b"expiring", b"", b""))
                    .expect("expiring bundle"),
            )
            .await
            .expect("stage expiring");
        sleep(Duration::from_millis(50)).await;
        assert_eq!(store.len().await, 0);
        assert_eq!(
            store
                .take("main", &expiring)
                .await
                .expect_err("expired entry removed")
                .code(),
            ManagedKeyStagingErrorCode::NotFound
        );
    }

    #[tokio::test]
    async fn closing_an_owner_drops_all_of_its_bundles() {
        let store = ManagedKeyStagingStore::default();
        for value in [b"one".as_slice(), b"two".as_slice()] {
            store
                .insert(
                    "main",
                    parse_managed_key_staging_envelope(&envelope(value, b"", b"")).expect("bundle"),
                )
                .await
                .expect("stage");
        }
        store
            .insert(
                "other",
                parse_managed_key_staging_envelope(&envelope(b"other", b"", b""))
                    .expect("other bundle"),
            )
            .await
            .expect("stage other");
        assert_eq!(store.purge_owner("main").await, 2);
        assert_eq!(store.len().await, 1);
    }
}
