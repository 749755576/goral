use std::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::{Uuid, Version};
use zeroize::Zeroizing;

use crate::{
    MAX_BUNDLE_PLAINTEXT_BYTES, SecretEnvelopeError, SecretEnvelopeErrorCode, SshSecretBundle,
};

const ENVELOPE_MAGIC: &[u8; 8] = b"NCATSBLB";
const ENVELOPE_FORMAT_VERSION: u16 = 1;
const CIPHER_XCHACHA20_POLY1305_HKDF_SHA256: u8 = 1;
const ENVELOPE_HEADER_BYTES: usize = 128;
const ENVELOPE_TAG_BYTES: usize = 16;
const ENVELOPE_RESERVED_OFFSET: usize = 116;
const NONCE_OFFSET: usize = 84;
const PLAINTEXT_LENGTH_OFFSET: usize = 108;
const ENTITY_ID_DOMAIN: &[u8] = b"netcatty-secret-entity-v1\0";
const SUBKEY_DOMAIN: &[u8] = b"netcatty-secret-envelope-subkey-v1\0";
const MAX_ENTITY_ID_BYTES: usize = 4_096;
const MIN_BUNDLE_PLAINTEXT_BYTES: usize = 33;

/// The immutable A/B destination to which an envelope belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretEnvelopeSlot {
    A,
    B,
}

impl SecretEnvelopeSlot {
    const fn tag(self) -> u8 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SecretEnvelopeError> {
        match tag {
            1 => Ok(Self::A),
            2 => Ok(Self::B),
            _ => Err(SecretEnvelopeErrorCode::InvalidEnvelope.into()),
        }
    }

    const fn owns_generation(self, generation: u64) -> bool {
        match self {
            Self::A => generation % 2 == 1,
            Self::B => generation % 2 == 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecretEntityDigest([u8; 32]);

impl SecretEntityDigest {
    pub(crate) fn derive(entity_id: &str) -> Result<Self, SecretEnvelopeError> {
        if entity_id.is_empty()
            || entity_id.len() > MAX_ENTITY_ID_BYTES
            || entity_id.chars().any(char::is_control)
        {
            return Err(SecretEnvelopeErrorCode::InvalidInput.into());
        }
        let length = u32::try_from(entity_id.len())
            .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidInput))?;
        let mut digest = Sha256::new();
        digest.update(ENTITY_ID_DOMAIN);
        digest.update(length.to_be_bytes());
        digest.update(entity_id.as_bytes());
        Ok(Self(digest.finalize().into()))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SecretEntityDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretEntityDigest([REDACTED])")
    }
}

/// Non-secret publication metadata authenticated by an encrypted envelope.
/// Store and entity identifiers are deliberately redacted from Debug output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretEnvelopeContext {
    store_id: Uuid,
    entity_digest: SecretEntityDigest,
    revision: u64,
    slot: SecretEnvelopeSlot,
    generation: u64,
    master_key_epoch: u32,
}

impl SecretEnvelopeContext {
    pub fn new(
        store_id: Uuid,
        entity_id: &str,
        revision: u64,
        slot: SecretEnvelopeSlot,
        generation: u64,
        master_key_epoch: u32,
    ) -> Result<Self, SecretEnvelopeError> {
        Self::from_digest(
            store_id,
            SecretEntityDigest::derive(entity_id)?,
            revision,
            slot,
            generation,
            master_key_epoch,
        )
    }

    pub(crate) fn from_digest(
        store_id: Uuid,
        entity_digest: SecretEntityDigest,
        revision: u64,
        slot: SecretEnvelopeSlot,
        generation: u64,
        master_key_epoch: u32,
    ) -> Result<Self, SecretEnvelopeError> {
        if store_id.get_version() != Some(Version::Random)
            || revision == 0
            || generation == 0
            || master_key_epoch == 0
            || !slot.owns_generation(generation)
        {
            return Err(SecretEnvelopeErrorCode::InvalidInput.into());
        }
        Ok(Self {
            store_id,
            entity_digest,
            revision,
            slot,
            generation,
            master_key_epoch,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn slot(&self) -> SecretEnvelopeSlot {
        self.slot
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn master_key_epoch(&self) -> u32 {
        self.master_key_epoch
    }

    pub(crate) const fn store_id(&self) -> Uuid {
        self.store_id
    }

    pub(crate) const fn entity_digest(&self) -> SecretEntityDigest {
        self.entity_digest
    }
}

impl fmt::Debug for SecretEnvelopeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvelopeContext")
            .field("store_id", &"[REDACTED]")
            .field("entity_digest", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .field("master_key_epoch", &self.master_key_epoch)
            .finish()
    }
}

/// A process-owned 256-bit encryption root key.
///
/// It deliberately has no `Clone`, Serde, or `Display` implementation.
///
/// ```compile_fail
/// use netcatty_secret_store::EnvelopeMasterKey;
/// let key = EnvelopeMasterKey::from_bytes([7; 32]).unwrap();
/// let _copy = key.clone();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::EnvelopeMasterKey;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<EnvelopeMasterKey>();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::EnvelopeMasterKey;
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<EnvelopeMasterKey>();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::EnvelopeMasterKey;
/// let key = EnvelopeMasterKey::from_bytes([7; 32]).unwrap();
/// let _rendered = format!("{key}");
/// ```
pub struct EnvelopeMasterKey(Zeroizing<[u8; 32]>);

impl EnvelopeMasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretEnvelopeError> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    /// Consumes an already-zeroizing key buffer without copying it through an
    /// ordinary stack array. This is the preferred OS-custody decode boundary.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Result<Self, SecretEnvelopeError> {
        if bool::from(bytes.ct_eq(&[0; 32])) {
            return Err(SecretEnvelopeErrorCode::InvalidInput.into());
        }
        Ok(Self(bytes))
    }

    pub fn generate() -> Result<Self, SecretEnvelopeError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| {
            SecretEnvelopeError::new(SecretEnvelopeErrorCode::RandomnessUnavailable)
        })?;
        Self::from_zeroizing(bytes)
            .map_err(|_| SecretEnvelopeErrorCode::RandomnessUnavailable.into())
    }

    /// Borrows the key for a trusted Rust custody adapter. The returned bytes
    /// must never enter serialization, diagnostics, or renderer IPC.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EnvelopeMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnvelopeMasterKey([REDACTED])")
    }
}

/// Authenticated ciphertext ready for a later immutable publication layer.
/// Ciphertext and metadata are not emitted through Debug or Serde.
pub struct EncryptedSecretEnvelope(Vec<u8>);

impl EncryptedSecretEnvelope {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for EncryptedSecretEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedSecretEnvelope([REDACTED])")
    }
}

/// Encrypts one bounded SSH bundle and authenticates every context field.
pub fn encrypt_ssh_secret_bundle(
    master_key: &EnvelopeMasterKey,
    context: &SecretEnvelopeContext,
    bundle: SshSecretBundle,
) -> Result<EncryptedSecretEnvelope, SecretEnvelopeError> {
    let mut plaintext = bundle.encode()?;
    if plaintext.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
        return Err(SecretEnvelopeErrorCode::TooLarge.into());
    }
    let plaintext_length = u64::try_from(plaintext.len())
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::TooLarge))?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::RandomnessUnavailable))?;
    let header = encode_header(context, nonce, plaintext_length);
    let cipher = cipher_for(master_key, &header)?;
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            header.as_slice(),
            plaintext.as_mut(),
        )
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::CryptographicFailure))?;

    let capacity = ENVELOPE_HEADER_BYTES
        .checked_add(plaintext.len())
        .and_then(|length| length.checked_add(ENVELOPE_TAG_BYTES))
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::TooLarge))?;
    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&plaintext);
    envelope.extend_from_slice(tag.as_slice());
    Ok(EncryptedSecretEnvelope(envelope))
}

/// Authenticates and decrypts one envelope for exactly the supplied context.
pub fn decrypt_ssh_secret_bundle(
    master_key: &EnvelopeMasterKey,
    expected_context: &SecretEnvelopeContext,
    envelope: &[u8],
) -> Result<SshSecretBundle, SecretEnvelopeError> {
    let parsed = parse_header(envelope)?;
    let context_matches = parsed.matches(expected_context);
    let cipher_end = ENVELOPE_HEADER_BYTES
        .checked_add(parsed.plaintext_length)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    let mut plaintext = Zeroizing::new(
        envelope
            .get(ENVELOPE_HEADER_BYTES..cipher_end)
            .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?
            .to_vec(),
    );
    let tag_bytes = envelope
        .get(cipher_end..)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    let cipher = cipher_for(master_key, parsed.header)?;
    let authentication = cipher.decrypt_in_place_detached(
        XNonce::from_slice(&parsed.nonce),
        parsed.header,
        plaintext.as_mut(),
        Tag::from_slice(tag_bytes),
    );
    // A valid envelope supplied for the wrong expected context performs the
    // same AEAD work and returns the same fixed error as authentication
    // failure. This avoids turning the API into a context-membership oracle.
    if authentication.is_err() || !context_matches {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    SshSecretBundle::decode(plaintext)
}

/// Authenticates an envelope against the context carried inside its header.
///
/// This is deliberately crate-private: filesystem-wide custody maintenance
/// needs to validate orphaned objects for which no real entity ID is still
/// available, while public callers must continue supplying an independently
/// trusted expected context.
pub(crate) fn decrypt_ssh_secret_bundle_with_embedded_context(
    master_key: &EnvelopeMasterKey,
    envelope: &[u8],
) -> Result<(SecretEnvelopeContext, SshSecretBundle), SecretEnvelopeError> {
    let context = parse_header(envelope)?.context;
    let bundle = decrypt_ssh_secret_bundle(master_key, &context, envelope)?;
    Ok((context, bundle))
}

struct ParsedHeader<'a> {
    header: &'a [u8],
    context: SecretEnvelopeContext,
    nonce: [u8; 24],
    plaintext_length: usize,
}

impl ParsedHeader<'_> {
    fn matches(&self, expected: &SecretEnvelopeContext) -> bool {
        let matches = self
            .context
            .store_id
            .as_bytes()
            .ct_eq(expected.store_id.as_bytes())
            & self
                .context
                .entity_digest
                .0
                .ct_eq(&expected.entity_digest.0)
            & self
                .context
                .revision
                .to_be_bytes()
                .ct_eq(&expected.revision.to_be_bytes())
            & [self.context.slot.tag()].ct_eq(&[expected.slot.tag()])
            & self
                .context
                .generation
                .to_be_bytes()
                .ct_eq(&expected.generation.to_be_bytes())
            & self
                .context
                .master_key_epoch
                .to_be_bytes()
                .ct_eq(&expected.master_key_epoch.to_be_bytes());
        bool::from(matches)
    }
}

fn encode_header(
    context: &SecretEnvelopeContext,
    nonce: [u8; 24],
    plaintext_length: u64,
) -> [u8; ENVELOPE_HEADER_BYTES] {
    let mut header = [0_u8; ENVELOPE_HEADER_BYTES];
    header[..8].copy_from_slice(ENVELOPE_MAGIC);
    header[8..10].copy_from_slice(&ENVELOPE_FORMAT_VERSION.to_be_bytes());
    header[10] = CIPHER_XCHACHA20_POLY1305_HKDF_SHA256;
    header[11] = context.slot.tag();
    header[12..16].copy_from_slice(&(ENVELOPE_HEADER_BYTES as u32).to_be_bytes());
    header[16..32].copy_from_slice(context.store_id.as_bytes());
    header[32..64].copy_from_slice(&context.entity_digest.0);
    header[64..72].copy_from_slice(&context.revision.to_be_bytes());
    header[72..80].copy_from_slice(&context.generation.to_be_bytes());
    header[80..84].copy_from_slice(&context.master_key_epoch.to_be_bytes());
    header[NONCE_OFFSET..PLAINTEXT_LENGTH_OFFSET].copy_from_slice(&nonce);
    header[PLAINTEXT_LENGTH_OFFSET..ENVELOPE_RESERVED_OFFSET]
        .copy_from_slice(&plaintext_length.to_be_bytes());
    header
}

fn parse_header(envelope: &[u8]) -> Result<ParsedHeader<'_>, SecretEnvelopeError> {
    let maximum_envelope_bytes = ENVELOPE_HEADER_BYTES
        .checked_add(MAX_BUNDLE_PLAINTEXT_BYTES)
        .and_then(|length| length.checked_add(ENVELOPE_TAG_BYTES))
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    if envelope.len() < ENVELOPE_HEADER_BYTES + MIN_BUNDLE_PLAINTEXT_BYTES + ENVELOPE_TAG_BYTES
        || envelope.len() > maximum_envelope_bytes
    {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    let header = &envelope[..ENVELOPE_HEADER_BYTES];
    if header.get(..8) != Some(ENVELOPE_MAGIC.as_slice()) {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    if read_u16(header, 8)? != ENVELOPE_FORMAT_VERSION {
        return Err(SecretEnvelopeErrorCode::UnsupportedVersion.into());
    }
    if header[10] != CIPHER_XCHACHA20_POLY1305_HKDF_SHA256 {
        return Err(SecretEnvelopeErrorCode::UnsupportedCipher.into());
    }
    if read_u32(header, 12)? as usize != ENVELOPE_HEADER_BYTES
        || header[ENVELOPE_RESERVED_OFFSET..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }

    let slot = SecretEnvelopeSlot::from_tag(header[11])?;
    let store_id = Uuid::from_slice(&header[16..32])
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    if store_id.get_version() != Some(Version::Random) {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    let mut entity_digest = [0_u8; 32];
    entity_digest.copy_from_slice(&header[32..64]);
    let revision = read_u64(header, 64)?;
    let generation = read_u64(header, 72)?;
    let master_key_epoch = read_u32(header, 80)?;
    if revision == 0
        || generation == 0
        || master_key_epoch == 0
        || !slot.owns_generation(generation)
    {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&header[NONCE_OFFSET..PLAINTEXT_LENGTH_OFFSET]);
    let plaintext_length = usize::try_from(read_u64(header, PLAINTEXT_LENGTH_OFFSET)?)
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    if !(MIN_BUNDLE_PLAINTEXT_BYTES..=MAX_BUNDLE_PLAINTEXT_BYTES).contains(&plaintext_length) {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }
    let expected_length = ENVELOPE_HEADER_BYTES
        .checked_add(plaintext_length)
        .and_then(|length| length.checked_add(ENVELOPE_TAG_BYTES))
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    if expected_length != envelope.len() {
        return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
    }

    Ok(ParsedHeader {
        header,
        context: SecretEnvelopeContext {
            store_id,
            entity_digest: SecretEntityDigest(entity_digest),
            revision,
            slot,
            generation,
            master_key_epoch,
        },
        nonce,
        plaintext_length,
    })
}

fn cipher_for(
    master_key: &EnvelopeMasterKey,
    header: &[u8],
) -> Result<XChaCha20Poly1305, SecretEnvelopeError> {
    let store_id = header
        .get(16..32)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    let hkdf = Hkdf::<Sha256>::new(Some(store_id), master_key.as_bytes());
    let mut info = Vec::with_capacity(SUBKEY_DOMAIN.len() + header.len());
    info.extend_from_slice(SUBKEY_DOMAIN);
    info.extend_from_slice(header);
    let mut subkey = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, subkey.as_mut())
        .map_err(|_| SecretEnvelopeError::new(SecretEnvelopeErrorCode::CryptographicFailure))?;
    XChaCha20Poly1305::new_from_slice(subkey.as_ref())
        .map_err(|_| SecretEnvelopeErrorCode::CryptographicFailure.into())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SecretEnvelopeError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SecretEnvelopeError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SecretEnvelopeError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    Ok(u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::{
        CIPHER_XCHACHA20_POLY1305_HKDF_SHA256, ENVELOPE_FORMAT_VERSION, ENVELOPE_HEADER_BYTES,
        ENVELOPE_RESERVED_OFFSET, ENVELOPE_TAG_BYTES, EnvelopeMasterKey, NONCE_OFFSET,
        PLAINTEXT_LENGTH_OFFSET, SecretEnvelopeContext, SecretEnvelopeSlot,
        decrypt_ssh_secret_bundle, encrypt_ssh_secret_bundle,
    };
    use crate::{
        MAX_CERTIFICATE_BYTES, MAX_PASSPHRASE_BYTES, MAX_PRIVATE_KEY_BYTES, MAX_PUBLIC_KEY_BYTES,
        SecretEnvelopeErrorCode, SshSecretBundle,
    };
    use uuid::Uuid;

    fn key(byte: u8) -> EnvelopeMasterKey {
        EnvelopeMasterKey::from_bytes([byte; 32]).expect("master key")
    }

    fn context(
        store_id: Uuid,
        entity_id: &str,
        revision: u64,
        slot: SecretEnvelopeSlot,
        generation: u64,
        epoch: u32,
    ) -> SecretEnvelopeContext {
        SecretEnvelopeContext::new(store_id, entity_id, revision, slot, generation, epoch)
            .expect("context")
    }

    fn bundle() -> SshSecretBundle {
        SshSecretBundle::new(
            b"private-key-marker".to_vec(),
            Some(b"public-key-marker".to_vec()),
            Some(b"certificate-marker".to_vec()),
            Some(b"passphrase-marker".to_vec()),
        )
        .expect("bundle")
    }

    fn assert_invalid_envelope(
        key: &EnvelopeMasterKey,
        context: &SecretEnvelopeContext,
        bytes: &[u8],
    ) {
        assert!(decrypt_ssh_secret_bundle(key, context, bytes).is_err());
    }

    #[test]
    fn complete_bundle_round_trips_and_nonce_makes_ciphertexts_distinct() {
        let key = key(7);
        let context = context(
            Uuid::new_v4(),
            "round-trip-entity",
            9,
            SecretEnvelopeSlot::A,
            11,
            3,
        );
        let first = encrypt_ssh_secret_bundle(&key, &context, bundle()).expect("first envelope");
        let second = encrypt_ssh_secret_bundle(&key, &context, bundle()).expect("second envelope");
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_ne!(
            &first.as_bytes()[NONCE_OFFSET..PLAINTEXT_LENGTH_OFFSET],
            &second.as_bytes()[NONCE_OFFSET..PLAINTEXT_LENGTH_OFFSET]
        );
        for marker in [
            b"private-key-marker".as_slice(),
            b"public-key-marker".as_slice(),
            b"certificate-marker".as_slice(),
            b"passphrase-marker".as_slice(),
        ] {
            assert!(
                !first
                    .as_bytes()
                    .windows(marker.len())
                    .any(|part| part == marker)
            );
        }

        let decoded = decrypt_ssh_secret_bundle(&key, &context, first.as_bytes()).expect("decrypt");
        assert_eq!(decoded.private_key(), b"private-key-marker");
        assert_eq!(decoded.public_key(), Some(b"public-key-marker".as_slice()));
        assert_eq!(
            decoded.certificate(),
            Some(b"certificate-marker".as_slice())
        );
        assert_eq!(decoded.passphrase(), Some(b"passphrase-marker".as_slice()));
    }

    #[test]
    fn maximum_accepted_bundle_encrypts_and_decrypts() {
        let key = key(7);
        let context = context(
            Uuid::new_v4(),
            "maximum-bundle-entity",
            1,
            SecretEnvelopeSlot::A,
            1,
            1,
        );
        let bundle = SshSecretBundle::new(
            vec![1; MAX_PRIVATE_KEY_BYTES],
            Some(vec![2; MAX_PUBLIC_KEY_BYTES]),
            Some(vec![3; MAX_CERTIFICATE_BYTES]),
            Some(vec![4; MAX_PASSPHRASE_BYTES]),
        )
        .expect("maximum bundle");
        let envelope =
            encrypt_ssh_secret_bundle(&key, &context, bundle).expect("encrypt maximum bundle");
        let decoded = decrypt_ssh_secret_bundle(&key, &context, envelope.as_bytes())
            .expect("decrypt maximum bundle");
        assert_eq!(decoded.private_key().len(), MAX_PRIVATE_KEY_BYTES);
        assert_eq!(
            decoded.public_key().map(<[u8]>::len),
            Some(MAX_PUBLIC_KEY_BYTES)
        );
        assert_eq!(
            decoded.certificate().map(<[u8]>::len),
            Some(MAX_CERTIFICATE_BYTES)
        );
        assert_eq!(
            decoded.passphrase().map(<[u8]>::len),
            Some(MAX_PASSPHRASE_BYTES)
        );
    }

    #[test]
    fn wrong_master_key_and_ciphertext_or_tag_tampering_fail_closed() {
        let first_key = key(7);
        let other_key = key(8);
        let context = context(
            Uuid::new_v4(),
            "tamper-entity",
            1,
            SecretEnvelopeSlot::A,
            1,
            1,
        );
        let envelope = encrypt_ssh_secret_bundle(&first_key, &context, bundle()).expect("envelope");
        assert_invalid_envelope(&other_key, &context, envelope.as_bytes());

        for index in [ENVELOPE_HEADER_BYTES, envelope.as_bytes().len() - 1] {
            let mut tampered = envelope.as_bytes().to_vec();
            tampered[index] ^= 0x80;
            assert_invalid_envelope(&first_key, &context, &tampered);
        }
    }

    #[test]
    fn truncation_and_declared_length_attacks_are_bounded() {
        let key = key(7);
        let context = context(
            Uuid::new_v4(),
            "truncation-entity",
            1,
            SecretEnvelopeSlot::A,
            1,
            1,
        );
        let envelope = encrypt_ssh_secret_bundle(&key, &context, bundle()).expect("envelope");
        for length in 0..ENVELOPE_HEADER_BYTES + ENVELOPE_TAG_BYTES {
            assert_invalid_envelope(&key, &context, &envelope.as_bytes()[..length]);
        }
        assert_invalid_envelope(
            &key,
            &context,
            &envelope.as_bytes()[..envelope.as_bytes().len() - 1],
        );

        let mut huge = envelope.as_bytes().to_vec();
        huge[PLAINTEXT_LENGTH_OFFSET..ENVELOPE_RESERVED_OFFSET]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_invalid_envelope(&key, &context, &huge);

        let mut short = envelope.as_bytes().to_vec();
        short[PLAINTEXT_LENGTH_OFFSET..ENVELOPE_RESERVED_OFFSET]
            .copy_from_slice(&1_u64.to_be_bytes());
        assert_invalid_envelope(&key, &context, &short);
    }

    #[test]
    fn strict_header_rejects_magic_header_length_reserved_version_and_cipher() {
        let key = key(7);
        let context = context(
            Uuid::new_v4(),
            "header-entity",
            1,
            SecretEnvelopeSlot::A,
            1,
            1,
        );
        let envelope = encrypt_ssh_secret_bundle(&key, &context, bundle()).expect("envelope");

        let mut magic = envelope.as_bytes().to_vec();
        magic[0] ^= 1;
        assert_invalid_envelope(&key, &context, &magic);

        let mut header_length = envelope.as_bytes().to_vec();
        header_length[12..16].copy_from_slice(&127_u32.to_be_bytes());
        assert_invalid_envelope(&key, &context, &header_length);

        let mut reserved = envelope.as_bytes().to_vec();
        reserved[ENVELOPE_RESERVED_OFFSET] = 1;
        assert_invalid_envelope(&key, &context, &reserved);

        let mut version = envelope.as_bytes().to_vec();
        version[8..10].copy_from_slice(&(ENVELOPE_FORMAT_VERSION + 1).to_be_bytes());
        assert_eq!(
            decrypt_ssh_secret_bundle(&key, &context, &version)
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::UnsupportedVersion)
        );

        let mut cipher = envelope.as_bytes().to_vec();
        cipher[10] = CIPHER_XCHACHA20_POLY1305_HKDF_SHA256 + 1;
        assert_eq!(
            decrypt_ssh_secret_bundle(&key, &context, &cipher)
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::UnsupportedCipher)
        );
    }

    #[test]
    fn whole_envelopes_cannot_move_across_any_bound_context() {
        let key = key(7);
        let store = Uuid::new_v4();
        let original = context(store, "bound-entity-a", 5, SecretEnvelopeSlot::A, 7, 3);
        let envelope = encrypt_ssh_secret_bundle(&key, &original, bundle()).expect("envelope");
        let alternatives = [
            context(
                Uuid::new_v4(),
                "bound-entity-a",
                5,
                SecretEnvelopeSlot::A,
                7,
                3,
            ),
            context(store, "bound-entity-b", 5, SecretEnvelopeSlot::A, 7, 3),
            context(store, "bound-entity-a", 6, SecretEnvelopeSlot::A, 7, 3),
            context(store, "bound-entity-a", 5, SecretEnvelopeSlot::B, 8, 3),
            context(store, "bound-entity-a", 5, SecretEnvelopeSlot::A, 9, 3),
            context(store, "bound-entity-a", 5, SecretEnvelopeSlot::A, 7, 4),
        ];
        for alternative in alternatives {
            assert_eq!(
                decrypt_ssh_secret_bundle(&key, &alternative, envelope.as_bytes())
                    .err()
                    .map(|error| error.code()),
                Some(SecretEnvelopeErrorCode::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn changing_header_to_another_valid_context_still_fails_aead() {
        let key = key(7);
        let original = context(
            Uuid::new_v4(),
            "aad-original",
            5,
            SecretEnvelopeSlot::A,
            7,
            3,
        );
        let replacement = context(
            Uuid::new_v4(),
            "aad-replacement",
            6,
            SecretEnvelopeSlot::B,
            8,
            4,
        );
        let envelope = encrypt_ssh_secret_bundle(&key, &original, bundle()).expect("envelope");
        let mut changed = envelope.as_bytes().to_vec();
        changed[11] = replacement.slot.tag();
        changed[16..32].copy_from_slice(replacement.store_id.as_bytes());
        changed[32..64].copy_from_slice(&replacement.entity_digest.0);
        changed[64..72].copy_from_slice(&replacement.revision.to_be_bytes());
        changed[72..80].copy_from_slice(&replacement.generation.to_be_bytes());
        changed[80..84].copy_from_slice(&replacement.master_key_epoch.to_be_bytes());
        assert_eq!(
            decrypt_ssh_secret_bundle(&key, &replacement, &changed)
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::InvalidEnvelope)
        );

        let mut nonce = envelope.as_bytes().to_vec();
        nonce[NONCE_OFFSET] ^= 1;
        assert_invalid_envelope(&key, &original, &nonce);
    }

    #[test]
    fn each_bound_header_field_rejects_individual_substitution() {
        let key = key(7);
        let store = Uuid::new_v4();
        let original = context(
            store,
            "individual-aad-entity",
            5,
            SecretEnvelopeSlot::A,
            7,
            3,
        );
        let envelope = encrypt_ssh_secret_bundle(&key, &original, bundle()).expect("envelope");

        let replacement_store = context(
            Uuid::new_v4(),
            "individual-aad-entity",
            5,
            SecretEnvelopeSlot::A,
            7,
            3,
        );
        let mut changed_store = envelope.as_bytes().to_vec();
        changed_store[16..32].copy_from_slice(replacement_store.store_id.as_bytes());
        assert_invalid_envelope(&key, &replacement_store, &changed_store);

        let replacement_entity = context(
            store,
            "individual-aad-other-entity",
            5,
            SecretEnvelopeSlot::A,
            7,
            3,
        );
        let mut changed_entity = envelope.as_bytes().to_vec();
        changed_entity[32..64].copy_from_slice(&replacement_entity.entity_digest.0);
        assert_invalid_envelope(&key, &replacement_entity, &changed_entity);

        let replacement_revision = context(
            store,
            "individual-aad-entity",
            6,
            SecretEnvelopeSlot::A,
            7,
            3,
        );
        let mut changed_revision = envelope.as_bytes().to_vec();
        changed_revision[64..72].copy_from_slice(&replacement_revision.revision.to_be_bytes());
        assert_invalid_envelope(&key, &replacement_revision, &changed_revision);

        let replacement_generation = context(
            store,
            "individual-aad-entity",
            5,
            SecretEnvelopeSlot::A,
            9,
            3,
        );
        let mut changed_generation = envelope.as_bytes().to_vec();
        changed_generation[72..80]
            .copy_from_slice(&replacement_generation.generation.to_be_bytes());
        assert_invalid_envelope(&key, &replacement_generation, &changed_generation);

        // Slot parity is structural, so a valid A-to-B substitution also uses
        // the adjacent B generation. Both fields remain separately bound in
        // the authenticated header and derived subkey.
        let replacement_slot = context(
            store,
            "individual-aad-entity",
            5,
            SecretEnvelopeSlot::B,
            8,
            3,
        );
        let mut changed_slot = envelope.as_bytes().to_vec();
        changed_slot[11] = replacement_slot.slot.tag();
        changed_slot[72..80].copy_from_slice(&replacement_slot.generation.to_be_bytes());
        assert_invalid_envelope(&key, &replacement_slot, &changed_slot);

        let replacement_epoch = context(
            store,
            "individual-aad-entity",
            5,
            SecretEnvelopeSlot::A,
            7,
            4,
        );
        let mut changed_epoch = envelope.as_bytes().to_vec();
        changed_epoch[80..84].copy_from_slice(&replacement_epoch.master_key_epoch.to_be_bytes());
        assert_invalid_envelope(&key, &replacement_epoch, &changed_epoch);

        let mut changed_nonce = envelope.as_bytes().to_vec();
        changed_nonce[NONCE_OFFSET + 1] ^= 0x40;
        assert_invalid_envelope(&key, &original, &changed_nonce);

        let mut changed_length = envelope.as_bytes().to_vec();
        let plaintext_length = u64::from_be_bytes(
            changed_length[PLAINTEXT_LENGTH_OFFSET..ENVELOPE_RESERVED_OFFSET]
                .try_into()
                .expect("length field"),
        );
        changed_length[PLAINTEXT_LENGTH_OFFSET..ENVELOPE_RESERVED_OFFSET]
            .copy_from_slice(&(plaintext_length + 1).to_be_bytes());
        let tag_offset = ENVELOPE_HEADER_BYTES + plaintext_length as usize;
        changed_length.insert(tag_offset, 0);
        assert_invalid_envelope(&key, &original, &changed_length);
    }

    #[test]
    fn context_and_master_key_inputs_are_strict() {
        assert_eq!(
            EnvelopeMasterKey::from_bytes([0; 32])
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::InvalidInput)
        );
        assert_eq!(
            EnvelopeMasterKey::from_zeroizing(zeroize::Zeroizing::new([0; 32]))
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::InvalidInput)
        );
        assert!(EnvelopeMasterKey::generate().is_ok());
        let store = Uuid::new_v4();
        let invalid = [
            SecretEnvelopeContext::new(Uuid::nil(), "entity", 1, SecretEnvelopeSlot::A, 1, 1),
            SecretEnvelopeContext::new(store, "", 1, SecretEnvelopeSlot::A, 1, 1),
            SecretEnvelopeContext::new(store, "entity\nmarker", 1, SecretEnvelopeSlot::A, 1, 1),
            SecretEnvelopeContext::new(store, "entity", 0, SecretEnvelopeSlot::A, 1, 1),
            SecretEnvelopeContext::new(store, "entity", 1, SecretEnvelopeSlot::A, 2, 1),
            SecretEnvelopeContext::new(store, "entity", 1, SecretEnvelopeSlot::A, 1, 0),
        ];
        for result in invalid {
            assert_eq!(
                result.err().map(|error| error.code()),
                Some(SecretEnvelopeErrorCode::InvalidInput)
            );
        }
    }

    #[test]
    fn errors_and_debug_forms_never_expose_secret_or_entity_markers() {
        let secret_markers = [
            "private-key-marker",
            "public-key-marker",
            "certificate-marker",
            "passphrase-marker",
            "debug-entity-marker",
        ];
        let key = key(7);
        let context = context(
            Uuid::new_v4(),
            secret_markers[4],
            1,
            SecretEnvelopeSlot::A,
            1,
            1,
        );
        let envelope = encrypt_ssh_secret_bundle(&key, &context, bundle()).expect("envelope");
        let wrong_key = super::EnvelopeMasterKey::from_bytes([8; 32]).expect("wrong key");
        let error = decrypt_ssh_secret_bundle(&wrong_key, &context, envelope.as_bytes())
            .expect_err("wrong key must fail");
        let rendered = format!("{key:?} {context:?} {envelope:?} {error:?} {error}");
        for marker in secret_markers {
            assert!(!rendered.contains(marker));
        }
        assert!(rendered.contains("[REDACTED]"));
    }
}
