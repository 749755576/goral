use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{SecretEnvelopeError, SecretEnvelopeErrorCode};

pub const MAX_PRIVATE_KEY_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_PUBLIC_KEY_BYTES: usize = 1 * 1_024 * 1_024;
pub const MAX_CERTIFICATE_BYTES: usize = 1 * 1_024 * 1_024;
pub const MAX_PASSPHRASE_BYTES: usize = 64 * 1_024;
pub const MAX_BUNDLE_PLAINTEXT_BYTES: usize = 8 * 1_024 * 1_024;

const PLAINTEXT_MAGIC: &[u8; 8] = b"NCATSSH1";
const PLAINTEXT_FORMAT_VERSION: u16 = 1;
const PLAINTEXT_HEADER_BYTES: usize = 32;
const PLAINTEXT_RESERVED_BYTES: usize = 4;

/// Secret SSH authentication material owned exclusively by Rust.
///
/// The value deliberately has no `Clone`, Serde, or `Display`
/// implementation. Debug output exposes only field-presence booleans.
///
/// ```compile_fail
/// use netcatty_secret_store::SshSecretBundle;
/// let bundle = SshSecretBundle::new(vec![1], None, None, None).unwrap();
/// let _copy = bundle.clone();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::SshSecretBundle;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<SshSecretBundle>();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::SshSecretBundle;
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<SshSecretBundle>();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::SshSecretBundle;
/// let bundle = SshSecretBundle::new(vec![1], None, None, None).unwrap();
/// let _rendered = format!("{bundle}");
/// ```
pub struct SshSecretBundle {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Option<Zeroizing<Vec<u8>>>,
    certificate: Option<Zeroizing<Vec<u8>>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

impl SshSecretBundle {
    pub fn new(
        private_key: Vec<u8>,
        public_key: Option<Vec<u8>>,
        certificate: Option<Vec<u8>>,
        passphrase: Option<Vec<u8>>,
    ) -> Result<Self, SecretEnvelopeError> {
        let private_key = Zeroizing::new(private_key);
        let public_key = normalize_optional(public_key);
        let certificate = normalize_optional(certificate);
        let passphrase = normalize_optional(passphrase);

        validate_required(&private_key, MAX_PRIVATE_KEY_BYTES)?;
        validate_optional(
            public_key.as_ref().map(|value| value.as_slice()),
            MAX_PUBLIC_KEY_BYTES,
        )?;
        validate_optional(
            certificate.as_ref().map(|value| value.as_slice()),
            MAX_CERTIFICATE_BYTES,
        )?;
        validate_optional(
            passphrase.as_ref().map(|value| value.as_slice()),
            MAX_PASSPHRASE_BYTES,
        )?;

        let encoded_len = encoded_length(
            private_key.len(),
            optional_len(&public_key),
            optional_len(&certificate),
            optional_len(&passphrase),
        )?;
        if encoded_len > MAX_BUNDLE_PLAINTEXT_BYTES {
            return Err(SecretEnvelopeErrorCode::TooLarge.into());
        }

        Ok(Self {
            private_key,
            public_key,
            certificate,
            passphrase,
        })
    }

    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_slice()
    }

    #[must_use]
    pub fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_ref().map(|value| value.as_slice())
    }

    #[must_use]
    pub fn certificate(&self) -> Option<&[u8]> {
        self.certificate.as_ref().map(|value| value.as_slice())
    }

    #[must_use]
    pub fn passphrase(&self) -> Option<&[u8]> {
        self.passphrase.as_ref().map(|value| value.as_slice())
    }

    /// Applies the caller's persistence policy without ever copying the
    /// passphrase into a non-zeroizing value. The private key and the other
    /// bundle fields remain unchanged.
    pub fn discard_passphrase(&mut self) {
        self.passphrase = None;
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SecretEnvelopeError> {
        let private_len = checked_u32(self.private_key.len())?;
        let public_len = checked_u32(optional_len(&self.public_key))?;
        let certificate_len = checked_u32(optional_len(&self.certificate))?;
        let passphrase_len = checked_u32(optional_len(&self.passphrase))?;
        let total_len = encoded_length(
            self.private_key.len(),
            optional_len(&self.public_key),
            optional_len(&self.certificate),
            optional_len(&self.passphrase),
        )?;
        if total_len > MAX_BUNDLE_PLAINTEXT_BYTES {
            return Err(SecretEnvelopeErrorCode::TooLarge.into());
        }

        let mut encoded = Zeroizing::new(Vec::with_capacity(total_len));
        encoded.extend_from_slice(PLAINTEXT_MAGIC);
        encoded.extend_from_slice(&PLAINTEXT_FORMAT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(PLAINTEXT_HEADER_BYTES as u16).to_be_bytes());
        encoded.extend_from_slice(&private_len.to_be_bytes());
        encoded.extend_from_slice(&public_len.to_be_bytes());
        encoded.extend_from_slice(&certificate_len.to_be_bytes());
        encoded.extend_from_slice(&passphrase_len.to_be_bytes());
        encoded.extend_from_slice(&[0; PLAINTEXT_RESERVED_BYTES]);
        encoded.extend_from_slice(&self.private_key);
        extend_optional(&mut encoded, &self.public_key);
        extend_optional(&mut encoded, &self.certificate);
        extend_optional(&mut encoded, &self.passphrase);
        debug_assert_eq!(encoded.len(), total_len);
        Ok(encoded)
    }

    pub(crate) fn contents_match(&self, other: &Self) -> bool {
        slices_match(self.private_key(), other.private_key())
            && optional_slices_match(self.public_key(), other.public_key())
            && optional_slices_match(self.certificate(), other.certificate())
            && optional_slices_match(self.passphrase(), other.passphrase())
    }

    pub(crate) fn decode(plaintext: Zeroizing<Vec<u8>>) -> Result<Self, SecretEnvelopeError> {
        if plaintext.len() < PLAINTEXT_HEADER_BYTES || plaintext.len() > MAX_BUNDLE_PLAINTEXT_BYTES
        {
            return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
        }
        if plaintext.get(..8) != Some(PLAINTEXT_MAGIC.as_slice()) {
            return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
        }
        if read_u16(&plaintext, 8)? != PLAINTEXT_FORMAT_VERSION {
            return Err(SecretEnvelopeErrorCode::UnsupportedVersion.into());
        }
        if usize::from(read_u16(&plaintext, 10)?) != PLAINTEXT_HEADER_BYTES
            || plaintext[28..32].iter().any(|byte| *byte != 0)
        {
            return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
        }

        let private_len = read_u32_as_usize(&plaintext, 12)?;
        let public_len = read_u32_as_usize(&plaintext, 16)?;
        let certificate_len = read_u32_as_usize(&plaintext, 20)?;
        let passphrase_len = read_u32_as_usize(&plaintext, 24)?;
        validate_required_len(private_len, MAX_PRIVATE_KEY_BYTES)?;
        validate_optional_len(public_len, MAX_PUBLIC_KEY_BYTES)?;
        validate_optional_len(certificate_len, MAX_CERTIFICATE_BYTES)?;
        validate_optional_len(passphrase_len, MAX_PASSPHRASE_BYTES)?;
        let expected_len =
            encoded_length(private_len, public_len, certificate_len, passphrase_len)?;
        if expected_len != plaintext.len() || expected_len > MAX_BUNDLE_PLAINTEXT_BYTES {
            return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
        }

        let mut cursor = PLAINTEXT_HEADER_BYTES;
        let private_key = take_field(&plaintext, &mut cursor, private_len)?;
        let public_key = take_optional_field(&plaintext, &mut cursor, public_len)?;
        let certificate = take_optional_field(&plaintext, &mut cursor, certificate_len)?;
        let passphrase = take_optional_field(&plaintext, &mut cursor, passphrase_len)?;
        if cursor != plaintext.len() {
            return Err(SecretEnvelopeErrorCode::InvalidEnvelope.into());
        }
        Self::new(private_key, public_key, certificate, passphrase)
            .map_err(|_| SecretEnvelopeErrorCode::InvalidEnvelope.into())
    }
}

impl fmt::Debug for SshSecretBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshSecretBundle")
            .field("private_key", &"[REDACTED]")
            .field("has_public_key", &self.public_key.is_some())
            .field("has_certificate", &self.certificate.is_some())
            .field("has_passphrase", &self.passphrase.is_some())
            .finish()
    }
}

fn validate_required(value: &[u8], maximum: usize) -> Result<(), SecretEnvelopeError> {
    validate_required_len(value.len(), maximum)
}

fn validate_optional(value: Option<&[u8]>, maximum: usize) -> Result<(), SecretEnvelopeError> {
    if let Some(value) = value {
        validate_optional_len(value.len(), maximum)?;
    }
    Ok(())
}

fn validate_required_len(length: usize, maximum: usize) -> Result<(), SecretEnvelopeError> {
    if length == 0 {
        return Err(SecretEnvelopeErrorCode::InvalidInput.into());
    }
    if length > maximum {
        return Err(SecretEnvelopeErrorCode::TooLarge.into());
    }
    Ok(())
}

fn validate_optional_len(length: usize, maximum: usize) -> Result<(), SecretEnvelopeError> {
    if length == 0 {
        return Ok(());
    }
    if length > maximum {
        return Err(SecretEnvelopeErrorCode::TooLarge.into());
    }
    Ok(())
}

fn optional_len(value: &Option<Zeroizing<Vec<u8>>>) -> usize {
    value.as_ref().map_or(0, |value| value.len())
}

fn normalize_optional(value: Option<Vec<u8>>) -> Option<Zeroizing<Vec<u8>>> {
    value.map(Zeroizing::new).filter(|value| !value.is_empty())
}

fn slices_match(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn optional_slices_match(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => slices_match(left, right),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn encoded_length(
    private_len: usize,
    public_len: usize,
    certificate_len: usize,
    passphrase_len: usize,
) -> Result<usize, SecretEnvelopeError> {
    [private_len, public_len, certificate_len, passphrase_len]
        .into_iter()
        .try_fold(PLAINTEXT_HEADER_BYTES, |total, length| {
            total
                .checked_add(length)
                .ok_or_else(|| SecretEnvelopeErrorCode::TooLarge.into())
        })
}

fn checked_u32(length: usize) -> Result<u32, SecretEnvelopeError> {
    u32::try_from(length).map_err(|_| SecretEnvelopeErrorCode::TooLarge.into())
}

fn extend_optional(target: &mut Vec<u8>, value: &Option<Zeroizing<Vec<u8>>>) {
    if let Some(value) = value {
        target.extend_from_slice(value);
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SecretEnvelopeError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32_as_usize(bytes: &[u8], offset: usize) -> Result<usize, SecretEnvelopeError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    usize::try_from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
        .map_err(|_| SecretEnvelopeErrorCode::InvalidEnvelope.into())
}

fn take_field(
    plaintext: &[u8],
    cursor: &mut usize,
    length: usize,
) -> Result<Vec<u8>, SecretEnvelopeError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?;
    let field = plaintext
        .get(*cursor..end)
        .ok_or_else(|| SecretEnvelopeError::new(SecretEnvelopeErrorCode::InvalidEnvelope))?
        .to_vec();
    *cursor = end;
    Ok(field)
}

fn take_optional_field(
    plaintext: &[u8],
    cursor: &mut usize,
    length: usize,
) -> Result<Option<Vec<u8>>, SecretEnvelopeError> {
    if length == 0 {
        return Ok(None);
    }
    take_field(plaintext, cursor, length).map(Some)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CERTIFICATE_BYTES, MAX_PASSPHRASE_BYTES, MAX_PRIVATE_KEY_BYTES, MAX_PUBLIC_KEY_BYTES,
        PLAINTEXT_HEADER_BYTES, SshSecretBundle,
    };
    use crate::SecretEnvelopeErrorCode;
    use zeroize::Zeroizing;

    #[test]
    fn boundaries_are_enforced_for_every_field() {
        let bundle = SshSecretBundle::new(
            vec![1; MAX_PRIVATE_KEY_BYTES],
            Some(vec![2; MAX_PUBLIC_KEY_BYTES]),
            Some(vec![3; MAX_CERTIFICATE_BYTES]),
            Some(vec![4; MAX_PASSPHRASE_BYTES]),
        )
        .expect("all exact field limits are accepted");
        let encoded = bundle.encode().expect("encode maximum bundle");
        assert_eq!(encoded.len(), PLAINTEXT_HEADER_BYTES + 6_356_992);

        let oversized = [
            SshSecretBundle::new(vec![1; MAX_PRIVATE_KEY_BYTES + 1], None, None, None),
            SshSecretBundle::new(vec![1], Some(vec![2; MAX_PUBLIC_KEY_BYTES + 1]), None, None),
            SshSecretBundle::new(
                vec![1],
                None,
                Some(vec![3; MAX_CERTIFICATE_BYTES + 1]),
                None,
            ),
            SshSecretBundle::new(vec![1], None, None, Some(vec![4; MAX_PASSPHRASE_BYTES + 1])),
        ];
        for result in oversized {
            assert_eq!(
                result.err().map(|error| error.code()),
                Some(SecretEnvelopeErrorCode::TooLarge)
            );
        }
    }

    #[test]
    fn required_and_optional_empty_values_are_canonical() {
        assert_eq!(
            SshSecretBundle::new(Vec::new(), None, None, None)
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::InvalidInput)
        );
        let bundle = SshSecretBundle::new(
            vec![1],
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
        )
        .expect("empty optional values normalize through the zero length encoding");
        assert_eq!(bundle.public_key(), None);
        assert_eq!(bundle.certificate(), None);
        assert_eq!(bundle.passphrase(), None);
        let decoded = SshSecretBundle::decode(bundle.encode().expect("encode"))
            .expect("decode canonical empty optionals");
        assert_eq!(decoded.public_key(), None);
        assert_eq!(decoded.certificate(), None);
        assert_eq!(decoded.passphrase(), None);
    }

    #[test]
    fn passphrase_policy_discards_only_the_zeroizing_passphrase_field() {
        let mut bundle = SshSecretBundle::new(
            b"private".to_vec(),
            Some(b"public".to_vec()),
            Some(b"certificate".to_vec()),
            Some(b"discard-me".to_vec()),
        )
        .expect("bundle");
        bundle.discard_passphrase();
        assert_eq!(bundle.private_key(), b"private");
        assert_eq!(bundle.public_key(), Some(b"public".as_slice()));
        assert_eq!(bundle.certificate(), Some(b"certificate".as_slice()));
        assert_eq!(bundle.passphrase(), None);
    }

    #[test]
    fn strict_plaintext_parser_rejects_truncation_lengths_reserved_and_versions() {
        let bundle = SshSecretBundle::new(
            b"private".to_vec(),
            Some(b"public".to_vec()),
            Some(b"certificate".to_vec()),
            Some(b"passphrase".to_vec()),
        )
        .expect("bundle");
        let valid = bundle.encode().expect("encode");
        for length in 0..PLAINTEXT_HEADER_BYTES {
            assert!(SshSecretBundle::decode(Zeroizing::new(valid[..length].to_vec())).is_err());
        }

        let mut wrong_length = valid.to_vec();
        wrong_length[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(SshSecretBundle::decode(Zeroizing::new(wrong_length)).is_err());

        let mut reserved = valid.to_vec();
        reserved[31] = 1;
        assert!(SshSecretBundle::decode(Zeroizing::new(reserved)).is_err());

        let mut future = valid.to_vec();
        future[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            SshSecretBundle::decode(Zeroizing::new(future))
                .err()
                .map(|error| error.code()),
            Some(SecretEnvelopeErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn debug_never_exposes_secret_fields_or_lengths() {
        let markers = [
            "private-debug-marker",
            "public-debug-marker",
            "certificate-debug-marker",
            "passphrase-debug-marker",
        ];
        let bundle = SshSecretBundle::new(
            markers[0].as_bytes().to_vec(),
            Some(markers[1].as_bytes().to_vec()),
            Some(markers[2].as_bytes().to_vec()),
            Some(markers[3].as_bytes().to_vec()),
        )
        .expect("bundle");
        let rendered = format!("{bundle:?}");
        for marker in markers {
            assert!(!rendered.contains(marker));
        }
        assert!(rendered.contains("[REDACTED]"));
    }
}
