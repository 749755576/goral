use zeroize::Zeroizing;

use crate::{CredentialError, CredentialErrorCode};

/// Raw IPC and ephemeral secrets retain Quick Connect's existing 64 KiB limit.
pub const MAX_SECRET_VALUE_BYTES: usize = 64 * 1_024;

/// A zeroizing secret buffer that deliberately implements neither `Debug`,
/// `Clone`, nor Serde serialization.
///
/// ```compile_fail
/// use netcatty_credentials::SecretValue;
/// let secret = SecretValue::from_utf8("not JSON".to_owned()).unwrap();
/// let _ = serde_json::to_string(&secret);
/// ```
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(value: Vec<u8>) -> Result<Self, CredentialError> {
        if value.is_empty() {
            return Err(CredentialErrorCode::InvalidSecret.into());
        }
        if value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(CredentialErrorCode::TooLarge.into());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn from_utf8(value: String) -> Result<Self, CredentialError> {
        Self::new(value.into_bytes())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_utf8(&self) -> Result<&str, CredentialError> {
        std::str::from_utf8(self.as_bytes())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidUtf8))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SECRET_VALUE_BYTES, SecretValue};
    use crate::CredentialErrorCode;

    #[test]
    fn secret_value_validates_size_and_utf8_without_debug_or_serde() {
        assert_eq!(
            SecretValue::new(Vec::new()).err().map(|error| error.code()),
            Some(CredentialErrorCode::InvalidSecret)
        );
        assert_eq!(
            SecretValue::new(vec![1; MAX_SECRET_VALUE_BYTES + 1])
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::TooLarge)
        );
        assert!(SecretValue::new(vec![1; MAX_SECRET_VALUE_BYTES]).is_ok());
        let text = SecretValue::from_utf8("runtime value".to_owned()).expect("secret");
        assert!(matches!(text.as_utf8(), Ok("runtime value")));
        let binary = SecretValue::new(vec![0xff]).expect("binary secret");
        assert_eq!(
            binary.as_utf8().err().map(|error| error.code()),
            Some(CredentialErrorCode::InvalidUtf8)
        );
    }
}
