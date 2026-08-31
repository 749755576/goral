use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::{Uuid, Version};

use crate::{CredentialError, CredentialErrorCode};

const STORED_PREFIX: &str = "os:v1:";
const EPHEMERAL_PREFIX: &str = "mem:v1:";
const SAVED_HOST_NAMESPACE: Uuid = Uuid::from_bytes([
    0x59, 0x47, 0x67, 0x26, 0x7e, 0x58, 0x4a, 0x22, 0x97, 0xcd, 0x75, 0xb2, 0x10, 0x2b, 0xe9, 0xa4,
]);
const SAVED_HOST_TELNET_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6f, 0xb6, 0x31, 0x8f, 0x61, 0xd0, 0x4d, 0xe4, 0xa7, 0x34, 0x0d, 0x98, 0x6e, 0x80, 0xc7, 0x9f,
]);
const SAVED_IDENTITY_NAMESPACE: Uuid = Uuid::from_bytes([
    0xb0, 0x9e, 0x2e, 0x1e, 0xe9, 0x60, 0x47, 0x04, 0x9f, 0xe6, 0xf5, 0xd6, 0xb7, 0x52, 0x4a, 0x21,
]);
const SAVED_HOST_PROXY_NAMESPACE: Uuid = Uuid::from_bytes([
    0xdc, 0x0d, 0x56, 0x8b, 0x8b, 0x67, 0x42, 0x8b, 0x94, 0xdb, 0x84, 0xf8, 0x2a, 0x6b, 0xf4, 0xb8,
]);
const SAVED_PROXY_PROFILE_NAMESPACE: Uuid = Uuid::from_bytes([
    0xc4, 0xbe, 0xea, 0x51, 0x36, 0x42, 0x4f, 0xc5, 0xab, 0x51, 0xce, 0xea, 0xf2, 0x39, 0x2a, 0xe5,
]);
const AI_PROVIDER_NAMESPACE: Uuid = Uuid::from_bytes([
    0xd1, 0x3b, 0xc2, 0xaf, 0x6e, 0x68, 0x4d, 0x80, 0x94, 0x33, 0xf6, 0xa3, 0x52, 0x65, 0xc4, 0xd1,
]);
const AI_PROVIDER_ENDPOINT_NAMESPACE: Uuid = Uuid::from_bytes([
    0x7a, 0x44, 0x19, 0x2e, 0xf1, 0x83, 0x47, 0x96, 0xa4, 0x6b, 0x72, 0x5d, 0x9c, 0x10, 0xe8, 0x33,
]);
const AI_PROVIDER_ENDPOINT_DOMAIN: &[u8] = b"netcatty-ai-provider-endpoint-v1\0";
const SAVED_GROUP_SSH_NAMESPACE: Uuid = Uuid::from_bytes([
    0x91, 0x6a, 0xd7, 0x6e, 0x51, 0xe2, 0x45, 0xa1, 0x88, 0x39, 0xa0, 0xb4, 0x7f, 0x74, 0xd1, 0x1b,
]);
const SAVED_GROUP_TELNET_NAMESPACE: Uuid = Uuid::from_bytes([
    0xe8, 0xef, 0xd2, 0xa9, 0xd3, 0x60, 0x41, 0xd8, 0xb5, 0x49, 0x0f, 0x17, 0x65, 0xea, 0x84, 0xa3,
]);
const SAVED_GROUP_PROXY_NAMESPACE: Uuid = Uuid::from_bytes([
    0x2a, 0x5b, 0x38, 0xc4, 0xf9, 0x72, 0x48, 0xd4, 0xb2, 0x61, 0x3e, 0x0a, 0x1d, 0xa4, 0x6c, 0x93,
]);
const LEGACY_IMPORT_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0xe4, 0x5c, 0x14, 0xb2, 0xf7, 0xd8, 0x4c, 0x5d, 0xa8, 0x28, 0xb3, 0xa4, 0x76, 0x59, 0x3d, 0x91,
]);
const LEGACY_IMPORT_HOST_TELNET_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x28, 0x5f, 0x35, 0x4b, 0x91, 0xd8, 0x49, 0x70, 0x9f, 0x03, 0x5c, 0x61, 0x8d, 0x72, 0x24, 0xb9,
]);
const LEGACY_IMPORT_IDENTITY_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x0d, 0xc5, 0x89, 0xac, 0x1b, 0x0c, 0x4a, 0xa7, 0xb2, 0x3d, 0x91, 0xb3, 0x2d, 0xce, 0xa2, 0x4f,
]);
const LEGACY_IMPORT_HOST_PROXY_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x69, 0xce, 0x15, 0xcd, 0x99, 0xab, 0x4c, 0x95, 0xb8, 0x07, 0xeb, 0xf0, 0xa0, 0xe2, 0x86, 0x3a,
]);
const LEGACY_IMPORT_PROXY_PROFILE_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0xcd, 0x41, 0xf0, 0x92, 0xa1, 0xad, 0x47, 0xf1, 0x96, 0xd8, 0x78, 0x94, 0x58, 0x3e, 0x16, 0x0d,
]);
const LEGACY_IMPORT_GROUP_SSH_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x10, 0x4a, 0x7c, 0x29, 0x63, 0x88, 0x4a, 0x2e, 0x9c, 0x13, 0x42, 0xfd, 0x5d, 0xb6, 0x91, 0xe7,
]);
const LEGACY_IMPORT_GROUP_TELNET_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x75, 0xc1, 0x03, 0xeb, 0xac, 0x49, 0x47, 0xca, 0x86, 0xe1, 0x11, 0x54, 0xc2, 0xe9, 0x38, 0x6d,
]);
const LEGACY_IMPORT_GROUP_PROXY_BACKUP_NAMESPACE: Uuid = Uuid::from_bytes([
    0xb2, 0x39, 0x58, 0x04, 0x3f, 0xb5, 0x4e, 0x91, 0xa6, 0xd7, 0x8c, 0x26, 0x70, 0xc3, 0xed, 0x14,
]);
const LEGACY_IMPORT_BACKUP_DOMAIN: &[u8] = b"netcatty-legacy-import-backup-v1\0";
const LEGACY_IMPORT_HOST_TELNET_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-host-telnet-backup-v1\0";
const LEGACY_IMPORT_IDENTITY_BACKUP_DOMAIN: &[u8] = b"netcatty-legacy-import-identity-backup-v1\0";
const LEGACY_IMPORT_HOST_PROXY_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-host-proxy-backup-v1\0";
const LEGACY_IMPORT_PROXY_PROFILE_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-proxy-profile-backup-v1\0";
const LEGACY_IMPORT_GROUP_SSH_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-group-ssh-backup-v1\0";
const LEGACY_IMPORT_GROUP_TELNET_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-group-telnet-backup-v1\0";
const LEGACY_IMPORT_GROUP_PROXY_BACKUP_DOMAIN: &[u8] =
    b"netcatty-legacy-import-group-proxy-backup-v1\0";
const MAX_SAVED_HOST_ID_BYTES: usize = 4_096;
const MAX_SAVED_IDENTITY_ID_BYTES: usize = 512;
const MAX_LEGACY_IMPORT_SAVED_HOST_ID_BYTES: usize = 512;
const MAX_SAVED_PROXY_OWNER_ID_BYTES: usize = 512;
const MAX_SAVED_GROUP_ID_BYTES: usize = 512;
const MAX_AI_PROVIDER_ID_BYTES: usize = 128;
const MAX_AI_CANONICAL_ENDPOINT_BYTES: usize = 2 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialId(Uuid);

impl CredentialId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, CredentialError> {
        let uuid = Uuid::parse_str(value)
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        if !matches!(uuid.get_version(), Some(Version::Random | Version::Sha1))
            || uuid.hyphenated().to_string() != value
        {
            return Err(CredentialErrorCode::InvalidReference.into());
        }
        Ok(Self(uuid))
    }

    pub fn for_saved_host(host_id: &str) -> Result<Self, CredentialError> {
        validate_saved_host_id(host_id)?;
        Ok(Self(Uuid::new_v5(
            &SAVED_HOST_NAMESPACE,
            host_id.as_bytes(),
        )))
    }

    /// Derives the stable Telnet-password owner for a saved host.
    ///
    /// Its namespace is deliberately distinct from the saved host's SSH
    /// password owner, even when both credentials use the same opaque host ID.
    pub fn for_saved_host_telnet(host_id: &str) -> Result<Self, CredentialError> {
        validate_saved_host_id(host_id)?;
        Ok(Self(Uuid::new_v5(
            &SAVED_HOST_TELNET_NAMESPACE,
            host_id.as_bytes(),
        )))
    }

    pub fn for_saved_identity(identity_id: &str) -> Result<Self, CredentialError> {
        validate_saved_identity_id(identity_id)?;
        Ok(Self(Uuid::new_v5(
            &SAVED_IDENTITY_NAMESPACE,
            identity_id.as_bytes(),
        )))
    }

    pub fn for_saved_host_proxy(host_id: &str) -> Result<Self, CredentialError> {
        validate_saved_proxy_owner_id(host_id)?;
        Ok(Self(Uuid::new_v5(
            &SAVED_HOST_PROXY_NAMESPACE,
            host_id.as_bytes(),
        )))
    }

    pub fn for_saved_proxy_profile(profile_id: &str) -> Result<Self, CredentialError> {
        validate_saved_proxy_owner_id(profile_id)?;
        Ok(Self(Uuid::new_v5(
            &SAVED_PROXY_PROFILE_NAMESPACE,
            profile_id.as_bytes(),
        )))
    }

    /// Derives the stable OS-keyring owner for one AI provider's API key.
    ///
    /// Provider IDs use a deliberately narrow renderer-compatible alphabet and
    /// an ownership namespace isolated from every SSH, Telnet, and proxy
    /// credential. The source provider ID is never embedded in the locator.
    pub fn for_ai_provider(provider_id: &str) -> Result<Self, CredentialError> {
        validate_ai_provider_id(provider_id)?;
        Ok(Self(Uuid::new_v5(
            &AI_PROVIDER_NAMESPACE,
            provider_id.as_bytes(),
        )))
    }

    /// Derives an endpoint-bound AI API-key owner. This intentionally uses a
    /// namespace distinct from the historical provider-only owner so an old
    /// key can never be selected without an explicit save into this account.
    pub fn for_ai_provider_endpoint(
        provider_id: &str,
        canonical_endpoint: &str,
    ) -> Result<Self, CredentialError> {
        validate_ai_provider_id(provider_id)?;
        validate_ai_canonical_endpoint(canonical_endpoint)?;
        let provider_length = u16::try_from(provider_id.len())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        let endpoint_length = u32::try_from(canonical_endpoint.len())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        let mut name = Vec::with_capacity(
            AI_PROVIDER_ENDPOINT_DOMAIN.len()
                + std::mem::size_of::<u16>()
                + provider_id.len()
                + std::mem::size_of::<u32>()
                + canonical_endpoint.len(),
        );
        name.extend_from_slice(AI_PROVIDER_ENDPOINT_DOMAIN);
        name.extend_from_slice(&provider_length.to_be_bytes());
        name.extend_from_slice(provider_id.as_bytes());
        name.extend_from_slice(&endpoint_length.to_be_bytes());
        name.extend_from_slice(canonical_endpoint.as_bytes());
        Ok(Self(Uuid::new_v5(&AI_PROVIDER_ENDPOINT_NAMESPACE, &name)))
    }

    pub fn for_saved_group_ssh(group_id: &str) -> Result<Self, CredentialError> {
        saved_group_credential_id(group_id, &SAVED_GROUP_SSH_NAMESPACE)
    }

    pub fn for_saved_group_telnet(group_id: &str) -> Result<Self, CredentialError> {
        saved_group_credential_id(group_id, &SAVED_GROUP_TELNET_NAMESPACE)
    }

    pub fn for_saved_group_proxy(group_id: &str) -> Result<Self, CredentialError> {
        saved_group_credential_id(group_id, &SAVED_GROUP_PROXY_NAMESPACE)
    }

    pub fn for_legacy_import_backup(
        transaction_id: &str,
        saved_host_id: &str,
    ) -> Result<Self, CredentialError> {
        let transaction_id = parse_legacy_import_transaction_id(transaction_id)?;
        validate_legacy_import_saved_host_id(saved_host_id)?;
        let host_id_len = u32::try_from(saved_host_id.len())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        let mut name = Vec::with_capacity(
            LEGACY_IMPORT_BACKUP_DOMAIN.len()
                + transaction_id.as_bytes().len()
                + std::mem::size_of::<u32>()
                + saved_host_id.len(),
        );
        name.extend_from_slice(LEGACY_IMPORT_BACKUP_DOMAIN);
        name.extend_from_slice(transaction_id.as_bytes());
        name.extend_from_slice(&host_id_len.to_be_bytes());
        name.extend_from_slice(saved_host_id.as_bytes());
        Ok(Self(Uuid::new_v5(&LEGACY_IMPORT_BACKUP_NAMESPACE, &name)))
    }

    /// Derives the crash-recovery backup for a saved host's Telnet password.
    /// Its namespace is isolated from the same host's SSH-password backup.
    pub fn for_legacy_import_host_telnet_backup(
        transaction_id: &str,
        saved_host_id: &str,
    ) -> Result<Self, CredentialError> {
        let transaction_id = parse_legacy_import_transaction_id(transaction_id)?;
        validate_legacy_import_saved_host_id(saved_host_id)?;
        let host_id_len = u32::try_from(saved_host_id.len())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        let mut name = Vec::with_capacity(
            LEGACY_IMPORT_HOST_TELNET_BACKUP_DOMAIN.len()
                + transaction_id.as_bytes().len()
                + std::mem::size_of::<u32>()
                + saved_host_id.len(),
        );
        name.extend_from_slice(LEGACY_IMPORT_HOST_TELNET_BACKUP_DOMAIN);
        name.extend_from_slice(transaction_id.as_bytes());
        name.extend_from_slice(&host_id_len.to_be_bytes());
        name.extend_from_slice(saved_host_id.as_bytes());
        Ok(Self(Uuid::new_v5(
            &LEGACY_IMPORT_HOST_TELNET_BACKUP_NAMESPACE,
            &name,
        )))
    }

    pub fn for_legacy_import_identity_backup(
        transaction_id: &str,
        identity_id: &str,
    ) -> Result<Self, CredentialError> {
        let transaction_id = parse_legacy_import_transaction_id(transaction_id)?;
        validate_saved_identity_id(identity_id)?;
        let identity_id_len = u32::try_from(identity_id.len())
            .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
        let mut name = Vec::with_capacity(
            LEGACY_IMPORT_IDENTITY_BACKUP_DOMAIN.len()
                + transaction_id.as_bytes().len()
                + std::mem::size_of::<u32>()
                + identity_id.len(),
        );
        name.extend_from_slice(LEGACY_IMPORT_IDENTITY_BACKUP_DOMAIN);
        name.extend_from_slice(transaction_id.as_bytes());
        name.extend_from_slice(&identity_id_len.to_be_bytes());
        name.extend_from_slice(identity_id.as_bytes());
        Ok(Self(Uuid::new_v5(
            &LEGACY_IMPORT_IDENTITY_BACKUP_NAMESPACE,
            &name,
        )))
    }

    pub fn for_legacy_import_host_proxy_backup(
        transaction_id: &str,
        host_id: &str,
    ) -> Result<Self, CredentialError> {
        legacy_import_proxy_backup_id(
            transaction_id,
            host_id,
            &LEGACY_IMPORT_HOST_PROXY_BACKUP_NAMESPACE,
            LEGACY_IMPORT_HOST_PROXY_BACKUP_DOMAIN,
        )
    }

    pub fn for_legacy_import_proxy_profile_backup(
        transaction_id: &str,
        profile_id: &str,
    ) -> Result<Self, CredentialError> {
        legacy_import_proxy_backup_id(
            transaction_id,
            profile_id,
            &LEGACY_IMPORT_PROXY_PROFILE_BACKUP_NAMESPACE,
            LEGACY_IMPORT_PROXY_PROFILE_BACKUP_DOMAIN,
        )
    }

    pub fn for_legacy_import_group_ssh_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        legacy_import_group_backup_id(
            transaction_id,
            group_id,
            &LEGACY_IMPORT_GROUP_SSH_BACKUP_NAMESPACE,
            LEGACY_IMPORT_GROUP_SSH_BACKUP_DOMAIN,
        )
    }

    pub fn for_legacy_import_group_telnet_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        legacy_import_group_backup_id(
            transaction_id,
            group_id,
            &LEGACY_IMPORT_GROUP_TELNET_BACKUP_NAMESPACE,
            LEGACY_IMPORT_GROUP_TELNET_BACKUP_DOMAIN,
        )
    }

    pub fn for_legacy_import_group_proxy_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        legacy_import_group_backup_id(
            transaction_id,
            group_id,
            &LEGACY_IMPORT_GROUP_PROXY_BACKUP_NAMESPACE,
            LEGACY_IMPORT_GROUP_PROXY_BACKUP_DOMAIN,
        )
    }

    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl FromStr for CredentialId {
    type Err = CredentialError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CredentialId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CredentialId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| D::Error::custom("invalid credential ID"))
    }
}

macro_rules! credential_reference {
    ($name:ident, $prefix:ident, $allow_v5:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(CredentialId);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(CredentialId::new())
            }

            #[must_use]
            pub const fn from_id(id: CredentialId) -> Self {
                Self(id)
            }

            #[must_use]
            pub const fn id(&self) -> CredentialId {
                self.0
            }

            pub fn parse(value: &str) -> Result<Self, CredentialError> {
                let suffix = value
                    .strip_prefix($prefix)
                    .ok_or_else(|| CredentialError::new(CredentialErrorCode::InvalidReference))?;
                let id = CredentialId::parse(suffix)?;
                if !$allow_v5 && id.as_uuid().get_version() != Some(Version::Random) {
                    return Err(CredentialErrorCode::InvalidReference.into());
                }
                Ok(Self(id))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = CredentialError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(&value).map_err(|_| D::Error::custom("invalid credential reference"))
            }
        }
    };
}

credential_reference!(StoredCredentialReference, STORED_PREFIX, true);
credential_reference!(EphemeralCredentialReference, EPHEMERAL_PREFIX, false);

impl StoredCredentialReference {
    pub fn for_saved_host(host_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_host(host_id)?))
    }

    /// Derives the stable OS-keyring reference for a saved host's Telnet
    /// password. The source host ID is not embedded in the account locator,
    /// and the owner is isolated from the host's SSH password.
    pub fn for_saved_host_telnet(host_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_host_telnet(host_id)?))
    }

    /// Derives the stable OS-keyring reference for a saved password identity.
    ///
    /// The UUID v5 namespace is deliberately distinct from saved-host
    /// credentials, so equal opaque host and identity IDs cannot select the
    /// same keyring account. The identity ID must be non-empty, contain at
    /// most 512 UTF-8 bytes, and contain no control characters; it remains an
    /// opaque value and is not required to be a UUID. The source identifier is
    /// not embedded in the resulting account locator.
    pub fn for_saved_identity(identity_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_identity(
            identity_id,
        )?))
    }

    /// Derives the stable OS-keyring reference for a saved host's manual
    /// inline proxy password. Its UUID v5 namespace is isolated from the
    /// host's SSH password, every identity, and every proxy profile.
    pub fn for_saved_host_proxy(host_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_host_proxy(host_id)?))
    }

    /// Derives the stable OS-keyring reference for a proxy profile's manual
    /// password. Equal opaque host/profile/identity IDs still select distinct
    /// accounts, and the source ID is never embedded in the locator.
    pub fn for_saved_proxy_profile(profile_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_proxy_profile(
            profile_id,
        )?))
    }

    /// Stable provider-owned API-key reference. Equal IDs remain isolated from
    /// every existing password ownership class.
    pub fn for_ai_provider(provider_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_ai_provider(provider_id)?))
    }

    /// Stable provider-and-endpoint-owned AI API-key reference. Neither source
    /// string is embedded in the returned OS-keyring locator.
    pub fn for_ai_provider_endpoint(
        provider_id: &str,
        canonical_endpoint: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_ai_provider_endpoint(
            provider_id,
            canonical_endpoint,
        )?))
    }

    /// Stable group-owned SSH password account. Group paths are deliberately
    /// not used so rename/reparent operations never move credential custody.
    pub fn for_saved_group_ssh(group_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_group_ssh(group_id)?))
    }

    /// Stable group-owned Telnet password account, isolated from SSH and proxy.
    pub fn for_saved_group_telnet(group_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_group_telnet(
            group_id,
        )?))
    }

    /// Stable group-owned inline-proxy password account.
    pub fn for_saved_group_proxy(group_id: &str) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_saved_group_proxy(
            group_id,
        )?))
    }

    /// Derives an OS-keyring reference for a crash-recovery backup owned by one
    /// legacy-import transaction and saved host.
    ///
    /// The transaction ID must be a canonical lowercase UUID v4. The returned
    /// UUID v5 uses a namespace and length-delimited domain that are distinct
    /// from normal saved-host credential references. Neither source identifier
    /// is embedded in the resulting account locator.
    pub fn for_legacy_import_backup(
        transaction_id: &str,
        saved_host_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(CredentialId::for_legacy_import_backup(
            transaction_id,
            saved_host_id,
        )?))
    }

    pub fn for_legacy_import_host_telnet_backup(
        transaction_id: &str,
        saved_host_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_host_telnet_backup(transaction_id, saved_host_id)?,
        ))
    }

    /// Derives an OS-keyring reference for a crash-recovery backup owned by one
    /// legacy-import transaction and password identity.
    ///
    /// Its UUID v5 namespace and domain are distinct from both normal identity
    /// credentials and saved-host import backups. The transaction ID must be a
    /// canonical lowercase UUID v4. The identity ID has the same strict
    /// opaque-ID constraints as [`Self::for_saved_identity`], and neither
    /// input is embedded in the resulting account locator.
    pub fn for_legacy_import_identity_backup(
        transaction_id: &str,
        identity_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_identity_backup(transaction_id, identity_id)?,
        ))
    }

    /// Derives a transaction- and host-isolated backup reference for a saved
    /// host's manual inline proxy password.
    pub fn for_legacy_import_host_proxy_backup(
        transaction_id: &str,
        host_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_host_proxy_backup(transaction_id, host_id)?,
        ))
    }

    /// Derives a transaction- and profile-isolated backup reference for a
    /// proxy profile's manual password.
    pub fn for_legacy_import_proxy_profile_backup(
        transaction_id: &str,
        profile_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_proxy_profile_backup(transaction_id, profile_id)?,
        ))
    }

    pub fn for_legacy_import_group_ssh_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_group_ssh_backup(transaction_id, group_id)?,
        ))
    }

    pub fn for_legacy_import_group_telnet_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_group_telnet_backup(transaction_id, group_id)?,
        ))
    }

    pub fn for_legacy_import_group_proxy_backup(
        transaction_id: &str,
        group_id: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self::from_id(
            CredentialId::for_legacy_import_group_proxy_backup(transaction_id, group_id)?,
        ))
    }
}

fn saved_group_credential_id(
    group_id: &str,
    namespace: &Uuid,
) -> Result<CredentialId, CredentialError> {
    validate_saved_group_id(group_id)?;
    Ok(CredentialId(Uuid::new_v5(namespace, group_id.as_bytes())))
}

fn legacy_import_group_backup_id(
    transaction_id: &str,
    group_id: &str,
    namespace: &Uuid,
    domain: &[u8],
) -> Result<CredentialId, CredentialError> {
    let transaction_id = parse_legacy_import_transaction_id(transaction_id)?;
    validate_saved_group_id(group_id)?;
    let group_id_len = u32::try_from(group_id.len())
        .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
    let mut name = Vec::with_capacity(
        domain.len()
            + transaction_id.as_bytes().len()
            + std::mem::size_of::<u32>()
            + group_id.len(),
    );
    name.extend_from_slice(domain);
    name.extend_from_slice(transaction_id.as_bytes());
    name.extend_from_slice(&group_id_len.to_be_bytes());
    name.extend_from_slice(group_id.as_bytes());
    Ok(CredentialId(Uuid::new_v5(namespace, &name)))
}

fn legacy_import_proxy_backup_id(
    transaction_id: &str,
    owner_id: &str,
    namespace: &Uuid,
    domain: &[u8],
) -> Result<CredentialId, CredentialError> {
    let transaction_id = parse_legacy_import_transaction_id(transaction_id)?;
    validate_saved_proxy_owner_id(owner_id)?;
    let owner_id_len = u32::try_from(owner_id.len())
        .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
    let mut name = Vec::with_capacity(
        domain.len()
            + transaction_id.as_bytes().len()
            + std::mem::size_of::<u32>()
            + owner_id.len(),
    );
    name.extend_from_slice(domain);
    name.extend_from_slice(transaction_id.as_bytes());
    name.extend_from_slice(&owner_id_len.to_be_bytes());
    name.extend_from_slice(owner_id.as_bytes());
    Ok(CredentialId(Uuid::new_v5(namespace, &name)))
}

fn parse_legacy_import_transaction_id(value: &str) -> Result<Uuid, CredentialError> {
    if value.len() != 36 || value.chars().any(char::is_control) {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    let id = Uuid::parse_str(value)
        .map_err(|_| CredentialError::new(CredentialErrorCode::InvalidReference))?;
    if id.get_version() != Some(Version::Random) || id.hyphenated().to_string() != value {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(id)
}

fn validate_legacy_import_saved_host_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > MAX_LEGACY_IMPORT_SAVED_HOST_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_saved_host_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty() || value.len() > MAX_SAVED_HOST_ID_BYTES {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_saved_identity_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > MAX_SAVED_IDENTITY_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_saved_proxy_owner_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > MAX_SAVED_PROXY_OWNER_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_saved_group_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > MAX_SAVED_GROUP_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_ai_provider_id(value: &str) -> Result<(), CredentialError> {
    let bytes = value.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || bytes.len() > MAX_AI_PROVIDER_ID_BYTES
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'-')
        })
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

fn validate_ai_canonical_endpoint(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > MAX_AI_CANONICAL_ENDPOINT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CredentialErrorCode::InvalidReference.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{CredentialId, EphemeralCredentialReference, StoredCredentialReference};
    use crate::test_support::{CredentialOperation, in_memory_credential_store};
    use crate::{CredentialErrorCode, CredentialKind, SecretValue};

    const TRANSACTION_A: &str = "11111111-1111-4111-8111-111111111111";
    const TRANSACTION_B: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn references_require_canonical_v4_uuid_and_exact_scheme() {
        let stored = StoredCredentialReference::new();
        let encoded = stored.to_string();
        assert_eq!(encoded.parse(), Ok(stored));
        assert!(encoded.starts_with("os:v1:"));
        assert!(
            encoded
                .to_uppercase()
                .parse::<StoredCredentialReference>()
                .is_err()
        );
        assert!(
            encoded
                .replace("os:v1:", "mem:v1:")
                .parse::<StoredCredentialReference>()
                .is_err()
        );
        assert!(
            "os:v1:00000000-0000-0000-0000-000000000000"
                .parse::<StoredCredentialReference>()
                .is_err()
        );
        assert!(
            "00000000000000000000000000000000"
                .parse::<CredentialId>()
                .is_err()
        );

        let ephemeral = EphemeralCredentialReference::new();
        assert_eq!(ephemeral.to_string().parse(), Ok(ephemeral));
    }

    #[test]
    fn references_round_trip_as_json_strings() {
        let reference = StoredCredentialReference::new();
        let json = serde_json::to_string(&reference).expect("reference JSON");
        let decoded: StoredCredentialReference =
            serde_json::from_str(&json).expect("decode reference JSON");
        assert_eq!(decoded, reference);
    }

    #[test]
    fn saved_host_references_are_deterministic_opaque_uuid_v5_values() {
        let first = StoredCredentialReference::for_saved_host("host-record-1").expect("reference");
        let again = StoredCredentialReference::for_saved_host("host-record-1").expect("reference");
        let other = StoredCredentialReference::for_saved_host("host-record-2").expect("reference");
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(
            first.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert!(!first.to_string().contains("host-record"));
        assert_eq!(first.to_string().parse(), Ok(first));
        assert!(
            EphemeralCredentialReference::parse(&first.to_string().replace("os:", "mem:")).is_err()
        );
        assert!(StoredCredentialReference::for_saved_host("").is_err());
    }

    #[test]
    fn ai_provider_references_are_stable_opaque_and_namespace_isolated() {
        let provider_id = "openai-compatible";
        let first =
            StoredCredentialReference::for_ai_provider(provider_id).expect("AI provider reference");
        let same = StoredCredentialReference::for_ai_provider(provider_id)
            .expect("stable AI provider reference");
        let other = StoredCredentialReference::for_ai_provider("local.openai_v1")
            .expect("other AI provider reference");
        let direct = CredentialId::for_ai_provider(provider_id).expect("AI provider ID");

        assert_eq!(first, same);
        assert_ne!(first, other);
        assert_eq!(first.id(), direct);
        assert_eq!(
            first.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert_eq!(first.to_string().parse(), Ok(first));
        assert!(!first.to_string().contains(provider_id));

        let all = [
            first,
            StoredCredentialReference::for_saved_host(provider_id).expect("host reference"),
            StoredCredentialReference::for_saved_host_telnet(provider_id)
                .expect("host Telnet reference"),
            StoredCredentialReference::for_saved_identity(provider_id).expect("identity reference"),
            StoredCredentialReference::for_saved_host_proxy(provider_id)
                .expect("host proxy reference"),
            StoredCredentialReference::for_saved_proxy_profile(provider_id)
                .expect("profile proxy reference"),
            StoredCredentialReference::for_saved_group_ssh(provider_id)
                .expect("group SSH reference"),
            StoredCredentialReference::for_saved_group_telnet(provider_id)
                .expect("group Telnet reference"),
            StoredCredentialReference::for_saved_group_proxy(provider_id)
                .expect("group proxy reference"),
        ];
        assert_eq!(
            all.into_iter().collect::<HashSet<_>>().len(),
            all.len(),
            "AI providers must use an ownership namespace distinct from every existing credential class"
        );
    }

    #[test]
    fn ai_endpoint_references_are_stable_opaque_and_isolated_from_legacy_owners() {
        let provider_id = "openai-compatible";
        let endpoint = "https://api.example.test/v1/chat/completions";
        let first = StoredCredentialReference::for_ai_provider_endpoint(provider_id, endpoint)
            .expect("endpoint-bound AI reference");
        let same = StoredCredentialReference::for_ai_provider_endpoint(provider_id, endpoint)
            .expect("stable endpoint-bound AI reference");
        let other_endpoint = StoredCredentialReference::for_ai_provider_endpoint(
            provider_id,
            "https://other.example.test/v1/chat/completions",
        )
        .expect("other endpoint reference");
        let other_provider =
            StoredCredentialReference::for_ai_provider_endpoint("deepseek", endpoint)
                .expect("other provider reference");
        let legacy = StoredCredentialReference::for_ai_provider(provider_id)
            .expect("legacy provider-only reference");

        assert_eq!(first, same);
        assert_ne!(first, other_endpoint);
        assert_ne!(first, other_provider);
        assert_ne!(first, legacy);
        let rendered = format!("{first:?} {first}");
        assert!(!rendered.contains(provider_id));
        assert!(!rendered.contains(endpoint));
        assert_eq!(first.to_string().parse(), Ok(first));
    }

    #[test]
    fn ai_endpoint_reference_rejects_unbounded_or_control_bearing_values() {
        for endpoint in [
            String::new(),
            "https://api.example.test/v1\n/chat/completions".to_owned(),
            "x".repeat(2 * 1_024 + 1),
        ] {
            let error =
                StoredCredentialReference::for_ai_provider_endpoint("openai-compatible", &endpoint)
                    .expect_err("invalid canonical endpoint");
            assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
            let rendered = format!("{error:?} {error}");
            if !endpoint.is_empty() {
                assert!(!rendered.contains(&endpoint));
            }
        }
    }

    #[test]
    fn ai_provider_ids_enforce_the_exact_bounded_ascii_contract() {
        for provider_id in [
            "a".to_owned(),
            "openai-compatible".to_owned(),
            "local.openai_v1".to_owned(),
            "a".repeat(128),
        ] {
            assert!(
                StoredCredentialReference::for_ai_provider(&provider_id).is_ok(),
                "valid provider preset must be accepted"
            );
            assert!(CredentialId::for_ai_provider(&provider_id).is_ok());
        }

        for provider_id in [
            String::new(),
            "a".repeat(129),
            "OpenAI-compatible".to_owned(),
            "-openai".to_owned(),
            ".openai".to_owned(),
            "_openai".to_owned(),
            "openai/compatible".to_owned(),
            "openai:compatible".to_owned(),
            "openai compatible".to_owned(),
            "openai\ncompatible".to_owned(),
            "鏅鸿兘-provider".to_owned(),
        ] {
            let error = StoredCredentialReference::for_ai_provider(&provider_id)
                .expect_err("invalid AI provider ID");
            assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
            assert_eq!(
                CredentialId::for_ai_provider(&provider_id)
                    .expect_err("invalid direct AI provider ID")
                    .code(),
                CredentialErrorCode::InvalidReference
            );
            let rendered = format!(
                "{error:?} {error} {}",
                serde_json::to_string(&error).expect("safe error JSON")
            );
            if !provider_id.is_empty() {
                assert!(!rendered.contains(&provider_id));
            }
            assert!(!rendered.contains("credential:"));
        }
    }

    #[test]
    fn saved_host_telnet_references_are_stable_opaque_and_owner_isolated() {
        let shared_id = "shared-host-owner-id";
        let telnet = StoredCredentialReference::for_saved_host_telnet(shared_id)
            .expect("host Telnet reference");
        let same = StoredCredentialReference::for_saved_host_telnet(shared_id)
            .expect("stable host Telnet reference");
        let other = StoredCredentialReference::for_saved_host_telnet("other-host-owner-id")
            .expect("other host Telnet reference");
        let references = [
            StoredCredentialReference::for_saved_host(shared_id).expect("host SSH reference"),
            telnet,
            StoredCredentialReference::for_saved_group_telnet(shared_id)
                .expect("group Telnet reference"),
            StoredCredentialReference::for_saved_identity(shared_id).expect("identity reference"),
        ];

        assert_eq!(telnet, same);
        assert_ne!(telnet, other);
        assert_eq!(
            references.into_iter().collect::<HashSet<_>>().len(),
            references.len(),
            "the same opaque ID must select distinct SSH, host Telnet, group Telnet, and identity owners"
        );
        assert_eq!(
            telnet.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert_eq!(telnet.to_string().parse(), Ok(telnet));
        let json = serde_json::to_string(&telnet).expect("host Telnet reference JSON");
        let decoded: StoredCredentialReference =
            serde_json::from_str(&json).expect("decode host Telnet reference JSON");
        assert_eq!(decoded, telnet);
        let rendered = format!("{telnet:?} {json}");
        assert!(!rendered.contains(shared_id));
        assert!(!rendered.contains("credential:"));
    }

    #[test]
    fn saved_host_telnet_uses_the_exact_saved_host_id_boundary() {
        let accepted = ["host\nwith-control".to_owned(), "h".repeat(4_096)];
        for host_id in accepted {
            assert!(StoredCredentialReference::for_saved_host(&host_id).is_ok());
            assert!(StoredCredentialReference::for_saved_host_telnet(&host_id).is_ok());
        }

        let rejected = [String::new(), "h".repeat(4_097)];
        for host_id in rejected {
            let ssh_error = StoredCredentialReference::for_saved_host(&host_id)
                .expect_err("invalid SSH host-owner ID");
            let telnet_error = StoredCredentialReference::for_saved_host_telnet(&host_id)
                .expect_err("invalid Telnet host-owner ID");
            assert_eq!(ssh_error.code(), CredentialErrorCode::InvalidReference);
            assert_eq!(telnet_error.code(), CredentialErrorCode::InvalidReference);
            let rendered = format!("{telnet_error:?} {telnet_error}");
            if !host_id.is_empty() {
                assert!(!rendered.contains(&host_id));
            }
            assert!(!rendered.contains("credential:"));
        }
    }

    #[test]
    fn saved_identity_references_are_deterministic_isolated_and_round_trip() {
        let identity_id = "shared-opaque-record-id";
        let first =
            StoredCredentialReference::for_saved_identity(identity_id).expect("identity reference");
        let same =
            StoredCredentialReference::for_saved_identity(identity_id).expect("stable reference");
        let other = StoredCredentialReference::for_saved_identity("other-identity-id")
            .expect("other identity reference");
        let host = StoredCredentialReference::for_saved_host(identity_id).expect("host reference");

        assert_eq!(first, same);
        assert_ne!(first, other);
        assert_ne!(first, host);
        assert_eq!(
            first.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert!(!first.to_string().contains(identity_id));
        assert_eq!(first.to_string().parse(), Ok(first));

        let json = serde_json::to_string(&first).expect("identity reference JSON");
        let decoded: StoredCredentialReference =
            serde_json::from_str(&json).expect("decode identity reference JSON");
        assert_eq!(decoded, first);
    }

    #[test]
    fn saved_identity_inputs_are_strict_and_errors_never_echo_them() {
        let control_marker = "identity-control-marker\n";
        let too_long = "i".repeat(513);
        for identity_id in ["", control_marker, too_long.as_str()] {
            let error = StoredCredentialReference::for_saved_identity(identity_id)
                .expect_err("invalid identity derivation input");
            assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
            let rendered = format!(
                "{error:?} {error} {}",
                serde_json::to_string(&error).expect("safe error JSON")
            );
            if !identity_id.is_empty() {
                assert!(!rendered.contains(identity_id));
            }
            assert!(!rendered.contains("credential:"));
        }

        assert!(
            StoredCredentialReference::for_saved_identity(&"i".repeat(512)).is_ok(),
            "the Vault identity-ID boundary must remain accepted"
        );
        assert!(StoredCredentialReference::for_saved_identity(&"界".repeat(170)).is_ok());
        assert!(StoredCredentialReference::for_saved_identity(&"界".repeat(171)).is_err());
    }

    #[test]
    fn proxy_final_references_are_stable_isolated_opaque_and_parseable() {
        let shared_id = "shared-proxy-owner-id";
        let host_proxy = StoredCredentialReference::for_saved_host_proxy(shared_id)
            .expect("host proxy reference");
        let same_host_proxy = StoredCredentialReference::for_saved_host_proxy(shared_id)
            .expect("stable host proxy reference");
        let other_host_proxy = StoredCredentialReference::for_saved_host_proxy("other-owner-id")
            .expect("other host proxy reference");
        let profile_proxy = StoredCredentialReference::for_saved_proxy_profile(shared_id)
            .expect("profile proxy reference");
        let host = StoredCredentialReference::for_saved_host(shared_id).expect("host reference");
        let identity =
            StoredCredentialReference::for_saved_identity(shared_id).expect("identity reference");

        assert_eq!(host_proxy, same_host_proxy);
        assert_ne!(host_proxy, other_host_proxy);
        assert_eq!(
            host_proxy.to_string(),
            "os:v1:9de1503e-fbbf-535c-add3-f637b65ecdd5"
        );
        assert_eq!(
            profile_proxy.to_string(),
            "os:v1:448ca210-5077-5b79-aefa-95c5cfd03b28"
        );
        assert_eq!(
            [host, identity, host_proxy, profile_proxy]
                .into_iter()
                .collect::<HashSet<_>>()
                .len(),
            4,
            "equal opaque IDs must remain isolated by ownership class"
        );
        for reference in [host_proxy, profile_proxy] {
            assert_eq!(
                reference.id().as_uuid().get_version(),
                Some(uuid::Version::Sha1)
            );
            assert_eq!(reference.to_string().parse(), Ok(reference));
            let rendered = format!(
                "{reference:?} {}",
                serde_json::to_string(&reference).expect("reference JSON")
            );
            assert!(!rendered.contains(shared_id));
            assert!(!rendered.contains("credential:"));
        }
    }

    #[test]
    fn group_credential_references_are_stable_and_isolated_from_every_existing_owner() {
        let shared_id = "shared-group-owner-id";
        let group_ssh =
            StoredCredentialReference::for_saved_group_ssh(shared_id).expect("group SSH reference");
        let group_telnet = StoredCredentialReference::for_saved_group_telnet(shared_id)
            .expect("group Telnet reference");
        let group_proxy = StoredCredentialReference::for_saved_group_proxy(shared_id)
            .expect("group proxy reference");
        assert_eq!(
            group_ssh,
            StoredCredentialReference::for_saved_group_ssh(shared_id)
                .expect("stable group SSH reference")
        );

        let all = [
            StoredCredentialReference::for_saved_host(shared_id).expect("host reference"),
            StoredCredentialReference::for_saved_identity(shared_id).expect("identity reference"),
            StoredCredentialReference::for_saved_host_proxy(shared_id)
                .expect("host proxy reference"),
            StoredCredentialReference::for_saved_proxy_profile(shared_id)
                .expect("profile proxy reference"),
            group_ssh,
            group_telnet,
            group_proxy,
        ];
        assert_eq!(all.into_iter().collect::<HashSet<_>>().len(), all.len());
        for reference in all {
            assert_eq!(reference.to_string().parse(), Ok(reference));
            assert!(!reference.to_string().contains(shared_id));
        }
    }

    #[test]
    fn group_backup_references_are_slot_transaction_and_final_namespace_isolated() {
        let shared_id = "shared-group-backup-owner";
        let ssh =
            StoredCredentialReference::for_legacy_import_group_ssh_backup(TRANSACTION_A, shared_id)
                .expect("group SSH backup");
        let telnet = StoredCredentialReference::for_legacy_import_group_telnet_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("group Telnet backup");
        let proxy = StoredCredentialReference::for_legacy_import_group_proxy_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("group proxy backup");
        let all = [
            ssh,
            telnet,
            proxy,
            StoredCredentialReference::for_saved_group_ssh(shared_id).expect("group SSH final"),
            StoredCredentialReference::for_saved_group_telnet(shared_id)
                .expect("group Telnet final"),
            StoredCredentialReference::for_saved_group_proxy(shared_id).expect("group proxy final"),
        ];
        assert_eq!(all.into_iter().collect::<HashSet<_>>().len(), all.len());
        assert_ne!(
            ssh,
            StoredCredentialReference::for_legacy_import_group_ssh_backup(
                TRANSACTION_B,
                shared_id,
            )
            .expect("transaction-isolated group SSH backup")
        );
        for reference in all {
            let rendered = format!(
                "{reference:?} {}",
                serde_json::to_string(&reference).expect("reference JSON")
            );
            for forbidden in [TRANSACTION_A, shared_id, "credential:"] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }

    #[test]
    fn group_reference_inputs_are_strict_and_errors_are_redacted() {
        let invalid = ["", "group-control-marker\n"];
        for group_id in invalid {
            for error in [
                StoredCredentialReference::for_saved_group_ssh(group_id)
                    .expect_err("invalid group SSH owner"),
                StoredCredentialReference::for_saved_group_telnet(group_id)
                    .expect_err("invalid group Telnet owner"),
                StoredCredentialReference::for_saved_group_proxy(group_id)
                    .expect_err("invalid group proxy owner"),
            ] {
                assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
                let rendered = format!("{error:?} {error}");
                if !group_id.is_empty() {
                    assert!(!rendered.contains(group_id));
                }
            }
        }
        assert!(StoredCredentialReference::for_saved_group_ssh(&"g".repeat(512)).is_ok());
        assert!(StoredCredentialReference::for_saved_group_ssh(&"g".repeat(513)).is_err());
    }

    #[test]
    fn proxy_backup_references_are_transaction_owner_and_namespace_isolated() {
        let shared_id = "shared-proxy-backup-owner";
        let host_proxy = StoredCredentialReference::for_legacy_import_host_proxy_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("host proxy backup");
        let same_host_proxy = StoredCredentialReference::for_legacy_import_host_proxy_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("stable host proxy backup");
        let other_transaction = StoredCredentialReference::for_legacy_import_host_proxy_backup(
            TRANSACTION_B,
            shared_id,
        )
        .expect("transaction-isolated host proxy backup");
        let other_owner = StoredCredentialReference::for_legacy_import_host_proxy_backup(
            TRANSACTION_A,
            "other-proxy-owner",
        )
        .expect("owner-isolated host proxy backup");
        let profile_proxy = StoredCredentialReference::for_legacy_import_proxy_profile_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("profile proxy backup");
        let host = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, shared_id)
            .expect("host backup");
        let identity =
            StoredCredentialReference::for_legacy_import_identity_backup(TRANSACTION_A, shared_id)
                .expect("identity backup");
        let host_final =
            StoredCredentialReference::for_saved_host_proxy(shared_id).expect("host proxy final");
        let profile_final = StoredCredentialReference::for_saved_proxy_profile(shared_id)
            .expect("profile proxy final");

        assert_eq!(host_proxy, same_host_proxy);
        assert_ne!(host_proxy, other_transaction);
        assert_ne!(host_proxy, other_owner);
        assert_eq!(
            host_proxy.to_string(),
            "os:v1:167796bd-f147-5fe0-bc81-2b69b99f37f5"
        );
        assert_eq!(
            profile_proxy.to_string(),
            "os:v1:fa12b2fe-d09d-52cc-93b8-2777bac02099"
        );
        assert_eq!(
            [
                host,
                identity,
                host_final,
                profile_final,
                host_proxy,
                profile_proxy,
            ]
            .into_iter()
            .collect::<HashSet<_>>()
            .len(),
            6,
            "final and backup namespaces must not overlap"
        );
        for reference in [host_proxy, profile_proxy] {
            assert_eq!(reference.to_string().parse(), Ok(reference));
            let rendered = format!(
                "{reference:?} {}",
                serde_json::to_string(&reference).expect("backup reference JSON")
            );
            for forbidden in [TRANSACTION_A, shared_id, "credential:"] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }

    #[test]
    fn host_telnet_backup_is_stable_and_isolated_from_ssh() {
        let shared_id = "shared-host-backup-owner";
        let telnet = StoredCredentialReference::for_legacy_import_host_telnet_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("host Telnet backup");
        let same = StoredCredentialReference::for_legacy_import_host_telnet_backup(
            TRANSACTION_A,
            shared_id,
        )
        .expect("stable host Telnet backup");
        let other_transaction = StoredCredentialReference::for_legacy_import_host_telnet_backup(
            TRANSACTION_B,
            shared_id,
        )
        .expect("transaction-isolated host Telnet backup");
        let ssh = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, shared_id)
            .expect("host SSH backup");
        let telnet_final =
            StoredCredentialReference::for_saved_host_telnet(shared_id).expect("host Telnet final");

        assert_eq!(telnet, same);
        assert_ne!(telnet, other_transaction);
        assert_ne!(telnet, ssh);
        assert_ne!(telnet, telnet_final);
        let rendered = format!("{telnet:?} {telnet}");
        assert!(!rendered.contains(TRANSACTION_A));
        assert!(!rendered.contains(shared_id));
    }

    #[test]
    fn proxy_reference_inputs_are_strict_and_errors_never_echo_them() {
        let control_marker = "proxy-owner-control-marker\n";
        let too_long = "p".repeat(513);
        for owner_id in ["", control_marker, too_long.as_str()] {
            for error in [
                StoredCredentialReference::for_saved_host_proxy(owner_id)
                    .expect_err("invalid host proxy owner"),
                StoredCredentialReference::for_saved_proxy_profile(owner_id)
                    .expect_err("invalid profile proxy owner"),
                StoredCredentialReference::for_legacy_import_host_proxy_backup(
                    TRANSACTION_A,
                    owner_id,
                )
                .expect_err("invalid host proxy backup owner"),
                StoredCredentialReference::for_legacy_import_proxy_profile_backup(
                    TRANSACTION_A,
                    owner_id,
                )
                .expect_err("invalid profile proxy backup owner"),
            ] {
                assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
                let rendered = format!(
                    "{error:?} {error} {}",
                    serde_json::to_string(&error).expect("safe error JSON")
                );
                if !owner_id.is_empty() {
                    assert!(!rendered.contains(owner_id));
                }
                assert!(!rendered.contains("credential:"));
            }
        }

        for transaction_id in [
            "invalid-proxy-transaction-marker\n",
            "11111111-1111-5111-8111-111111111111",
            "11111111-1111-4111-8111-11111111111A",
        ] {
            for error in [
                StoredCredentialReference::for_legacy_import_host_proxy_backup(
                    transaction_id,
                    "valid-owner",
                )
                .expect_err("invalid host proxy backup transaction"),
                StoredCredentialReference::for_legacy_import_proxy_profile_backup(
                    transaction_id,
                    "valid-owner",
                )
                .expect_err("invalid profile proxy backup transaction"),
            ] {
                assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
                let rendered = format!("{error:?} {error}");
                assert!(!rendered.contains(transaction_id));
            }
        }

        assert!(StoredCredentialReference::for_saved_host_proxy(&"p".repeat(512)).is_ok());
        assert!(StoredCredentialReference::for_saved_proxy_profile(&"p".repeat(512)).is_ok());
        assert!(StoredCredentialReference::for_saved_host_proxy(&"界".repeat(170)).is_ok());
        assert!(StoredCredentialReference::for_saved_host_proxy(&"界".repeat(171)).is_err());
    }

    #[test]
    fn legacy_import_backup_references_are_stable_isolated_and_opaque() {
        let host_a = "legacy-backup-host-a";
        let host_b = "legacy-backup-host-b";
        let first = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, host_a)
            .expect("backup reference");
        let same = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, host_a)
            .expect("stable backup reference");
        let other_transaction =
            StoredCredentialReference::for_legacy_import_backup(TRANSACTION_B, host_a)
                .expect("transaction-isolated reference");
        let other_host = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, host_b)
            .expect("host-isolated reference");
        let formal = StoredCredentialReference::for_saved_host(host_a).expect("formal reference");

        assert_eq!(first, same);
        assert_ne!(first, other_transaction);
        assert_ne!(first, other_host);
        assert_ne!(first, formal);
        assert_eq!(
            first.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert_eq!(first.to_string().parse(), Ok(first));

        let rendered = format!(
            "{first:?} {}",
            serde_json::to_string(&first).expect("reference JSON")
        );
        for forbidden in [TRANSACTION_A, host_a, "credential:"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn legacy_identity_backup_references_are_stable_isolated_and_opaque() {
        let shared_id = "shared-legacy-record-id";
        let first =
            StoredCredentialReference::for_legacy_import_identity_backup(TRANSACTION_A, shared_id)
                .expect("identity backup reference");
        let same =
            StoredCredentialReference::for_legacy_import_identity_backup(TRANSACTION_A, shared_id)
                .expect("stable identity backup reference");
        let other_transaction =
            StoredCredentialReference::for_legacy_import_identity_backup(TRANSACTION_B, shared_id)
                .expect("transaction-isolated identity backup reference");
        let other_identity = StoredCredentialReference::for_legacy_import_identity_backup(
            TRANSACTION_A,
            "other-identity-id",
        )
        .expect("identity-isolated backup reference");
        let host_backup =
            StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, shared_id)
                .expect("host backup reference");
        let formal_identity = StoredCredentialReference::for_saved_identity(shared_id)
            .expect("formal identity reference");
        let formal_host =
            StoredCredentialReference::for_saved_host(shared_id).expect("formal host reference");

        assert_eq!(first, same);
        assert_ne!(first, other_transaction);
        assert_ne!(first, other_identity);
        assert_ne!(first, host_backup);
        assert_ne!(first, formal_identity);
        assert_ne!(first, formal_host);
        assert_eq!(
            first.id().as_uuid().get_version(),
            Some(uuid::Version::Sha1)
        );
        assert_eq!(first.to_string().parse(), Ok(first));

        let json = serde_json::to_string(&first).expect("identity backup JSON");
        let decoded: StoredCredentialReference =
            serde_json::from_str(&json).expect("decode identity backup JSON");
        assert_eq!(decoded, first);

        let rendered = format!("{first:?} {json}");
        for forbidden in [TRANSACTION_A, shared_id, "credential:"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn legacy_identity_backup_inputs_are_strict_and_errors_never_echo_them() {
        let transaction_marker = "invalid-identity-transaction-marker\n";
        let identity_marker = "invalid-identity-marker\r";
        let too_long_transaction = "t".repeat(4_097);
        let too_long_identity = "i".repeat(513);
        let invalid = [
            (transaction_marker, "valid-identity"),
            (too_long_transaction.as_str(), "valid-identity"),
            (TRANSACTION_A, ""),
            (TRANSACTION_A, identity_marker),
            (TRANSACTION_A, too_long_identity.as_str()),
            ("11111111-1111-5111-8111-111111111111", "valid-identity"),
            ("11111111-1111-4111-8111-11111111111A", "valid-identity"),
        ];

        for (transaction_id, identity_id) in invalid {
            let error = StoredCredentialReference::for_legacy_import_identity_backup(
                transaction_id,
                identity_id,
            )
            .expect_err("invalid identity backup derivation input");
            assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
            let rendered = format!(
                "{error:?} {error} {}",
                serde_json::to_string(&error).expect("safe error JSON")
            );
            assert!(!rendered.contains(transaction_id));
            if !identity_id.is_empty() {
                assert!(!rendered.contains(identity_id));
            }
            assert!(!rendered.contains("credential:"));
        }
    }

    #[test]
    fn legacy_import_backup_inputs_are_strict_and_errors_never_echo_them() {
        let transaction_marker = "invalid-transaction-marker\n";
        let host_marker = "invalid-host-marker\r";
        let too_long_transaction = "t".repeat(4_097);
        let too_long_host = "h".repeat(513);
        let invalid = [
            (transaction_marker, "valid-host"),
            (too_long_transaction.as_str(), "valid-host"),
            (TRANSACTION_A, ""),
            (TRANSACTION_A, host_marker),
            (TRANSACTION_A, too_long_host.as_str()),
            ("11111111-1111-5111-8111-111111111111", "valid-host"),
            ("11111111-1111-4111-8111-11111111111A", "valid-host"),
        ];

        for (transaction_id, saved_host_id) in invalid {
            let error =
                StoredCredentialReference::for_legacy_import_backup(transaction_id, saved_host_id)
                    .expect_err("invalid backup derivation input");
            assert_eq!(error.code(), CredentialErrorCode::InvalidReference);
            let rendered = format!(
                "{error:?} {error} {}",
                serde_json::to_string(&error).expect("safe error JSON")
            );
            assert!(!rendered.contains(transaction_id));
            if !saved_host_id.is_empty() {
                assert!(!rendered.contains(saved_host_id));
            }
            assert!(!rendered.contains("credential:"));
        }
    }

    #[tokio::test]
    async fn legacy_import_backup_reference_round_trips_and_cleans_up_in_memory_backend() {
        let host_id = "memory-backup-host-marker";
        let secret_marker = "memory-backup-secret-marker";
        let reference = StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, host_id)
            .expect("backup reference");
        let (store, controller) = in_memory_credential_store();

        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(secret_marker.to_owned()).expect("test secret"),
            )
            .await
            .expect("store backup");
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("resolve backup");
        assert_eq!(resolved.as_utf8().expect("UTF-8 backup"), secret_marker);
        drop(resolved);
        store.delete(&reference).await.expect("delete backup");
        let missing = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .err()
            .expect("deleted backup must be absent");
        assert_eq!(missing.code(), CredentialErrorCode::NotFound);

        let log = controller.operation_log();
        assert_eq!(log.count(CredentialOperation::Upsert), 1);
        assert_eq!(log.count(CredentialOperation::Resolve), 2);
        assert_eq!(log.count(CredentialOperation::Delete), 1);
        let rendered = format!(
            "{controller:?} {log:?} {reference:?} {}",
            serde_json::to_string(&reference).expect("reference JSON")
        );
        for forbidden in [TRANSACTION_A, host_id, secret_marker, "credential:"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn same_id_host_and_identity_accounts_and_backups_are_independent_and_clean_up() {
        let shared_id = "shared-memory-record-marker";
        let host = StoredCredentialReference::for_saved_host(shared_id).expect("host reference");
        let identity =
            StoredCredentialReference::for_saved_identity(shared_id).expect("identity reference");
        let host_backup =
            StoredCredentialReference::for_legacy_import_backup(TRANSACTION_A, shared_id)
                .expect("host backup reference");
        let identity_backup =
            StoredCredentialReference::for_legacy_import_identity_backup(TRANSACTION_A, shared_id)
                .expect("identity backup reference");
        let references = [host, identity, host_backup, identity_backup];
        assert_eq!(
            references.into_iter().collect::<HashSet<_>>().len(),
            references.len(),
            "each ownership class must derive a different keyring account"
        );

        let secrets = [
            "host-final-secret-marker",
            "identity-final-secret-marker",
            "host-backup-secret-marker",
            "identity-backup-secret-marker",
        ];
        let (store, controller) = in_memory_credential_store();
        for (reference, value) in references.iter().zip(secrets) {
            store
                .upsert(
                    reference,
                    CredentialKind::SshPassword,
                    SecretValue::from_utf8(value.to_owned()).expect("test secret"),
                )
                .await
                .expect("store isolated credential");
        }
        for (reference, expected) in references.iter().zip(secrets) {
            let resolved = store
                .resolve(reference, CredentialKind::SshPassword)
                .await
                .expect("resolve isolated credential");
            assert_eq!(resolved.as_utf8().expect("UTF-8 credential"), expected);
        }

        for reference in [identity, identity_backup] {
            store
                .delete(&reference)
                .await
                .expect("delete identity entry");
            assert_eq!(
                store
                    .resolve(&reference, CredentialKind::SshPassword)
                    .await
                    .err()
                    .expect("deleted identity entry")
                    .code(),
                CredentialErrorCode::NotFound
            );
        }
        for (reference, expected) in [
            (host, "host-final-secret-marker"),
            (host_backup, "host-backup-secret-marker"),
        ] {
            let resolved = store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .expect("host entry must remain after identity cleanup");
            assert_eq!(resolved.as_utf8().expect("UTF-8 credential"), expected);
            drop(resolved);
            store.delete(&reference).await.expect("delete host entry");
            assert_eq!(
                store
                    .resolve(&reference, CredentialKind::SshPassword)
                    .await
                    .err()
                    .expect("deleted host entry")
                    .code(),
                CredentialErrorCode::NotFound
            );
        }

        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Upsert),
            4
        );
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Delete),
            4
        );
        let rendered = format!("{controller:?} {:?}", controller.operation_log());
        for forbidden in [shared_id, TRANSACTION_A]
            .into_iter()
            .chain(secrets.into_iter())
        {
            assert!(!rendered.contains(forbidden));
        }
        assert!(!rendered.contains("credential:"));
    }
}
