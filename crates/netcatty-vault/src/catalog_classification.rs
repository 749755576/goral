use std::collections::HashMap;

use crate::group::SavedGroupCatalog;
use crate::group_config::SavedGroupConfig;
use crate::model::{
    SavedHost, SavedIdentityReference, SavedManagedSshKey, SavedPasswordIdentity,
    SavedProxyProfile, SavedSshKeyReference,
};
use crate::notes_snippets::{SavedSnippet, SavedVaultNote};
use crate::port_forward::SavedPortForwardRule;
use crate::store::SavedVaultImportDisposition;

pub(super) fn classify_hosts(
    existing: &[SavedHost],
    candidates: &[SavedHost],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|host| (&host.id, host))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| match existing.get(&candidate.id) {
            None => SavedVaultImportDisposition::Importable,
            Some(current) if import_business_fields_equal(current, candidate) => {
                SavedVaultImportDisposition::Duplicate
            }
            Some(_) => SavedVaultImportDisposition::Conflict,
        })
        .collect()
}

pub(super) fn classify_ssh_key_references(
    existing: &[SavedSshKeyReference],
    existing_managed: &[SavedManagedSshKey],
    candidates: &[SavedSshKeyReference],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|reference| (&reference.id, reference))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| {
            if existing_managed
                .iter()
                .any(|managed| managed.id == candidate.id)
            {
                return SavedVaultImportDisposition::Conflict;
            }
            match existing.get(&candidate.id) {
                None => SavedVaultImportDisposition::Importable,
                Some(current) if ssh_key_business_fields_equal(current, candidate) => {
                    SavedVaultImportDisposition::Duplicate
                }
                Some(_) => SavedVaultImportDisposition::Conflict,
            }
        })
        .collect()
}

pub(super) fn classify_managed_ssh_keys(
    existing: &[SavedManagedSshKey],
    existing_references: &[SavedSshKeyReference],
    candidates: &[SavedManagedSshKey],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|managed| (&managed.id, managed))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| {
            if existing_references
                .iter()
                .any(|reference| reference.id == candidate.id)
            {
                return SavedVaultImportDisposition::Conflict;
            }
            match existing.get(&candidate.id) {
                None => SavedVaultImportDisposition::Importable,
                Some(current) if managed_key_business_fields_equal(current, candidate) => {
                    SavedVaultImportDisposition::Duplicate
                }
                Some(_) => SavedVaultImportDisposition::Conflict,
            }
        })
        .collect()
}

pub(super) fn classify_identity_references(
    existing: &[SavedIdentityReference],
    existing_password_identities: &[SavedPasswordIdentity],
    candidates: &[SavedIdentityReference],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|reference| (&reference.id, reference))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| {
            if existing_password_identities
                .iter()
                .any(|identity| identity.id.as_str() == candidate.id.as_str())
            {
                return SavedVaultImportDisposition::Conflict;
            }
            match existing.get(&candidate.id) {
                None => SavedVaultImportDisposition::Importable,
                Some(current) if identity_business_fields_equal(current, candidate) => {
                    SavedVaultImportDisposition::Duplicate
                }
                Some(_) => SavedVaultImportDisposition::Conflict,
            }
        })
        .collect()
}

pub(super) fn classify_password_identities(
    existing: &[SavedPasswordIdentity],
    existing_identity_references: &[SavedIdentityReference],
    candidates: &[SavedPasswordIdentity],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|identity| (&identity.id, identity))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| {
            if existing_identity_references
                .iter()
                .any(|identity| identity.id.as_str() == candidate.id.as_str())
            {
                return SavedVaultImportDisposition::Conflict;
            }
            match existing.get(&candidate.id) {
                None => SavedVaultImportDisposition::Importable,
                Some(current) if password_identity_business_fields_equal(current, candidate) => {
                    SavedVaultImportDisposition::Duplicate
                }
                Some(_) => SavedVaultImportDisposition::Conflict,
            }
        })
        .collect()
}

pub(super) fn classify_proxy_profiles(
    existing: &[SavedProxyProfile],
    candidates: &[SavedProxyProfile],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|profile| (&profile.id, profile))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| match existing.get(&candidate.id) {
            None => SavedVaultImportDisposition::Importable,
            Some(current) if proxy_profile_business_fields_equal(current, candidate) => {
                SavedVaultImportDisposition::Duplicate
            }
            Some(_) => SavedVaultImportDisposition::Conflict,
        })
        .collect()
}

pub(super) fn classify_groups(
    existing: &[SavedGroupConfig],
    candidates: &[SavedGroupConfig],
) -> Vec<SavedVaultImportDisposition> {
    let existing_by_id = existing
        .iter()
        .map(|group| (&group.id, group))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| {
            if existing
                .iter()
                .any(|group| group.path == candidate.path && group.id != candidate.id)
            {
                return SavedVaultImportDisposition::Conflict;
            }
            match existing_by_id.get(&candidate.id) {
                None => SavedVaultImportDisposition::Importable,
                Some(current) if group_business_fields_equal(current, candidate) => {
                    SavedVaultImportDisposition::Duplicate
                }
                Some(_) => SavedVaultImportDisposition::Conflict,
            }
        })
        .collect()
}

pub(super) fn classify_custom_groups(
    existing: Option<&SavedGroupCatalog>,
    candidates: Option<&SavedGroupCatalog>,
) -> Vec<SavedVaultImportDisposition> {
    let Some(candidates) = candidates else {
        return Vec::new();
    };
    candidates
        .explicit_paths()
        .iter()
        .map(|candidate| {
            if existing.is_some_and(|catalog| catalog.is_explicit(candidate)) {
                SavedVaultImportDisposition::Duplicate
            } else {
                SavedVaultImportDisposition::Importable
            }
        })
        .collect()
}

pub(super) fn classify_snippets(
    existing: &[SavedSnippet],
    candidates: &[SavedSnippet],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|snippet| (snippet.id(), snippet))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| match existing.get(candidate.id()) {
            None => SavedVaultImportDisposition::Importable,
            Some(current) if *current == candidate => SavedVaultImportDisposition::Duplicate,
            Some(_) => SavedVaultImportDisposition::Conflict,
        })
        .collect()
}

pub(super) fn classify_notes(
    existing: &[SavedVaultNote],
    candidates: &[SavedVaultNote],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|note| (note.id(), note))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| match existing.get(candidate.id()) {
            None => SavedVaultImportDisposition::Importable,
            Some(current) if *current == candidate => SavedVaultImportDisposition::Duplicate,
            Some(_) => SavedVaultImportDisposition::Conflict,
        })
        .collect()
}

pub(super) fn classify_port_forward_rules(
    existing: &[SavedPortForwardRule],
    candidates: &[SavedPortForwardRule],
) -> Vec<SavedVaultImportDisposition> {
    let existing = existing
        .iter()
        .map(|rule| (rule.id.as_str(), rule))
        .collect::<HashMap<_, _>>();
    candidates
        .iter()
        .map(|candidate| match existing.get(candidate.id.as_str()) {
            None => SavedVaultImportDisposition::Importable,
            Some(current) if *current == candidate => SavedVaultImportDisposition::Duplicate,
            Some(_) => SavedVaultImportDisposition::Conflict,
        })
        .collect()
}

pub(super) fn import_business_fields_equal(left: &SavedHost, right: &SavedHost) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.hostname == right.hostname
        && left.port == right.port
        && left.username == right.username
        && left.protocol == right.protocol
        && left.auth_method == right.auth_method
        && left.auth_policy_version == right.auth_policy_version
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn ssh_key_business_fields_equal(
    left: &SavedSshKeyReference,
    right: &SavedSshKeyReference,
) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.file_path == right.file_path
        && left.category == right.category
        && left.source == right.source
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn managed_key_business_fields_equal(
    left: &SavedManagedSshKey,
    right: &SavedManagedSshKey,
) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.category == right.category
        && left.source == right.source
        && left.has_saved_passphrase == right.has_saved_passphrase
        && left.custody() == right.custody()
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn identity_business_fields_equal(
    left: &SavedIdentityReference,
    right: &SavedIdentityReference,
) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.username == right.username
        && left.auth_method == right.auth_method
        && left.key_id == right.key_id
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn password_identity_business_fields_equal(
    left: &SavedPasswordIdentity,
    right: &SavedPasswordIdentity,
) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.username == right.username
        && left.has_saved_credential == right.has_saved_credential
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn proxy_profile_business_fields_equal(
    left: &SavedProxyProfile,
    right: &SavedProxyProfile,
) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.config == right.config
        && left.compatibility_fields() == right.compatibility_fields()
}

pub(super) fn group_business_fields_equal(
    left: &SavedGroupConfig,
    right: &SavedGroupConfig,
) -> bool {
    left.id == right.id && left.path == right.path && left.defaults == right.defaults
}
