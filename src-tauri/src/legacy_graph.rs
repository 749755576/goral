use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use netcatty_vault::{
    SavedGroupConfig, SavedGroupHostChain, SavedGroupIdentityReference, SavedGroupOverride,
    SavedGroupProxyOverride, SavedHost, SavedHostId, SavedIdentityReference,
    SavedIdentityReferenceId, SavedManagedSshKey, SavedPasswordIdentity, SavedPasswordIdentityId,
    SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId, SavedSshKeyReference,
    SavedSshKeyReferenceId, SavedVaultGraph, SavedVaultGraphImportAssessment,
    SavedVaultImportDisposition,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const REMAP_DOMAIN: &[u8] = b"netcatty-legacy-vault-graph-remap-v1\0";
const KEY_DOMAIN: &[u8] = b"ssh-key-reference\0";
const MANAGED_KEY_DOMAIN: &[u8] = b"managed-ssh-key\0";
const IDENTITY_DOMAIN: &[u8] = b"identity-reference\0";
const PASSWORD_IDENTITY_DOMAIN: &[u8] = b"password-identity\0";
const PROXY_PROFILE_DOMAIN: &[u8] = b"proxy-profile\0";
const HOST_DOMAIN: &[u8] = b"saved-host\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyGraphRemapError;

impl fmt::Display for LegacyGraphRemapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("legacy Vault graph remapping failed")
    }
}

impl std::error::Error for LegacyGraphRemapError {}

/// Rewrites every entity that conflicts with the current Vault and all graph
/// edges that point to a rewritten key, identity, or proxy profile.
///
/// `None` means the assessment contains no conflicts and `graph` is unchanged.
/// Generated IDs are the complete lowercase hexadecimal SHA-256 digest of a
/// source-bound, entity-domain-separated payload. If a generated ID still
/// conflicts, callers can assess again and deterministically remap that current
/// ID in another iteration.
pub(crate) fn remap_conflicting_graph(
    graph: SavedVaultGraph,
    assessment: &SavedVaultGraphImportAssessment,
    source_sha256: &[u8; 32],
) -> Result<Option<SavedVaultGraph>, LegacyGraphRemapError> {
    remap_conflicting_graph_inner(graph, assessment, source_sha256, true)
}

pub(crate) fn remap_conflicting_graph_without_host_ids(
    graph: SavedVaultGraph,
    assessment: &SavedVaultGraphImportAssessment,
    source_sha256: &[u8; 32],
) -> Result<Option<SavedVaultGraph>, LegacyGraphRemapError> {
    remap_conflicting_graph_inner(graph, assessment, source_sha256, false)
}

fn remap_conflicting_graph_inner(
    graph: SavedVaultGraph,
    assessment: &SavedVaultGraphImportAssessment,
    source_sha256: &[u8; 32],
    remap_host_ids: bool,
) -> Result<Option<SavedVaultGraph>, LegacyGraphRemapError> {
    if graph.hosts().len() != assessment.host_dispositions().len()
        || graph.ssh_key_references().len() != assessment.ssh_key_reference_dispositions().len()
        || graph.managed_ssh_keys().len() != assessment.managed_ssh_key_dispositions().len()
        || graph.identity_references().len() != assessment.identity_reference_dispositions().len()
        || graph.password_identities().len() != assessment.password_identity_dispositions().len()
        || graph.proxy_profiles().len() != assessment.proxy_profile_dispositions().len()
        || graph.groups().len() != assessment.group_dispositions().len()
    {
        return Err(LegacyGraphRemapError);
    }

    let key_ids = build_key_remap(
        graph.ssh_key_references(),
        assessment.ssh_key_reference_dispositions(),
        graph.managed_ssh_keys(),
        assessment.managed_ssh_key_dispositions(),
        source_sha256,
    )?;
    let (identity_ids, password_identity_ids) = build_identity_remaps(
        graph.identity_references(),
        assessment.identity_reference_dispositions(),
        graph.password_identities(),
        assessment.password_identity_dispositions(),
        source_sha256,
    )?;
    let host_ids = if remap_host_ids {
        build_host_remap(graph.hosts(), assessment.host_dispositions(), source_sha256)?
    } else {
        HashMap::new()
    };
    let proxy_profile_ids = build_proxy_profile_remap(
        graph.proxy_profiles(),
        assessment.proxy_profile_dispositions(),
        source_sha256,
    )?;

    if key_ids.is_empty()
        && identity_ids.is_empty()
        && password_identity_ids.is_empty()
        && proxy_profile_ids.is_empty()
        && host_ids.is_empty()
    {
        return Ok(None);
    }

    let (
        hosts,
        keys,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    let keys = keys
        .into_iter()
        .map(|mut key| {
            if let Some(replacement) = key_ids.get(key.id.as_str()) {
                key.id = replacement.clone();
            }
            key
        })
        .collect();
    let managed_keys = managed_keys
        .into_iter()
        .map(|mut key| {
            if let Some(replacement) = key_ids.get(key.id.as_str()) {
                key.id = replacement.clone();
            }
            key
        })
        .collect();
    let identities = identities
        .into_iter()
        .map(|mut identity| {
            if let Some(replacement) = key_ids.get(identity.key_id.as_str()) {
                identity.key_id = replacement.clone();
            }
            if let Some(replacement) = identity_ids.get(identity.id.as_str()) {
                identity.id = replacement.clone();
            }
            identity
        })
        .collect();
    let password_identities = password_identities
        .into_iter()
        .map(|mut identity| {
            if let Some(replacement) = password_identity_ids.get(identity.id.as_str()) {
                identity.id = replacement.clone();
            }
            identity
        })
        .collect();
    let proxy_profiles = proxy_profiles
        .into_iter()
        .map(|mut profile| {
            profile.config = rewrite_proxy_config(profile.config, &password_identity_ids)?;
            if let Some(replacement) = proxy_profile_ids.get(profile.id.as_str()) {
                profile.id = replacement.clone();
            }
            Ok(profile)
        })
        .collect::<Result<Vec<_>, LegacyGraphRemapError>>()?;
    let hosts = hosts
        .into_iter()
        .map(|host| {
            rewrite_host(
                host,
                &host_ids,
                &identity_ids,
                &password_identity_ids,
                &key_ids,
                &proxy_profile_ids,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let groups = groups
        .into_iter()
        .map(|group| {
            rewrite_group(
                group,
                &host_ids,
                &identity_ids,
                &password_identity_ids,
                &key_ids,
                &proxy_profile_ids,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let host_id_remap = host_ids
        .iter()
        .map(|(source, target)| {
            SavedHostId::from_opaque(source.clone())
                .map(|source| (source, target.clone()))
                .map_err(|_| LegacyGraphRemapError)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let final_host_ids = hosts
        .iter()
        .map(|host| host.id.clone())
        .collect::<BTreeSet<_>>();
    let notes_snippets = notes_snippets
        .plan_host_id_remap(&host_id_remap, &final_host_ids)
        .map_err(|_| LegacyGraphRemapError)?
        .into_catalog();
    let port_forward_rules = port_forward_rules
        .into_iter()
        .map(|mut rule| {
            if let Some(replacement) = host_ids.get(rule.host_id.as_str()) {
                rule.host_id = replacement.clone();
            }
            rule
        })
        .collect();

    Ok(Some(
        SavedVaultGraph::new_with_port_forward_rules(
            hosts,
            keys,
            managed_keys,
            identities,
            password_identities,
            proxy_profiles,
            groups,
            notes_snippets,
            port_forward_rules,
        )
        .with_group_catalog(custom_groups),
    ))
}

fn build_proxy_profile_remap(
    entities: &[SavedProxyProfile],
    dispositions: &[SavedVaultImportDisposition],
    source_sha256: &[u8; 32],
) -> Result<HashMap<String, SavedProxyProfileId>, LegacyGraphRemapError> {
    let original = entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<HashSet<_>>();
    let mut generated = HashSet::new();
    let mut remap = HashMap::new();
    for (entity, disposition) in entities.iter().zip(dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, PROXY_PROFILE_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement =
            SavedProxyProfileId::from_opaque(replacement).map_err(|_| LegacyGraphRemapError)?;
        remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    Ok(remap)
}

fn build_key_remap(
    entities: &[SavedSshKeyReference],
    dispositions: &[SavedVaultImportDisposition],
    managed_entities: &[SavedManagedSshKey],
    managed_dispositions: &[SavedVaultImportDisposition],
    source_sha256: &[u8; 32],
) -> Result<HashMap<String, SavedSshKeyReferenceId>, LegacyGraphRemapError> {
    let original = entities
        .iter()
        .map(|entity| entity.id.as_str())
        .chain(managed_entities.iter().map(|entity| entity.id.as_str()))
        .collect::<HashSet<_>>();
    let mut generated = HashSet::new();
    let mut remap = HashMap::new();
    for (entity, disposition) in entities.iter().zip(dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, KEY_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement =
            SavedSshKeyReferenceId::from_opaque(replacement).map_err(|_| LegacyGraphRemapError)?;
        remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    for (entity, disposition) in managed_entities.iter().zip(managed_dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, MANAGED_KEY_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement =
            SavedSshKeyReferenceId::from_opaque(replacement).map_err(|_| LegacyGraphRemapError)?;
        remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    Ok(remap)
}

fn build_identity_remaps(
    entities: &[SavedIdentityReference],
    dispositions: &[SavedVaultImportDisposition],
    password_entities: &[SavedPasswordIdentity],
    password_dispositions: &[SavedVaultImportDisposition],
    source_sha256: &[u8; 32],
) -> Result<
    (
        HashMap<String, SavedIdentityReferenceId>,
        HashMap<String, SavedPasswordIdentityId>,
    ),
    LegacyGraphRemapError,
> {
    let original = entities
        .iter()
        .map(|entity| entity.id.as_str())
        .chain(password_entities.iter().map(|entity| entity.id.as_str()))
        .collect::<HashSet<_>>();
    let mut generated = HashSet::new();
    let mut remap = HashMap::new();
    for (entity, disposition) in entities.iter().zip(dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, IDENTITY_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement = SavedIdentityReferenceId::from_opaque(replacement)
            .map_err(|_| LegacyGraphRemapError)?;
        remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    let mut password_remap = HashMap::new();
    for (entity, disposition) in password_entities.iter().zip(password_dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, PASSWORD_IDENTITY_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement =
            SavedPasswordIdentityId::from_opaque(replacement).map_err(|_| LegacyGraphRemapError)?;
        password_remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    Ok((remap, password_remap))
}

fn build_host_remap(
    entities: &[SavedHost],
    dispositions: &[SavedVaultImportDisposition],
    source_sha256: &[u8; 32],
) -> Result<HashMap<String, SavedHostId>, LegacyGraphRemapError> {
    let original = entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<HashSet<_>>();
    let mut generated = HashSet::new();
    let mut remap = HashMap::new();
    for (entity, disposition) in entities.iter().zip(dispositions) {
        if *disposition != SavedVaultImportDisposition::Conflict {
            continue;
        }
        let replacement = derive_id(source_sha256, HOST_DOMAIN, entity.id.as_str());
        if original.contains(replacement.as_str()) || !generated.insert(replacement.clone()) {
            return Err(LegacyGraphRemapError);
        }
        let replacement =
            SavedHostId::from_opaque(replacement).map_err(|_| LegacyGraphRemapError)?;
        remap.insert(entity.id.as_str().to_owned(), replacement);
    }
    Ok(remap)
}

fn rewrite_group(
    mut group: SavedGroupConfig,
    host_ids: &HashMap<String, SavedHostId>,
    identity_ids: &HashMap<String, SavedIdentityReferenceId>,
    password_identity_ids: &HashMap<String, SavedPasswordIdentityId>,
    key_ids: &HashMap<String, SavedSshKeyReferenceId>,
    proxy_profile_ids: &HashMap<String, SavedProxyProfileId>,
) -> Result<SavedGroupConfig, LegacyGraphRemapError> {
    if let SavedGroupOverride::Set(reference) = &mut group.defaults.identity_id {
        match reference {
            SavedGroupIdentityReference::Key(id) => {
                if let Some(replacement) = identity_ids.get(id.as_str()) {
                    *id = replacement.clone();
                }
            }
            SavedGroupIdentityReference::Password(id) => {
                if let Some(replacement) = password_identity_ids.get(id.as_str()) {
                    *id = replacement.clone();
                }
            }
        }
    }
    if let SavedGroupOverride::Set(id) = &mut group.defaults.identity_file_id
        && let Some(replacement) = key_ids.get(id.as_str())
    {
        *id = replacement.clone();
    }
    if let SavedGroupOverride::Set(id) = &mut group.defaults.telnet_identity_id
        && let Some(replacement) = password_identity_ids.get(id.as_str())
    {
        *id = replacement.clone();
    }
    if let SavedGroupOverride::Set(chain) = &mut group.defaults.host_chain {
        let remapped = chain
            .host_ids()
            .iter()
            .map(|id| {
                host_ids
                    .get(id.as_str())
                    .cloned()
                    .unwrap_or_else(|| id.clone())
            })
            .collect();
        *chain = SavedGroupHostChain::new(remapped).map_err(|_| LegacyGraphRemapError)?;
    }
    group.defaults.proxy = match std::mem::take(&mut group.defaults.proxy) {
        SavedGroupProxyOverride::Profile(id) => SavedGroupProxyOverride::Profile(
            proxy_profile_ids.get(id.as_str()).cloned().unwrap_or(id),
        ),
        SavedGroupProxyOverride::Inline(config) => {
            SavedGroupProxyOverride::Inline(rewrite_proxy_config(config, password_identity_ids)?)
        }
        other => other,
    };
    group.validate().map_err(|_| LegacyGraphRemapError)?;
    Ok(group)
}

fn rewrite_host(
    mut host: SavedHost,
    host_ids: &HashMap<String, SavedHostId>,
    identity_ids: &HashMap<String, SavedIdentityReferenceId>,
    password_identity_ids: &HashMap<String, SavedPasswordIdentityId>,
    key_ids: &HashMap<String, SavedSshKeyReferenceId>,
    proxy_profile_ids: &HashMap<String, SavedProxyProfileId>,
) -> Result<SavedHost, LegacyGraphRemapError> {
    if let Some(replacement) = host_ids.get(host.id.as_str()) {
        host.id = replacement.clone();
    }
    let identity_replacement = if host.auth_method.is_password() {
        flattened_reference_replacement(
            host.compatibility_fields()
                .get("identityId")
                .and_then(|value| value.as_str()),
            password_identity_ids,
        )
    } else {
        flattened_reference_replacement(
            host.compatibility_fields()
                .get("identityId")
                .and_then(|value| value.as_str()),
            identity_ids,
        )
    };
    let key_replacement = flattened_reference_replacement(
        host.compatibility_fields()
            .get("identityFileId")
            .and_then(|value| value.as_str()),
        key_ids,
    );
    let proxy_profile_replacement = flattened_reference_replacement(
        host.compatibility_fields()
            .get("proxyProfileId")
            .and_then(Value::as_str),
        proxy_profile_ids,
    );
    let inline_identity_replacement = host
        .proxy_config()
        .map_err(|_| LegacyGraphRemapError)?
        .and_then(|config| {
            flattened_reference_replacement(
                config.identity_id().map(SavedPasswordIdentityId::as_str),
                password_identity_ids,
            )
        });
    let host_chain_has_replacement = host
        .compatibility_fields()
        .get("hostChain")
        .and_then(Value::as_array)
        .is_some_and(|chain| {
            chain
                .iter()
                .filter_map(Value::as_str)
                .any(|id| host_ids.contains_key(id))
        });
    if identity_replacement.is_none()
        && key_replacement.is_none()
        && proxy_profile_replacement.is_none()
        && inline_identity_replacement.is_none()
        && !host_chain_has_replacement
    {
        return Ok(host);
    }

    let mut value = serde_json::to_value(host).map_err(|_| LegacyGraphRemapError)?;
    let object = value.as_object_mut().ok_or(LegacyGraphRemapError)?;
    if let Some(replacement) = identity_replacement {
        object.insert("identityId".to_owned(), Value::String(replacement));
    }
    if let Some(replacement) = key_replacement {
        object.insert("identityFileId".to_owned(), Value::String(replacement));
    }
    if let Some(replacement) = proxy_profile_replacement {
        object.insert("proxyProfileId".to_owned(), Value::String(replacement));
    }
    if let Some(replacement) = inline_identity_replacement {
        object
            .get_mut("proxyConfig")
            .and_then(Value::as_object_mut)
            .ok_or(LegacyGraphRemapError)?
            .insert("identityId".to_owned(), Value::String(replacement));
    }
    if host_chain_has_replacement {
        let chain = object
            .get_mut("hostChain")
            .and_then(Value::as_array_mut)
            .ok_or(LegacyGraphRemapError)?;
        for id in chain {
            let Some(current) = id.as_str() else {
                return Err(LegacyGraphRemapError);
            };
            if let Some(replacement) = host_ids.get(current) {
                *id = Value::String(replacement.to_string());
            }
        }
    }
    serde_json::from_value(value).map_err(|_| LegacyGraphRemapError)
}

fn rewrite_proxy_config(
    config: SavedProxyConfig,
    password_identity_ids: &HashMap<String, SavedPasswordIdentityId>,
) -> Result<SavedProxyConfig, LegacyGraphRemapError> {
    let replacement = flattened_reference_replacement(
        config.identity_id().map(SavedPasswordIdentityId::as_str),
        password_identity_ids,
    );
    let Some(replacement) = replacement else {
        return Ok(config);
    };
    let mut value = serde_json::to_value(config).map_err(|_| LegacyGraphRemapError)?;
    value
        .as_object_mut()
        .ok_or(LegacyGraphRemapError)?
        .insert("identityId".to_owned(), Value::String(replacement));
    serde_json::from_value(value).map_err(|_| LegacyGraphRemapError)
}

fn flattened_reference_replacement<T>(
    value: Option<&str>,
    remap: &HashMap<String, T>,
) -> Option<String>
where
    T: ToString,
{
    value
        .and_then(|current| remap.get(current))
        .map(ToString::to_string)
}

fn derive_id(source_sha256: &[u8; 32], entity_domain: &[u8], current_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(REMAP_DOMAIN);
    digest.update(source_sha256);
    digest.update(entity_domain);
    digest.update((current_id.len() as u64).to_be_bytes());
    digest.update(current_id.as_bytes());
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use netcatty_vault::{
        SavedGroupConfig, SavedGroupDefaults, SavedGroupHostChain, SavedGroupId,
        SavedGroupOverride, SavedGroupPath, SavedHost, SavedHostId, SavedHostStore,
        SavedIdentityReference, SavedIdentityReferenceId, SavedManagedSshKey,
        SavedNotesSnippetsCatalog, SavedPasswordIdentity, SavedPasswordIdentityId,
        SavedPortForwardKind, SavedPortForwardRule, SavedProxyConfig, SavedProxyProfile,
        SavedProxyProfileId, SavedSecretObjectLocator, SavedSshKeyCategory,
        SavedSshKeyCustodyReference, SavedSshKeyReference, SavedSshKeyReferenceId,
        SavedSshKeySource, SavedVaultGraph, SavedVaultImportDisposition,
    };
    use serde_json::json;

    use super::{LegacyGraphRemapError, remap_conflicting_graph, rewrite_host};

    const SOURCE_SHA256: [u8; 32] = [0x5a; 32];

    fn key(id: &str, label: &str, path: &str, marker: &str) -> SavedSshKeyReference {
        SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("key ID"),
            label,
            path,
            SavedSshKeyCategory::key(),
            10,
            20,
            BTreeMap::from([("legacyKeyMarker".to_owned(), json!(marker))]),
        )
        .expect("key reference")
    }

    fn identity(id: &str, label: &str, key_id: &str, marker: &str) -> SavedIdentityReference {
        SavedIdentityReference::from_parts(
            SavedIdentityReferenceId::from_opaque(id).expect("identity ID"),
            label,
            "legacy-user",
            SavedSshKeyReferenceId::from_opaque(key_id).expect("identity key ID"),
            10,
            20,
            BTreeMap::from([("legacyIdentityMarker".to_owned(), json!(marker))]),
        )
        .expect("identity reference")
    }

    fn managed_key(id: &str, label: &str, locator_byte: u8) -> SavedManagedSshKey {
        SavedManagedSshKey::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("managed key ID"),
            label,
            SavedSshKeyCategory::key(),
            SavedSshKeySource::imported(),
            false,
            10,
            20,
            SavedSshKeyCustodyReference::new(
                SavedSecretObjectLocator::from_hex(format!("{locator_byte:02x}").repeat(32))
                    .expect("locator"),
                1,
            )
            .expect("custody"),
            BTreeMap::new(),
        )
        .expect("managed key")
    }

    fn password_identity(
        id: &str,
        label: &str,
        username: &str,
        marker: &str,
    ) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("password identity ID"),
            1,
            label,
            username,
            true,
            10,
            20,
            BTreeMap::from([("legacyIdentityMarker".to_owned(), json!(marker))]),
        )
        .expect("password identity")
    }

    fn proxy_profile(
        id: &str,
        label: &str,
        config: SavedProxyConfig,
        marker: &str,
    ) -> SavedProxyProfile {
        SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque(id).expect("proxy profile ID"),
            1,
            label,
            config,
            10,
            20,
            BTreeMap::from([("legacyProxyMarker".to_owned(), json!(marker))]),
        )
        .expect("proxy profile")
    }

    fn inline_proxy_host(
        id: &str,
        hostname: &str,
        proxy_profile_id: &str,
        inline_identity_id: &str,
        marker: &str,
    ) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": hostname,
            "hostname": hostname,
            "port": 22,
            "username": "host-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "proxyProfileId": proxy_profile_id,
            "proxyConfig": {
                "type": "http",
                "host": "inline-proxy.example.test",
                "port": 8080,
                "identityId": inline_identity_id,
                "username": "",
                "hasSavedCredential": false
            },
            "legacyHostMarker": marker
        }))
        .expect("inline proxy host")
    }

    fn password_host(id: &str, hostname: &str, identity_id: &str, marker: &str) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": hostname,
            "hostname": hostname,
            "port": 22,
            "username": "host-fallback-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "identityId": identity_id,
            "legacyHostMarker": marker
        }))
        .expect("password host")
    }

    fn host(id: &str, hostname: &str, identity_id: &str, key_id: &str, marker: &str) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": hostname,
            "hostname": hostname,
            "port": 22,
            "username": "legacy-user",
            "protocol": "ssh",
            "authMethod": "key",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "identityId": identity_id,
            "identityFileId": key_id,
            "legacyHostMarker": marker
        }))
        .expect("saved host")
    }

    fn graph(
        key_label: &str,
        key_path: &str,
        identity_label: &str,
        hostname: &str,
        marker: &str,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new(
            vec![host(
                "host-id-sentinel",
                hostname,
                "identity-id-sentinel",
                "key-id-sentinel",
                marker,
            )],
            vec![key("key-id-sentinel", key_label, key_path, marker)],
            vec![identity(
                "identity-id-sentinel",
                identity_label,
                "key-id-sentinel",
                marker,
            )],
        )
    }

    fn assessment_against(
        current: SavedVaultGraph,
        candidates: &SavedVaultGraph,
    ) -> (
        tempfile::TempDir,
        SavedHostStore,
        netcatty_vault::SavedVaultGraphImportAssessment,
    ) {
        let root = tempfile::tempdir().expect("temporary Vault");
        let store = SavedHostStore::open(root.path().join("vault")).expect("open Vault");
        if !current.hosts().is_empty()
            || !current.ssh_key_references().is_empty()
            || !current.managed_ssh_keys().is_empty()
            || !current.identity_references().is_empty()
            || !current.password_identities().is_empty()
            || !current.proxy_profiles().is_empty()
        {
            let revision = store
                .assess_graph_import(&current)
                .expect("current assessment")
                .into_revision();
            store
                .commit_graph_import(revision, current)
                .expect("seed current graph");
        }
        let assessment = store
            .assess_graph_import(candidates)
            .expect("candidate assessment");
        (root, store, assessment)
    }

    fn assert_full_hex_id(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn same_round_key_identity_and_host_conflicts_rewrite_every_edge() {
        let current = graph(
            "Current key",
            "D:\\keys\\current",
            "Current identity",
            "current.example.test",
            "current-marker",
        );
        let candidates = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.ssh_key_reference_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.identity_reference_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.host_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("remap")
            .expect("conflicts changed graph");
        let key = &remapped.ssh_key_references()[0];
        let identity = &remapped.identity_references()[0];
        let host = &remapped.hosts()[0];
        assert_full_hex_id(key.id.as_str());
        assert_full_hex_id(identity.id.as_str());
        assert_full_hex_id(host.id.as_str());
        assert_eq!(identity.key_id.as_str(), key.id.as_str());
        assert_eq!(
            host.compatibility_fields()["identityId"],
            identity.id.as_str()
        );
        assert_eq!(
            host.compatibility_fields()["identityFileId"],
            key.id.as_str()
        );
        assert_eq!(
            key.compatibility_fields()["legacyKeyMarker"],
            "source-marker"
        );
        assert_eq!(
            identity.compatibility_fields()["legacyIdentityMarker"],
            "source-marker"
        );
        assert_eq!(
            host.compatibility_fields()["legacyHostMarker"],
            "source-marker"
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("remapped graph remains valid");
        assert_eq!(
            reassessed.ssh_key_reference_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.identity_reference_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn host_remap_preserves_v8_catalogs_and_rewrites_every_host_edge() {
        let current = graph(
            "Current key",
            "D:\\keys\\current",
            "Current identity",
            "current.example.test",
            "current-marker",
        );
        let base = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let chained_host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "chain-target",
            "revision": 1,
            "label": "chain-target.example.test",
            "hostname": "chain-target.example.test",
            "port": 22,
            "username": "legacy-user",
            "protocol": "ssh",
            "authMethod": "key",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "identityId": "identity-id-sentinel",
            "identityFileId": "key-id-sentinel",
            "hostChain": ["host-id-sentinel"]
        }))
        .expect("chained host");
        let group = SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque("v8-group").expect("group ID"),
            1,
            SavedGroupPath::new("Operations").expect("group path"),
            SavedGroupDefaults {
                host_chain: SavedGroupOverride::Set(
                    SavedGroupHostChain::new(vec![
                        SavedHostId::from_opaque("host-id-sentinel").expect("host ID"),
                    ])
                    .expect("group host chain"),
                ),
                ..SavedGroupDefaults::default()
            },
            10,
            10,
        )
        .expect("group config");
        let notes_snippets: SavedNotesSnippetsCatalog = serde_json::from_value(json!({
            "snippets": [{
                "id": "v8-snippet",
                "label": "V8 snippet",
                "command": "uptime",
                "targets": ["host-id-sentinel"]
            }],
            "snippetPackages": ["Operations"],
            "notes": [{
                "id": "v8-note",
                "title": "V8 note",
                "content": "preserved",
                "linkedHostIds": ["host-id-sentinel"],
                "createdAt": 10.0,
                "updatedAt": 10.0
            }],
            "noteGroups": ["Operations"]
        }))
        .expect("notes/snippets catalog");
        let port_forward = SavedPortForwardRule::new(
            "v8-forward",
            "V8 forward",
            SavedPortForwardKind::Dynamic,
            1080,
            "127.0.0.1",
            None,
            None,
            "host-id-sentinel",
            false,
            10,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        let mut hosts = base.hosts().to_vec();
        hosts.push(chained_host);
        let candidates = SavedVaultGraph::new_with_port_forward_rules(
            hosts,
            base.ssh_key_references().to_vec(),
            base.managed_ssh_keys().to_vec(),
            base.identity_references().to_vec(),
            base.password_identities().to_vec(),
            base.proxy_profiles().to_vec(),
            vec![group],
            notes_snippets,
            vec![port_forward],
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("remap")
            .expect("conflicts changed graph");
        let remapped_host_id = remapped.hosts()[0].id.clone();

        assert_eq!(
            remapped.hosts()[1].compatibility_fields()["hostChain"][0],
            remapped_host_id.as_str()
        );
        let SavedGroupOverride::Set(group_chain) = &remapped.groups()[0].defaults.host_chain else {
            panic!("group chain must remain explicit");
        };
        assert_eq!(
            group_chain.host_ids(),
            std::slice::from_ref(&remapped_host_id)
        );
        assert_eq!(
            remapped.notes_snippets().snippets().expect("snippets")[0]
                .targets()
                .expect("snippet targets"),
            std::slice::from_ref(&remapped_host_id)
        );
        assert_eq!(
            remapped.notes_snippets().notes().expect("notes")[0]
                .linked_host_ids()
                .expect("note links"),
            std::slice::from_ref(&remapped_host_id)
        );
        assert_eq!(remapped.port_forward_rules()[0].host_id, remapped_host_id);
        store
            .assess_graph_import(&remapped)
            .expect("remapped v8 graph remains valid");
    }

    #[test]
    fn key_only_conflict_rewrites_identity_and_host_key_edges_only() {
        let current = SavedVaultGraph::new(
            Vec::new(),
            vec![key(
                "key-id-sentinel",
                "Current key",
                "D:\\keys\\current",
                "current-marker",
            )],
            Vec::new(),
        );
        let candidates = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.ssh_key_reference_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.identity_reference_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            assessment.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("remap")
            .expect("key conflict changed graph");
        let key = &remapped.ssh_key_references()[0];
        let identity = &remapped.identity_references()[0];
        let host = &remapped.hosts()[0];
        assert_ne!(key.id.as_str(), "key-id-sentinel");
        assert_eq!(identity.id.as_str(), "identity-id-sentinel");
        assert_eq!(host.id.as_str(), "host-id-sentinel");
        assert_eq!(identity.key_id.as_str(), key.id.as_str());
        assert_eq!(
            host.compatibility_fields()["identityFileId"],
            key.id.as_str()
        );
        assert_eq!(
            host.compatibility_fields()["identityId"],
            "identity-id-sentinel"
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("key-remapped graph remains valid");
        assert_eq!(
            reassessed.ssh_key_reference_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.identity_reference_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn managed_key_conflict_rewrites_identity_and_host_edges() {
        let current = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            Vec::new(),
            vec![managed_key(
                "managed-key-sentinel",
                "Current managed key",
                0x61,
            )],
            Vec::new(),
        );
        let candidate_key = managed_key("managed-key-sentinel", "Imported managed key", 0x62);
        let candidate_identity = identity(
            "managed-identity-sentinel",
            "Managed identity",
            candidate_key.id.as_str(),
            "managed-source-marker",
        );
        let candidate_host = host(
            "managed-host-sentinel",
            "managed.example.test",
            candidate_identity.id.as_str(),
            candidate_key.id.as_str(),
            "managed-source-marker",
        );
        let candidates = SavedVaultGraph::new_with_managed_ssh_keys(
            vec![candidate_host],
            Vec::new(),
            vec![candidate_key],
            vec![candidate_identity],
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.managed_ssh_key_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("remap managed conflict")
            .expect("managed conflict changed graph");
        let key = &remapped.managed_ssh_keys()[0];
        let identity = &remapped.identity_references()[0];
        let host = &remapped.hosts()[0];
        assert_full_hex_id(key.id.as_str());
        assert_eq!(identity.key_id, key.id);
        assert_eq!(
            host.compatibility_fields()["identityFileId"],
            key.id.as_str()
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("remapped managed graph remains valid");
        assert_eq!(
            reassessed.managed_ssh_key_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn unrelated_key_remap_preserves_the_complete_password_identity_catalog() {
        let current = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            vec![key(
                "key-id-sentinel",
                "Current key",
                "D:\\keys\\current",
                "current-marker",
            )],
            Vec::new(),
            Vec::new(),
        );
        let base = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let (hosts, keys, managed_keys, identities, _) = base.into_all_parts();
        let password_identity = password_identity(
            "preserved-password-identity",
            "Preserved password identity",
            "password-user",
            "password-marker",
        );
        let candidates = SavedVaultGraph::new_with_password_identities(
            hosts,
            keys,
            managed_keys,
            identities,
            vec![password_identity.clone()],
        );
        let (_root, _store, assessment) = assessment_against(current, &candidates);

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("remap")
            .expect("key conflict changed graph");
        assert_eq!(
            remapped.password_identities(),
            std::slice::from_ref(&password_identity)
        );
    }

    #[test]
    fn password_identity_conflict_rewrites_only_password_host_identity_edges() {
        let current_identity = password_identity(
            "password-identity-sentinel",
            "Current password identity",
            "current-user",
            "current-marker",
        );
        let current = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current_identity],
        );
        let imported_identity = password_identity(
            "password-identity-sentinel",
            "Imported password identity",
            "imported-user",
            "source-marker",
        );
        let imported_host = password_host(
            "password-host-sentinel",
            "password.example.test",
            imported_identity.id.as_str(),
            "source-marker",
        );
        let candidates = SavedVaultGraph::new_with_password_identities(
            vec![imported_host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![imported_identity],
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.password_identity_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("password identity remap")
            .expect("password identity conflict changed graph");
        let identity = &remapped.password_identities()[0];
        let host = &remapped.hosts()[0];
        assert_full_hex_id(identity.id.as_str());
        assert_eq!(
            host.compatibility_fields()["identityId"],
            identity.id.as_str()
        );
        assert_eq!(
            identity.compatibility_fields()["legacyIdentityMarker"],
            "source-marker"
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("remapped password graph remains valid");
        assert_eq!(
            reassessed.password_identity_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn proxy_profile_conflict_uses_its_own_domain_and_preserves_metadata() {
        let current = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "proxy-profile-sentinel",
                "Current proxy",
                SavedProxyConfig::command("current-proxy-command").expect("command proxy"),
                "current-marker",
            )],
            Vec::new(),
        );
        let candidates = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "proxy-profile-sentinel",
                "Imported proxy",
                SavedProxyConfig::command("imported-proxy-command").expect("command proxy"),
                "source-marker",
            )],
            Vec::new(),
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("proxy remap")
            .expect("proxy conflict changed graph");
        let profile = &remapped.proxy_profiles()[0];
        assert_full_hex_id(profile.id.as_str());
        assert_ne!(profile.id.as_str(), "proxy-profile-sentinel");
        assert_eq!(
            profile.compatibility_fields()["legacyProxyMarker"],
            "source-marker"
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("remapped proxy graph remains valid");
        assert_eq!(
            reassessed.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn same_round_password_identity_profile_and_host_conflicts_rewrite_all_proxy_edges() {
        // Cross-entity ID reuse is legal; domain separation must still derive
        // three distinct replacement IDs from the same source ID.
        let identity_id = "proxy-shared-id-sentinel";
        let profile_id = "proxy-shared-id-sentinel";
        let host_id = "proxy-shared-id-sentinel";
        let current_identity = password_identity(
            identity_id,
            "Current proxy identity",
            "current-user",
            "current-marker",
        );
        let current_profile = proxy_profile(
            profile_id,
            "Current proxy profile",
            SavedProxyConfig::http(
                "current-proxy.example.test",
                8080,
                Some(current_identity.id.clone()),
                "",
                false,
            )
            .expect("current proxy config"),
            "current-marker",
        );
        let current_host = inline_proxy_host(
            host_id,
            "current-host.example.test",
            profile_id,
            identity_id,
            "current-marker",
        );
        let current = SavedVaultGraph::new_with_proxy_profiles(
            vec![current_host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current_identity],
            vec![current_profile],
            Vec::new(),
        );

        let imported_identity = password_identity(
            identity_id,
            "Imported proxy identity",
            "imported-user",
            "source-marker",
        );
        let imported_profile = proxy_profile(
            profile_id,
            "Imported proxy profile",
            SavedProxyConfig::http(
                "imported-proxy.example.test",
                9080,
                Some(imported_identity.id.clone()),
                "",
                false,
            )
            .expect("imported proxy config"),
            "source-marker",
        );
        let imported_host = inline_proxy_host(
            host_id,
            "imported-host.example.test",
            profile_id,
            identity_id,
            "source-marker",
        );
        let candidates = SavedVaultGraph::new_with_proxy_profiles(
            vec![imported_host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![imported_identity],
            vec![imported_profile],
            Vec::new(),
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.password_identity_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.host_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("complete proxy remap")
            .expect("complete proxy conflicts changed graph");
        let identity = &remapped.password_identities()[0];
        let profile = &remapped.proxy_profiles()[0];
        let host = &remapped.hosts()[0];
        assert_full_hex_id(identity.id.as_str());
        assert_full_hex_id(profile.id.as_str());
        assert_full_hex_id(host.id.as_str());
        assert_ne!(identity.id.as_str(), profile.id.as_str());
        assert_ne!(identity.id.as_str(), host.id.as_str());
        assert_ne!(profile.id.as_str(), host.id.as_str());
        assert_eq!(
            profile
                .config
                .identity_id()
                .map(SavedPasswordIdentityId::as_str),
            Some(identity.id.as_str())
        );
        assert_eq!(
            host.proxy_profile_id()
                .expect("profile edge")
                .expect("profile ID")
                .as_str(),
            profile.id.as_str()
        );
        assert_eq!(
            host.proxy_config()
                .expect("inline edge")
                .expect("inline config")
                .identity_id()
                .map(SavedPasswordIdentityId::as_str),
            Some(identity.id.as_str())
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("complete remapped graph remains valid");
        assert_eq!(
            reassessed.password_identity_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn shadowed_profile_edge_is_remapped_without_changing_inline_precedence() {
        let identity = password_identity(
            "shadow-inline-identity",
            "Shadow inline identity",
            "inline-user",
            "source-marker",
        );
        let current = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "shadow-profile-sentinel",
                "Current shadowed profile",
                SavedProxyConfig::command("current-command").expect("current command"),
                "current-marker",
            )],
            Vec::new(),
        );
        let candidates = SavedVaultGraph::new_with_proxy_profiles(
            vec![inline_proxy_host(
                "shadow-host",
                "shadow-host.example.test",
                "shadow-profile-sentinel",
                identity.id.as_str(),
                "source-marker",
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity.clone()],
            vec![proxy_profile(
                "shadow-profile-sentinel",
                "Imported shadowed profile",
                SavedProxyConfig::command("imported-command").expect("imported command"),
                "source-marker",
            )],
            Vec::new(),
        );
        let (_root, store, assessment) = assessment_against(current, &candidates);
        assert_eq!(
            assessment.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Conflict]
        );
        assert_eq!(
            assessment.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );

        let remapped = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("shadowed edge remap")
            .expect("profile conflict changed graph");
        let profile = &remapped.proxy_profiles()[0];
        let host = &remapped.hosts()[0];
        assert_eq!(
            host.proxy_profile_id()
                .expect("shadowed profile edge")
                .expect("shadowed profile ID"),
            profile.id
        );
        assert_eq!(
            host.proxy_config()
                .expect("inline still valid")
                .expect("inline remains present")
                .identity_id(),
            Some(&identity.id)
        );
        let reassessed = store
            .assess_graph_import(&remapped)
            .expect("shadowed remapped graph remains valid");
        assert_eq!(
            reassessed.proxy_profile_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            reassessed.host_dispositions(),
            &[SavedVaultImportDisposition::Importable]
        );
    }

    #[test]
    fn proxy_remapping_is_stable_and_proxy_assessment_shape_is_checked() {
        let current = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "stable-proxy-profile",
                "Current stable proxy",
                SavedProxyConfig::command("current-command").expect("current command"),
                "current-marker",
            )],
            Vec::new(),
        );
        let candidates = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "stable-proxy-profile",
                "Imported stable proxy",
                SavedProxyConfig::command("imported-command").expect("imported command"),
                "source-marker",
            )],
            Vec::new(),
        );
        let (_root, _store, assessment) = assessment_against(current, &candidates);
        let first = remap_conflicting_graph(candidates.clone(), &assessment, &SOURCE_SHA256)
            .expect("first proxy remap")
            .expect("first proxy graph changed");
        let second = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("second proxy remap")
            .expect("second proxy graph changed");
        assert_eq!(first, second);

        let shape_candidates = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proxy_profile(
                "shape-proxy-profile",
                "Shape proxy",
                SavedProxyConfig::command("shape-command").expect("shape command"),
                "shape-marker",
            )],
            Vec::new(),
        );
        let (_root, _store, shape_assessment) =
            assessment_against(SavedVaultGraph::default(), &shape_candidates);
        assert_eq!(
            remap_conflicting_graph(
                SavedVaultGraph::default(),
                &shape_assessment,
                &SOURCE_SHA256
            ),
            Err(LegacyGraphRemapError)
        );
    }

    #[test]
    fn conflict_free_graph_is_a_no_op() {
        let candidates = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let (_root, _store, assessment) =
            assessment_against(SavedVaultGraph::default(), &candidates);
        let result =
            remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256).expect("no-op remap");
        assert!(result.is_none());
    }

    #[test]
    fn remapping_is_stable_across_calls() {
        let current = graph(
            "Current key",
            "D:\\keys\\current",
            "Current identity",
            "current.example.test",
            "current-marker",
        );
        let candidates = graph(
            "Imported key",
            "D:\\keys\\imported",
            "Imported identity",
            "imported.example.test",
            "source-marker",
        );
        let (_root, _store, assessment) = assessment_against(current, &candidates);
        let first = remap_conflicting_graph(candidates.clone(), &assessment, &SOURCE_SHA256)
            .expect("first remap")
            .expect("changed graph");
        let second = remap_conflicting_graph(candidates, &assessment, &SOURCE_SHA256)
            .expect("second remap")
            .expect("changed graph");
        assert_eq!(first, second);
    }

    #[test]
    fn assessment_shape_errors_are_fixed_and_never_leak_source_values() {
        let candidates = graph(
            "label-leak-sentinel",
            "D:\\path-leak-sentinel",
            "identity-label-leak-sentinel",
            "hostname-leak-sentinel.example.test",
            "compatibility-leak-sentinel",
        );
        let (_root, _store, assessment) =
            assessment_against(SavedVaultGraph::default(), &candidates);
        let error = remap_conflicting_graph(SavedVaultGraph::default(), &assessment, &[0xab; 32])
            .expect_err("assessment vectors must match the graph");
        assert_eq!(error, LegacyGraphRemapError);
        let rendered = format!("{error:?} {error}");
        for forbidden in [
            "key-id-sentinel",
            "identity-id-sentinel",
            "host-id-sentinel",
            "label-leak-sentinel",
            "path-leak-sentinel",
            "hostname-leak-sentinel",
            "compatibility-leak-sentinel",
            "abababababababab",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn host_rebuild_errors_use_the_same_fixed_non_leaking_error() {
        let mut damaged = host(
            "host-rebuild-id-sentinel",
            "host-rebuild.example.test",
            "identity-rebuild-id-sentinel",
            "key-rebuild-id-sentinel",
            "host-rebuild-marker-sentinel",
        );
        damaged.created_at = 30;
        damaged.updated_at = 20;
        let identity_ids = HashMap::from([(
            "identity-rebuild-id-sentinel".to_owned(),
            SavedIdentityReferenceId::from_opaque("remapped-identity-id").expect("remapped ID"),
        )]);
        let error = rewrite_host(
            damaged,
            &HashMap::new(),
            &identity_ids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect_err("invalid host cannot be rebuilt");
        assert_eq!(error, LegacyGraphRemapError);
        let rendered = format!("{error:?} {error}");
        for forbidden in [
            "host-rebuild-id-sentinel",
            "identity-rebuild-id-sentinel",
            "key-rebuild-id-sentinel",
            "host-rebuild.example.test",
            "host-rebuild-marker-sentinel",
            "remapped-identity-id",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
