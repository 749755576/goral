use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use netcatty_vault::{
    MAX_NOTES_SNIPPETS_CATALOG_ENTITIES, MAX_NOTES_SNIPPETS_LIST_VALUES, SavedGroupConfig,
    SavedGroupOpaqueId, SavedGroupOverride, SavedHost, SavedHostId, SavedHostReferenceKind,
    SavedNotesSnippetsCatalog, SavedNotesSnippetsError, SavedSnippet, SavedSnippetId,
    SavedSnippetKind, SavedVaultNote, SavedVaultNoteDraft, SavedVaultNoteId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const REMAP_DOMAIN: &[u8] = b"netcatty-legacy-notes-snippets-remap-v1\0";
const SNIPPET_DOMAIN: &[u8] = b"snippet\0";
const NOTE_DOMAIN: &[u8] = b"note\0";
const MAX_REMAP_ROUNDS: usize = 32;
const MISSING_NOTE_TIMESTAMP: f64 = 0.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyNotesSnippetsRecordKind {
    Catalog,
    Snippet,
    Note,
    Host,
    Group,
}

/// Stable failure categories. None of these variants carries source text or an
/// opaque ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyNotesSnippetsErrorCode {
    InvalidSnippets,
    InvalidSnippetPackages,
    InvalidNotes,
    InvalidNoteGroups,
    CatalogLimitExceeded,
    InvalidCatalog,
    InvalidHostRemap,
    InvalidHostScriptEdge,
    InvalidGroupScriptEdge,
    DanglingHostReference,
    DanglingScriptReference,
    IncompatibleScriptReference,
    DeterministicRemapExhausted,
}

/// Payload-free parsing/planning failure. Array positions are safe to expose;
/// labels, commands, note bodies, paths, and IDs are never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyNotesSnippetsError {
    pub code: LegacyNotesSnippetsErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_kind: Option<LegacyNotesSnippetsRecordKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_index: Option<u32>,
}

impl LegacyNotesSnippetsError {
    const fn catalog(code: LegacyNotesSnippetsErrorCode) -> Self {
        Self {
            code,
            record_kind: Some(LegacyNotesSnippetsRecordKind::Catalog),
            record_index: None,
            reference_index: None,
        }
    }

    fn record(
        code: LegacyNotesSnippetsErrorCode,
        kind: LegacyNotesSnippetsRecordKind,
        record_index: usize,
    ) -> Self {
        Self {
            code,
            record_kind: Some(kind),
            record_index: u32::try_from(record_index).ok(),
            reference_index: None,
        }
    }

    fn reference(
        code: LegacyNotesSnippetsErrorCode,
        kind: LegacyNotesSnippetsRecordKind,
        record_index: usize,
        reference_index: Option<usize>,
    ) -> Self {
        Self {
            code,
            record_kind: Some(kind),
            record_index: u32::try_from(record_index).ok(),
            reference_index: reference_index.and_then(|index| u32::try_from(index).ok()),
        }
    }
}

impl fmt::Display for LegacyNotesSnippetsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            LegacyNotesSnippetsErrorCode::InvalidSnippets => "legacy snippets catalog is invalid",
            LegacyNotesSnippetsErrorCode::InvalidSnippetPackages => {
                "legacy snippet packages catalog is invalid"
            }
            LegacyNotesSnippetsErrorCode::InvalidNotes => "legacy notes catalog is invalid",
            LegacyNotesSnippetsErrorCode::InvalidNoteGroups => {
                "legacy note groups catalog is invalid"
            }
            LegacyNotesSnippetsErrorCode::CatalogLimitExceeded => {
                "legacy notes/scripts catalog exceeds a fixed limit"
            }
            LegacyNotesSnippetsErrorCode::InvalidCatalog => {
                "legacy notes/scripts catalog failed validation"
            }
            LegacyNotesSnippetsErrorCode::InvalidHostRemap => "legacy host remap is invalid",
            LegacyNotesSnippetsErrorCode::InvalidHostScriptEdge => {
                "legacy host script relationship is invalid"
            }
            LegacyNotesSnippetsErrorCode::InvalidGroupScriptEdge => {
                "legacy group script relationship is invalid"
            }
            LegacyNotesSnippetsErrorCode::DanglingHostReference => {
                "legacy notes/scripts graph contains a missing host reference"
            }
            LegacyNotesSnippetsErrorCode::DanglingScriptReference => {
                "legacy notes/scripts graph contains a missing script reference"
            }
            LegacyNotesSnippetsErrorCode::IncompatibleScriptReference => {
                "legacy host relationship does not point to a script"
            }
            LegacyNotesSnippetsErrorCode::DeterministicRemapExhausted => {
                "legacy notes/scripts ID remapping failed"
            }
        })
    }
}

impl std::error::Error for LegacyNotesSnippetsError {}

/// Parsed source catalogs plus safe raw counts. This trusted value deliberately
/// implements neither `Debug`, `Clone`, nor Serde because its catalog contains
/// user-authored commands and note bodies.
pub struct LegacyNotesSnippetsCandidates {
    catalog: SavedNotesSnippetsCatalog,
    source_snippet_count: u32,
    source_snippet_package_count: u32,
    source_note_count: u32,
    source_note_group_count: u32,
}

impl LegacyNotesSnippetsCandidates {
    pub(crate) fn absent() -> Self {
        Self {
            catalog: SavedNotesSnippetsCatalog::default(),
            source_snippet_count: 0,
            source_snippet_package_count: 0,
            source_note_count: 0,
            source_note_group_count: 0,
        }
    }

    #[must_use]
    pub fn catalog(&self) -> &SavedNotesSnippetsCatalog {
        &self.catalog
    }

    #[must_use]
    pub const fn source_snippet_count(&self) -> u32 {
        self.source_snippet_count
    }

    #[must_use]
    pub const fn source_snippet_package_count(&self) -> u32 {
        self.source_snippet_package_count
    }

    #[must_use]
    pub const fn source_note_count(&self) -> u32 {
        self.source_note_count
    }

    #[must_use]
    pub const fn source_note_group_count(&self) -> u32 {
        self.source_note_group_count
    }

    #[must_use]
    pub fn into_catalog(self) -> SavedNotesSnippetsCatalog {
        self.catalog
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyVaultNoteWire {
    id: Option<Value>,
    #[serde(default)]
    title: Value,
    #[serde(default)]
    content: Value,
    #[serde(default)]
    group: Value,
    #[serde(default)]
    tags: Value,
    #[serde(default)]
    linked_host_ids: Value,
    #[serde(default)]
    created_at: Value,
    #[serde(default)]
    updated_at: Value,
    #[serde(default)]
    order: Value,
}

/// Strictly parses the four optional legacy top-level catalogs. `None` and
/// JSON `null` mean absent; `Some([])` remains an explicit empty scope.
pub fn parse_legacy_notes_snippets_catalogs(
    snippets: Option<Value>,
    snippet_packages: Option<Value>,
    notes: Option<Value>,
    note_groups: Option<Value>,
    now_ms: u64,
) -> Result<LegacyNotesSnippetsCandidates, LegacyNotesSnippetsError> {
    let (snippet_values, source_snippet_count) =
        take_optional_array(snippets, LegacyNotesSnippetsErrorCode::InvalidSnippets)?;
    let (snippet_package_values, source_snippet_package_count) = take_optional_array(
        snippet_packages,
        LegacyNotesSnippetsErrorCode::InvalidSnippetPackages,
    )?;
    let (note_values, source_note_count) =
        take_optional_array(notes, LegacyNotesSnippetsErrorCode::InvalidNotes)?;
    let (note_group_values, source_note_group_count) =
        take_optional_array(note_groups, LegacyNotesSnippetsErrorCode::InvalidNoteGroups)?;

    if snippet_values
        .as_ref()
        .is_some_and(|values| values.len() > MAX_NOTES_SNIPPETS_CATALOG_ENTITIES)
        || note_values
            .as_ref()
            .is_some_and(|values| values.len() > MAX_NOTES_SNIPPETS_CATALOG_ENTITIES)
        || snippet_package_values
            .as_ref()
            .is_some_and(|values| values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES)
        || note_group_values
            .as_ref()
            .is_some_and(|values| values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES)
    {
        return Err(LegacyNotesSnippetsError::catalog(
            LegacyNotesSnippetsErrorCode::CatalogLimitExceeded,
        ));
    }

    let snippets = snippet_values
        .map(|values| {
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    serde_json::from_value::<SavedSnippet>(value).map_err(|_| {
                        LegacyNotesSnippetsError::record(
                            LegacyNotesSnippetsErrorCode::InvalidSnippets,
                            LegacyNotesSnippetsRecordKind::Snippet,
                            index,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let snippet_packages = snippet_package_values
        .map(|values| {
            values
                .into_iter()
                .map(|value| match value {
                    Value::String(value) => Ok(value),
                    _ => Err(LegacyNotesSnippetsError::catalog(
                        LegacyNotesSnippetsErrorCode::InvalidSnippetPackages,
                    )),
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let notes = note_values
        .map(|values| {
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| parse_note(value, now_ms, index))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let note_groups = note_group_values.map(|values| {
        values
            .into_iter()
            .filter_map(|value| match value {
                Value::String(value) => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>()
    });

    let catalog =
        SavedNotesSnippetsCatalog::from_parts(snippets, snippet_packages, notes, note_groups)
            .map_err(|_| {
                LegacyNotesSnippetsError::catalog(LegacyNotesSnippetsErrorCode::InvalidCatalog)
            })?;

    Ok(LegacyNotesSnippetsCandidates {
        catalog,
        source_snippet_count,
        source_snippet_package_count,
        source_note_count,
        source_note_group_count,
    })
}

fn take_optional_array(
    value: Option<Value>,
    invalid_code: LegacyNotesSnippetsErrorCode,
) -> Result<(Option<Vec<Value>>, u32), LegacyNotesSnippetsError> {
    match value {
        None | Some(Value::Null) => Ok((None, 0)),
        Some(Value::Array(values)) => {
            let count = values.len().min(u32::MAX as usize) as u32;
            Ok((Some(values), count))
        }
        Some(_) => Err(LegacyNotesSnippetsError::catalog(invalid_code)),
    }
}

fn parse_note(
    value: Value,
    _now_ms: u64,
    index: usize,
) -> Result<SavedVaultNote, LegacyNotesSnippetsError> {
    let wire = serde_json::from_value::<LegacyVaultNoteWire>(value).map_err(|_| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidNotes,
            LegacyNotesSnippetsRecordKind::Note,
            index,
        )
    })?;
    let Some(Value::String(id)) = wire.id else {
        return Err(LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidNotes,
            LegacyNotesSnippetsRecordKind::Note,
            index,
        ));
    };
    let title = string_or_default(wire.title);
    let content = string_or_default(wire.content);
    let group = match wire.group {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    };
    let tags = clean_note_string_array(wire.tags, index)?;
    let linked_host_ids = clean_note_string_array(wire.linked_host_ids, index)?;
    // A wall-clock fallback would make reparsing the exact same source produce
    // a different candidate and defeat deterministic duplicate detection.
    let created_at = finite_number(wire.created_at).unwrap_or(MISSING_NOTE_TIMESTAMP);
    let updated_at = finite_number(wire.updated_at).unwrap_or(created_at);
    let order = finite_number(wire.order);
    let mut draft = SavedVaultNoteDraft::new(id, title, content, created_at, updated_at);
    draft.group = group;
    draft.tags = tags;
    draft.linked_host_ids = linked_host_ids;
    draft.order = order;
    SavedVaultNote::from_draft(draft).map_err(|_| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidNotes,
            LegacyNotesSnippetsRecordKind::Note,
            index,
        )
    })
}

fn string_or_default(value: Value) -> String {
    match value {
        Value::String(value) => value,
        _ => String::new(),
    }
}

fn finite_number(value: Value) -> Option<f64> {
    value.as_f64().filter(|value| value.is_finite())
}

fn clean_note_string_array(
    value: Value,
    record_index: usize,
) -> Result<Option<Vec<String>>, LegacyNotesSnippetsError> {
    let Value::Array(values) = value else {
        return Ok(None);
    };
    if values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES {
        return Err(LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::CatalogLimitExceeded,
            LegacyNotesSnippetsRecordKind::Note,
            record_index,
        ));
    }
    let mut seen = HashSet::new();
    let cleaned = values
        .into_iter()
        .filter_map(|value| match value {
            Value::String(value) => {
                let value = value.trim().to_owned();
                (!value.is_empty() && seen.insert(value.clone())).then_some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    Ok((!cleaned.is_empty()).then_some(cleaned))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyNotesSnippetsDisposition {
    Importable,
    Duplicate,
    RemappedImportable,
    RemappedDuplicate,
}

/// Renderer-safe assessment: counts and typed dispositions only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyNotesSnippetsAssessment {
    pub snippets_present: bool,
    pub snippet_packages_present: bool,
    pub notes_present: bool,
    pub note_groups_present: bool,
    pub source_snippet_count: u32,
    pub source_snippet_package_count: u32,
    pub source_note_count: u32,
    pub source_note_group_count: u32,
    pub snippet_dispositions: Vec<LegacyNotesSnippetsDisposition>,
    pub note_dispositions: Vec<LegacyNotesSnippetsDisposition>,
    pub importable_snippet_package_count: u32,
    pub duplicate_snippet_package_count: u32,
    pub importable_note_group_count: u32,
    pub duplicate_note_group_count: u32,
    pub catalog_scope_change_count: u32,
    pub remapped_snippet_id_count: u32,
    pub remapped_note_id_count: u32,
    pub remapped_snippet_target_count: u32,
    pub remapped_note_link_count: u32,
    pub remapped_host_script_edge_count: u32,
    pub remapped_group_script_edge_count: u32,
}

impl LegacyNotesSnippetsAssessment {
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.catalog_scope_change_count > 0
            || self.importable_snippet_package_count > 0
            || self.importable_note_group_count > 0
            || self.snippet_dispositions.iter().any(|disposition| {
                matches!(
                    disposition,
                    LegacyNotesSnippetsDisposition::Importable
                        | LegacyNotesSnippetsDisposition::RemappedImportable
                )
            })
            || self.note_dispositions.iter().any(|disposition| {
                matches!(
                    disposition,
                    LegacyNotesSnippetsDisposition::Importable
                        | LegacyNotesSnippetsDisposition::RemappedImportable
                )
            })
    }
}

/// Complete all-or-nothing projection. Its custom `Debug` shows only the safe
/// assessment and host count, never commands, note bodies, labels, or IDs.
pub struct LegacyNotesSnippetsImportPlan {
    assessment: LegacyNotesSnippetsAssessment,
    catalog: SavedNotesSnippetsCatalog,
    hosts: Vec<SavedHost>,
    groups: Vec<SavedGroupConfig>,
}

impl fmt::Debug for LegacyNotesSnippetsImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyNotesSnippetsImportPlan")
            .field("assessment", &self.assessment)
            .field("host_count", &self.hosts.len())
            .field("group_count", &self.groups.len())
            .finish()
    }
}

impl LegacyNotesSnippetsImportPlan {
    #[must_use]
    pub fn assessment(&self) -> &LegacyNotesSnippetsAssessment {
        &self.assessment
    }

    #[must_use]
    pub fn catalog(&self) -> &SavedNotesSnippetsCatalog {
        &self.catalog
    }

    #[must_use]
    pub fn hosts(&self) -> &[SavedHost] {
        &self.hosts
    }

    #[must_use]
    pub fn groups(&self) -> &[SavedGroupConfig] {
        &self.groups
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LegacyNotesSnippetsAssessment,
        SavedNotesSnippetsCatalog,
        Vec<SavedHost>,
        Vec<SavedGroupConfig>,
    ) {
        (self.assessment, self.catalog, self.hosts, self.groups)
    }
}

/// Plans one Notes/Scripts batch against the current catalog without writing.
///
/// `candidate_hosts` must already carry their final host IDs. `host_id_remap`
/// maps legacy IDs still present in snippet/note edges to those final IDs. The
/// function rewrites every Host and GroupConfig script edge, validates the
/// complete projected closure against current plus candidate entities, and
/// returns no partial result on any dangling or incompatible relationship.
pub fn plan_legacy_notes_snippets_import(
    candidates: &LegacyNotesSnippetsCandidates,
    current_catalog: &SavedNotesSnippetsCatalog,
    candidate_hosts: &[SavedHost],
    current_hosts: &[SavedHost],
    candidate_groups: &[SavedGroupConfig],
    current_groups: &[SavedGroupConfig],
    host_id_remap: &BTreeMap<SavedHostId, SavedHostId>,
    source_sha256: &[u8; 32],
) -> Result<LegacyNotesSnippetsImportPlan, LegacyNotesSnippetsError> {
    let final_host_ids = current_hosts
        .iter()
        .chain(candidate_hosts)
        .map(|host| host.id.clone())
        .collect::<BTreeSet<_>>();
    let host_plan = candidates
        .catalog
        .plan_host_id_remap(host_id_remap, &final_host_ids)
        .map_err(map_catalog_reference_error)?;
    let remapped_snippet_target_count = bounded_u32(host_plan.remapped_snippet_targets());
    let remapped_note_link_count = bounded_u32(host_plan.remapped_note_links());
    let candidate_catalog = host_plan.into_catalog();

    let (snippets, snippet_dispositions, snippet_id_remap) = plan_snippet_ids(
        candidate_catalog.snippets(),
        current_catalog.snippets(),
        source_sha256,
    )?;
    let (notes, note_dispositions, remapped_note_id_count) = plan_note_ids(
        candidate_catalog.notes(),
        current_catalog.notes(),
        source_sha256,
    )?;
    let catalog = rebuild_catalog(&candidate_catalog, snippets, notes)?;

    let mut hosts = Vec::with_capacity(candidate_hosts.len());
    let mut remapped_host_script_edge_count = 0usize;
    for (index, host) in candidate_hosts.iter().enumerate() {
        let (host, changed) = rewrite_host_script_references(host, &snippet_id_remap, index)?;
        remapped_host_script_edge_count = remapped_host_script_edge_count.saturating_add(changed);
        hosts.push(host);
    }
    let mut groups = Vec::with_capacity(candidate_groups.len());
    let mut remapped_group_script_edge_count = 0usize;
    for (index, group) in candidate_groups.iter().enumerate() {
        let (group, changed) = rewrite_group_script_reference(group, &snippet_id_remap, index)?;
        remapped_group_script_edge_count = remapped_group_script_edge_count.saturating_add(changed);
        groups.push(group);
    }

    let available_scripts = build_available_scripts(current_catalog, &catalog);
    if current_catalog.snippets().is_some() || catalog.snippets().is_some() {
        if catalog.snippets().is_some() {
            for (index, host) in current_hosts.iter().enumerate() {
                validate_host_script_references(host, &available_scripts, index)?;
            }
            for (index, group) in current_groups.iter().enumerate() {
                validate_group_script_reference(group, &available_scripts, index)?;
            }
        }
        for (index, host) in hosts.iter().enumerate() {
            validate_host_script_references(host, &available_scripts, index)?;
        }
        for (index, group) in groups.iter().enumerate() {
            validate_group_script_reference(group, &available_scripts, index)?;
        }
    }

    let (importable_snippet_package_count, duplicate_snippet_package_count) = classify_plain_values(
        catalog.snippet_packages(),
        current_catalog.snippet_packages(),
    );
    let (importable_note_group_count, duplicate_note_group_count) =
        classify_plain_values(catalog.note_groups(), current_catalog.note_groups());
    let catalog_scope_change_count = [
        (
            catalog.snippets().is_some(),
            current_catalog.snippets().is_none(),
        ),
        (
            catalog.snippet_packages().is_some(),
            current_catalog.snippet_packages().is_none(),
        ),
        (catalog.notes().is_some(), current_catalog.notes().is_none()),
        (
            catalog.note_groups().is_some(),
            current_catalog.note_groups().is_none(),
        ),
    ]
    .into_iter()
    .filter(|(present, absent)| *present && *absent)
    .count();

    let assessment = LegacyNotesSnippetsAssessment {
        snippets_present: catalog.snippets().is_some(),
        snippet_packages_present: catalog.snippet_packages().is_some(),
        notes_present: catalog.notes().is_some(),
        note_groups_present: catalog.note_groups().is_some(),
        source_snippet_count: candidates.source_snippet_count,
        source_snippet_package_count: candidates.source_snippet_package_count,
        source_note_count: candidates.source_note_count,
        source_note_group_count: candidates.source_note_group_count,
        remapped_snippet_id_count: bounded_u32(snippet_id_remap.len()),
        remapped_note_id_count: bounded_u32(remapped_note_id_count),
        snippet_dispositions,
        note_dispositions,
        importable_snippet_package_count: bounded_u32(importable_snippet_package_count),
        duplicate_snippet_package_count: bounded_u32(duplicate_snippet_package_count),
        importable_note_group_count: bounded_u32(importable_note_group_count),
        duplicate_note_group_count: bounded_u32(duplicate_note_group_count),
        catalog_scope_change_count: bounded_u32(catalog_scope_change_count),
        remapped_snippet_target_count,
        remapped_note_link_count,
        remapped_host_script_edge_count: bounded_u32(remapped_host_script_edge_count),
        remapped_group_script_edge_count: bounded_u32(remapped_group_script_edge_count),
    };

    Ok(LegacyNotesSnippetsImportPlan {
        assessment,
        catalog,
        hosts,
        groups,
    })
}

fn map_catalog_reference_error(error: SavedNotesSnippetsError) -> LegacyNotesSnippetsError {
    match error {
        SavedNotesSnippetsError::MissingHostReference {
            kind,
            record_index,
            reference_index,
        } => LegacyNotesSnippetsError::reference(
            LegacyNotesSnippetsErrorCode::DanglingHostReference,
            match kind {
                SavedHostReferenceKind::SnippetTarget => LegacyNotesSnippetsRecordKind::Snippet,
                SavedHostReferenceKind::NoteLinkedHost => LegacyNotesSnippetsRecordKind::Note,
            },
            record_index,
            Some(reference_index),
        ),
        SavedNotesSnippetsError::InvalidOpaqueId(_) => {
            LegacyNotesSnippetsError::catalog(LegacyNotesSnippetsErrorCode::InvalidHostRemap)
        }
        _ => LegacyNotesSnippetsError::catalog(LegacyNotesSnippetsErrorCode::InvalidCatalog),
    }
}

type SnippetIdPlan = (
    Option<Vec<SavedSnippet>>,
    Vec<LegacyNotesSnippetsDisposition>,
    BTreeMap<String, String>,
);

fn plan_snippet_ids(
    candidates: Option<&[SavedSnippet]>,
    current: Option<&[SavedSnippet]>,
    source_sha256: &[u8; 32],
) -> Result<SnippetIdPlan, LegacyNotesSnippetsError> {
    let Some(candidates) = candidates else {
        return Ok((None, Vec::new(), BTreeMap::new()));
    };
    let current = current.unwrap_or_default();
    let current_by_id = current
        .iter()
        .map(|snippet| (snippet.id().as_str().to_owned(), snippet))
        .collect::<HashMap<_, _>>();
    let source_ids = candidates
        .iter()
        .map(|snippet| snippet.id().as_str().to_owned())
        .collect::<HashSet<_>>();
    let mut assigned = HashSet::new();
    let mut remap = BTreeMap::new();
    let mut dispositions = Vec::with_capacity(candidates.len());
    let mut planned = Vec::with_capacity(candidates.len());

    for (index, candidate) in candidates.iter().enumerate() {
        let original = candidate.id().as_str();
        match current_by_id.get(original) {
            None => {
                assigned.insert(original.to_owned());
                dispositions.push(LegacyNotesSnippetsDisposition::Importable);
                planned.push(candidate.clone());
            }
            Some(existing) if **existing == *candidate => {
                assigned.insert(original.to_owned());
                dispositions.push(LegacyNotesSnippetsDisposition::Duplicate);
                planned.push(candidate.clone());
            }
            Some(_) => {
                let mut seed = original.to_owned();
                let mut accepted = None;
                for _ in 0..MAX_REMAP_ROUNDS {
                    let replacement = derive_id(source_sha256, SNIPPET_DOMAIN, &seed);
                    seed = replacement.clone();
                    if source_ids.contains(&replacement) || assigned.contains(&replacement) {
                        continue;
                    }
                    let id = SavedSnippetId::from_opaque(replacement.clone()).map_err(|_| {
                        LegacyNotesSnippetsError::record(
                            LegacyNotesSnippetsErrorCode::DeterministicRemapExhausted,
                            LegacyNotesSnippetsRecordKind::Snippet,
                            index,
                        )
                    })?;
                    let projected = candidate.clone().with_id(id);
                    match current_by_id.get(&replacement) {
                        None => {
                            accepted = Some((
                                replacement,
                                projected,
                                LegacyNotesSnippetsDisposition::RemappedImportable,
                            ));
                            break;
                        }
                        Some(existing) if **existing == projected => {
                            accepted = Some((
                                replacement,
                                projected,
                                LegacyNotesSnippetsDisposition::RemappedDuplicate,
                            ));
                            break;
                        }
                        Some(_) => {}
                    }
                }
                let Some((replacement, projected, disposition)) = accepted else {
                    return Err(LegacyNotesSnippetsError::record(
                        LegacyNotesSnippetsErrorCode::DeterministicRemapExhausted,
                        LegacyNotesSnippetsRecordKind::Snippet,
                        index,
                    ));
                };
                assigned.insert(replacement.clone());
                remap.insert(original.to_owned(), replacement);
                dispositions.push(disposition);
                planned.push(projected);
            }
        }
    }
    Ok((Some(planned), dispositions, remap))
}

type NoteIdPlan = (
    Option<Vec<SavedVaultNote>>,
    Vec<LegacyNotesSnippetsDisposition>,
    usize,
);

fn plan_note_ids(
    candidates: Option<&[SavedVaultNote]>,
    current: Option<&[SavedVaultNote]>,
    source_sha256: &[u8; 32],
) -> Result<NoteIdPlan, LegacyNotesSnippetsError> {
    let Some(candidates) = candidates else {
        return Ok((None, Vec::new(), 0));
    };
    let current = current.unwrap_or_default();
    let current_by_id = current
        .iter()
        .map(|note| (note.id().as_str().to_owned(), note))
        .collect::<HashMap<_, _>>();
    let source_ids = candidates
        .iter()
        .map(|note| note.id().as_str().to_owned())
        .collect::<HashSet<_>>();
    let mut assigned = HashSet::new();
    let mut remapped = 0usize;
    let mut dispositions = Vec::with_capacity(candidates.len());
    let mut planned = Vec::with_capacity(candidates.len());

    for (index, candidate) in candidates.iter().enumerate() {
        let original = candidate.id().as_str();
        match current_by_id.get(original) {
            None => {
                assigned.insert(original.to_owned());
                dispositions.push(LegacyNotesSnippetsDisposition::Importable);
                planned.push(candidate.clone());
            }
            Some(existing) if **existing == *candidate => {
                assigned.insert(original.to_owned());
                dispositions.push(LegacyNotesSnippetsDisposition::Duplicate);
                planned.push(candidate.clone());
            }
            Some(_) => {
                let mut seed = original.to_owned();
                let mut accepted = None;
                for _ in 0..MAX_REMAP_ROUNDS {
                    let replacement = derive_id(source_sha256, NOTE_DOMAIN, &seed);
                    seed = replacement.clone();
                    if source_ids.contains(&replacement) || assigned.contains(&replacement) {
                        continue;
                    }
                    let id = SavedVaultNoteId::from_opaque(replacement.clone()).map_err(|_| {
                        LegacyNotesSnippetsError::record(
                            LegacyNotesSnippetsErrorCode::DeterministicRemapExhausted,
                            LegacyNotesSnippetsRecordKind::Note,
                            index,
                        )
                    })?;
                    let projected = candidate.clone().with_id(id);
                    match current_by_id.get(&replacement) {
                        None => {
                            accepted = Some((
                                projected,
                                LegacyNotesSnippetsDisposition::RemappedImportable,
                            ));
                            break;
                        }
                        Some(existing) if **existing == projected => {
                            accepted = Some((
                                projected,
                                LegacyNotesSnippetsDisposition::RemappedDuplicate,
                            ));
                            break;
                        }
                        Some(_) => {}
                    }
                }
                let Some((projected, disposition)) = accepted else {
                    return Err(LegacyNotesSnippetsError::record(
                        LegacyNotesSnippetsErrorCode::DeterministicRemapExhausted,
                        LegacyNotesSnippetsRecordKind::Note,
                        index,
                    ));
                };
                assigned.insert(projected.id().as_str().to_owned());
                remapped = remapped.saturating_add(1);
                dispositions.push(disposition);
                planned.push(projected);
            }
        }
    }
    Ok((Some(planned), dispositions, remapped))
}

fn rebuild_catalog(
    source: &SavedNotesSnippetsCatalog,
    snippets: Option<Vec<SavedSnippet>>,
    notes: Option<Vec<SavedVaultNote>>,
) -> Result<SavedNotesSnippetsCatalog, LegacyNotesSnippetsError> {
    SavedNotesSnippetsCatalog::from_parts(
        snippets,
        source.snippet_packages().map(<[String]>::to_vec),
        notes,
        source.note_groups().map(|groups| {
            groups
                .iter()
                .map(|group| group.as_str().to_owned())
                .collect()
        }),
    )
    .map_err(|_| LegacyNotesSnippetsError::catalog(LegacyNotesSnippetsErrorCode::InvalidCatalog))
}

fn rewrite_host_script_references(
    host: &SavedHost,
    remap: &BTreeMap<String, String>,
    record_index: usize,
) -> Result<(SavedHost, usize), LegacyNotesSnippetsError> {
    if remap.is_empty() {
        return Ok((host.clone(), 0));
    }
    let mut value = serde_json::to_value(host).map_err(|_| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidHostScriptEdge,
            LegacyNotesSnippetsRecordKind::Host,
            record_index,
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidHostScriptEdge,
            LegacyNotesSnippetsRecordKind::Host,
            record_index,
        )
    })?;
    let mut changed = 0usize;

    if let Some(value) = object.get_mut("loginScriptId") {
        match value {
            Value::Null => {}
            Value::String(id) => {
                if let Some(replacement) = remap.get(id) {
                    *id = replacement.clone();
                    changed = changed.saturating_add(1);
                }
            }
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }
    if let Some(value) = object.get_mut("connectScriptIds") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for (reference_index, value) in values.iter_mut().enumerate() {
                    let Value::String(id) = value else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    if let Some(replacement) = remap.get(id) {
                        *id = replacement.clone();
                        changed = changed.saturating_add(1);
                    }
                }
            }
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }
    if let Some(value) = object.get_mut("outputTriggers") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for (reference_index, value) in values.iter_mut().enumerate() {
                    let Value::Object(trigger) = value else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    let Some(Value::String(id)) = trigger.get_mut("scriptId") else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    if let Some(replacement) = remap.get(id) {
                        *id = replacement.clone();
                        changed = changed.saturating_add(1);
                    }
                }
            }
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }

    let host = serde_json::from_value(value).map_err(|_| invalid_host_edge(record_index, None))?;
    Ok((host, changed))
}

fn rewrite_group_script_reference(
    group: &SavedGroupConfig,
    remap: &BTreeMap<String, String>,
    record_index: usize,
) -> Result<(SavedGroupConfig, usize), LegacyNotesSnippetsError> {
    let SavedGroupOverride::Set(id) = &group.defaults.login_script_id else {
        return Ok((group.clone(), 0));
    };
    let Some(replacement) = remap.get(id.as_str()) else {
        return Ok((group.clone(), 0));
    };
    let replacement = SavedGroupOpaqueId::from_opaque(replacement.clone()).map_err(|_| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidGroupScriptEdge,
            LegacyNotesSnippetsRecordKind::Group,
            record_index,
        )
    })?;
    let mut group = group.clone();
    group.defaults.login_script_id = SavedGroupOverride::Set(replacement);
    group.validate().map_err(|_| {
        LegacyNotesSnippetsError::record(
            LegacyNotesSnippetsErrorCode::InvalidGroupScriptEdge,
            LegacyNotesSnippetsRecordKind::Group,
            record_index,
        )
    })?;
    Ok((group, 1))
}

fn invalid_host_edge(
    record_index: usize,
    reference_index: Option<usize>,
) -> LegacyNotesSnippetsError {
    LegacyNotesSnippetsError::reference(
        LegacyNotesSnippetsErrorCode::InvalidHostScriptEdge,
        LegacyNotesSnippetsRecordKind::Host,
        record_index,
        reference_index,
    )
}

fn build_available_scripts(
    current: &SavedNotesSnippetsCatalog,
    candidates: &SavedNotesSnippetsCatalog,
) -> HashMap<String, Option<SavedSnippetKind>> {
    let mut scripts = HashMap::new();
    for snippet in current.snippets().unwrap_or_default() {
        scripts.insert(snippet.id().as_str().to_owned(), snippet.kind());
    }
    for snippet in candidates.snippets().unwrap_or_default() {
        scripts
            .entry(snippet.id().as_str().to_owned())
            .or_insert(snippet.kind());
    }
    scripts
}

fn validate_host_script_references(
    host: &SavedHost,
    scripts: &HashMap<String, Option<SavedSnippetKind>>,
    record_index: usize,
) -> Result<(), LegacyNotesSnippetsError> {
    let fields = host.compatibility_fields();
    if let Some(value) = fields.get("loginScriptId") {
        match value {
            Value::Null => {}
            Value::String(id) if id.is_empty() => {}
            Value::String(id) => validate_script_id(
                id,
                scripts,
                LegacyNotesSnippetsRecordKind::Host,
                record_index,
                None,
            )?,
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }
    if let Some(value) = fields.get("connectScriptIds") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for (reference_index, value) in values.iter().enumerate() {
                    let Value::String(id) = value else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    if id.is_empty() {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    }
                    validate_script_id(
                        id,
                        scripts,
                        LegacyNotesSnippetsRecordKind::Host,
                        record_index,
                        Some(reference_index),
                    )?;
                }
            }
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }
    if let Some(value) = fields.get("outputTriggers") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for (reference_index, value) in values.iter().enumerate() {
                    let Value::Object(trigger) = value else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    let Some(Value::String(id)) = trigger.get("scriptId") else {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    };
                    if id.is_empty() {
                        return Err(invalid_host_edge(record_index, Some(reference_index)));
                    }
                    validate_script_id(
                        id,
                        scripts,
                        LegacyNotesSnippetsRecordKind::Host,
                        record_index,
                        Some(reference_index),
                    )?;
                }
            }
            _ => return Err(invalid_host_edge(record_index, None)),
        }
    }
    Ok(())
}

fn validate_group_script_reference(
    group: &SavedGroupConfig,
    scripts: &HashMap<String, Option<SavedSnippetKind>>,
    record_index: usize,
) -> Result<(), LegacyNotesSnippetsError> {
    if let SavedGroupOverride::Set(id) = &group.defaults.login_script_id {
        validate_script_id(
            id.as_str(),
            scripts,
            LegacyNotesSnippetsRecordKind::Group,
            record_index,
            None,
        )?;
    }
    Ok(())
}

fn validate_script_id(
    id: &str,
    scripts: &HashMap<String, Option<SavedSnippetKind>>,
    record_kind: LegacyNotesSnippetsRecordKind,
    record_index: usize,
    reference_index: Option<usize>,
) -> Result<(), LegacyNotesSnippetsError> {
    match scripts.get(id) {
        None => Err(LegacyNotesSnippetsError::reference(
            LegacyNotesSnippetsErrorCode::DanglingScriptReference,
            record_kind,
            record_index,
            reference_index,
        )),
        Some(Some(SavedSnippetKind::Script)) => Ok(()),
        Some(_) => Err(LegacyNotesSnippetsError::reference(
            LegacyNotesSnippetsErrorCode::IncompatibleScriptReference,
            record_kind,
            record_index,
            reference_index,
        )),
    }
}

fn classify_plain_values<T: Eq>(candidates: Option<&[T]>, current: Option<&[T]>) -> (usize, usize) {
    let Some(candidates) = candidates else {
        return (0, 0);
    };
    let current = current.unwrap_or_default();
    candidates
        .iter()
        .fold((0usize, 0usize), |(importable, duplicate), value| {
            if current.contains(value) {
                (importable, duplicate.saturating_add(1))
            } else {
                (importable.saturating_add(1), duplicate)
            }
        })
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

fn bounded_u32(value: usize) -> u32 {
    value.min(u32::MAX as usize) as u32
}
