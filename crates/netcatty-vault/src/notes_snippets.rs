use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::model::SavedHostId;

/// Matches the independently bounded legacy catalog size used by migration.
pub const MAX_NOTES_SNIPPETS_CATALOG_ENTITIES: usize = 10_000;
/// Bounds every legacy string-array field before it can become catalog state.
pub const MAX_NOTES_SNIPPETS_LIST_VALUES: usize = 10_000;

const MAX_OPAQUE_ID_BYTES: usize = 512;
const MAX_SMALL_TEXT_BYTES: usize = 32 * 1_024;
const MAX_FREEFORM_TEXT_BYTES: usize = 25 * 1_024 * 1_024;
const MAX_CATALOG_TEXT_BYTES: usize = 25 * 1_024 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedNotesSnippetsEntityKind {
    Snippet,
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedHostReferenceKind {
    SnippetTarget,
    NoteLinkedHost,
}

/// Secret-safe validation errors. They identify only a field or stable array
/// position and never echo note text, commands, labels, paths, or opaque IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedNotesSnippetsError {
    MissingField(&'static str),
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    InvalidOpaqueId(&'static str),
    InvalidFiniteNumber(&'static str),
    TooManyValues {
        field: &'static str,
        max: usize,
    },
    TooManyEntities {
        kind: SavedNotesSnippetsEntityKind,
        max: usize,
    },
    DuplicateEntityId {
        kind: SavedNotesSnippetsEntityKind,
        record_index: usize,
    },
    MissingHostReference {
        kind: SavedHostReferenceKind,
        record_index: usize,
        reference_index: usize,
    },
    CatalogTextTooLarge {
        max_bytes: usize,
    },
}

impl fmt::Display for SavedNotesSnippetsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(formatter, "{field} is required"),
            Self::TooLong { field, max_bytes } => {
                write!(formatter, "{field} exceeds {max_bytes} UTF-8 bytes")
            }
            Self::InvalidOpaqueId(field) => write!(formatter, "{field} is invalid"),
            Self::InvalidFiniteNumber(field) => {
                write!(formatter, "{field} must be a finite number")
            }
            Self::TooManyValues { field, max } => {
                write!(formatter, "{field} contains more than {max} values")
            }
            Self::TooManyEntities { kind, max } => {
                write!(
                    formatter,
                    "{kind:?} catalog contains more than {max} records"
                )
            }
            Self::DuplicateEntityId { kind, record_index } => write!(
                formatter,
                "{kind:?} catalog record {record_index} duplicates an earlier ID"
            ),
            Self::MissingHostReference {
                kind,
                record_index,
                reference_index,
            } => write!(
                formatter,
                "{kind:?} at record {record_index}, reference {reference_index} points to a missing host"
            ),
            Self::CatalogTextTooLarge { max_bytes } => write!(
                formatter,
                "notes/snippets catalog text exceeds {max_bytes} UTF-8 bytes"
            ),
        }
    }
}

impl std::error::Error for SavedNotesSnippetsError {}

macro_rules! saved_opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            pub fn from_opaque(value: impl Into<String>) -> Result<Self, SavedNotesSnippetsError> {
                let value = value.into();
                validate_opaque_id($field, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::from_opaque(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

saved_opaque_id!(SavedSnippetId, "snippet ID");
saved_opaque_id!(SavedVaultNoteId, "note ID");

/// Canonical Notes-domain group path.
///
/// This follows `cleanNoteGroupPath`: split only on `/`, trim each segment,
/// remove empty segments, and retain backslashes and literal `.`/`..` labels.
/// It is intentionally not interchangeable with either [`SavedSnippetTargetGroupPath`]
/// or the host/custom-group `SavedGroupPath` type.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedNoteGroupPath(String);

impl SavedNoteGroupPath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, SavedNotesSnippetsError> {
        let normalized = normalize_note_group_path(value.as_ref());
        if normalized.is_empty() {
            return Err(SavedNotesSnippetsError::MissingField("note group"));
        }
        validate_text("note group", &normalized, MAX_SMALL_TEXT_BYTES)?;
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn ancestors(&self) -> Vec<Self> {
        let mut current = String::new();
        self.0
            .split('/')
            .map(|segment| {
                if !current.is_empty() {
                    current.push('/');
                }
                current.push_str(segment);
                Self(current.clone())
            })
            .collect()
    }
}

impl fmt::Debug for SavedNoteGroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedNoteGroupPath([redacted])")
    }
}

impl Serialize for SavedNoteGroupPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedNoteGroupPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Canonical group target used only by snippets.
///
/// The legacy helper first converts every `\` to `/`, then trims segments and
/// removes empty ones. Keeping this in a separate type prevents accidental use
/// of the host/custom-group or Notes normalizers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedSnippetTargetGroupPath(String);

impl SavedSnippetTargetGroupPath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, SavedNotesSnippetsError> {
        let normalized = normalize_snippet_target_group_path(value.as_ref());
        if normalized.is_empty() {
            return Err(SavedNotesSnippetsError::MissingField(
                "snippet target group",
            ));
        }
        validate_text("snippet target group", &normalized, MAX_SMALL_TEXT_BYTES)?;
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedSnippetTargetGroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedSnippetTargetGroupPath([redacted])")
    }
}

impl Serialize for SavedSnippetTargetGroupPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedSnippetTargetGroupPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

pub fn normalize_note_group_path(value: &str) -> String {
    value
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn normalize_snippet_target_group_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn normalize_note_groups<I, S>(
    values: I,
) -> Result<Vec<SavedNoteGroupPath>, SavedNotesSnippetsError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    normalize_group_values(values, SavedNoteGroupPath::new, normalize_note_group_path)
}

pub fn normalize_snippet_target_groups<I, S>(
    values: I,
) -> Result<Vec<SavedSnippetTargetGroupPath>, SavedNotesSnippetsError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    normalize_group_values(
        values,
        SavedSnippetTargetGroupPath::new,
        normalize_snippet_target_group_path,
    )
}

fn normalize_group_values<I, S, P, N, C>(
    values: I,
    create: C,
    normalize: N,
) -> Result<Vec<P>, SavedNotesSnippetsError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    P: Clone + Ord,
    N: Fn(&str) -> String,
    C: Fn(String) -> Result<P, SavedNotesSnippetsError>,
{
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, value) in values.into_iter().enumerate() {
        if index >= MAX_NOTES_SNIPPETS_LIST_VALUES {
            return Err(SavedNotesSnippetsError::TooManyValues {
                field: "group paths",
                max: MAX_NOTES_SNIPPETS_LIST_VALUES,
            });
        }
        let normalized = normalize(value.as_ref());
        if normalized.is_empty() {
            continue;
        }
        let path = create(normalized)?;
        if seen.insert(path.clone()) {
            result.push(path);
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedSnippetKind {
    #[serde(rename = "snippet")]
    Snippet,
    #[serde(rename = "script")]
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedSnippetMultiLineRunMode {
    #[serde(rename = "lineDelay")]
    LineDelay,
    #[serde(rename = "paste")]
    Paste,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedScriptLanguage {
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "python")]
    Python,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedScriptTrigger {
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "onConnect")]
    OnConnect,
    #[serde(rename = "onOutput")]
    OnOutput,
}

/// Construction input for one persisted legacy-compatible snippet.
///
/// `target_groups: None` and `target_groups: Some(vec![])` remain distinct:
/// the old on-output and terminal applicability helpers give them different
/// meaning. No running/execution status belongs in this draft or saved model.
#[derive(Clone, PartialEq)]
pub struct SavedSnippetDraft {
    pub id: String,
    pub label: String,
    pub command: String,
    pub tags: Option<Vec<String>>,
    pub package: Option<String>,
    pub targets: Option<Vec<String>>,
    pub target_groups: Option<Vec<String>>,
    pub targets_all_hosts: Option<bool>,
    pub shortkey: Option<String>,
    pub no_auto_run: Option<bool>,
    pub multi_line_run_mode: Option<SavedSnippetMultiLineRunMode>,
    pub order: Option<f64>,
    pub kind: Option<SavedSnippetKind>,
    pub language: Option<SavedScriptLanguage>,
    pub description: Option<String>,
    pub trigger: Option<SavedScriptTrigger>,
    pub trigger_pattern: Option<String>,
}

impl SavedSnippetDraft {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            command: command.into(),
            tags: None,
            package: None,
            targets: None,
            target_groups: None,
            targets_all_hosts: None,
            shortkey: None,
            no_auto_run: None,
            multi_line_run_mode: None,
            order: None,
            kind: None,
            language: None,
            description: None,
            trigger: None,
            trigger_pattern: None,
        }
    }
}

impl fmt::Debug for SavedSnippetDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedSnippetDraft")
            .field("id", &"[redacted]")
            .field("label", &"[redacted]")
            .field("command", &"[redacted]")
            .field("tag_count", &self.tags.as_ref().map(Vec::len))
            .field("target_count", &self.targets.as_ref().map(Vec::len))
            .field(
                "target_group_count",
                &self.target_groups.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedSnippet {
    id: SavedSnippetId,
    label: String,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    targets: Option<Vec<SavedHostId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_groups: Option<Vec<SavedSnippetTargetGroupPath>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    targets_all_hosts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shortkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_auto_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multi_line_run_mode: Option<SavedSnippetMultiLineRunMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    order: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<SavedSnippetKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<SavedScriptLanguage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger: Option<SavedScriptTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger_pattern: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedSnippetWire {
    id: String,
    label: String,
    command: String,
    tags: Option<Vec<String>>,
    package: Option<String>,
    targets: Option<Vec<String>>,
    target_groups: Option<Vec<String>>,
    targets_all_hosts: Option<bool>,
    shortkey: Option<String>,
    no_auto_run: Option<bool>,
    multi_line_run_mode: Option<SavedSnippetMultiLineRunMode>,
    order: Option<f64>,
    kind: Option<SavedSnippetKind>,
    language: Option<SavedScriptLanguage>,
    description: Option<String>,
    trigger: Option<SavedScriptTrigger>,
    trigger_pattern: Option<String>,
}

impl<'de> Deserialize<'de> for SavedSnippet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedSnippetWire::deserialize(deserializer)?;
        Self::from_draft(SavedSnippetDraft {
            id: wire.id,
            label: wire.label,
            command: wire.command,
            tags: wire.tags,
            package: wire.package,
            targets: wire.targets,
            target_groups: wire.target_groups,
            targets_all_hosts: wire.targets_all_hosts,
            shortkey: wire.shortkey,
            no_auto_run: wire.no_auto_run,
            multi_line_run_mode: wire.multi_line_run_mode,
            order: wire.order,
            kind: wire.kind,
            language: wire.language,
            description: wire.description,
            trigger: wire.trigger,
            trigger_pattern: wire.trigger_pattern,
        })
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SavedSnippet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedSnippet")
            .field("id", &"[redacted]")
            .field("label", &"[redacted]")
            .field("command", &"[redacted]")
            .field("tag_count", &self.tags.as_ref().map(Vec::len))
            .field("target_count", &self.targets.as_ref().map(Vec::len))
            .field(
                "target_group_count",
                &self.target_groups.as_ref().map(Vec::len),
            )
            .field("targets_all_hosts", &self.targets_all_hosts)
            .field("kind", &self.kind)
            .field("language", &self.language)
            .field("trigger", &self.trigger)
            .finish_non_exhaustive()
    }
}

impl SavedSnippet {
    pub fn from_draft(draft: SavedSnippetDraft) -> Result<Self, SavedNotesSnippetsError> {
        let id = SavedSnippetId::from_opaque(draft.id)?;
        validate_text("snippet label", &draft.label, MAX_SMALL_TEXT_BYTES)?;
        validate_text("snippet command", &draft.command, MAX_FREEFORM_TEXT_BYTES)?;
        validate_optional_text(
            "snippet package",
            draft.package.as_deref(),
            MAX_SMALL_TEXT_BYTES,
        )?;
        validate_optional_text(
            "snippet shortkey",
            draft.shortkey.as_deref(),
            MAX_SMALL_TEXT_BYTES,
        )?;
        validate_optional_text(
            "snippet description",
            draft.description.as_deref(),
            MAX_FREEFORM_TEXT_BYTES,
        )?;
        validate_optional_text(
            "snippet trigger pattern",
            draft.trigger_pattern.as_deref(),
            MAX_SMALL_TEXT_BYTES,
        )?;
        validate_string_values("snippet tags", draft.tags.as_deref())?;
        validate_finite("snippet order", draft.order)?;

        let targets = normalize_host_ids("snippet targets", draft.targets, false)?;
        let target_groups = match draft.target_groups {
            Some(values) => Some(normalize_snippet_target_groups(values)?),
            None => None,
        };

        Ok(Self {
            id,
            label: draft.label,
            command: draft.command,
            tags: draft.tags,
            package: draft.package,
            targets,
            target_groups,
            targets_all_hosts: draft.targets_all_hosts,
            shortkey: draft.shortkey,
            no_auto_run: draft.no_auto_run,
            multi_line_run_mode: draft.multi_line_run_mode,
            order: draft.order,
            kind: draft.kind,
            language: draft.language,
            description: draft.description,
            trigger: draft.trigger,
            trigger_pattern: draft.trigger_pattern,
        })
    }

    pub fn id(&self) -> &SavedSnippetId {
        &self.id
    }

    /// Returns the same validated snippet under a different validated opaque
    /// ID. Migration planners use this pure operation before atomically
    /// rewriting every inbound script reference.
    pub fn with_id(mut self, id: SavedSnippetId) -> Self {
        self.id = id;
        self
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn tags(&self) -> Option<&[String]> {
        self.tags.as_deref()
    }

    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }

    pub fn targets(&self) -> Option<&[SavedHostId]> {
        self.targets.as_deref()
    }

    pub fn target_groups(&self) -> Option<&[SavedSnippetTargetGroupPath]> {
        self.target_groups.as_deref()
    }

    pub fn targets_all_hosts(&self) -> Option<bool> {
        self.targets_all_hosts
    }

    pub fn shortkey(&self) -> Option<&str> {
        self.shortkey.as_deref()
    }

    pub fn no_auto_run(&self) -> Option<bool> {
        self.no_auto_run
    }

    pub fn multi_line_run_mode(&self) -> Option<SavedSnippetMultiLineRunMode> {
        self.multi_line_run_mode
    }

    pub fn order(&self) -> Option<f64> {
        self.order
    }

    pub fn kind(&self) -> Option<SavedSnippetKind> {
        self.kind
    }

    pub fn language(&self) -> Option<SavedScriptLanguage> {
        self.language
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn trigger(&self) -> Option<SavedScriptTrigger> {
        self.trigger
    }

    pub fn trigger_pattern(&self) -> Option<&str> {
        self.trigger_pattern.as_deref()
    }
}

/// Construction input for one persisted legacy-compatible Vault note.
#[derive(Clone, PartialEq)]
pub struct SavedVaultNoteDraft {
    pub id: String,
    pub title: String,
    pub content: String,
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
    pub linked_host_ids: Option<Vec<String>>,
    pub created_at: f64,
    pub updated_at: f64,
    pub order: Option<f64>,
}

impl SavedVaultNoteDraft {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        content: impl Into<String>,
        created_at: f64,
        updated_at: f64,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            content: content.into(),
            group: None,
            tags: None,
            linked_host_ids: None,
            created_at,
            updated_at,
            order: None,
        }
    }
}

impl fmt::Debug for SavedVaultNoteDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedVaultNoteDraft")
            .field("id", &"[redacted]")
            .field("title", &"[redacted]")
            .field("content", &"[redacted]")
            .field("tag_count", &self.tags.as_ref().map(Vec::len))
            .field(
                "linked_host_count",
                &self.linked_host_ids.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedVaultNote {
    id: SavedVaultNoteId,
    title: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<SavedNoteGroupPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    linked_host_ids: Option<Vec<SavedHostId>>,
    created_at: f64,
    updated_at: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    order: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedVaultNoteWire {
    id: String,
    title: String,
    content: String,
    group: Option<String>,
    tags: Option<Vec<String>>,
    linked_host_ids: Option<Vec<String>>,
    created_at: f64,
    updated_at: f64,
    order: Option<f64>,
}

impl<'de> Deserialize<'de> for SavedVaultNote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedVaultNoteWire::deserialize(deserializer)?;
        Self::from_draft(SavedVaultNoteDraft {
            id: wire.id,
            title: wire.title,
            content: wire.content,
            group: wire.group,
            tags: wire.tags,
            linked_host_ids: wire.linked_host_ids,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            order: wire.order,
        })
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SavedVaultNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedVaultNote")
            .field("id", &"[redacted]")
            .field("title", &"[redacted]")
            .field("content", &"[redacted]")
            .field("has_group", &self.group.is_some())
            .field("tag_count", &self.tags.as_ref().map(Vec::len))
            .field(
                "linked_host_count",
                &self.linked_host_ids.as_ref().map(Vec::len),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("order", &self.order)
            .finish()
    }
}

impl SavedVaultNote {
    pub fn from_draft(draft: SavedVaultNoteDraft) -> Result<Self, SavedNotesSnippetsError> {
        let id = SavedVaultNoteId::from_opaque(draft.id)?;
        let title = draft.title.trim().to_owned();
        validate_text("note title", &title, MAX_SMALL_TEXT_BYTES)?;
        validate_text("note content", &draft.content, MAX_FREEFORM_TEXT_BYTES)?;
        validate_finite("note createdAt", Some(draft.created_at))?;
        validate_finite("note updatedAt", Some(draft.updated_at))?;
        validate_finite("note order", draft.order)?;

        let group = match draft.group {
            Some(value) if !normalize_note_group_path(&value).is_empty() => {
                Some(SavedNoteGroupPath::new(value)?)
            }
            _ => None,
        };
        let tags = clean_note_string_values("note tags", draft.tags)?;
        let linked_host_ids = normalize_host_ids(
            "note linkedHostIds",
            clean_note_string_values("note linkedHostIds", draft.linked_host_ids)?,
            false,
        )?;

        Ok(Self {
            id,
            title,
            content: draft.content,
            group,
            tags,
            linked_host_ids,
            created_at: draft.created_at,
            updated_at: draft.updated_at,
            order: draft.order,
        })
    }

    pub fn id(&self) -> &SavedVaultNoteId {
        &self.id
    }

    /// Returns the same validated note under a different validated opaque ID.
    /// Notes have no inbound Vault edges, but deterministic migration remaps
    /// still need a typed way to avoid rebuilding free-form content through
    /// an intermediate JSON value.
    pub fn with_id(mut self, id: SavedVaultNoteId) -> Self {
        self.id = id;
        self
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn group(&self) -> Option<&SavedNoteGroupPath> {
        self.group.as_ref()
    }

    pub fn tags(&self) -> Option<&[String]> {
        self.tags.as_deref()
    }

    pub fn linked_host_ids(&self) -> Option<&[SavedHostId]> {
        self.linked_host_ids.as_deref()
    }

    pub fn created_at(&self) -> f64 {
        self.created_at
    }

    pub fn updated_at(&self) -> f64 {
        self.updated_at
    }

    pub fn order(&self) -> Option<f64> {
        self.order
    }
}

/// Host-independent Notes + Snippets catalog boundary.
///
/// This deliberately is not a Vault snapshot/store graph. It has no revision,
/// active/running phase, session handle, last error, or renderer DTO. Optional
/// top-level catalogs preserve the legacy distinction between an absent field
/// and a supplied empty catalog for later import planning.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedNotesSnippetsCatalog {
    #[serde(skip_serializing_if = "Option::is_none")]
    snippets: Option<Vec<SavedSnippet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet_packages: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<Vec<SavedVaultNote>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note_groups: Option<Vec<SavedNoteGroupPath>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedNotesSnippetsCatalogWire {
    snippets: Option<Vec<SavedSnippet>>,
    snippet_packages: Option<Vec<String>>,
    notes: Option<Vec<SavedVaultNote>>,
    note_groups: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for SavedNotesSnippetsCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedNotesSnippetsCatalogWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.snippets,
            wire.snippet_packages,
            wire.notes,
            wire.note_groups,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SavedNotesSnippetsCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedNotesSnippetsCatalog")
            .field("snippet_count", &self.snippets.as_ref().map(Vec::len))
            .field(
                "snippet_package_count",
                &self.snippet_packages.as_ref().map(Vec::len),
            )
            .field("note_count", &self.notes.as_ref().map(Vec::len))
            .field("note_group_count", &self.note_groups.as_ref().map(Vec::len))
            .finish()
    }
}

impl Default for SavedNotesSnippetsCatalog {
    fn default() -> Self {
        Self {
            snippets: None,
            snippet_packages: None,
            notes: None,
            note_groups: None,
        }
    }
}

impl SavedNotesSnippetsCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_parts(
        snippets: Option<Vec<SavedSnippet>>,
        snippet_packages: Option<Vec<String>>,
        notes: Option<Vec<SavedVaultNote>>,
        note_groups: Option<Vec<String>>,
    ) -> Result<Self, SavedNotesSnippetsError> {
        let note_groups = match note_groups {
            Some(groups) => Some(normalize_note_groups(groups)?),
            None => None,
        };
        Self::from_normalized_parts(snippets, snippet_packages, notes, note_groups)
    }

    pub(crate) fn from_normalized_parts(
        snippets: Option<Vec<SavedSnippet>>,
        snippet_packages: Option<Vec<String>>,
        notes: Option<Vec<SavedVaultNote>>,
        note_groups: Option<Vec<SavedNoteGroupPath>>,
    ) -> Result<Self, SavedNotesSnippetsError> {
        validate_entity_count(SavedNotesSnippetsEntityKind::Snippet, snippets.as_deref())?;
        validate_entity_count(SavedNotesSnippetsEntityKind::Note, notes.as_deref())?;
        validate_unique_snippet_ids(snippets.as_deref())?;
        validate_unique_note_ids(notes.as_deref())?;
        let snippet_packages = normalize_plain_catalog_values("snippetPackages", snippet_packages)?;
        if note_groups
            .as_ref()
            .is_some_and(|groups| groups.len() > MAX_NOTES_SNIPPETS_LIST_VALUES)
        {
            return Err(SavedNotesSnippetsError::TooManyValues {
                field: "noteGroups",
                max: MAX_NOTES_SNIPPETS_LIST_VALUES,
            });
        }
        let catalog = Self {
            snippets,
            snippet_packages,
            notes,
            note_groups,
        };
        catalog.validate_catalog_text_bound()?;
        Ok(catalog)
    }

    pub fn is_absent(&self) -> bool {
        self.snippets.is_none()
            && self.snippet_packages.is_none()
            && self.notes.is_none()
            && self.note_groups.is_none()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<Vec<SavedSnippet>>,
        Option<Vec<String>>,
        Option<Vec<SavedVaultNote>>,
        Option<Vec<SavedNoteGroupPath>>,
    ) {
        (
            self.snippets,
            self.snippet_packages,
            self.notes,
            self.note_groups,
        )
    }

    pub fn snippets(&self) -> Option<&[SavedSnippet]> {
        self.snippets.as_deref()
    }

    pub fn snippet_packages(&self) -> Option<&[String]> {
        self.snippet_packages.as_deref()
    }

    pub fn notes(&self) -> Option<&[SavedVaultNote]> {
        self.notes.as_deref()
    }

    pub fn note_groups(&self) -> Option<&[SavedNoteGroupPath]> {
        self.note_groups.as_deref()
    }

    /// Validates every explicit host edge without treating dynamic target
    /// groups as host-ID edges. Even references shadowed by `targetsAllHosts`
    /// are checked so a future mode change cannot reveal a dangling edge.
    pub fn validate_host_references(
        &self,
        final_host_ids: &BTreeSet<SavedHostId>,
    ) -> Result<(), SavedNotesSnippetsError> {
        validate_host_id_set(final_host_ids)?;
        validate_catalog_host_references(self, final_host_ids)
    }

    /// Produces a deterministic, non-mutating host-reference rewrite plan.
    ///
    /// Each source ID is rewritten exactly once to its final mapping (mapping
    /// chains are not followed). Remap collisions are de-duplicated in stable
    /// first-seen order. The complete projected catalog is validated against
    /// `final_host_ids` before the plan is returned, so callers cannot obtain a
    /// partially remapped result.
    pub fn plan_host_id_remap(
        &self,
        host_id_remap: &BTreeMap<SavedHostId, SavedHostId>,
        final_host_ids: &BTreeSet<SavedHostId>,
    ) -> Result<SavedNotesSnippetsHostRemapPlan, SavedNotesSnippetsError> {
        validate_host_id_map(host_id_remap)?;
        validate_host_id_set(final_host_ids)?;

        let mut projected = self.clone();
        let mut remapped_snippet_targets = 0usize;
        let mut remapped_note_links = 0usize;

        if let Some(snippets) = &mut projected.snippets {
            for snippet in snippets {
                if let Some(targets) = &mut snippet.targets {
                    let (next, changed) = remap_host_ids(targets, host_id_remap);
                    *targets = next;
                    remapped_snippet_targets += changed;
                }
            }
        }
        if let Some(notes) = &mut projected.notes {
            for note in notes {
                if let Some(linked_host_ids) = &mut note.linked_host_ids {
                    let (next, changed) = remap_host_ids(linked_host_ids, host_id_remap);
                    *linked_host_ids = next;
                    remapped_note_links += changed;
                }
            }
        }

        validate_catalog_host_references(&projected, final_host_ids)?;
        Ok(SavedNotesSnippetsHostRemapPlan {
            catalog: projected,
            remapped_snippet_targets,
            remapped_note_links,
        })
    }

    fn validate_catalog_text_bound(&self) -> Result<(), SavedNotesSnippetsError> {
        let mut total = 0usize;
        if let Some(snippets) = &self.snippets {
            for snippet in snippets {
                add_text_bytes(&mut total, snippet.id.as_str())?;
                add_text_bytes(&mut total, &snippet.label)?;
                add_text_bytes(&mut total, &snippet.command)?;
                add_optional_values_bytes(&mut total, snippet.tags.as_deref())?;
                add_optional_text_bytes(&mut total, snippet.package.as_deref())?;
                add_host_id_bytes(&mut total, snippet.targets.as_deref())?;
                if let Some(groups) = &snippet.target_groups {
                    for group in groups {
                        add_text_bytes(&mut total, group.as_str())?;
                    }
                }
                add_optional_text_bytes(&mut total, snippet.shortkey.as_deref())?;
                add_optional_text_bytes(&mut total, snippet.description.as_deref())?;
                add_optional_text_bytes(&mut total, snippet.trigger_pattern.as_deref())?;
            }
        }
        add_optional_values_bytes(&mut total, self.snippet_packages.as_deref())?;
        if let Some(notes) = &self.notes {
            for note in notes {
                add_text_bytes(&mut total, note.id.as_str())?;
                add_text_bytes(&mut total, &note.title)?;
                add_text_bytes(&mut total, &note.content)?;
                if let Some(group) = &note.group {
                    add_text_bytes(&mut total, group.as_str())?;
                }
                add_optional_values_bytes(&mut total, note.tags.as_deref())?;
                add_host_id_bytes(&mut total, note.linked_host_ids.as_deref())?;
            }
        }
        if let Some(groups) = &self.note_groups {
            for group in groups {
                add_text_bytes(&mut total, group.as_str())?;
            }
        }
        Ok(())
    }
}

/// A fully validated projection only; it has no publication or runtime state.
#[derive(Clone, PartialEq)]
pub struct SavedNotesSnippetsHostRemapPlan {
    catalog: SavedNotesSnippetsCatalog,
    remapped_snippet_targets: usize,
    remapped_note_links: usize,
}

impl fmt::Debug for SavedNotesSnippetsHostRemapPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedNotesSnippetsHostRemapPlan")
            .field("catalog", &self.catalog)
            .field("remapped_snippet_targets", &self.remapped_snippet_targets)
            .field("remapped_note_links", &self.remapped_note_links)
            .finish()
    }
}

impl SavedNotesSnippetsHostRemapPlan {
    pub fn catalog(&self) -> &SavedNotesSnippetsCatalog {
        &self.catalog
    }

    pub fn remapped_snippet_targets(&self) -> usize {
        self.remapped_snippet_targets
    }

    pub fn remapped_note_links(&self) -> usize {
        self.remapped_note_links
    }

    pub fn into_catalog(self) -> SavedNotesSnippetsCatalog {
        self.catalog
    }
}

fn validate_opaque_id(field: &'static str, value: &str) -> Result<(), SavedNotesSnippetsError> {
    if value.is_empty() || value.len() > MAX_OPAQUE_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(SavedNotesSnippetsError::InvalidOpaqueId(field));
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), SavedNotesSnippetsError> {
    if value.len() > max_bytes {
        return Err(SavedNotesSnippetsError::TooLong { field, max_bytes });
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), SavedNotesSnippetsError> {
    if let Some(value) = value {
        validate_text(field, value, max_bytes)?;
    }
    Ok(())
}

fn validate_finite(field: &'static str, value: Option<f64>) -> Result<(), SavedNotesSnippetsError> {
    if value.is_some_and(|value| !value.is_finite()) {
        return Err(SavedNotesSnippetsError::InvalidFiniteNumber(field));
    }
    Ok(())
}

fn validate_string_values(
    field: &'static str,
    values: Option<&[String]>,
) -> Result<(), SavedNotesSnippetsError> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES {
        return Err(SavedNotesSnippetsError::TooManyValues {
            field,
            max: MAX_NOTES_SNIPPETS_LIST_VALUES,
        });
    }
    for value in values {
        validate_text(field, value, MAX_SMALL_TEXT_BYTES)?;
    }
    Ok(())
}

fn normalize_plain_catalog_values(
    field: &'static str,
    values: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, SavedNotesSnippetsError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES {
        return Err(SavedNotesSnippetsError::TooManyValues {
            field,
            max: MAX_NOTES_SNIPPETS_LIST_VALUES,
        });
    }

    let mut result = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(field, &value, MAX_SMALL_TEXT_BYTES)?;
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    Ok(Some(result))
}

fn clean_note_string_values(
    field: &'static str,
    values: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, SavedNotesSnippetsError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES {
        return Err(SavedNotesSnippetsError::TooManyValues {
            field,
            max: MAX_NOTES_SNIPPETS_LIST_VALUES,
        });
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.trim().to_owned();
        if value.is_empty() {
            continue;
        }
        validate_text(field, &value, MAX_SMALL_TEXT_BYTES)?;
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    Ok((!result.is_empty()).then_some(result))
}

fn normalize_host_ids(
    field: &'static str,
    values: Option<Vec<String>>,
    trim: bool,
) -> Result<Option<Vec<SavedHostId>>, SavedNotesSnippetsError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.len() > MAX_NOTES_SNIPPETS_LIST_VALUES {
        return Err(SavedNotesSnippetsError::TooManyValues {
            field,
            max: MAX_NOTES_SNIPPETS_LIST_VALUES,
        });
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let value = if trim { value.trim().to_owned() } else { value };
        let id = SavedHostId::from_opaque(value)
            .map_err(|_| SavedNotesSnippetsError::InvalidOpaqueId(field))?;
        if seen.insert(id.clone()) {
            result.push(id);
        }
    }
    Ok(Some(result))
}

fn validate_entity_count<T>(
    kind: SavedNotesSnippetsEntityKind,
    values: Option<&[T]>,
) -> Result<(), SavedNotesSnippetsError> {
    if values.is_some_and(|values| values.len() > MAX_NOTES_SNIPPETS_CATALOG_ENTITIES) {
        return Err(SavedNotesSnippetsError::TooManyEntities {
            kind,
            max: MAX_NOTES_SNIPPETS_CATALOG_ENTITIES,
        });
    }
    Ok(())
}

fn validate_unique_snippet_ids(
    snippets: Option<&[SavedSnippet]>,
) -> Result<(), SavedNotesSnippetsError> {
    let mut seen = BTreeSet::new();
    for (record_index, snippet) in snippets.unwrap_or_default().iter().enumerate() {
        if !seen.insert(snippet.id.clone()) {
            return Err(SavedNotesSnippetsError::DuplicateEntityId {
                kind: SavedNotesSnippetsEntityKind::Snippet,
                record_index,
            });
        }
    }
    Ok(())
}

fn validate_unique_note_ids(
    notes: Option<&[SavedVaultNote]>,
) -> Result<(), SavedNotesSnippetsError> {
    let mut seen = BTreeSet::new();
    for (record_index, note) in notes.unwrap_or_default().iter().enumerate() {
        if !seen.insert(note.id.clone()) {
            return Err(SavedNotesSnippetsError::DuplicateEntityId {
                kind: SavedNotesSnippetsEntityKind::Note,
                record_index,
            });
        }
    }
    Ok(())
}

fn validate_host_id(id: &SavedHostId) -> Result<(), SavedNotesSnippetsError> {
    SavedHostId::from_opaque(id.as_str().to_owned())
        .map(|_| ())
        .map_err(|_| SavedNotesSnippetsError::InvalidOpaqueId("host ID"))
}

fn validate_host_id_set(ids: &BTreeSet<SavedHostId>) -> Result<(), SavedNotesSnippetsError> {
    ids.iter().try_for_each(validate_host_id)
}

fn validate_host_id_map(
    ids: &BTreeMap<SavedHostId, SavedHostId>,
) -> Result<(), SavedNotesSnippetsError> {
    for (source, target) in ids {
        validate_host_id(source)?;
        validate_host_id(target)?;
    }
    Ok(())
}

fn validate_catalog_host_references(
    catalog: &SavedNotesSnippetsCatalog,
    final_host_ids: &BTreeSet<SavedHostId>,
) -> Result<(), SavedNotesSnippetsError> {
    for (record_index, snippet) in catalog
        .snippets
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        for (reference_index, host_id) in snippet
            .targets
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            if !final_host_ids.contains(host_id) {
                return Err(SavedNotesSnippetsError::MissingHostReference {
                    kind: SavedHostReferenceKind::SnippetTarget,
                    record_index,
                    reference_index,
                });
            }
        }
    }
    for (record_index, note) in catalog
        .notes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        for (reference_index, host_id) in note
            .linked_host_ids
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            if !final_host_ids.contains(host_id) {
                return Err(SavedNotesSnippetsError::MissingHostReference {
                    kind: SavedHostReferenceKind::NoteLinkedHost,
                    record_index,
                    reference_index,
                });
            }
        }
    }
    Ok(())
}

fn remap_host_ids(
    values: &[SavedHostId],
    remap: &BTreeMap<SavedHostId, SavedHostId>,
) -> (Vec<SavedHostId>, usize) {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut changed = 0usize;
    for value in values {
        let mapped = remap.get(value).unwrap_or(value);
        if mapped != value {
            changed += 1;
        }
        if seen.insert(mapped.clone()) {
            result.push(mapped.clone());
        }
    }
    (result, changed)
}

fn add_text_bytes(total: &mut usize, value: &str) -> Result<(), SavedNotesSnippetsError> {
    *total =
        total
            .checked_add(value.len())
            .ok_or(SavedNotesSnippetsError::CatalogTextTooLarge {
                max_bytes: MAX_CATALOG_TEXT_BYTES,
            })?;
    if *total > MAX_CATALOG_TEXT_BYTES {
        return Err(SavedNotesSnippetsError::CatalogTextTooLarge {
            max_bytes: MAX_CATALOG_TEXT_BYTES,
        });
    }
    Ok(())
}

fn add_optional_text_bytes(
    total: &mut usize,
    value: Option<&str>,
) -> Result<(), SavedNotesSnippetsError> {
    if let Some(value) = value {
        add_text_bytes(total, value)?;
    }
    Ok(())
}

fn add_optional_values_bytes(
    total: &mut usize,
    values: Option<&[String]>,
) -> Result<(), SavedNotesSnippetsError> {
    for value in values.unwrap_or_default() {
        add_text_bytes(total, value)?;
    }
    Ok(())
}

fn add_host_id_bytes(
    total: &mut usize,
    values: Option<&[SavedHostId]>,
) -> Result<(), SavedNotesSnippetsError> {
    for value in values.unwrap_or_default() {
        add_text_bytes(total, value.as_str())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host_id(value: &str) -> SavedHostId {
        SavedHostId::from_opaque(value).expect("host ID")
    }

    fn snippet(id: &str, targets: Option<Vec<&str>>) -> SavedSnippet {
        let mut draft = SavedSnippetDraft::new(id, format!("label-{id}"), "echo safe");
        draft.targets = targets.map(|values| values.into_iter().map(str::to_owned).collect());
        SavedSnippet::from_draft(draft).expect("snippet")
    }

    fn note(id: &str, linked: Option<Vec<&str>>) -> SavedVaultNote {
        let mut draft = SavedVaultNoteDraft::new(id, format!("title-{id}"), "body", 1.5, 2.5);
        draft.linked_host_ids =
            linked.map(|values| values.into_iter().map(str::to_owned).collect());
        SavedVaultNote::from_draft(draft).expect("note")
    }

    fn catalog(
        snippets: Vec<SavedSnippet>,
        notes: Vec<SavedVaultNote>,
    ) -> SavedNotesSnippetsCatalog {
        SavedNotesSnippetsCatalog::from_parts(Some(snippets), None, Some(notes), None)
            .expect("catalog")
    }

    #[test]
    fn note_and_snippet_group_normalizers_are_deliberately_distinct() {
        let raw = r" / Team \\ Core // ./ ../ Ops / ";
        assert_eq!(normalize_note_group_path(raw), r"Team \\ Core/./../Ops");
        assert_eq!(
            normalize_snippet_target_group_path(raw),
            "Team/Core/./../Ops"
        );
    }

    #[test]
    fn group_catalog_normalizers_filter_empty_and_deduplicate_stably() {
        let note_groups =
            normalize_note_groups([" A / B ", "//", "A/B", r"A\B"]).expect("note groups");
        assert_eq!(
            note_groups
                .iter()
                .map(SavedNoteGroupPath::as_str)
                .collect::<Vec<_>>(),
            ["A/B", r"A\B"]
        );

        let snippet_groups = normalize_snippet_target_groups([r" A\B ", "A//B", " / ", "C"])
            .expect("snippet groups");
        assert_eq!(
            snippet_groups
                .iter()
                .map(SavedSnippetTargetGroupPath::as_str)
                .collect::<Vec<_>>(),
            ["A/B", "C"]
        );
    }

    #[test]
    fn note_group_ancestors_are_root_to_leaf_in_the_notes_domain() {
        let ancestors = SavedNoteGroupPath::new(" A / B / C ")
            .expect("path")
            .ancestors();
        assert_eq!(
            ancestors
                .iter()
                .map(SavedNoteGroupPath::as_str)
                .collect::<Vec<_>>(),
            ["A", "A/B", "A/B/C"]
        );
    }

    #[test]
    fn snippet_round_trip_preserves_every_legacy_field_and_camel_case() {
        let value = json!({
            "id": "snippet-1",
            "label": "Deploy",
            "command": "echo deploy",
            "tags": ["ops", "prod"],
            "package": "Admin/Linux",
            "targets": ["host-1"],
            "targetGroups": [r" Team\Prod "],
            "targetsAllHosts": false,
            "shortkey": "Ctrl + F1",
            "noAutoRun": true,
            "multiLineRunMode": "lineDelay",
            "order": 3.5,
            "kind": "script",
            "language": "python",
            "description": "description",
            "trigger": "onOutput",
            "triggerPattern": "ready>"
        });
        let decoded: SavedSnippet = serde_json::from_value(value).expect("decode");
        let encoded = serde_json::to_value(&decoded).expect("encode");
        assert_eq!(encoded["targetGroups"], json!(["Team/Prod"]));
        assert_eq!(encoded["targetsAllHosts"], json!(false));
        assert_eq!(encoded["multiLineRunMode"], json!("lineDelay"));
        assert_eq!(encoded["kind"], json!("script"));
        assert_eq!(encoded["language"], json!("python"));
        assert_eq!(encoded["trigger"], json!("onOutput"));
        assert_eq!(encoded.as_object().expect("object").len(), 17);
    }

    #[test]
    fn absent_and_explicitly_empty_target_groups_remain_distinct() {
        let absent: SavedSnippet = serde_json::from_value(json!({
            "id": "absent", "label": "a", "command": "a"
        }))
        .expect("absent");
        let empty: SavedSnippet = serde_json::from_value(json!({
            "id": "empty", "label": "e", "command": "e", "targetGroups": []
        }))
        .expect("empty");

        assert_eq!(absent.target_groups(), None);
        assert_eq!(empty.target_groups(), Some([].as_slice()));
        assert!(
            serde_json::to_value(absent)
                .expect("serialize")
                .get("targetGroups")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(empty).expect("serialize")["targetGroups"],
            json!([])
        );
    }

    #[test]
    fn note_sanitization_matches_legacy_title_tag_link_and_group_rules() {
        let mut draft = SavedVaultNoteDraft::new("note-1", "  Title  ", " body ", -1.25, 2.75);
        draft.group = Some(r" / Team /  Ops\DB / ".to_owned());
        draft.tags = Some(vec![
            " ops ".to_owned(),
            "".to_owned(),
            "ops".to_owned(),
            " db ".to_owned(),
        ]);
        draft.linked_host_ids = Some(vec![
            " host-1 ".to_owned(),
            "host-1".to_owned(),
            "host-2".to_owned(),
        ]);
        draft.order = Some(-3.5);

        let note = SavedVaultNote::from_draft(draft).expect("note");
        assert_eq!(note.title(), "Title");
        assert_eq!(note.content(), " body ");
        assert_eq!(note.group().expect("group").as_str(), r"Team/Ops\DB");
        assert_eq!(note.tags().expect("tags"), ["ops", "db"]);
        assert_eq!(
            note.linked_host_ids()
                .expect("links")
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            ["host-1", "host-2"]
        );
        assert_eq!(note.created_at(), -1.25);
        assert_eq!(note.updated_at(), 2.75);
        assert_eq!(note.order(), Some(-3.5));
    }

    #[test]
    fn catalog_preserves_absent_and_supplied_empty_top_level_catalogs() {
        let absent = SavedNotesSnippetsCatalog::empty();
        let supplied = SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
        )
        .expect("catalog");

        assert_eq!(serde_json::to_value(absent).expect("absent"), json!({}));
        assert_eq!(
            serde_json::to_value(supplied).expect("supplied"),
            json!({"snippets": [], "snippetPackages": [], "notes": [], "noteGroups": []})
        );
    }

    #[test]
    fn snippet_packages_preserve_exact_values_and_deduplicate_stably() {
        let catalog = SavedNotesSnippetsCatalog::from_parts(
            None,
            Some(vec![
                "package".to_owned(),
                " package ".to_owned(),
                String::new(),
                "package".to_owned(),
                String::new(),
            ]),
            None,
            None,
        )
        .expect("catalog");
        assert_eq!(
            catalog.snippet_packages(),
            Some(&["package".to_owned(), " package ".to_owned(), String::new(),][..])
        );
    }

    #[test]
    fn catalog_rejects_duplicate_entity_ids_without_echoing_them() {
        let duplicate = snippet("private-opaque-id", None);
        let error = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![duplicate.clone(), duplicate]),
            None,
            None,
            None,
        )
        .expect_err("duplicate");
        assert_eq!(
            error,
            SavedNotesSnippetsError::DuplicateEntityId {
                kind: SavedNotesSnippetsEntityKind::Snippet,
                record_index: 1
            }
        );
        assert!(!error.to_string().contains("private-opaque-id"));
    }

    #[test]
    fn validates_snippet_and_note_host_edges_by_safe_location() {
        let value = catalog(
            vec![snippet("snippet", Some(vec!["host-a", "missing"]))],
            vec![note("note", Some(vec!["host-a"]))],
        );
        let hosts = BTreeSet::from([host_id("host-a")]);
        assert_eq!(
            value.validate_host_references(&hosts),
            Err(SavedNotesSnippetsError::MissingHostReference {
                kind: SavedHostReferenceKind::SnippetTarget,
                record_index: 0,
                reference_index: 1
            })
        );
    }

    #[test]
    fn targets_all_hosts_does_not_hide_a_dangling_explicit_edge() {
        let mut draft = SavedSnippetDraft::new("snippet", "label", "command");
        draft.targets_all_hosts = Some(true);
        draft.targets = Some(vec!["missing".to_owned()]);
        let value = catalog(
            vec![SavedSnippet::from_draft(draft).expect("snippet")],
            Vec::new(),
        );
        assert!(matches!(
            value.validate_host_references(&BTreeSet::new()),
            Err(SavedNotesSnippetsError::MissingHostReference {
                kind: SavedHostReferenceKind::SnippetTarget,
                ..
            })
        ));
    }

    #[test]
    fn remap_rewrites_both_edge_kinds_and_preserves_unmapped_order() {
        let original = catalog(
            vec![snippet("snippet", Some(vec!["old-a", "keep", "old-b"]))],
            vec![note("note", Some(vec!["old-b", "keep"]))],
        );
        let remap = BTreeMap::from([
            (host_id("old-a"), host_id("new-a")),
            (host_id("old-b"), host_id("new-b")),
        ]);
        let final_hosts = BTreeSet::from([host_id("new-a"), host_id("new-b"), host_id("keep")]);
        let plan = original
            .plan_host_id_remap(&remap, &final_hosts)
            .expect("plan");

        assert_eq!(plan.remapped_snippet_targets(), 2);
        assert_eq!(plan.remapped_note_links(), 1);
        assert_eq!(
            plan.catalog().snippets().expect("snippets")[0]
                .targets()
                .expect("targets")
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            ["new-a", "keep", "new-b"]
        );
        assert_eq!(
            plan.catalog().notes().expect("notes")[0]
                .linked_host_ids()
                .expect("links")
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            ["new-b", "keep"]
        );
        assert_eq!(
            original.snippets().expect("snippets")[0]
                .targets()
                .expect("targets")[0]
                .as_str(),
            "old-a"
        );
    }

    #[test]
    fn remap_collisions_deduplicate_in_stable_first_seen_order() {
        let value = catalog(
            vec![snippet("snippet", Some(vec!["old-a", "keep", "old-b"]))],
            Vec::new(),
        );
        let remap = BTreeMap::from([
            (host_id("old-a"), host_id("same")),
            (host_id("old-b"), host_id("same")),
        ]);
        let hosts = BTreeSet::from([host_id("same"), host_id("keep")]);

        let first = value
            .plan_host_id_remap(&remap, &hosts)
            .expect("first plan");
        let second = value
            .plan_host_id_remap(&remap, &hosts)
            .expect("second plan");
        assert_eq!(first, second);
        assert_eq!(
            first.catalog().snippets().expect("snippets")[0]
                .targets()
                .expect("targets")
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            ["same", "keep"]
        );
    }

    #[test]
    fn remap_is_single_step_and_fails_atomically_when_the_projection_dangles() {
        let value = catalog(
            vec![snippet("snippet", Some(vec!["a"]))],
            vec![note("note", Some(vec!["keep"]))],
        );
        let remap = BTreeMap::from([(host_id("a"), host_id("b")), (host_id("b"), host_id("c"))]);
        let error = value
            .plan_host_id_remap(&remap, &BTreeSet::from([host_id("c"), host_id("keep")]))
            .expect_err("single-step b is missing");
        assert_eq!(
            error,
            SavedNotesSnippetsError::MissingHostReference {
                kind: SavedHostReferenceKind::SnippetTarget,
                record_index: 0,
                reference_index: 0
            }
        );
        assert_eq!(
            value.snippets().expect("snippets")[0]
                .targets()
                .expect("targets")[0]
                .as_str(),
            "a"
        );
    }

    #[test]
    fn dynamic_group_targets_are_normalized_but_never_treated_as_host_ids() {
        let mut draft = SavedSnippetDraft::new("snippet", "label", "command");
        draft.target_groups = Some(vec![r" Team\Prod ".to_owned()]);
        let value = catalog(
            vec![SavedSnippet::from_draft(draft).expect("snippet")],
            Vec::new(),
        );
        value
            .validate_host_references(&BTreeSet::new())
            .expect("no ID edges");
        assert_eq!(
            value.snippets().expect("snippets")[0]
                .target_groups()
                .expect("target groups")[0]
                .as_str(),
            "Team/Prod"
        );
    }

    #[test]
    fn non_finite_numbers_and_oversized_arrays_fail_closed() {
        let mut invalid_note = SavedVaultNoteDraft::new("note", "title", "body", f64::NAN, 1.0);
        invalid_note.order = Some(f64::INFINITY);
        assert_eq!(
            SavedVaultNote::from_draft(invalid_note),
            Err(SavedNotesSnippetsError::InvalidFiniteNumber(
                "note createdAt"
            ))
        );

        let mut invalid_snippet = SavedSnippetDraft::new("snippet", "label", "command");
        invalid_snippet.targets = Some(
            (0..=MAX_NOTES_SNIPPETS_LIST_VALUES)
                .map(|index| format!("host-{index}"))
                .collect(),
        );
        assert_eq!(
            SavedSnippet::from_draft(invalid_snippet),
            Err(SavedNotesSnippetsError::TooManyValues {
                field: "snippet targets",
                max: MAX_NOTES_SNIPPETS_LIST_VALUES
            })
        );
    }

    #[test]
    fn serde_rejects_runtime_state_and_unknown_persistent_fields() {
        let snippet_json = json!({
            "id": "snippet", "label": "label", "command": "command", "running": true
        });
        let note_json = json!({
            "id": "note", "title": "title", "content": "body",
            "createdAt": 1, "updatedAt": 1, "lastError": "sensitive"
        });
        let catalog_json = json!({"snippets": [], "activeExecutions": []});
        assert!(serde_json::from_value::<SavedSnippet>(snippet_json).is_err());
        assert!(serde_json::from_value::<SavedVaultNote>(note_json).is_err());
        assert!(serde_json::from_value::<SavedNotesSnippetsCatalog>(catalog_json).is_err());
    }

    #[test]
    fn debug_output_redacts_free_form_text_paths_and_ids() {
        let mut snippet_draft = SavedSnippetDraft::new(
            "sensitive-snippet-id",
            "sensitive label",
            "sensitive command",
        );
        snippet_draft.target_groups = Some(vec!["sensitive/group".to_owned()]);
        let mut note_draft = SavedVaultNoteDraft::new(
            "sensitive-note-id",
            "sensitive title",
            "sensitive content",
            1.0,
            1.0,
        );
        note_draft.group = Some("sensitive/note/group".to_owned());
        let value = catalog(
            vec![SavedSnippet::from_draft(snippet_draft).expect("snippet")],
            vec![SavedVaultNote::from_draft(note_draft).expect("note")],
        );

        let debug = format!("{value:?}");
        for sensitive in [
            "sensitive-snippet-id",
            "sensitive label",
            "sensitive command",
            "sensitive/group",
            "sensitive-note-id",
            "sensitive title",
            "sensitive content",
            "sensitive/note/group",
        ] {
            assert!(!debug.contains(sensitive), "leaked {sensitive}");
        }
    }
}
