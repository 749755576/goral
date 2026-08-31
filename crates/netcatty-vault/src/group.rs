use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Group paths are logical Vault labels, not filesystem paths. Keep the bound
// aligned with other large legacy-compatible text fields without imposing a
// new per-segment limit that the legacy product never had.
const MAX_GROUP_PATH_BYTES: usize = 32 * 1024;
const MAX_GROUP_CATALOG_ENTITIES: usize = 10_000;

/// A normalized, non-empty legacy-compatible group path.
///
/// Only `/` is structural, matching `buildHostGroupTree` and
/// `resolveGroupDefaults` in the legacy product. Empty slash-delimited parts
/// are collapsed. Backslashes, whitespace, control characters, `.` and `..`
/// remain ordinary label text; this value is never interpreted as a filesystem
/// path. Snippet target-path cleanup has different legacy rules and must use a
/// separate type when that slice is implemented.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedGroupPath(String);

impl SavedGroupPath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, SavedGroupPathError> {
        normalize_group_path(value.as_ref()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> &str {
        self.0
            .rsplit_once('/')
            .map_or(self.0.as_str(), |(_, name)| name)
    }

    pub fn parent(&self) -> Option<Self> {
        self.0
            .rsplit_once('/')
            .map(|(parent, _)| Self(parent.to_owned()))
    }

    /// Returns the complete ancestor chain from the root through this path.
    ///
    /// For `A/B/C`, the result is exactly `A`, `A/B`, `A/B/C`.
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

impl AsRef<str> for SavedGroupPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SavedGroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SavedGroupPath {
    type Err = SavedGroupPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for SavedGroupPath {
    type Error = SavedGroupPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for SavedGroupPath {
    type Error = SavedGroupPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for SavedGroupPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedGroupPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedGroupPathError {
    Empty,
    TooLong { max_bytes: usize },
    CatalogTooLarge { max_entities: usize },
}

impl fmt::Display for SavedGroupPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("saved group path is empty"),
            Self::TooLong { max_bytes } => {
                write!(
                    formatter,
                    "saved group path exceeds {max_bytes} UTF-8 bytes"
                )
            }
            Self::CatalogTooLarge { max_entities } => {
                write!(
                    formatter,
                    "saved group catalog exceeds {max_entities} explicit paths"
                )
            }
        }
    }
}

impl std::error::Error for SavedGroupPathError {}

/// Minimal host-independent catalog for explicitly saved group paths.
///
/// A path remains explicit even when no host refers to it, matching the legacy
/// `customGroups[]` behavior. Implicit ancestors are projected by
/// [`Self::hierarchy_paths`] and are not silently promoted to explicit groups.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct SavedGroupCatalog {
    explicit_paths: Vec<SavedGroupPath>,
}

impl SavedGroupCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_paths<I, P>(paths: I) -> Result<Self, SavedGroupPathError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let mut catalog = Self::new();
        for path in paths {
            catalog.insert(path)?;
        }
        Ok(catalog)
    }

    /// Inserts a normalized explicit path while preserving first-seen order.
    pub fn insert(&mut self, value: impl AsRef<str>) -> Result<bool, SavedGroupPathError> {
        let path = SavedGroupPath::new(value)?;
        self.insert_path(path)
    }

    pub fn insert_path(&mut self, path: SavedGroupPath) -> Result<bool, SavedGroupPathError> {
        if self.explicit_paths.contains(&path) {
            return Ok(false);
        }
        if self.explicit_paths.len() >= MAX_GROUP_CATALOG_ENTITIES {
            return Err(SavedGroupPathError::CatalogTooLarge {
                max_entities: MAX_GROUP_CATALOG_ENTITIES,
            });
        }
        self.explicit_paths.push(path);
        Ok(true)
    }

    pub fn remove(&mut self, path: &SavedGroupPath) -> bool {
        let Some(index) = self.explicit_paths.iter().position(|saved| saved == path) else {
            return false;
        };
        self.explicit_paths.remove(index);
        true
    }

    pub fn is_explicit(&self, path: &SavedGroupPath) -> bool {
        self.explicit_paths.contains(path)
    }

    pub fn explicit_paths(&self) -> &[SavedGroupPath] {
        &self.explicit_paths
    }

    pub fn len(&self) -> usize {
        self.explicit_paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.explicit_paths.is_empty()
    }

    /// Projects explicit groups and their ancestors in stable first-seen order.
    pub fn hierarchy_paths(&self) -> Vec<SavedGroupPath> {
        let mut seen = BTreeSet::new();
        let mut hierarchy = Vec::new();
        for path in &self.explicit_paths {
            for ancestor in path.ancestors() {
                if seen.insert(ancestor.clone()) {
                    hierarchy.push(ancestor);
                }
            }
        }
        hierarchy
    }
}

impl<'de> Deserialize<'de> for SavedGroupCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let paths = Vec::<SavedGroupPath>::deserialize(deserializer)?;
        if paths.len() > MAX_GROUP_CATALOG_ENTITIES {
            return Err(serde::de::Error::custom(
                "saved group catalog exceeds the entity limit",
            ));
        }
        let mut catalog = Self::new();
        for path in paths {
            if !catalog
                .insert_path(path)
                .map_err(serde::de::Error::custom)?
            {
                return Err(serde::de::Error::custom(
                    "saved group catalog contains a duplicate path",
                ));
            }
        }
        Ok(catalog)
    }
}

fn normalize_group_path(value: &str) -> Result<String, SavedGroupPathError> {
    let segments = value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    if segments.is_empty() {
        return Err(SavedGroupPathError::Empty);
    }

    let normalized = segments.join("/");
    if normalized.len() > MAX_GROUP_PATH_BYTES {
        return Err(SavedGroupPathError::TooLong {
            max_bytes: MAX_GROUP_PATH_BYTES,
        });
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_GROUP_CATALOG_ENTITIES, MAX_GROUP_PATH_BYTES, SavedGroupCatalog, SavedGroupPath,
        SavedGroupPathError,
    };

    fn path(value: &str) -> SavedGroupPath {
        SavedGroupPath::new(value).expect("valid group path")
    }

    fn strings(paths: &[SavedGroupPath]) -> Vec<&str> {
        paths.iter().map(SavedGroupPath::as_str).collect()
    }

    #[test]
    fn normalizes_only_empty_slash_parts_and_preserves_legacy_label_text() {
        let normalized = path(r"/ Team Alpha //Ops\DB/../ Production /");
        assert_eq!(normalized.as_str(), r" Team Alpha /Ops\DB/../ Production ");
        assert_eq!(normalized.name(), " Production ");
        assert_eq!(normalized.parent(), Some(path(r" Team Alpha /Ops\DB/..")));
    }

    #[test]
    fn ancestors_are_ordered_from_root_to_exact_path() {
        let ancestors = path("A/B/C").ancestors();
        assert_eq!(strings(&ancestors), ["A", "A/B", "A/B/C"]);
    }

    #[test]
    fn rejects_only_structurally_empty_paths() {
        for value in ["", "/", "////"] {
            assert_eq!(SavedGroupPath::new(value), Err(SavedGroupPathError::Empty));
        }
        assert_eq!(path("A/./../B").as_str(), "A/./../B");
        assert_eq!(path(r"A\B").as_str(), r"A\B");
        assert_eq!(path(" A / B ").as_str(), " A / B ");
        assert_eq!(path("A/\0/\n/B").as_str(), "A/\0/\n/B");
    }

    #[test]
    fn bounds_only_the_canonical_path_after_empty_parts_are_collapsed() {
        assert_eq!(
            SavedGroupPath::new(format!(
                "{}A{}",
                "/".repeat(MAX_GROUP_PATH_BYTES),
                "/".repeat(MAX_GROUP_PATH_BYTES)
            ))
            .expect("redundant separators collapse")
            .as_str(),
            "A"
        );
        let oversized = "x".repeat(MAX_GROUP_PATH_BYTES + 1);
        assert_eq!(
            SavedGroupPath::new(oversized),
            Err(SavedGroupPathError::TooLong {
                max_bytes: MAX_GROUP_PATH_BYTES
            })
        );
    }

    #[test]
    fn serde_uses_only_the_canonical_path() {
        let decoded: SavedGroupPath =
            serde_json::from_value(serde_json::json!(r"/ Team Alpha //Ops\DB/../ Production /"))
                .expect("canonicalized group path");
        assert_eq!(decoded.as_str(), r" Team Alpha /Ops\DB/../ Production ");
        assert_eq!(
            serde_json::to_value(decoded).expect("serialized group path"),
            serde_json::json!(r" Team Alpha /Ops\DB/../ Production ")
        );
    }

    #[test]
    fn catalog_deduplicates_normalized_paths_and_preserves_first_seen_order() {
        let catalog =
            SavedGroupCatalog::from_paths(["A//B/C", "A/B/C", r"A\B\C", "Z", "A/D", "A/B"])
                .expect("group catalog");
        assert_eq!(
            strings(catalog.explicit_paths()),
            ["A/B/C", r"A\B\C", "Z", "A/D", "A/B"]
        );
        assert_eq!(
            strings(&catalog.hierarchy_paths()),
            ["A", "A/B", "A/B/C", r"A\B\C", "Z", "A/D"]
        );
    }

    #[test]
    fn explicit_empty_leaf_is_not_confused_with_its_implicit_ancestors() {
        let mut catalog =
            SavedGroupCatalog::from_paths(["Empty/Leaf"]).expect("explicit empty group catalog");
        let parent = path("Empty");
        let leaf = path("Empty/Leaf");

        assert!(!catalog.is_explicit(&parent));
        assert!(catalog.is_explicit(&leaf));
        assert_eq!(strings(&catalog.hierarchy_paths()), ["Empty", "Empty/Leaf"]);
        assert!(catalog.remove(&leaf));
        assert!(catalog.is_empty());
        assert!(catalog.hierarchy_paths().is_empty());
    }

    #[test]
    fn oversized_insert_leaves_existing_catalog_unchanged() {
        let mut catalog =
            SavedGroupCatalog::from_paths(["Existing"]).expect("initial group catalog");
        assert_eq!(
            catalog.insert("x".repeat(MAX_GROUP_PATH_BYTES + 1)),
            Err(SavedGroupPathError::TooLong {
                max_bytes: MAX_GROUP_PATH_BYTES
            })
        );
        assert_eq!(strings(catalog.explicit_paths()), ["Existing"]);
        assert_eq!(catalog.len(), 1);
    }

    #[test]
    fn catalog_deserialization_rejects_duplicate_paths_and_entity_overflow() {
        assert!(
            serde_json::from_value::<SavedGroupCatalog>(serde_json::json!(["A//B", "A/B"]))
                .is_err()
        );
        let oversized = (0..=MAX_GROUP_CATALOG_ENTITIES)
            .map(|index| format!("group-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            SavedGroupCatalog::from_paths(&oversized),
            Err(SavedGroupPathError::CatalogTooLarge {
                max_entities: MAX_GROUP_CATALOG_ENTITIES,
            })
        );
    }
}
