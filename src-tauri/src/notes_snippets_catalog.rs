use netcatty_vault::{
    SavedNotesSnippetsCatalog, SavedScriptLanguage, SavedScriptTrigger, SavedSnippet,
    SavedSnippetDraft, SavedSnippetId, SavedSnippetKind, SavedSnippetMultiLineRunMode,
    SavedVaultGraph, SavedVaultInventoryRevision, SavedVaultNote, SavedVaultNoteDraft,
    SavedVaultNoteId,
};
use serde::{Deserialize, Serialize};

pub(crate) const NOTES_SNIPPETS_INVALID: &str = "NOTES_SNIPPETS_INVALID";
pub(crate) const NOTES_SNIPPETS_NOT_FOUND: &str = "NOTES_SNIPPETS_NOT_FOUND";
pub(crate) const NOTES_SNIPPETS_INVENTORY_CHANGED: &str = "NOTES_SNIPPETS_INVENTORY_CHANGED";
pub(crate) const NOTES_SNIPPETS_PUBLICATION_FAILED: &str = "NOTES_SNIPPETS_PUBLICATION_FAILED";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultNoteDraftRequest {
    pub(crate) title: String,
    pub(crate) content: String,
    pub(crate) group: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) linked_host_ids: Option<Vec<String>>,
    pub(crate) order: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateVaultNoteRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) draft: VaultNoteDraftRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateVaultNoteRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) draft: VaultNoteDraftRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteVaultNoteRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedSnippetDraftRequest {
    pub(crate) label: String,
    pub(crate) command: String,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) package: Option<String>,
    pub(crate) targets: Option<Vec<String>>,
    pub(crate) target_groups: Option<Vec<String>>,
    pub(crate) targets_all_hosts: Option<bool>,
    pub(crate) shortkey: Option<String>,
    pub(crate) no_auto_run: Option<bool>,
    pub(crate) multi_line_run_mode: Option<SavedSnippetMultiLineRunMode>,
    pub(crate) order: Option<f64>,
    pub(crate) kind: Option<SavedSnippetKind>,
    pub(crate) language: Option<SavedScriptLanguage>,
    pub(crate) description: Option<String>,
    pub(crate) trigger: Option<SavedScriptTrigger>,
    pub(crate) trigger_pattern: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateSavedSnippetRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) draft: SavedSnippetDraftRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateSavedSnippetRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) draft: SavedSnippetDraftRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteSavedSnippetRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotesSnippetsCatalog {
    pub(crate) inventory_revision: SavedVaultInventoryRevision,
    pub(crate) notes: Vec<SavedVaultNote>,
    pub(crate) note_groups: Vec<String>,
    pub(crate) snippets: Vec<SavedSnippet>,
    pub(crate) snippet_packages: Vec<String>,
}

impl NotesSnippetsCatalog {
    pub(crate) fn from_graph(
        inventory_revision: SavedVaultInventoryRevision,
        graph: &SavedVaultGraph,
    ) -> Self {
        let catalog = graph.notes_snippets();
        Self {
            inventory_revision,
            notes: catalog.notes().unwrap_or_default().to_vec(),
            note_groups: catalog
                .note_groups()
                .unwrap_or_default()
                .iter()
                .map(|group| group.as_str().to_owned())
                .collect(),
            snippets: catalog.snippets().unwrap_or_default().to_vec(),
            snippet_packages: catalog.snippet_packages().unwrap_or_default().to_vec(),
        }
    }
}

pub(crate) struct PreparedNotesSnippetsMutation {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) target_graph: SavedVaultGraph,
}

pub(crate) fn prepare_note_creation(
    graph: SavedVaultGraph,
    request: CreateVaultNoteRequest,
    id: SavedVaultNoteId,
    now: f64,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let note = build_note(id, request.draft, now, now)?;
    if graph
        .notes_snippets()
        .notes()
        .unwrap_or_default()
        .iter()
        .any(|candidate| candidate.id() == note.id())
    {
        return Err(notes_snippets_invalid());
    }
    let mut notes = graph.notes_snippets().notes().unwrap_or_default().to_vec();
    notes.push(note);
    let catalog = catalog_with_notes(graph.notes_snippets(), notes)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

pub(crate) fn prepare_note_update(
    graph: SavedVaultGraph,
    request: UpdateVaultNoteRequest,
    now: f64,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let id = SavedVaultNoteId::from_opaque(request.id).map_err(|_| notes_snippets_invalid())?;
    let mut notes = graph.notes_snippets().notes().unwrap_or_default().to_vec();
    let index = notes
        .iter()
        .position(|candidate| candidate.id() == &id)
        .ok_or_else(notes_snippets_not_found)?;
    notes[index] = build_note(id, request.draft, notes[index].created_at(), now)?;
    let catalog = catalog_with_notes(graph.notes_snippets(), notes)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

pub(crate) fn prepare_note_deletion(
    graph: SavedVaultGraph,
    request: DeleteVaultNoteRequest,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let id = SavedVaultNoteId::from_opaque(request.id).map_err(|_| notes_snippets_invalid())?;
    let mut notes = graph.notes_snippets().notes().unwrap_or_default().to_vec();
    let original_len = notes.len();
    notes.retain(|candidate| candidate.id() != &id);
    if notes.len() == original_len {
        return Err(notes_snippets_not_found());
    }
    let catalog = catalog_with_notes(graph.notes_snippets(), notes)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

pub(crate) fn prepare_snippet_creation(
    graph: SavedVaultGraph,
    request: CreateSavedSnippetRequest,
    id: SavedSnippetId,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let snippet = build_snippet(id, request.draft)?;
    if graph
        .notes_snippets()
        .snippets()
        .unwrap_or_default()
        .iter()
        .any(|candidate| candidate.id() == snippet.id())
    {
        return Err(notes_snippets_invalid());
    }
    let mut snippets = graph
        .notes_snippets()
        .snippets()
        .unwrap_or_default()
        .to_vec();
    snippets.push(snippet);
    let catalog = catalog_with_snippets(graph.notes_snippets(), snippets)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

pub(crate) fn prepare_snippet_update(
    graph: SavedVaultGraph,
    request: UpdateSavedSnippetRequest,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let id = SavedSnippetId::from_opaque(request.id).map_err(|_| notes_snippets_invalid())?;
    let mut snippets = graph
        .notes_snippets()
        .snippets()
        .unwrap_or_default()
        .to_vec();
    let index = snippets
        .iter()
        .position(|candidate| candidate.id() == &id)
        .ok_or_else(notes_snippets_not_found)?;
    snippets[index] = build_snippet(id, request.draft)?;
    let catalog = catalog_with_snippets(graph.notes_snippets(), snippets)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

pub(crate) fn prepare_snippet_deletion(
    graph: SavedVaultGraph,
    request: DeleteSavedSnippetRequest,
) -> Result<PreparedNotesSnippetsMutation, String> {
    let id = SavedSnippetId::from_opaque(request.id).map_err(|_| notes_snippets_invalid())?;
    let mut snippets = graph
        .notes_snippets()
        .snippets()
        .unwrap_or_default()
        .to_vec();
    let original_len = snippets.len();
    snippets.retain(|candidate| candidate.id() != &id);
    if snippets.len() == original_len {
        return Err(notes_snippets_not_found());
    }
    let catalog = catalog_with_snippets(graph.notes_snippets(), snippets)?;
    Ok(PreparedNotesSnippetsMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph_with_catalog(graph, catalog),
    })
}

fn build_note(
    id: SavedVaultNoteId,
    request: VaultNoteDraftRequest,
    created_at: f64,
    updated_at: f64,
) -> Result<SavedVaultNote, String> {
    let mut draft = SavedVaultNoteDraft::new(
        id.as_str(),
        request.title,
        request.content,
        created_at,
        updated_at,
    );
    draft.group = request.group;
    draft.tags = request.tags;
    draft.linked_host_ids = request.linked_host_ids;
    draft.order = request.order;
    SavedVaultNote::from_draft(draft).map_err(|_| notes_snippets_invalid())
}

fn build_snippet(
    id: SavedSnippetId,
    request: SavedSnippetDraftRequest,
) -> Result<SavedSnippet, String> {
    let mut draft = SavedSnippetDraft::new(id.as_str(), request.label, request.command);
    draft.tags = request.tags;
    draft.package = request.package;
    draft.targets = request.targets;
    draft.target_groups = request.target_groups;
    draft.targets_all_hosts = request.targets_all_hosts;
    draft.shortkey = request.shortkey;
    draft.no_auto_run = request.no_auto_run;
    draft.multi_line_run_mode = request.multi_line_run_mode;
    draft.order = request.order;
    draft.kind = request.kind;
    draft.language = request.language;
    draft.description = request.description;
    draft.trigger = request.trigger;
    draft.trigger_pattern = request.trigger_pattern;
    SavedSnippet::from_draft(draft).map_err(|_| notes_snippets_invalid())
}

fn catalog_parts(
    catalog: &SavedNotesSnippetsCatalog,
) -> (
    Option<Vec<SavedSnippet>>,
    Option<Vec<String>>,
    Option<Vec<SavedVaultNote>>,
    Option<Vec<String>>,
) {
    (
        catalog.snippets().map(<[SavedSnippet]>::to_vec),
        catalog.snippet_packages().map(<[String]>::to_vec),
        catalog.notes().map(<[SavedVaultNote]>::to_vec),
        catalog.note_groups().map(|groups| {
            groups
                .iter()
                .map(|group| group.as_str().to_owned())
                .collect()
        }),
    )
}

fn catalog_with_notes(
    catalog: &SavedNotesSnippetsCatalog,
    notes: Vec<SavedVaultNote>,
) -> Result<SavedNotesSnippetsCatalog, String> {
    let (snippets, snippet_packages, _, note_groups) = catalog_parts(catalog);
    SavedNotesSnippetsCatalog::from_parts(snippets, snippet_packages, Some(notes), note_groups)
        .map_err(|_| notes_snippets_invalid())
}

fn catalog_with_snippets(
    catalog: &SavedNotesSnippetsCatalog,
    snippets: Vec<SavedSnippet>,
) -> Result<SavedNotesSnippetsCatalog, String> {
    let (_, snippet_packages, notes, note_groups) = catalog_parts(catalog);
    SavedNotesSnippetsCatalog::from_parts(Some(snippets), snippet_packages, notes, note_groups)
        .map_err(|_| notes_snippets_invalid())
}

fn graph_with_catalog(
    graph: SavedVaultGraph,
    notes_snippets: SavedNotesSnippetsCatalog,
) -> SavedVaultGraph {
    let (
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        _,
        port_forward_rules,
    ) = graph.into_current_parts();
    SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups)
}

pub(crate) fn notes_snippets_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn notes_snippets_invalid() -> String {
    notes_snippets_error(
        NOTES_SNIPPETS_INVALID,
        "The notes/snippets metadata is invalid",
    )
}

pub(crate) fn notes_snippets_not_found() -> String {
    notes_snippets_error(
        NOTES_SNIPPETS_NOT_FOUND,
        "The note or snippet was not found",
    )
}

#[cfg(test)]
mod tests {
    use netcatty_vault::{
        SavedHost, SavedHostDraft, SavedHostStore, SavedNotesSnippetsCatalog, SavedPortForwardKind,
        SavedPortForwardRule, SavedSnippet, SavedSnippetDraft, SavedSnippetId, SavedVaultGraph,
        SavedVaultInventoryRevision, SavedVaultNote, SavedVaultNoteDraft, SavedVaultNoteId,
        StoreError,
    };

    use super::{
        CreateSavedSnippetRequest, CreateVaultNoteRequest, DeleteSavedSnippetRequest,
        DeleteVaultNoteRequest, NotesSnippetsCatalog, SavedSnippetDraftRequest,
        UpdateSavedSnippetRequest, UpdateVaultNoteRequest, VaultNoteDraftRequest,
        prepare_note_creation, prepare_note_deletion, prepare_note_update,
        prepare_snippet_creation, prepare_snippet_deletion, prepare_snippet_update,
    };

    fn revision(generation: u64) -> SavedVaultInventoryRevision {
        serde_json::from_value(serde_json::json!({
            "storeId": "00000000-0000-4000-8000-000000000001",
            "loadedGeneration": generation,
            "maxSeenGeneration": generation,
            "seal": "ab".repeat(32),
        }))
        .expect("inventory revision")
    }

    fn note_draft(title: &str, group: Option<&str>) -> VaultNoteDraftRequest {
        VaultNoteDraftRequest {
            title: title.to_owned(),
            content: "body".to_owned(),
            group: group.map(str::to_owned),
            tags: Some(vec!["ops".to_owned()]),
            linked_host_ids: None,
            order: Some(1.0),
        }
    }

    fn snippet_draft(label: &str, package: Option<&str>) -> SavedSnippetDraftRequest {
        SavedSnippetDraftRequest {
            label: label.to_owned(),
            command: "echo safe".to_owned(),
            tags: None,
            package: package.map(str::to_owned),
            targets: None,
            target_groups: Some(Vec::new()),
            targets_all_hosts: None,
            shortkey: None,
            no_auto_run: None,
            multi_line_run_mode: None,
            order: Some(2.0),
            kind: None,
            language: None,
            description: None,
            trigger: None,
            trigger_pattern: None,
        }
    }

    fn full_graph() -> (SavedVaultGraph, SavedHost, SavedVaultNote, SavedSnippet) {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("notes.example.test", "notes-user"),
            1,
        )
        .expect("host");
        let mut note_draft =
            SavedVaultNoteDraft::new("existing-note", "Existing", "body", 1.0, 1.0);
        note_draft.group = Some("Existing/Group".to_owned());
        let note = SavedVaultNote::from_draft(note_draft).expect("note");
        let mut snippet_draft =
            SavedSnippetDraft::new("existing-snippet", "Existing", "echo existing");
        snippet_draft.package = Some("existing-package".to_owned());
        let snippet = SavedSnippet::from_draft(snippet_draft).expect("snippet");
        let catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![snippet.clone()]),
            Some(vec!["existing-package".to_owned()]),
            Some(vec![note.clone()]),
            Some(vec!["Existing/Group".to_owned()]),
        )
        .expect("catalog");
        let forward = SavedPortForwardRule::new(
            "notes-forward",
            "Notes forward",
            SavedPortForwardKind::Dynamic,
            1080,
            "127.0.0.1",
            None,
            None,
            host.id.as_str(),
            false,
            1,
            None,
            None,
        )
        .expect("port forward");
        (
            SavedVaultGraph::new_with_port_forward_rules(
                vec![host.clone()],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                catalog,
                vec![forward],
            ),
            host,
            note,
            snippet,
        )
    }

    #[test]
    fn note_crud_preserves_the_complete_v8_graph_and_rust_owned_times() {
        let (graph, host, existing_note, existing_snippet) = full_graph();
        let expected = revision(7);
        let created = prepare_note_creation(
            graph,
            CreateVaultNoteRequest {
                expected_inventory_revision: expected.clone(),
                draft: note_draft("Created", Some("New / Group")),
            },
            SavedVaultNoteId::from_opaque("created-note").expect("note ID"),
            100.0,
        )
        .expect("create note");
        assert_eq!(created.expected_inventory_revision, expected);
        assert_eq!(created.target_graph.hosts(), std::slice::from_ref(&host));
        assert_eq!(created.target_graph.port_forward_rules().len(), 1);
        assert_eq!(
            created.target_graph.notes_snippets().snippets(),
            Some(std::slice::from_ref(&existing_snippet))
        );
        let notes = created
            .target_graph
            .notes_snippets()
            .notes()
            .expect("notes");
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[1].created_at(), 100.0);
        assert_eq!(notes[1].updated_at(), 100.0);
        assert_eq!(
            created
                .target_graph
                .notes_snippets()
                .note_groups()
                .expect("groups")[0]
                .as_str(),
            "Existing/Group"
        );

        let updated = prepare_note_update(
            created.target_graph,
            UpdateVaultNoteRequest {
                id: "created-note".to_owned(),
                expected_inventory_revision: revision(8),
                draft: note_draft("Updated", None),
            },
            200.0,
        )
        .expect("update note");
        let updated_note = updated
            .target_graph
            .notes_snippets()
            .notes()
            .expect("notes")
            .iter()
            .find(|note| note.id().as_str() == "created-note")
            .expect("updated note");
        assert_eq!(updated_note.created_at(), 100.0);
        assert_eq!(updated_note.updated_at(), 200.0);

        let deleted = prepare_note_deletion(
            updated.target_graph,
            DeleteVaultNoteRequest {
                id: "created-note".to_owned(),
                expected_inventory_revision: revision(9),
            },
        )
        .expect("delete note");
        assert_eq!(
            deleted.target_graph.notes_snippets().notes(),
            Some(std::slice::from_ref(&existing_note))
        );
        assert_eq!(deleted.target_graph.port_forward_rules().len(), 1);
    }

    #[test]
    fn snippet_crud_preserves_notes_hosts_and_port_forwards() {
        let (graph, host, existing_note, existing_snippet) = full_graph();
        let created = prepare_snippet_creation(
            graph,
            CreateSavedSnippetRequest {
                expected_inventory_revision: revision(7),
                draft: snippet_draft("Created", Some("new-package")),
            },
            SavedSnippetId::from_opaque("created-snippet").expect("snippet ID"),
        )
        .expect("create snippet");
        assert_eq!(created.target_graph.hosts(), std::slice::from_ref(&host));
        assert_eq!(created.target_graph.port_forward_rules().len(), 1);
        assert_eq!(
            created.target_graph.notes_snippets().notes(),
            Some(std::slice::from_ref(&existing_note))
        );
        assert_eq!(
            created.target_graph.notes_snippets().snippet_packages(),
            Some(&["existing-package".to_owned()][..])
        );

        let updated = prepare_snippet_update(
            created.target_graph,
            UpdateSavedSnippetRequest {
                id: "created-snippet".to_owned(),
                expected_inventory_revision: revision(8),
                draft: snippet_draft("Updated", None),
            },
        )
        .expect("update snippet");
        assert_eq!(
            updated
                .target_graph
                .notes_snippets()
                .snippets()
                .expect("snippets")
                .iter()
                .find(|snippet| snippet.id().as_str() == "created-snippet")
                .expect("updated snippet")
                .label(),
            "Updated"
        );

        let deleted = prepare_snippet_deletion(
            updated.target_graph,
            DeleteSavedSnippetRequest {
                id: "created-snippet".to_owned(),
                expected_inventory_revision: revision(9),
            },
        )
        .expect("delete snippet");
        assert_eq!(
            deleted.target_graph.notes_snippets().snippets(),
            Some(std::slice::from_ref(&existing_snippet))
        );
        assert_eq!(deleted.target_graph.port_forward_rules().len(), 1);
    }

    #[test]
    fn complete_inventory_cas_rejects_a_second_notes_snippets_writer() {
        let directory = tempfile::tempdir().expect("temporary store");
        let store = SavedHostStore::open(directory.path()).expect("store");
        let empty = store
            .confirm_current_snapshot_durability()
            .expect("empty snapshot");
        let (graph, _, _, _) = full_graph();
        let seed_plan = store
            .plan_graph_replacement(empty.revision().clone(), &graph)
            .expect("seed plan");
        let seeded = store
            .commit_planned_graph_replacement(seed_plan, graph)
            .expect("seed graph");

        let note = prepare_note_creation(
            seeded.graph().clone(),
            CreateVaultNoteRequest {
                expected_inventory_revision: seeded.revision().clone(),
                draft: note_draft("Writer one", None),
            },
            SavedVaultNoteId::from_opaque("writer-one-note").expect("note ID"),
            300.0,
        )
        .expect("first mutation");
        let snippet = prepare_snippet_creation(
            seeded.graph().clone(),
            CreateSavedSnippetRequest {
                expected_inventory_revision: seeded.revision().clone(),
                draft: snippet_draft("Writer two", None),
            },
            SavedSnippetId::from_opaque("writer-two-snippet").expect("snippet ID"),
        )
        .expect("second mutation");

        let note_plan = store
            .plan_graph_replacement(note.expected_inventory_revision, &note.target_graph)
            .expect("first plan");
        store
            .commit_planned_graph_replacement(note_plan, note.target_graph)
            .expect("first commit");
        assert!(matches!(
            store.plan_graph_replacement(
                snippet.expected_inventory_revision,
                &snippet.target_graph,
            ),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
    }

    #[test]
    fn renderer_contract_normalizes_absent_arrays_and_rejects_forged_ownership_fields() {
        let projection = NotesSnippetsCatalog::from_graph(revision(1), &SavedVaultGraph::default());
        let json = serde_json::to_value(projection).expect("catalog JSON");
        assert_eq!(json["notes"], serde_json::json!([]));
        assert_eq!(json["noteGroups"], serde_json::json!([]));
        assert_eq!(json["snippets"], serde_json::json!([]));
        assert_eq!(json["snippetPackages"], serde_json::json!([]));

        let inventory = serde_json::to_value(revision(2)).expect("inventory JSON");
        assert!(
            serde_json::from_value::<CreateVaultNoteRequest>(serde_json::json!({
                "expectedInventoryRevision": inventory,
                "draft": {
                    "id": "renderer-forged-note",
                    "title": "Title",
                    "content": "Body",
                    "createdAt": 1,
                    "updatedAt": 2
                }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateSavedSnippetRequest>(serde_json::json!({
                "expectedInventoryRevision": serde_json::to_value(revision(3))
                    .expect("inventory JSON"),
                "draft": {
                    "id": "renderer-forged-snippet",
                    "label": "Label",
                    "command": "echo safe"
                }
            }))
            .is_err()
        );
    }
}
