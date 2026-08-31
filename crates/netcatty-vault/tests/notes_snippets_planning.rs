use std::collections::{BTreeMap, BTreeSet};

use netcatty_vault::{
    SavedHost, SavedHostDraft, SavedHostId, SavedHostStore, SavedNoteGroupPath,
    SavedNotesSnippetsCatalog, SavedSnippet, SavedSnippetDraft, SavedSnippetKind,
    SavedSnippetTargetGroupPath, SavedVaultGraph, SavedVaultNote, SavedVaultNoteDraft,
};

fn host_id(value: &str) -> SavedHostId {
    SavedHostId::from_opaque(value).expect("host ID")
}

#[test]
fn public_api_builds_and_plans_the_host_independent_catalog_without_a_store() {
    let mut snippet = SavedSnippetDraft::new("snippet-1", "Deploy", "echo deploy");
    snippet.targets = Some(vec!["legacy-host".to_owned()]);
    snippet.target_groups = Some(vec![r" Team\Production ".to_owned()]);

    let mut note = SavedVaultNoteDraft::new("note-1", "Runbook", "body", 1.0, 2.0);
    note.linked_host_ids = Some(vec!["legacy-host".to_owned()]);
    note.group = Some(r" Team / Runbooks\SSH ".to_owned());

    let catalog = SavedNotesSnippetsCatalog::from_parts(
        Some(vec![SavedSnippet::from_draft(snippet).expect("snippet")]),
        Some(vec!["Team package".to_owned()]),
        Some(vec![SavedVaultNote::from_draft(note).expect("note")]),
        Some(vec![r" Team / Runbooks\SSH ".to_owned()]),
    )
    .expect("catalog");

    let plan = catalog
        .plan_host_id_remap(
            &BTreeMap::from([(host_id("legacy-host"), host_id("native-host"))]),
            &BTreeSet::from([host_id("native-host")]),
        )
        .expect("remap plan");

    assert_eq!(plan.remapped_snippet_targets(), 1);
    assert_eq!(plan.remapped_note_links(), 1);
    assert_eq!(
        plan.catalog().snippets().expect("snippets")[0]
            .target_groups()
            .expect("target groups")[0]
            .as_str(),
        "Team/Production"
    );
    assert_eq!(
        plan.catalog().notes().expect("notes")[0]
            .group()
            .expect("group")
            .as_str(),
        r"Team/Runbooks\SSH"
    );
}

#[test]
fn public_group_types_cannot_cross_normalizer_domains() {
    let note = SavedNoteGroupPath::new(r" Team\Production ").expect("note group");
    let snippet =
        SavedSnippetTargetGroupPath::new(r" Team\Production ").expect("snippet target group");

    assert_eq!(note.as_str(), r"Team\Production");
    assert_eq!(snippet.as_str(), "Team/Production");
}

#[test]
fn public_graph_api_commits_the_complete_notes_snippets_transaction() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = SavedHostStore::open(root.path().join("vault")).expect("open store");
    let mut host = SavedHost::from_draft(
        SavedHostDraft::ssh_password("notes.example.com", "alice"),
        1,
    )
    .expect("host");
    host.id = host_id("notes-host");

    let mut snippet = SavedSnippetDraft::new("script-1", "Login", "echo ready");
    snippet.kind = Some(SavedSnippetKind::Script);
    snippet.targets = Some(vec![host.id.as_str().to_owned()]);
    let mut note = SavedVaultNoteDraft::new("note-1", "Runbook", "body", 1.0, 2.0);
    note.linked_host_ids = Some(vec![host.id.as_str().to_owned()]);
    let catalog = SavedNotesSnippetsCatalog::from_parts(
        Some(vec![SavedSnippet::from_draft(snippet).expect("snippet")]),
        Some(vec!["package".to_owned()]),
        Some(vec![SavedVaultNote::from_draft(note).expect("note")]),
        Some(vec!["Runbooks".to_owned()]),
    )
    .expect("catalog");
    let graph = SavedVaultGraph::new_with_notes_snippets(
        vec![host],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        catalog.clone(),
    );
    let assessment = store.assess_graph_import(&graph).expect("assessment");
    let plan = store
        .plan_graph_import(assessment.into_revision(), &graph)
        .expect("plan");
    assert!(plan.has_changes());
    let committed = store
        .commit_planned_graph_import(plan, graph)
        .expect("commit");
    assert_eq!(committed.imported().notes_snippets(), &catalog);
    assert_eq!(
        store.graph().expect("stored graph").notes_snippets(),
        &catalog
    );
}
