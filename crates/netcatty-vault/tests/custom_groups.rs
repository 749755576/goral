use netcatty_vault::{
    SavedGroupCatalog, SavedHostStore, SavedVaultGraph, SavedVaultImportDisposition,
};

fn catalog(paths: &[&str]) -> SavedGroupCatalog {
    SavedGroupCatalog::from_paths(paths.iter().copied()).expect("custom group catalog")
}

#[test]
#[should_panic(expected = "custom groups require SavedVaultGraph::into_current_parts")]
fn legacy_complete_parts_cannot_silently_discard_custom_groups() {
    let graph = SavedVaultGraph::default().with_group_catalog(Some(catalog(&["Empty/Leaf"])));
    let _ = graph.into_complete_parts();
}

#[test]
fn explicit_empty_custom_groups_is_distinct_from_an_absent_catalog_and_is_durable() {
    let root = tempfile::tempdir().expect("temporary root");
    let vault = root.path().join("vault");
    let store = SavedHostStore::open(&vault).expect("open store");
    assert!(
        store
            .graph()
            .expect("initial graph")
            .group_catalog()
            .is_none()
    );

    let candidate = SavedVaultGraph::default().with_group_catalog(Some(catalog(&[])));
    let assessment = store
        .assess_graph_import(&candidate)
        .expect("assess explicit empty catalog");
    assert!(assessment.custom_group_dispositions().is_empty());
    let plan = store
        .plan_graph_import(assessment.into_revision(), &candidate)
        .expect("plan explicit empty catalog");
    assert!(plan.has_changes());
    let committed = store
        .commit_planned_graph_import(plan, candidate.clone())
        .expect("commit explicit empty catalog");
    assert_eq!(
        committed
            .imported()
            .group_catalog()
            .expect("published catalog")
            .len(),
        0
    );
    let committed_revision = committed.revision().clone();

    let repeat = store
        .commit_graph_import(committed_revision, candidate)
        .expect("repeat explicit empty import");
    assert!(repeat.imported().group_catalog().is_none());
    assert_eq!(repeat.revision(), committed.revision());
    drop(store);

    let reopened = SavedHostStore::open(&vault).expect("reopen store");
    assert_eq!(
        reopened
            .graph()
            .expect("reopened graph")
            .group_catalog()
            .expect("explicit empty catalog")
            .len(),
        0
    );
}

#[test]
fn custom_group_import_stably_appends_paths_and_reports_duplicates() {
    let root = tempfile::tempdir().expect("temporary root");
    let vault = root.path().join("vault");
    let store = SavedHostStore::open(&vault).expect("open store");

    let first =
        SavedVaultGraph::default().with_group_catalog(Some(catalog(&["Ops/DB", "Empty/Leaf"])));
    let assessment = store.assess_graph_import(&first).expect("first assessment");
    assert_eq!(
        assessment.custom_group_dispositions(),
        &[
            SavedVaultImportDisposition::Importable,
            SavedVaultImportDisposition::Importable,
        ]
    );
    let first_commit = store
        .commit_graph_import(assessment.into_revision(), first)
        .expect("first import");
    assert_eq!(
        first_commit
            .imported()
            .group_catalog()
            .expect("first additions")
            .explicit_paths()
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>(),
        ["Ops/DB", "Empty/Leaf"]
    );

    let second =
        SavedVaultGraph::default().with_group_catalog(Some(catalog(&["Ops//DB", "Empty/Another"])));
    let assessment = store
        .assess_graph_import(&second)
        .expect("second assessment");
    assert_eq!(
        assessment.custom_group_dispositions(),
        &[
            SavedVaultImportDisposition::Duplicate,
            SavedVaultImportDisposition::Importable,
        ]
    );
    let second_commit = store
        .commit_graph_import(assessment.into_revision(), second)
        .expect("second import");
    assert_eq!(
        second_commit
            .imported()
            .group_catalog()
            .expect("second additions")
            .explicit_paths()[0]
            .as_str(),
        "Empty/Another"
    );
    drop(store);

    let reopened = SavedHostStore::open(&vault).expect("reopen store");
    assert_eq!(
        reopened
            .graph()
            .expect("reopened graph")
            .group_catalog()
            .expect("stored custom groups")
            .explicit_paths()
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>(),
        ["Ops/DB", "Empty/Leaf", "Empty/Another"]
    );
}
