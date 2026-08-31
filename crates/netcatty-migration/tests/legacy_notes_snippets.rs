use std::collections::BTreeMap;

use netcatty_migration::{
    LegacyNotesSnippetsDisposition, LegacyNotesSnippetsError, LegacyNotesSnippetsErrorCode,
    LegacyNotesSnippetsRecordKind, parse_legacy_notes_snippets_catalogs, parse_legacy_vault_str,
    plan_legacy_notes_snippets_import,
};
use netcatty_vault::{
    SavedGroupConfig, SavedGroupDefaults, SavedGroupId, SavedGroupOpaqueId, SavedGroupOverride,
    SavedGroupPath, SavedHost, SavedHostId, SavedNotesSnippetsCatalog, SavedSnippet,
    SavedSnippetKind, SavedVaultNote,
};
use serde_json::json;

const NOW_MS: u64 = 1_700_000_000_000;
const SOURCE_SHA256: [u8; 32] = [0x5a; 32];

fn host_id(value: &str) -> SavedHostId {
    SavedHostId::from_opaque(value).expect("host ID")
}

fn saved_host(id: &str, script_id: Option<&str>, all_script_edges: bool) -> SavedHost {
    let mut value = json!({
        "id": id,
        "label": "Migration host",
        "hostname": "migration.example.test",
        "port": 22,
        "username": "alice",
        "protocol": "ssh",
        "authMethod": "password",
        "authPolicyVersion": 1,
        "createdAt": 1,
        "updatedAt": 1
    });
    if let Some(script_id) = script_id {
        value["loginScriptId"] = json!(script_id);
        if all_script_edges {
            value["connectScriptIds"] = json!([script_id]);
            value["outputTriggers"] = json!([{
                "id": "private-output-trigger-id",
                "pattern": "private-output-pattern",
                "scriptId": script_id,
                "enabled": false
            }]);
        }
    }
    serde_json::from_value(value).expect("saved host")
}

fn snippet(id: &str, label: &str, command: &str, kind: SavedSnippetKind) -> SavedSnippet {
    serde_json::from_value(json!({
        "id": id,
        "label": label,
        "command": command,
        "kind": match kind {
            SavedSnippetKind::Snippet => "snippet",
            SavedSnippetKind::Script => "script",
        }
    }))
    .expect("saved snippet")
}

fn note(id: &str, title: &str, content: &str) -> SavedVaultNote {
    serde_json::from_value(json!({
        "id": id,
        "title": title,
        "content": content,
        "createdAt": 1,
        "updatedAt": 1
    }))
    .expect("saved note")
}

fn saved_group(id: &str, path: &str, script_id: &str) -> SavedGroupConfig {
    let mut defaults = SavedGroupDefaults::default();
    defaults.login_script_id = SavedGroupOverride::Set(
        SavedGroupOpaqueId::from_opaque(script_id).expect("group script ID"),
    );
    SavedGroupConfig::from_parts(
        SavedGroupId::from_opaque(id).expect("group ID"),
        1,
        SavedGroupPath::new(path).expect("group path"),
        defaults,
        1,
        1,
    )
    .expect("saved group")
}

fn catalog(
    snippets: Option<Vec<SavedSnippet>>,
    snippet_packages: Option<Vec<String>>,
    notes: Option<Vec<SavedVaultNote>>,
    note_groups: Option<Vec<String>>,
) -> SavedNotesSnippetsCatalog {
    SavedNotesSnippetsCatalog::from_parts(snippets, snippet_packages, notes, note_groups)
        .expect("notes/scripts catalog")
}

fn assert_error_safe(error: LegacyNotesSnippetsError, forbidden: &[&str]) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    let json = serde_json::to_string(&error).expect("safe error JSON");
    for value in forbidden {
        assert!(!display.contains(value), "Display leaked source data");
        assert!(!debug.contains(value), "Debug leaked source data");
        assert!(!json.contains(value), "serialized error leaked source data");
    }
}

#[test]
fn full_document_group_ids_are_stable_across_inspection_and_commit_reparse() {
    let source = json!({
        "hosts": [],
        "groupConfigs": [{
            "path": "Stable/Operations",
            "loginScriptId": "stable-script"
        }],
        "snippets": [{
            "id": "stable-script",
            "label": "Stable script",
            "command": "echo stable",
            "kind": "script"
        }]
    })
    .to_string();
    let parse_id = |source: &str, now_ms| {
        parse_legacy_vault_str(source, now_ms)
            .expect("legacy document")
            .group_config_candidates()
            .expect("group configs")[0]
            .config()
            .id
            .as_str()
            .to_owned()
    };

    let inspection_id = parse_id(&source, NOW_MS);
    let commit_id = parse_id(&source, NOW_MS.saturating_add(60_000));
    assert_eq!(inspection_id, commit_id);

    let other_source = source.replace("echo stable", "echo another source");
    assert_ne!(inspection_id, parse_id(&other_source, NOW_MS));

    let other_path = source.replace("Stable/Operations", "Stable/Other");
    assert_ne!(inspection_id, parse_id(&other_path, NOW_MS));
}

#[test]
fn document_and_planner_preserve_each_absent_or_explicit_empty_scope() {
    let absent = parse_legacy_notes_snippets_catalogs(None, None, None, None, NOW_MS)
        .expect("absent catalogs");
    assert!(absent.catalog().is_absent());

    let explicit = parse_legacy_notes_snippets_catalogs(
        Some(json!([])),
        Some(json!([])),
        Some(json!([])),
        Some(json!([])),
        NOW_MS,
    )
    .expect("explicit empty catalogs");
    assert_eq!(explicit.catalog().snippets(), Some([].as_slice()));
    assert_eq!(explicit.catalog().snippet_packages(), Some([].as_slice()));
    assert_eq!(explicit.catalog().notes(), Some([].as_slice()));
    assert_eq!(explicit.catalog().note_groups(), Some([].as_slice()));

    let first = plan_legacy_notes_snippets_import(
        &explicit,
        &SavedNotesSnippetsCatalog::default(),
        &[],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect("first presence-scope projection");
    assert!(first.assessment().snippets_present);
    assert!(first.assessment().snippet_packages_present);
    assert!(first.assessment().notes_present);
    assert!(first.assessment().note_groups_present);
    assert_eq!(first.assessment().catalog_scope_change_count, 4);
    assert!(first.assessment().has_changes());

    let already_present = catalog(
        Some(vec![snippet(
            "kept-script",
            "Kept script",
            "echo kept",
            SavedSnippetKind::Script,
        )]),
        Some(vec!["kept-package".to_owned()]),
        Some(vec![note("kept-note", "Kept note", "kept body")]),
        Some(vec!["Kept group".to_owned()]),
    );
    let repeated = plan_legacy_notes_snippets_import(
        &explicit,
        &already_present,
        &[],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect("append-scope empty projection");
    assert_eq!(repeated.assessment().catalog_scope_change_count, 0);
    assert!(!repeated.assessment().has_changes());

    let document = parse_legacy_vault_str(
        &json!({
            "hosts": [],
            "snippets": [],
            "snippetPackages": [],
            "notes": [],
            "noteGroups": []
        })
        .to_string(),
        NOW_MS,
    )
    .expect("document");
    let attached = document.notes_snippets_candidates().catalog();
    assert_eq!(attached.snippets(), Some([].as_slice()));
    assert_eq!(attached.snippet_packages(), Some([].as_slice()));
    assert_eq!(attached.notes(), Some([].as_slice()));
    assert_eq!(attached.note_groups(), Some([].as_slice()));

    let document = parse_legacy_vault_str(
        &json!({
            "hosts": [{
                "id": "document-host",
                "label": "Document host",
                "hostname": "document.example.test",
                "username": "alice",
                "authMethod": "password",
                "authPolicyVersion": 1,
                "outputTriggers": [{
                    "id": "document-trigger-id",
                    "pattern": "document-trigger-pattern",
                    "scriptId": "document-script"
                }]
            }],
            "snippets": [{
                "id": "document-script",
                "label": "Document script",
                "command": "echo document",
                "kind": "script"
            }]
        })
        .to_string(),
        NOW_MS,
    )
    .expect("document with a complete legacy output trigger");
    assert_eq!(
        document.candidates().len(),
        1,
        "preview: {:?}",
        document.preview()
    );
    assert_eq!(
        document
            .notes_snippets_candidates()
            .catalog()
            .snippets()
            .expect("document snippets")
            .len(),
        1
    );
    let host = document.candidates()[0].host();
    let trigger = &host.compatibility_fields()["outputTriggers"][0];
    assert_eq!(trigger["id"], json!("document-trigger-id"));
    assert_eq!(trigger["pattern"], json!("document-trigger-pattern"));
    assert_eq!(trigger["scriptId"], json!("document-script"));
    let round_trip: SavedHost = serde_json::from_value(
        serde_json::to_value(host).expect("serialize document candidate host"),
    )
    .expect("round-trip document candidate host");
    assert_eq!(&round_trip, host);
    let (
        _preview,
        hosts,
        _reference_keys,
        _managed_keys,
        _key_identities,
        _password_identities,
        _proxy_profiles,
        groups,
        notes_snippets,
    ) = document.into_current_graph_parts();
    assert_eq!(hosts.len(), 1);
    assert!(groups.custom_groups().is_none());
    assert!(groups.group_configs().is_none());
    assert_eq!(
        notes_snippets
            .catalog()
            .snippets()
            .expect("consumed document snippets")
            .len(),
        1
    );
}

#[test]
fn absent_snippets_preserve_legacy_host_script_fields_but_explicit_empty_closes_them() {
    let host = saved_host("legacy-host", Some("unavailable-legacy-script"), true);
    let group = saved_group("legacy-group", "Legacy/Group", "unavailable-legacy-script");
    let absent = parse_legacy_notes_snippets_catalogs(None, None, None, None, NOW_MS)
        .expect("absent catalogs");
    let plan = plan_legacy_notes_snippets_import(
        &absent,
        &SavedNotesSnippetsCatalog::default(),
        std::slice::from_ref(&host),
        &[],
        std::slice::from_ref(&group),
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect("absent snippet scope retains opaque legacy compatibility fields");
    assert_eq!(plan.hosts(), std::slice::from_ref(&host));
    assert_eq!(plan.groups(), std::slice::from_ref(&group));
    assert!(!plan.assessment().snippets_present);
    assert!(!plan.assessment().has_changes());

    let explicit_empty =
        parse_legacy_notes_snippets_catalogs(Some(json!([])), None, None, None, NOW_MS)
            .expect("empty snippet scope");
    let error = plan_legacy_notes_snippets_import(
        &explicit_empty,
        &SavedNotesSnippetsCatalog::default(),
        &[host],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect_err("an included empty snippet scope must reject a dangling script edge");
    assert_eq!(
        error.code,
        LegacyNotesSnippetsErrorCode::DanglingScriptReference
    );
    assert_eq!(error.record_kind, Some(LegacyNotesSnippetsRecordKind::Host));
}

#[test]
fn conflicting_ids_remap_deterministically_and_rewrite_the_complete_edge_closure() {
    let source_script_id = "private-conflicting-script-id";
    let source_note_id = "private-conflicting-note-id";
    let current_script = snippet(
        source_script_id,
        "Current private label",
        "echo current-private-command",
        SavedSnippetKind::Script,
    );
    let current_note = note(
        source_note_id,
        "Current private title",
        "current private note body",
    );
    let current = catalog(
        Some(vec![current_script]),
        None,
        Some(vec![current_note]),
        None,
    );
    let candidates = parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": source_script_id,
            "label": "Imported private label",
            "command": "echo imported-private-command",
            "kind": "script",
            "targets": ["private-legacy-host-id", "final-host"]
        }])),
        None,
        Some(json!([{
            "id": source_note_id,
            "title": "Imported private title",
            "content": "imported private note body",
            "linkedHostIds": ["private-legacy-host-id"],
            "createdAt": 1,
            "updatedAt": 1
        }])),
        None,
        NOW_MS,
    )
    .expect("candidate catalogs");
    let candidate_host = saved_host("final-host", Some(source_script_id), true);
    let current_host = saved_host("current-host", Some(source_script_id), false);
    let candidate_group = saved_group(
        "private-candidate-group-id",
        "Private/Candidate Group",
        source_script_id,
    );
    let current_group = saved_group(
        "private-current-group-id",
        "Private/Current Group",
        source_script_id,
    );
    let host_remap = BTreeMap::from([(host_id("private-legacy-host-id"), host_id("final-host"))]);

    let first = plan_legacy_notes_snippets_import(
        &candidates,
        &current,
        std::slice::from_ref(&candidate_host),
        std::slice::from_ref(&current_host),
        std::slice::from_ref(&candidate_group),
        std::slice::from_ref(&current_group),
        &host_remap,
        &SOURCE_SHA256,
    )
    .expect("complete remap plan");
    let second = plan_legacy_notes_snippets_import(
        &candidates,
        &current,
        std::slice::from_ref(&candidate_host),
        std::slice::from_ref(&current_host),
        std::slice::from_ref(&candidate_group),
        std::slice::from_ref(&current_group),
        &host_remap,
        &SOURCE_SHA256,
    )
    .expect("repeat deterministic plan");
    assert_eq!(first.assessment(), second.assessment());
    assert_eq!(first.catalog(), second.catalog());
    assert_eq!(first.hosts(), second.hosts());
    assert_eq!(first.groups(), second.groups());
    assert_eq!(
        first.assessment().snippet_dispositions,
        [LegacyNotesSnippetsDisposition::RemappedImportable]
    );
    assert_eq!(
        first.assessment().note_dispositions,
        [LegacyNotesSnippetsDisposition::RemappedImportable]
    );
    assert_eq!(first.assessment().remapped_snippet_id_count, 1);
    assert_eq!(first.assessment().remapped_note_id_count, 1);
    assert_eq!(first.assessment().remapped_snippet_target_count, 1);
    assert_eq!(first.assessment().remapped_note_link_count, 1);
    assert_eq!(first.assessment().remapped_host_script_edge_count, 3);
    assert_eq!(first.assessment().remapped_group_script_edge_count, 1);

    let projected_script = &first.catalog().snippets().expect("snippets")[0];
    let projected_script_id = projected_script.id().as_str();
    assert_ne!(projected_script_id, source_script_id);
    assert_eq!(
        projected_script
            .targets()
            .expect("targets")
            .iter()
            .map(SavedHostId::as_str)
            .collect::<Vec<_>>(),
        ["final-host"]
    );
    let projected_note = &first.catalog().notes().expect("notes")[0];
    assert_ne!(projected_note.id().as_str(), source_note_id);
    assert_eq!(
        projected_note
            .linked_host_ids()
            .expect("links")
            .iter()
            .map(SavedHostId::as_str)
            .collect::<Vec<_>>(),
        ["final-host"]
    );

    let fields = first.hosts()[0].compatibility_fields();
    assert_eq!(fields["loginScriptId"], json!(projected_script_id));
    assert_eq!(fields["connectScriptIds"], json!([projected_script_id]));
    assert_eq!(
        fields["outputTriggers"][0]["scriptId"],
        json!(projected_script_id)
    );
    assert_eq!(
        fields["outputTriggers"][0]["id"],
        json!("private-output-trigger-id")
    );
    assert_eq!(
        fields["outputTriggers"][0]["pattern"],
        json!("private-output-pattern")
    );
    assert_eq!(
        current_host.compatibility_fields()["loginScriptId"],
        json!(source_script_id),
        "existing host edges must continue to target the existing conflicting script"
    );
    let SavedGroupOverride::Set(projected_group_script_id) =
        &first.groups()[0].defaults.login_script_id
    else {
        panic!("projected group script edge was cleared");
    };
    assert_eq!(projected_group_script_id.as_str(), projected_script_id);
    let SavedGroupOverride::Set(current_group_script_id) = &current_group.defaults.login_script_id
    else {
        panic!("current group script edge was cleared");
    };
    assert_eq!(current_group_script_id.as_str(), source_script_id);

    let safe_debug = format!("{first:?}");
    let safe_assessment_json = serde_json::to_string(first.assessment()).expect("assessment JSON");
    for forbidden in [
        source_script_id,
        source_note_id,
        "Imported private label",
        "echo imported-private-command",
        "Imported private title",
        "imported private note body",
        "private-legacy-host-id",
        "private-output-trigger-id",
        "private-output-pattern",
        "private-candidate-group-id",
        "Private/Candidate Group",
        projected_script_id,
        projected_note.id().as_str(),
    ] {
        assert!(
            !safe_debug.contains(forbidden),
            "plan Debug leaked source data"
        );
        assert!(
            !safe_assessment_json.contains(forbidden),
            "assessment JSON leaked source data"
        );
    }
}

#[test]
fn repeated_conflicting_import_is_a_remapped_duplicate_and_has_no_catalog_changes() {
    let source_script_id = "repeat-private-script-id";
    let source_note_id = "repeat-private-note-id";
    let initial = catalog(
        Some(vec![snippet(
            source_script_id,
            "Existing label",
            "echo existing",
            SavedSnippetKind::Script,
        )]),
        Some(vec!["existing-package".to_owned()]),
        Some(vec![note(
            source_note_id,
            "Existing title",
            "existing note body",
        )]),
        Some(vec!["Existing group".to_owned()]),
    );
    let candidates = parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": source_script_id,
            "label": "Imported label",
            "command": "echo imported",
            "kind": "script"
        }])),
        Some(json!(["imported-package"])),
        Some(json!([{
            "id": source_note_id,
            "title": "Imported title",
            "content": "imported note body"
        }])),
        Some(json!(["Imported group"])),
        NOW_MS,
    )
    .expect("candidates");
    assert_eq!(
        candidates.catalog().notes().expect("candidate notes")[0].created_at(),
        0.0,
        "missing legacy timestamps use a stable fallback"
    );
    let first = plan_legacy_notes_snippets_import(
        &candidates,
        &initial,
        &[],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect("first plan");

    let mut final_snippets = initial.snippets().expect("initial snippets").to_vec();
    final_snippets.extend_from_slice(first.catalog().snippets().expect("imported snippets"));
    let mut final_notes = initial.notes().expect("initial notes").to_vec();
    final_notes.extend_from_slice(first.catalog().notes().expect("imported notes"));
    let final_catalog = catalog(
        Some(final_snippets),
        Some(vec![
            "existing-package".to_owned(),
            "imported-package".to_owned(),
        ]),
        Some(final_notes),
        Some(vec![
            "Existing group".to_owned(),
            "Imported group".to_owned(),
        ]),
    );

    let reparsed = parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": source_script_id,
            "label": "Imported label",
            "command": "echo imported",
            "kind": "script"
        }])),
        Some(json!(["imported-package"])),
        Some(json!([{
            "id": source_note_id,
            "title": "Imported title",
            "content": "imported note body"
        }])),
        Some(json!(["Imported group"])),
        NOW_MS + 86_400_000,
    )
    .expect("same source reparsed at a later wall-clock time");
    let repeated = plan_legacy_notes_snippets_import(
        &reparsed,
        &final_catalog,
        &[],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect("repeated plan");
    assert_eq!(
        repeated.assessment().snippet_dispositions,
        [LegacyNotesSnippetsDisposition::RemappedDuplicate]
    );
    assert_eq!(
        repeated.assessment().note_dispositions,
        [LegacyNotesSnippetsDisposition::RemappedDuplicate]
    );
    assert_eq!(repeated.assessment().importable_snippet_package_count, 0);
    assert_eq!(repeated.assessment().duplicate_snippet_package_count, 1);
    assert_eq!(repeated.assessment().importable_note_group_count, 0);
    assert_eq!(repeated.assessment().duplicate_note_group_count, 1);
    assert_eq!(repeated.assessment().catalog_scope_change_count, 0);
    assert!(!repeated.assessment().has_changes());
    assert_eq!(
        repeated.catalog().snippets().expect("repeated snippets")[0].id(),
        first.catalog().snippets().expect("first snippets")[0].id()
    );
    assert_eq!(
        repeated.catalog().notes().expect("repeated notes")[0].id(),
        first.catalog().notes().expect("first notes")[0].id()
    );
}

#[test]
fn dangling_or_incompatible_edges_reject_the_whole_batch_with_payload_free_errors() {
    let missing_host_id = "private-missing-host-id";
    let private_script_id = "private-non-script-id";
    let private_label = "private snippet label";
    let private_command = "echo private command";
    let candidates = parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": private_script_id,
            "label": private_label,
            "command": private_command,
            "kind": "snippet",
            "targets": ["valid-host", missing_host_id]
        }])),
        None,
        Some(json!([{
            "id": "private-note-id",
            "title": "private note title",
            "content": "private note body",
            "linkedHostIds": ["valid-host"],
            "createdAt": 1,
            "updatedAt": 1
        }])),
        None,
        NOW_MS,
    )
    .expect("candidates");
    let valid_host = saved_host("valid-host", Some(private_script_id), false);
    let error = plan_legacy_notes_snippets_import(
        &candidates,
        &SavedNotesSnippetsCatalog::default(),
        std::slice::from_ref(&valid_host),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect_err("one dangling host edge rejects the complete batch");
    assert_eq!(
        error.code,
        LegacyNotesSnippetsErrorCode::DanglingHostReference
    );
    assert_eq!(
        error.record_kind,
        Some(LegacyNotesSnippetsRecordKind::Snippet)
    );
    assert_eq!(error.record_index, Some(0));
    assert_eq!(error.reference_index, Some(1));
    assert_error_safe(
        error,
        &[
            missing_host_id,
            private_script_id,
            private_label,
            private_command,
            "private-note-id",
            "private note title",
            "private note body",
        ],
    );

    let incompatible = parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": private_script_id,
            "label": private_label,
            "command": private_command,
            "kind": "snippet"
        }])),
        None,
        None,
        None,
        NOW_MS,
    )
    .expect("incompatible candidates");
    let error = plan_legacy_notes_snippets_import(
        &incompatible,
        &SavedNotesSnippetsCatalog::default(),
        &[valid_host],
        &[],
        &[],
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect_err("host script relationship must target kind=script");
    assert_eq!(
        error.code,
        LegacyNotesSnippetsErrorCode::IncompatibleScriptReference
    );
    assert_error_safe(error, &[private_script_id, private_label, private_command]);

    let private_group_id = "private-group-id";
    let private_group_path = "Private/Group Path";
    let incompatible_group = saved_group(private_group_id, private_group_path, private_script_id);
    let error = plan_legacy_notes_snippets_import(
        &incompatible,
        &SavedNotesSnippetsCatalog::default(),
        &[],
        &[],
        std::slice::from_ref(&incompatible_group),
        &[],
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect_err("group login script relationship must target kind=script");
    assert_eq!(
        error.code,
        LegacyNotesSnippetsErrorCode::IncompatibleScriptReference
    );
    assert_eq!(
        error.record_kind,
        Some(LegacyNotesSnippetsRecordKind::Group)
    );
    assert_error_safe(
        error,
        &[
            private_group_id,
            private_group_path,
            private_script_id,
            private_label,
            private_command,
        ],
    );

    let explicit_empty =
        parse_legacy_notes_snippets_catalogs(Some(json!([])), None, None, None, NOW_MS)
            .expect("explicit empty snippets");
    let dangling_group = saved_group(
        "private-current-group-id",
        "Private/Current Group",
        "private-missing-group-script-id",
    );
    let error = plan_legacy_notes_snippets_import(
        &explicit_empty,
        &SavedNotesSnippetsCatalog::default(),
        &[],
        &[],
        &[],
        std::slice::from_ref(&dangling_group),
        &BTreeMap::new(),
        &SOURCE_SHA256,
    )
    .expect_err("an included snippet scope must close current group script edges");
    assert_eq!(
        error.code,
        LegacyNotesSnippetsErrorCode::DanglingScriptReference
    );
    assert_eq!(
        error.record_kind,
        Some(LegacyNotesSnippetsRecordKind::Group)
    );
    assert_error_safe(
        error,
        &[
            "private-current-group-id",
            "Private/Current Group",
            "private-missing-group-script-id",
        ],
    );

    let invalid_value = "private-invalid-enum-and-id";
    let parse_error = match parse_legacy_notes_snippets_catalogs(
        Some(json!([{
            "id": invalid_value,
            "label": "private invalid label",
            "command": "private invalid command",
            "kind": invalid_value
        }])),
        None,
        None,
        None,
        NOW_MS,
    ) {
        Ok(_) => panic!("invalid snippet kind was accepted"),
        Err(error) => error,
    };
    assert_eq!(
        parse_error.code,
        LegacyNotesSnippetsErrorCode::InvalidSnippets
    );
    assert_error_safe(
        parse_error,
        &[
            invalid_value,
            "private invalid label",
            "private invalid command",
        ],
    );
}
