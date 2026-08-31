use netcatty_migration::parse_legacy_vault_str;
use serde_json::{Value, json};

#[test]
fn legacy_host_visual_metadata_survives_the_safe_import_boundary() {
    let source = json!([{
        "id": "legacy-visual-host",
        "label": "Visual host",
        "hostname": "visual.example.test",
        "port": 22,
        "username": "root",
        "protocol": "ssh",
        "authMethod": "password",
        "authPolicyVersion": 1,
        "password": "discarded-by-policy",
        "savePassword": false,
        "os": "linux",
        "distro": "Ubuntu 24.04 LTS",
        "distroMode": "manual",
        "manualDistro": "rocky",
        "iconMode": "custom",
        "iconId": "database",
        "iconColorMode": "manual",
        "iconColor": "violet",
        "iconColorCustom": "#12Ab34"
    }]);
    let document = parse_legacy_vault_str(&source.to_string(), 1)
        .expect("legacy host with safe visual metadata");
    let candidate = document.candidates().first().expect("host candidate");
    let host = candidate.host();
    let fields = host.compatibility_fields();

    for (key, expected) in [
        ("os", json!("linux")),
        ("distro", json!("Ubuntu 24.04 LTS")),
        ("distroMode", json!("manual")),
        ("manualDistro", json!("rocky")),
        ("iconMode", json!("custom")),
        ("iconId", json!("database")),
        ("iconColorMode", json!("manual")),
        ("iconColor", json!("violet")),
        ("iconColorCustom", json!("#12Ab34")),
    ] {
        assert_eq!(fields.get(key), Some(&expected), "field {key}");
    }

    let serialized = serde_json::to_value(host).expect("safe SavedHost serialization");
    assert_eq!(serialized["distro"], "Ubuntu 24.04 LTS");
    assert_eq!(serialized["iconId"], "database");
    assert_eq!(serialized.get("password"), None);
    assert_eq!(
        serialized["hasSavedCredential"],
        Value::Bool(false),
        "imported visual metadata must not turn a legacy password hint into custody proof"
    );
}
