use netcatty_vault::{
    SavedHost, SavedHostAuthentication, SavedHostDraft, SavedHostProtocol, SavedHostUpdate,
    SavedPasswordIdentityId, SavedSshKeyReferenceId, ValidationError,
};

#[test]
fn public_saved_host_planning_builds_complete_records_without_a_store_write() {
    let draft = SavedHostDraft::ssh_password("planned.example.test", "planned-user")
        .with_compatibility_field("hasSavedCredential", serde_json::json!(true))
        .expect("credential hint");
    let host = SavedHost::from_draft(draft, 10).expect("pure host construction");

    assert_eq!(host.revision, 1);
    assert_eq!(host.created_at, 10);
    assert_eq!(host.updated_at, 10);
    assert_eq!(
        host.compatibility_fields().get("hasSavedCredential"),
        Some(&serde_json::json!(true))
    );

    let mut update = SavedHostUpdate::default();
    update.label = Some("Planned replacement".to_owned());
    update = update
        .with_compatibility_field("hasSavedCredential", serde_json::json!(false))
        .expect("updated credential hint");
    let updated = host.apply_update(update, 20).expect("pure host update");

    assert_eq!(updated.id, host.id);
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.created_at, host.created_at);
    assert_eq!(updated.updated_at, 20);
    assert_eq!(updated.label, "Planned replacement");
    assert_eq!(
        updated.compatibility_fields().get("hasSavedCredential"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn public_saved_host_authentication_api_preserves_password_identity_fallback_and_switches_cleanly()
{
    let identity_id =
        SavedPasswordIdentityId::from_opaque("shared-login").expect("password identity ID");
    let host = SavedHost::from_draft(
        SavedHostDraft::ssh_password_identity(
            "identity.example.test",
            "host-user",
            identity_id.clone(),
            true,
        ),
        10,
    )
    .expect("password identity host");
    assert_eq!(
        host.authentication(),
        Ok(SavedHostAuthentication::PasswordIdentity {
            identity_id,
            has_saved_host_credential: true,
        })
    );
    assert_eq!(
        host.compatibility_fields().get("hasSavedCredential"),
        Some(&serde_json::json!(true))
    );

    let key_id = SavedSshKeyReferenceId::from_opaque("managed-certificate").expect("key ID");
    let certificate = host
        .apply_update(
            SavedHostUpdate::default().with_authentication(
                SavedHostAuthentication::ManagedCertificate {
                    key_id: key_id.clone(),
                },
            ),
            20,
        )
        .expect("switch to certificate");
    assert_eq!(
        certificate.authentication(),
        Ok(SavedHostAuthentication::ManagedCertificate { key_id })
    );
    assert!(
        !certificate
            .compatibility_fields()
            .contains_key("identityId")
    );
    assert!(
        !certificate
            .compatibility_fields()
            .contains_key("hasSavedCredential")
    );
}

#[test]
fn public_telnet_model_uses_telnet_defaults_and_keeps_ssh_fields_inactive_until_a_switch() {
    let key_id = SavedSshKeyReferenceId::from_opaque("legacy-telnet-key").expect("key ID");
    let mut draft = SavedHostDraft::telnet("console.example.test", "");
    draft.protocol = Some(SavedHostProtocol::compatible("TeLnEt"));
    let telnet = SavedHost::from_draft(
        draft
            .with_compatibility_field("identityFileId", serde_json::json!(key_id.as_str()))
            .expect("legacy SSH field"),
        10,
    )
    .expect("Telnet host");

    assert!(telnet.protocol.is_telnet());
    assert_eq!(telnet.protocol.as_str(), "telnet");
    assert_eq!(telnet.port, 23);
    assert!(telnet.username.is_empty());
    assert_eq!(telnet.auth_method.as_str(), "password");
    assert_eq!(
        telnet.authentication(),
        Err(ValidationError::UnsupportedProtocol)
    );
    assert_eq!(
        telnet.compatibility_fields().get("identityFileId"),
        Some(&serde_json::json!(key_id.as_str()))
    );

    let mut ssh_update = SavedHostUpdate::default();
    ssh_update.port = Some(22);
    ssh_update.protocol = Some(SavedHostProtocol::compatible("SSH"));
    ssh_update = ssh_update.with_authentication(SavedHostAuthentication::ManagedPrivateKey {
        key_id: key_id.clone(),
    });
    let ssh = telnet.apply_update(ssh_update, 20).expect("switch to SSH");
    assert!(ssh.protocol.is_ssh());
    assert_eq!(ssh.protocol.as_str(), "ssh");
    assert_eq!(
        ssh.authentication(),
        Ok(SavedHostAuthentication::ManagedPrivateKey {
            key_id: key_id.clone()
        })
    );

    let mut telnet_update = SavedHostUpdate::default();
    telnet_update.port = Some(23);
    telnet_update.protocol = Some(SavedHostProtocol::compatible("TELNET"));
    let telnet_again = ssh
        .apply_update(telnet_update, 30)
        .expect("switch back to Telnet");
    assert!(telnet_again.protocol.is_telnet());
    assert_eq!(
        telnet_again.authentication(),
        Err(ValidationError::UnsupportedProtocol)
    );
    assert_eq!(
        telnet_again.compatibility_fields().get("identityFileId"),
        Some(&serde_json::json!(key_id.as_str()))
    );
}

#[test]
fn unknown_protocols_remain_round_trip_readable_but_cannot_be_created_or_updated() {
    let encoded = serde_json::json!({
        "recordVersion": 1,
        "id": "legacy-plugin-host",
        "revision": 1,
        "label": "Legacy plugin host",
        "hostname": "legacy.example.test",
        "port": 2022,
        "username": "legacy-user",
        "protocol": "plugin-protocol",
        "authMethod": "plugin-auth",
        "authPolicyVersion": 1,
        "createdAt": 1,
        "updatedAt": 1,
        "pluginFlag": true
    });
    let host: SavedHost = serde_json::from_value(encoded.clone()).expect("legacy host");
    assert_eq!(serde_json::to_value(&host).expect("round trip"), encoded);
    let mut update = SavedHostUpdate::default();
    update.label = Some("Blocked mutation".to_owned());
    assert_eq!(
        host.apply_update(update, 2),
        Err(ValidationError::UnsupportedProtocol)
    );

    let mut draft = SavedHostDraft::ssh_password("new.example.test", "user");
    draft.protocol = Some(SavedHostProtocol::compatible("plugin-protocol"));
    assert_eq!(
        SavedHost::from_draft(draft, 2),
        Err(ValidationError::UnsupportedProtocol)
    );
}
