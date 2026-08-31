use netcatty_vault::{
    SavedHost, SavedHostDraft, SavedHostProtocol, SavedHostUpdate, SavedSerialBackspaceBehavior,
    SavedSerialConfig, SavedSerialDataBits, SavedSerialFlowControl, SavedSerialParity,
    SavedSerialStopBits, ValidationError,
};

#[test]
fn serial_hosts_round_trip_high_baud_rates_and_space_containing_paths() {
    for (path, baud_rate) in [("COM12", 115_200), ("/tmp/serial link", 921_600)] {
        let mut config = SavedSerialConfig::new(path, baud_rate).expect("serial config");
        config.data_bits = SavedSerialDataBits::Seven;
        config.stop_bits = SavedSerialStopBits::OnePointFive;
        config.parity = SavedSerialParity::Space;
        config.flow_control = SavedSerialFlowControl::XonXoff;
        config.local_echo = true;
        config.line_mode = true;
        config.backspace_behavior = Some(SavedSerialBackspaceBehavior::CtrlH);

        let host = SavedHost::from_draft(
            SavedHostDraft::serial(config.clone()).expect("serial draft"),
            10,
        )
        .expect("serial host");
        assert!(host.protocol.is_serial());
        assert_eq!(host.hostname, path);
        assert_eq!(host.port, baud_rate);
        assert_eq!(host.effective_serial_config(), Ok(config));
        assert_eq!(
            host.network_port(),
            Err(ValidationError::UnsupportedProtocol)
        );

        let encoded = serde_json::to_value(&host).expect("serial host JSON");
        assert_eq!(encoded["protocol"], "serial");
        assert_eq!(encoded["hostname"], path);
        assert_eq!(encoded["port"], baud_rate);
        assert_eq!(encoded["serialConfig"]["baudRate"], baud_rate);
        let decoded: SavedHost = serde_json::from_value(encoded).expect("serial host round trip");
        assert_eq!(decoded, host);
    }
}

#[test]
fn legacy_serial_host_without_config_uses_hostname_baud_and_exact_defaults() {
    let host: SavedHost = serde_json::from_value(serde_json::json!({
        "id": "legacy-serial",
        "label": "Legacy serial",
        "hostname": "COM42",
        "port": 921600,
        "username": "",
        "protocol": "serial",
        "createdAt": 1,
        "updatedAt": 1
    }))
    .expect("legacy Serial host");

    assert!(host.serial_config().expect("optional config").is_none());
    let effective = host.effective_serial_config().expect("effective config");
    assert_eq!(effective.path, "COM42");
    assert_eq!(effective.baud_rate, 921_600);
    assert_eq!(effective.data_bits, SavedSerialDataBits::Eight);
    assert_eq!(effective.stop_bits, SavedSerialStopBits::One);
    assert_eq!(effective.parity, SavedSerialParity::None);
    assert_eq!(effective.flow_control, SavedSerialFlowControl::None);
    assert!(!effective.local_echo);
    assert!(!effective.line_mode);
    assert_eq!(
        effective.backspace_behavior,
        Some(SavedSerialBackspaceBehavior::Default)
    );
}

#[test]
fn legacy_serial_config_repairs_a_stale_flattened_endpoint_on_read() {
    let host: SavedHost = serde_json::from_value(serde_json::json!({
        "id": "legacy-serial-stale-mirror",
        "label": "Legacy serial",
        "hostname": "stale-device",
        "port": 22,
        "username": "",
        "protocol": "serial",
        "createdAt": 1,
        "updatedAt": 1,
        "serialConfig": {
            "path": "/tmp/serial link",
            "baudRate": 921600
        }
    }))
    .expect("legacy Serial host with stale mirror");

    assert_eq!(host.hostname, "/tmp/serial link");
    assert_eq!(host.port, 921_600);
    assert_eq!(
        host.effective_serial_config()
            .expect("authoritative Serial config")
            .baud_rate,
        921_600
    );
}

#[test]
fn serial_updates_keep_flattened_endpoint_and_typed_config_synchronized() {
    let host = SavedHost::from_draft(
        SavedHostDraft::serial(
            SavedSerialConfig::new("COM3", 115_200).expect("initial serial config"),
        )
        .expect("serial draft"),
        10,
    )
    .expect("serial host");

    let mut endpoint_update = SavedHostUpdate::default();
    endpoint_update.hostname = Some("/tmp/serial link".to_owned());
    endpoint_update.port = Some(921_600);
    let endpoint_updated = host
        .apply_update(endpoint_update, 20)
        .expect("update flattened endpoint");
    let synchronized = endpoint_updated
        .serial_config()
        .expect("typed config")
        .expect("stored config");
    assert_eq!(synchronized.path, "/tmp/serial link");
    assert_eq!(synchronized.baud_rate, 921_600);

    let replacement =
        SavedSerialConfig::new(r"\\.\COM25", 230_400).expect("replacement serial config");
    let config_updated = endpoint_updated
        .apply_update(
            SavedHostUpdate::default()
                .with_serial_config(replacement.clone())
                .expect("typed update"),
            30,
        )
        .expect("replace serial config");
    assert_eq!(config_updated.hostname, replacement.path);
    assert_eq!(config_updated.port, replacement.baud_rate);
    assert_eq!(config_updated.serial_config(), Ok(Some(replacement)));
}

#[test]
fn network_protocols_still_reject_serial_sized_ports() {
    for protocol in [SavedHostProtocol::ssh(), SavedHostProtocol::telnet()] {
        let mut draft = SavedHostDraft::ssh_password("server.example.test", "user");
        draft.protocol = Some(protocol);
        draft.port = Some(115_200);
        assert_eq!(
            SavedHost::from_draft(draft, 1),
            Err(ValidationError::InvalidPort)
        );
    }
}
