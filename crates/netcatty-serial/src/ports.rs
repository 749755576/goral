use serde::{Deserialize, Serialize};
use tokio_serial::{SerialPortInfo as BackendPortInfo, SerialPortType};

use crate::{SerialIoOperation, SerialRuntimeError, runtime::map_backend_error_kind};

pub const MAX_PORT_INVENTORY_ENTRIES: usize = 1_024;
pub const MAX_PORT_METADATA_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SerialPortKind {
    Hardware,
    Pseudo,
    Custom,
}

/// Renderer-safe legacy-compatible serial port inventory row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SerialPortInfo {
    pub path: String,
    pub manufacturer: String,
    pub serial_number: String,
    pub vendor_id: String,
    pub product_id: String,
    pub pnp_id: String,
    #[serde(rename = "type")]
    pub port_type: SerialPortKind,
}

/// Enumerate native ports synchronously. Desktop adapters should normally use
/// [`list_serial_ports_async`] so platform inventory APIs cannot block the
/// Tauri event loop.
pub fn list_serial_ports() -> Result<Vec<SerialPortInfo>, SerialRuntimeError> {
    let ports = tokio_serial::available_ports().map_err(|error| SerialRuntimeError::IoFailed {
        operation: SerialIoOperation::Enumerate,
        kind: map_backend_error_kind(error.kind()),
    })?;
    if ports.len() > MAX_PORT_INVENTORY_ENTRIES {
        return Err(SerialRuntimeError::PortInventoryTooLarge {
            maximum_entries: MAX_PORT_INVENTORY_ENTRIES,
        });
    }

    ports
        .into_iter()
        .map(convert_port)
        .collect::<Result<Vec<_>, _>>()
}

pub async fn list_serial_ports_async() -> Result<Vec<SerialPortInfo>, SerialRuntimeError> {
    tokio::task::spawn_blocking(list_serial_ports)
        .await
        .map_err(|_| SerialRuntimeError::RuntimeTaskFailed {
            operation: SerialIoOperation::Enumerate,
        })?
}

fn convert_port(port: BackendPortInfo) -> Result<SerialPortInfo, SerialRuntimeError> {
    validate_text(&port.port_name)?;
    match port.port_type {
        SerialPortType::UsbPort(usb) => {
            let manufacturer = usb.manufacturer.unwrap_or_default();
            let serial_number = usb.serial_number.unwrap_or_default();
            validate_optional_text(&manufacturer)?;
            validate_optional_text(&serial_number)?;
            Ok(SerialPortInfo {
                path: port.port_name,
                manufacturer,
                serial_number,
                vendor_id: format!("{:04X}", usb.vid),
                product_id: format!("{:04X}", usb.pid),
                // `serialport` exposes no portable PnP ID. Keep the legacy
                // empty-string field instead of fabricating one.
                pnp_id: String::new(),
                port_type: SerialPortKind::Hardware,
            })
        }
        SerialPortType::PciPort | SerialPortType::BluetoothPort | SerialPortType::Unknown => {
            Ok(empty_metadata(port.port_name))
        }
    }
}

fn empty_metadata(path: String) -> SerialPortInfo {
    SerialPortInfo {
        path,
        manufacturer: String::new(),
        serial_number: String::new(),
        vendor_id: String::new(),
        product_id: String::new(),
        pnp_id: String::new(),
        port_type: SerialPortKind::Hardware,
    }
}

fn validate_optional_text(value: &str) -> Result<(), SerialRuntimeError> {
    if !value.is_empty() {
        validate_text(value)?;
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), SerialRuntimeError> {
    if value.is_empty()
        || value.len() > MAX_PORT_METADATA_BYTES
        || value.chars().any(char::is_control)
    {
        Err(SerialRuntimeError::InvalidPortMetadata {
            maximum_bytes: MAX_PORT_METADATA_BYTES,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio_serial::UsbPortInfo;

    #[test]
    fn usb_inventory_maps_to_exact_legacy_fields_and_hex_ids() {
        let converted = convert_port(BackendPortInfo {
            port_name: "COM12".to_owned(),
            port_type: SerialPortType::UsbPort(UsbPortInfo {
                vid: 0x1a86,
                pid: 0x7523,
                serial_number: Some("ABC123".to_owned()),
                manufacturer: Some("QinHeng".to_owned()),
                product: Some("USB Serial".to_owned()),
            }),
        })
        .unwrap();
        assert_eq!(converted.vendor_id, "1A86");
        assert_eq!(converted.product_id, "7523");
        assert_eq!(converted.port_type, SerialPortKind::Hardware);
        assert_eq!(
            serde_json::to_value(&converted).unwrap(),
            json!({
                "path": "COM12",
                "manufacturer": "QinHeng",
                "serialNumber": "ABC123",
                "vendorId": "1A86",
                "productId": "7523",
                "pnpId": "",
                "type": "hardware"
            })
        );
    }

    #[test]
    fn non_usb_inventory_keeps_legacy_empty_metadata() {
        let converted = convert_port(BackendPortInfo {
            port_name: "/dev/ttyS0".to_owned(),
            port_type: SerialPortType::Unknown,
        })
        .unwrap();
        assert_eq!(converted.path, "/dev/ttyS0");
        assert_eq!(converted.port_type, SerialPortKind::Hardware);
        assert!(converted.manufacturer.is_empty());
        assert!(converted.pnp_id.is_empty());
    }

    #[test]
    fn native_metadata_is_bounded_and_control_free() {
        assert!(
            convert_port(BackendPortInfo {
                port_name: "bad\nport".to_owned(),
                port_type: SerialPortType::Unknown,
            })
            .is_err()
        );
        assert!(
            convert_port(BackendPortInfo {
                port_name: "x".repeat(MAX_PORT_METADATA_BYTES + 1),
                port_type: SerialPortType::Unknown,
            })
            .is_err()
        );
    }
}
