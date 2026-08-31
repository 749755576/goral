use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Legacy default used by both Quick Serial and saved Serial hosts.
pub const DEFAULT_SERIAL_BAUD_RATE: u32 = 115_200;

/// Serial paths are local device identifiers rather than DNS hostnames. Keep
/// the same generous bound used for other local paths while still preventing
/// an unbounded value from entering the durable Vault graph.
pub const MAX_SERIAL_PATH_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedSerialConfigError {
    MissingPath,
    PathTooLong,
    UnsafePath,
    InvalidBaudRate,
    InvalidDataBits,
    InvalidStopBits,
    InvalidBackspaceBehavior,
    EndpointMismatch,
    MalformedConfig,
}

impl fmt::Display for SavedSerialConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPath => "serial path is required",
            Self::PathTooLong => "serial path is too long",
            Self::UnsafePath => "serial path contains unsafe control characters",
            Self::InvalidBaudRate => "serial baud rate must be a positive integer",
            Self::InvalidDataBits => "serial data bits must be 5, 6, 7, or 8",
            Self::InvalidStopBits => "serial stop bits must be 1, 1.5, or 2",
            Self::InvalidBackspaceBehavior => "serial backspace behavior must be default or ctrl-h",
            Self::EndpointMismatch => {
                "serial path and baud rate must match the host endpoint mirror"
            }
            Self::MalformedConfig => "serial configuration is invalid",
        })
    }
}

impl std::error::Error for SavedSerialConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedSerialDataBits {
    Five,
    Six,
    Seven,
    Eight,
}

impl SavedSerialDataBits {
    pub const fn get(self) -> u8 {
        match self {
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }

    pub const fn from_u8(value: u8) -> Result<Self, SavedSerialConfigError> {
        match value {
            5 => Ok(Self::Five),
            6 => Ok(Self::Six),
            7 => Ok(Self::Seven),
            8 => Ok(Self::Eight),
            _ => Err(SavedSerialConfigError::InvalidDataBits),
        }
    }
}

impl Default for SavedSerialDataBits {
    fn default() -> Self {
        Self::Eight
    }
}

impl Serialize for SavedSerialDataBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.get())
    }
}

impl<'de> Deserialize<'de> for SavedSerialDataBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_u8(u8::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedSerialStopBits {
    One,
    OnePointFive,
    Two,
}

impl SavedSerialStopBits {
    pub const fn as_tenths(self) -> u8 {
        match self {
            Self::One => 10,
            Self::OnePointFive => 15,
            Self::Two => 20,
        }
    }

    pub const fn as_f64(self) -> f64 {
        match self {
            Self::One => 1.0,
            Self::OnePointFive => 1.5,
            Self::Two => 2.0,
        }
    }

    pub fn from_f64(value: f64) -> Result<Self, SavedSerialConfigError> {
        match value {
            value if value == 1.0 => Ok(Self::One),
            value if value == 1.5 => Ok(Self::OnePointFive),
            value if value == 2.0 => Ok(Self::Two),
            _ => Err(SavedSerialConfigError::InvalidStopBits),
        }
    }
}

impl Default for SavedSerialStopBits {
    fn default() -> Self {
        Self::One
    }
}

impl Serialize for SavedSerialStopBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::One => serializer.serialize_u8(1),
            Self::OnePointFive => serializer.serialize_f64(1.5),
            Self::Two => serializer.serialize_u8(2),
        }
    }
}

impl<'de> Deserialize<'de> for SavedSerialStopBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_f64(f64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedSerialParity {
    #[default]
    None,
    Even,
    Odd,
    Mark,
    Space,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedSerialFlowControl {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "xon/xoff")]
    XonXoff,
    #[serde(rename = "rts/cts")]
    RtsCts,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedSerialBackspaceBehavior {
    #[default]
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "ctrl-h")]
    CtrlH,
}

/// Secret-free, strict representation of the legacy `serialConfig` object.
///
/// The legacy fields after `baudRate` were optional. Missing values therefore
/// deserialize to the exact UI/runtime defaults. `backspaceBehavior` stays
/// optional because absence means that the old top-level or GroupConfig value
/// may still be inherited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedSerialConfig {
    pub path: String,
    pub baud_rate: u32,
    pub data_bits: SavedSerialDataBits,
    pub stop_bits: SavedSerialStopBits,
    pub parity: SavedSerialParity,
    pub flow_control: SavedSerialFlowControl,
    pub local_echo: bool,
    pub line_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backspace_behavior: Option<SavedSerialBackspaceBehavior>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedSerialConfigWire {
    path: String,
    baud_rate: u32,
    #[serde(default)]
    data_bits: SavedSerialDataBits,
    #[serde(default)]
    stop_bits: SavedSerialStopBits,
    #[serde(default)]
    parity: SavedSerialParity,
    #[serde(default)]
    flow_control: SavedSerialFlowControl,
    #[serde(default)]
    local_echo: bool,
    #[serde(default)]
    line_mode: bool,
    #[serde(default)]
    backspace_behavior: Option<SavedSerialBackspaceBehavior>,
}

impl<'de> Deserialize<'de> for SavedSerialConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedSerialConfigWire::deserialize(deserializer)?;
        let config = Self {
            path: normalize_serial_path(&wire.path).map_err(serde::de::Error::custom)?,
            baud_rate: wire.baud_rate,
            data_bits: wire.data_bits,
            stop_bits: wire.stop_bits,
            parity: wire.parity,
            flow_control: wire.flow_control,
            local_echo: wire.local_echo,
            line_mode: wire.line_mode,
            backspace_behavior: wire.backspace_behavior,
        };
        config.validate().map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

impl SavedSerialConfig {
    pub fn new(path: impl Into<String>, baud_rate: u32) -> Result<Self, SavedSerialConfigError> {
        let config = Self {
            path: normalize_serial_path(&path.into())?,
            baud_rate,
            data_bits: SavedSerialDataBits::default(),
            stop_bits: SavedSerialStopBits::default(),
            parity: SavedSerialParity::default(),
            flow_control: SavedSerialFlowControl::default(),
            local_echo: false,
            line_mode: false,
            backspace_behavior: None,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), SavedSerialConfigError> {
        if normalize_serial_path(&self.path)? != self.path {
            return Err(SavedSerialConfigError::UnsafePath);
        }
        if self.baud_rate == 0 {
            return Err(SavedSerialConfigError::InvalidBaudRate);
        }
        Ok(())
    }
}

pub(crate) fn normalize_serial_path(value: &str) -> Result<String, SavedSerialConfigError> {
    if value.chars().any(char::is_control) {
        return Err(SavedSerialConfigError::UnsafePath);
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(SavedSerialConfigError::MissingPath);
    }
    if value.len() > MAX_SERIAL_PATH_BYTES {
        return Err(SavedSerialConfigError::PathTooLong);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_SERIAL_BAUD_RATE, SavedSerialBackspaceBehavior, SavedSerialConfig,
        SavedSerialDataBits, SavedSerialFlowControl, SavedSerialParity, SavedSerialStopBits,
    };

    #[test]
    fn legacy_minimal_config_applies_exact_defaults() {
        let config: SavedSerialConfig = serde_json::from_value(serde_json::json!({
            "path": " COM12 ",
            "baudRate": DEFAULT_SERIAL_BAUD_RATE
        }))
        .expect("minimal serial config");
        assert_eq!(config.path, "COM12");
        assert_eq!(config.data_bits, SavedSerialDataBits::Eight);
        assert_eq!(config.stop_bits, SavedSerialStopBits::One);
        assert_eq!(config.parity, SavedSerialParity::None);
        assert_eq!(config.flow_control, SavedSerialFlowControl::None);
        assert!(!config.local_echo);
        assert!(!config.line_mode);
        assert_eq!(config.backspace_behavior, None);
        assert_eq!(
            serde_json::to_value(config).expect("default Serial JSON")["stopBits"],
            1
        );
    }

    #[test]
    fn every_legacy_value_round_trips_with_numeric_data_and_stop_bits() {
        let config: SavedSerialConfig = serde_json::from_value(serde_json::json!({
            "path": "/tmp/serial link",
            "baudRate": 921600,
            "dataBits": 7,
            "stopBits": 1.5,
            "parity": "mark",
            "flowControl": "rts/cts",
            "localEcho": true,
            "lineMode": true,
            "backspaceBehavior": "ctrl-h"
        }))
        .expect("full serial config");
        assert_eq!(config.data_bits, SavedSerialDataBits::Seven);
        assert_eq!(config.stop_bits, SavedSerialStopBits::OnePointFive);
        assert_eq!(config.parity, SavedSerialParity::Mark);
        assert_eq!(config.flow_control, SavedSerialFlowControl::RtsCts);
        assert_eq!(
            config.backspace_behavior,
            Some(SavedSerialBackspaceBehavior::CtrlH)
        );
        let encoded = serde_json::to_value(config).expect("serial JSON");
        assert_eq!(encoded["dataBits"], 7);
        assert_eq!(encoded["stopBits"], 1.5);
    }

    #[test]
    fn invalid_values_and_control_characters_fail_closed() {
        for value in [
            serde_json::json!({"path":"COM1\u{0}","baudRate":115200}),
            serde_json::json!({"path":"COM1","baudRate":0}),
            serde_json::json!({"path":"COM1","baudRate":115200,"dataBits":9}),
            serde_json::json!({"path":"COM1","baudRate":115200,"stopBits":1.25}),
            serde_json::json!({"path":"COM1","baudRate":115200,"parity":"plugin"}),
            serde_json::json!({"path":"COM1","baudRate":115200,"extra":true}),
        ] {
            assert!(serde_json::from_value::<SavedSerialConfig>(value).is_err());
        }
    }
}
