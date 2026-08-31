use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const DEFAULT_BAUD_RATE: u32 = 115_200;
pub const MAX_SERIAL_PATH_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SerialParity {
    #[default]
    None,
    Even,
    Odd,
    Mark,
    Space,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SerialFlowControl {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "xon/xoff")]
    XonXoff,
    #[serde(rename = "rts/cts")]
    RtsCts,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SerialBackspaceBehavior {
    #[default]
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "ctrl-h")]
    CtrlH,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SerialDataBits {
    Five,
    Six,
    Seven,
    #[default]
    Eight,
}

impl SerialDataBits {
    pub const fn value(self) -> u8 {
        match self {
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }
}

impl TryFrom<u8> for SerialDataBits {
    type Error = SerialConfigError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            5 => Ok(Self::Five),
            6 => Ok(Self::Six),
            7 => Ok(Self::Seven),
            8 => Ok(Self::Eight),
            _ => Err(SerialConfigError::InvalidDataBits),
        }
    }
}

impl Serialize for SerialDataBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.value())
    }
}

impl<'de> Deserialize<'de> for SerialDataBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SerialStopBits {
    #[default]
    One,
    OnePointFive,
    Two,
}

impl SerialStopBits {
    pub const fn value(self) -> f64 {
        match self {
            Self::One => 1.0,
            Self::OnePointFive => 1.5,
            Self::Two => 2.0,
        }
    }
}

impl Serialize for SerialStopBits {
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

impl<'de> Deserialize<'de> for SerialStopBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StopBitsVisitor;

        impl de::Visitor<'_> for StopBitsVisitor {
            type Value = SerialStopBits;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the serial stop-bit value 1, 1.5, or 2")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    1 => Ok(SerialStopBits::One),
                    2 => Ok(SerialStopBits::Two),
                    _ => Err(E::custom(SerialConfigError::InvalidStopBits)),
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                u64::try_from(value)
                    .map_err(|_| E::custom(SerialConfigError::InvalidStopBits))
                    .and_then(|value| self.visit_u64(value))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == 1.0 {
                    Ok(SerialStopBits::One)
                } else if value == 1.5 {
                    Ok(SerialStopBits::OnePointFive)
                } else if value == 2.0 {
                    Ok(SerialStopBits::Two)
                } else {
                    Err(E::custom(SerialConfigError::InvalidStopBits))
                }
            }
        }

        deserializer.deserialize_any(StopBitsVisitor)
    }
}

/// Legacy-compatible serial settings. The device path may contain spaces, but
/// is bounded and may not contain control characters (including NUL).
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SerialConfig {
    pub path: String,
    #[serde(default = "default_baud_rate")]
    pub baud_rate: u32,
    #[serde(default)]
    pub data_bits: SerialDataBits,
    #[serde(default)]
    pub stop_bits: SerialStopBits,
    #[serde(default)]
    pub parity: SerialParity,
    #[serde(default)]
    pub flow_control: SerialFlowControl,
    #[serde(default)]
    pub local_echo: bool,
    #[serde(default)]
    pub line_mode: bool,
    #[serde(default)]
    pub backspace_behavior: SerialBackspaceBehavior,
}

const fn default_baud_rate() -> u32 {
    DEFAULT_BAUD_RATE
}

impl SerialConfig {
    pub fn new(path: impl Into<String>) -> Result<Self, SerialConfigError> {
        let config = Self {
            path: path.into(),
            baud_rate: DEFAULT_BAUD_RATE,
            data_bits: SerialDataBits::Eight,
            stop_bits: SerialStopBits::One,
            parity: SerialParity::None,
            flow_control: SerialFlowControl::None,
            local_echo: false,
            line_mode: false,
            backspace_behavior: SerialBackspaceBehavior::Default,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), SerialConfigError> {
        if self.path.is_empty()
            || self.path.len() > MAX_SERIAL_PATH_BYTES
            || self.path.chars().any(char::is_control)
        {
            return Err(SerialConfigError::InvalidPath {
                maximum_bytes: MAX_SERIAL_PATH_BYTES,
            });
        }
        if self.baud_rate == 0 {
            return Err(SerialConfigError::InvalidBaudRate);
        }
        Ok(())
    }

    /// Validate settings against the selected async backend. The model keeps
    /// every legacy value even where `tokio-serial` cannot express it; callers
    /// get a stable error instead of a silent parity/stop-bit downgrade.
    pub fn validate_backend_support(&self) -> Result<(), SerialConfigError> {
        self.validate()?;
        if matches!(self.parity, SerialParity::Mark | SerialParity::Space) {
            return Err(SerialConfigError::UnsupportedParity {
                parity: self.parity,
            });
        }
        if self.stop_bits == SerialStopBits::OnePointFive {
            return Err(SerialConfigError::UnsupportedStopBits {
                stop_bits: self.stop_bits,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SerialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialConfig")
            .field("path", &"<redacted>")
            .field("path_bytes", &self.path.len())
            .field("baud_rate", &self.baud_rate)
            .field("data_bits", &self.data_bits)
            .field("stop_bits", &self.stop_bits)
            .field("parity", &self.parity)
            .field("flow_control", &self.flow_control)
            .field("local_echo", &self.local_echo)
            .field("line_mode", &self.line_mode)
            .field("backspace_behavior", &self.backspace_behavior)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SerialConfigError {
    InvalidPath { maximum_bytes: usize },
    InvalidBaudRate,
    InvalidDataBits,
    InvalidStopBits,
    UnsupportedParity { parity: SerialParity },
    UnsupportedStopBits { stop_bits: SerialStopBits },
}

impl fmt::Display for SerialConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { maximum_bytes } => write!(
                formatter,
                "Serial device path is invalid or exceeds {maximum_bytes} bytes"
            ),
            Self::InvalidBaudRate => formatter.write_str("Serial baud rate must be positive"),
            Self::InvalidDataBits => formatter.write_str("Serial data bits must be 5, 6, 7, or 8"),
            Self::InvalidStopBits => formatter.write_str("Serial stop bits must be 1, 1.5, or 2"),
            Self::UnsupportedParity { parity } => write!(
                formatter,
                "Serial parity {parity:?} is not supported by this platform backend"
            ),
            Self::UnsupportedStopBits { stop_bits } => write!(
                formatter,
                "Serial stop-bit setting {stop_bits:?} is not supported by this platform backend"
            ),
        }
    }
}

impl Error for SerialConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn constructor_applies_exact_legacy_defaults_and_allows_spaces() {
        let config = SerialConfig::new("/tmp/serial link").unwrap();
        assert_eq!(config.baud_rate, 115_200);
        assert_eq!(config.data_bits, SerialDataBits::Eight);
        assert_eq!(config.stop_bits, SerialStopBits::One);
        assert_eq!(config.parity, SerialParity::None);
        assert_eq!(config.flow_control, SerialFlowControl::None);
        assert!(!config.local_echo);
        assert!(!config.line_mode);
        assert_eq!(config.backspace_behavior, SerialBackspaceBehavior::Default);
    }

    #[test]
    fn legacy_json_round_trips_all_typed_values_without_stringifying_numbers() {
        let document = json!({
            "path": "COM12",
            "baudRate": 921600,
            "dataBits": 7,
            "stopBits": 1.5,
            "parity": "space",
            "flowControl": "rts/cts",
            "localEcho": true,
            "lineMode": true,
            "backspaceBehavior": "ctrl-h"
        });
        let config: SerialConfig = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(config.data_bits, SerialDataBits::Seven);
        assert_eq!(config.stop_bits, SerialStopBits::OnePointFive);
        assert_eq!(config.parity, SerialParity::Space);
        assert_eq!(config.flow_control, SerialFlowControl::RtsCts);
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(encoded, document);
        assert!(encoded["dataBits"].is_number());
        assert!(encoded["stopBits"].is_number());
    }

    #[test]
    fn omitted_optional_fields_receive_legacy_defaults() {
        let config: SerialConfig = serde_json::from_value(json!({ "path": "COM3" })).unwrap();
        assert_eq!(config, SerialConfig::new("COM3").unwrap());
    }

    #[test]
    fn parsing_and_runtime_validation_are_strict_and_payload_safe() {
        for bad in [
            json!({ "path": "COM3", "dataBits": 9 }),
            json!({ "path": "COM3", "stopBits": 1.25 }),
            json!({ "path": "COM3", "parity": "automatic" }),
            json!({ "path": "COM3", "flowControl": "hardware" }),
            json!({ "path": "COM3", "unknown": true }),
        ] {
            assert!(serde_json::from_value::<SerialConfig>(bad).is_err());
        }

        let mut zero_baud = SerialConfig::new("COM3").unwrap();
        zero_baud.baud_rate = 0;
        assert_eq!(
            zero_baud.validate(),
            Err(SerialConfigError::InvalidBaudRate)
        );
        assert!(SerialConfig::new("bad\0path").is_err());
        assert!(SerialConfig::new("x".repeat(MAX_SERIAL_PATH_BYTES + 1)).is_err());

        let marker = "PRIVATE-SERIAL-PATH";
        let config = SerialConfig::new(marker).unwrap();
        assert!(!format!("{config:?}").contains(marker));
        assert!(!format!("{:?}", config.validate()).contains(marker));
    }

    #[test]
    fn unsupported_legacy_values_fail_explicitly_without_downgrade() {
        for parity in [SerialParity::Mark, SerialParity::Space] {
            let mut config = SerialConfig::new("COM3").unwrap();
            config.parity = parity;
            assert_eq!(
                config.validate_backend_support(),
                Err(SerialConfigError::UnsupportedParity { parity })
            );
        }

        let mut config = SerialConfig::new("COM3").unwrap();
        config.stop_bits = SerialStopBits::OnePointFive;
        assert_eq!(
            config.validate_backend_support(),
            Err(SerialConfigError::UnsupportedStopBits {
                stop_bits: SerialStopBits::OnePointFive
            })
        );
        assert_eq!(
            serde_json::to_value(&config).unwrap()["stopBits"],
            Value::from(1.5)
        );
    }
}
