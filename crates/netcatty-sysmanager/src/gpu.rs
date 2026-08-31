//! Read-only NVIDIA GPU inventory over a remote session.
//!
//! The renderer never supplies a command or query field. This module owns one
//! fixed `nvidia-smi` query and a bounded parser for its machine-readable CSV
//! output, keeping command construction and response validation on the native
//! side of the application.

use std::fmt;

use serde::Serialize;

/// A fixed, read-only query supported by NVIDIA's management CLI.
pub const LIST_NVIDIA_GPUS: &str = concat!(
    "nvidia-smi ",
    "--query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total,",
    "temperature.gpu,power.draw,power.limit,fan.speed,driver_version ",
    "--format=csv,noheader,nounits"
);

/// The command output is bounded again at the parser boundary so this module
/// remains safe even when reused with a different transport.
pub const MAX_NVIDIA_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_NVIDIA_GPUS: usize = 64;
const MAX_NVIDIA_LINE_BYTES: usize = 2 * 1024;
const MAX_UUID_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 256;
const MAX_DRIVER_VERSION_BYTES: usize = 128;
const FIELD_COUNT: usize = 11;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NvidiaGpu {
    pub index: u32,
    pub uuid: String,
    pub name: String,
    pub utilization_percent: Option<f64>,
    pub memory_used_mib: Option<f64>,
    pub memory_total_mib: Option<f64>,
    pub temperature_c: Option<f64>,
    pub power_draw_w: Option<f64>,
    pub power_limit_w: Option<f64>,
    pub fan_percent: Option<f64>,
    pub driver_version: Option<String>,
}

/// A response-shape error. It deliberately carries no remote field contents,
/// so malformed output cannot be reflected into logs or renderer messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuParseError {
    OutputTooLarge,
    TooManyRows,
    LineTooLong { line: usize },
    WrongFieldCount { line: usize },
    InvalidField { line: usize, field: &'static str },
}

impl fmt::Display for GpuParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLarge => formatter.write_str("GPU output exceeded its size limit"),
            Self::TooManyRows => formatter.write_str("GPU output contained too many rows"),
            Self::LineTooLong { line } => write!(formatter, "GPU row {line} was too long"),
            Self::WrongFieldCount { line } => {
                write!(formatter, "GPU row {line} had an unexpected field count")
            }
            Self::InvalidField { line, field } => {
                write!(formatter, "GPU row {line} had an invalid {field} field")
            }
        }
    }
}

impl std::error::Error for GpuParseError {}

fn is_unavailable(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "-" | "n/a" | "[n/a]" | "not supported" | "[not supported]"
    )
}

fn required_text(
    value: &str,
    max_bytes: usize,
    line: usize,
    field: &'static str,
) -> Result<String, GpuParseError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(GpuParseError::InvalidField { line, field });
    }
    Ok(value.to_owned())
}

fn optional_text(
    value: &str,
    max_bytes: usize,
    line: usize,
    field: &'static str,
) -> Result<Option<String>, GpuParseError> {
    if is_unavailable(value) {
        return Ok(None);
    }
    required_text(value, max_bytes, line, field).map(Some)
}

fn optional_number(
    value: &str,
    min: f64,
    max: f64,
    line: usize,
    field: &'static str,
) -> Result<Option<f64>, GpuParseError> {
    if is_unavailable(value) {
        return Ok(None);
    }
    let number = value
        .trim()
        .parse::<f64>()
        .map_err(|_| GpuParseError::InvalidField { line, field })?;
    if !number.is_finite() || !(min..=max).contains(&number) {
        return Err(GpuParseError::InvalidField { line, field });
    }
    Ok(Some(number))
}

/// Parses the exact CSV shape emitted by [`LIST_NVIDIA_GPUS`].
///
/// Empty lines are ignored so a trailing newline is harmless. Every actual
/// row must have exactly eleven fields and every field is validated before a
/// row is returned. A malformed row rejects the snapshot rather than mixing
/// trusted and untrusted inventory.
pub fn parse_nvidia_gpus(stdout: &str) -> Result<Vec<NvidiaGpu>, GpuParseError> {
    if stdout.len() > MAX_NVIDIA_OUTPUT_BYTES {
        return Err(GpuParseError::OutputTooLarge);
    }

    let mut rows = Vec::new();
    for (line_index, raw_line) in stdout.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_NVIDIA_LINE_BYTES {
            return Err(GpuParseError::LineTooLong { line: line_number });
        }
        if rows.len() == MAX_NVIDIA_GPUS {
            return Err(GpuParseError::TooManyRows);
        }

        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != FIELD_COUNT {
            return Err(GpuParseError::WrongFieldCount { line: line_number });
        }

        let index = fields[0]
            .parse::<u32>()
            .map_err(|_| GpuParseError::InvalidField {
                line: line_number,
                field: "index",
            })?;
        let uuid = required_text(fields[1], MAX_UUID_BYTES, line_number, "uuid")?;
        if !uuid
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(GpuParseError::InvalidField {
                line: line_number,
                field: "uuid",
            });
        }
        let name = required_text(fields[2], MAX_NAME_BYTES, line_number, "name")?;

        let utilization_percent =
            optional_number(fields[3], 0.0, 100.0, line_number, "utilization")?;
        let memory_used_mib =
            optional_number(fields[4], 0.0, 1_000_000_000.0, line_number, "memory used")?;
        let memory_total_mib =
            optional_number(fields[5], 0.0, 1_000_000_000.0, line_number, "memory total")?;
        if matches!((memory_used_mib, memory_total_mib), (Some(used), Some(total)) if used > total)
        {
            return Err(GpuParseError::InvalidField {
                line: line_number,
                field: "memory",
            });
        }
        let temperature_c =
            optional_number(fields[6], -273.15, 1_000.0, line_number, "temperature")?;
        let power_draw_w = optional_number(fields[7], 0.0, 1_000_000.0, line_number, "power draw")?;
        let power_limit_w =
            optional_number(fields[8], 0.0, 1_000_000.0, line_number, "power limit")?;
        let fan_percent = optional_number(fields[9], 0.0, 100.0, line_number, "fan")?;
        let driver_version = optional_text(
            fields[10],
            MAX_DRIVER_VERSION_BYTES,
            line_number,
            "driver version",
        )?;

        rows.push(NvidiaGpu {
            index,
            uuid,
            name,
            utilization_percent,
            memory_used_mib,
            memory_total_mib,
            temperature_c,
            power_draw_w,
            power_limit_w,
            fan_percent,
            driver_version,
        });
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_query_has_the_expected_machine_readable_shape() {
        assert_eq!(
            LIST_NVIDIA_GPUS,
            concat!(
                "nvidia-smi --query-gpu=index,uuid,name,utilization.gpu,memory.used,",
                "memory.total,temperature.gpu,power.draw,power.limit,fan.speed,driver_version ",
                "--format=csv,noheader,nounits"
            )
        );
        assert!(!LIST_NVIDIA_GPUS.contains("sudo"));
    }

    #[test]
    fn parses_multiple_nvidia_gpus_and_nullable_metrics() {
        let output = concat!(
            "0, GPU-aaa, NVIDIA GeForce RTX 4090, 42, 1024, 24576, 61, 120.5, 450.0, 35, 550.54.15\n",
            "1, GPU-bbb, NVIDIA A100-SXM4-80GB, [N/A], 0, 81920, 38, 70.0, 400.0, [N/A], 550.54.15\n",
        );
        let rows = parse_nvidia_gpus(output).expect("valid nvidia-smi output");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].index, 0);
        assert_eq!(rows[0].name, "NVIDIA GeForce RTX 4090");
        assert_eq!(rows[0].utilization_percent, Some(42.0));
        assert_eq!(rows[0].memory_total_mib, Some(24_576.0));
        assert_eq!(rows[0].power_draw_w, Some(120.5));
        assert_eq!(rows[1].utilization_percent, None);
        assert_eq!(rows[1].fan_percent, None);
    }

    #[test]
    fn serializes_renderer_fields_in_camel_case() {
        let row =
            parse_nvidia_gpus("0, GPU-aaa, RTX 4090, 12, 1024, 24576, 44, 100, 450, 30, 550.54\n")
                .expect("valid row")
                .remove(0);
        let json = serde_json::to_value(row).expect("serialize row");
        assert_eq!(json["memoryUsedMib"], 1024.0);
        assert_eq!(json["driverVersion"], "550.54");
        assert!(json.get("memory_used_mib").is_none());
    }

    #[test]
    fn rejects_a_partial_or_extra_csv_row() {
        assert!(matches!(
            parse_nvidia_gpus("0, GPU-aaa, RTX\n"),
            Err(GpuParseError::WrongFieldCount { line: 1 })
        ));
        assert!(matches!(
            parse_nvidia_gpus("0, GPU-aaa, RTX, 1, 2, 3, 4, 5, 6, 7, 8, extra\n"),
            Err(GpuParseError::WrongFieldCount { line: 1 })
        ));
    }

    #[test]
    fn rejects_invalid_numbers_and_unsafe_uuid_text() {
        assert!(matches!(
            parse_nvidia_gpus("0, GPU-aaa, RTX, busy, 1, 2, 30, 40, 50, 20, 550\n"),
            Err(GpuParseError::InvalidField {
                line: 1,
                field: "utilization"
            })
        ));
        assert!(matches!(
            parse_nvidia_gpus("0, GPU-aaa;echo, RTX, 1, 1, 2, 30, 40, 50, 20, 550\n"),
            Err(GpuParseError::InvalidField {
                line: 1,
                field: "uuid"
            })
        ));
    }

    #[test]
    fn bounds_total_output_line_length_and_row_count() {
        assert_eq!(
            parse_nvidia_gpus(&"x".repeat(MAX_NVIDIA_OUTPUT_BYTES + 1)),
            Err(GpuParseError::OutputTooLarge)
        );
        assert!(matches!(
            parse_nvidia_gpus(&format!(
                "0, GPU-aaa, {}, 1, 1, 2, 30, 40, 50, 20, 550\n",
                "x".repeat(MAX_NVIDIA_LINE_BYTES)
            )),
            Err(GpuParseError::LineTooLong { line: 1 })
        ));

        let output = (0..=MAX_NVIDIA_GPUS)
            .map(|index| format!("{index}, GPU-{index}, RTX, 1, 1, 2, 30, 40, 50, 20, 550\n"))
            .collect::<String>();
        assert_eq!(parse_nvidia_gpus(&output), Err(GpuParseError::TooManyRows));
    }
}
