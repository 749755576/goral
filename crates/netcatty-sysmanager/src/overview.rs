//! Read-only system overview collection for Linux and macOS hosts.
//!
//! The renderer supplies only a session identifier. This module owns the
//! complete command and the response grammar, so neither shell fragments nor
//! query parameters can cross the renderer boundary.

use std::fmt;

use serde::Serialize;

/// Fixed POSIX-shell probe. Every operation is read-only, needs no elevation,
/// and degrades to an empty field when a platform tool is unavailable.
pub const GET_SYSTEM_OVERVIEW: &str = r#"sh -c 'LC_ALL=C
clean() { printf "%s" "$1" | tr "\r\n\t" "   "; }
emit() { printf "%s=" "$1"; clean "$2"; printf "\n"; }
os_type=$(uname -s 2>/dev/null)
hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null)
kernel_release=$(uname -r 2>/dev/null)
os_name=""
uptime_seconds=""
load_average=""
cpu_count=""
memory_total_bytes=""
memory_used_bytes=""
root_disk_total_bytes=""
root_disk_used_bytes=""
if [ "$os_type" = "Linux" ]; then
  os_name=$(sed -n "s/^PRETTY_NAME=//p" /etc/os-release 2>/dev/null | head -n 1 | sed "s/^\"//;s/\"$//")
  [ -n "$os_name" ] || os_name=$(uname -s 2>/dev/null)
  set -- $(cat /proc/uptime 2>/dev/null); uptime_seconds=${1%%.*}
  set -- $(cat /proc/loadavg 2>/dev/null); load_average="$1 $2 $3"
  cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null)
  memory_total_kib=$(sed -n "s/^MemTotal:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1)
  memory_available_kib=$(sed -n "s/^MemAvailable:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1)
  if [ -z "$memory_available_kib" ]; then
    memory_free_kib=$(sed -n "s/^MemFree:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1)
    memory_buffers_kib=$(sed -n "s/^Buffers:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1)
    memory_cached_kib=$(sed -n "s/^Cached:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1)
    if [ -n "$memory_free_kib" ] && [ -n "$memory_buffers_kib" ] && [ -n "$memory_cached_kib" ]; then
      memory_available_kib=$((memory_free_kib + memory_buffers_kib + memory_cached_kib))
    fi
  fi
  if [ -n "$memory_total_kib" ]; then
    memory_total_bytes=$((memory_total_kib * 1024))
    if [ -n "$memory_available_kib" ] && [ "$memory_available_kib" -le "$memory_total_kib" ] 2>/dev/null; then
      memory_used_bytes=$(((memory_total_kib - memory_available_kib) * 1024))
    fi
  fi
elif [ "$os_type" = "Darwin" ]; then
  product_name=$(sw_vers -productName 2>/dev/null)
  product_version=$(sw_vers -productVersion 2>/dev/null)
  os_name="$product_name $product_version"
  boot_seconds=$(sysctl -n kern.boottime 2>/dev/null | sed -n "s/.*sec = \([0-9][0-9]*\).*/\1/p")
  now_seconds=$(date +%s 2>/dev/null)
  if [ -n "$boot_seconds" ] && [ -n "$now_seconds" ] && [ "$now_seconds" -ge "$boot_seconds" ] 2>/dev/null; then
    uptime_seconds=$((now_seconds - boot_seconds))
  fi
  set -- $(sysctl -n vm.loadavg 2>/dev/null | tr -d "{}"); load_average="$1 $2 $3"
  cpu_count=$(sysctl -n hw.logicalcpu 2>/dev/null)
  memory_total_bytes=$(sysctl -n hw.memsize 2>/dev/null)
  page_size=$(sysctl -n hw.pagesize 2>/dev/null)
  free_pages=$(sysctl -n vm.page_free_count 2>/dev/null)
  inactive_pages=$(sysctl -n vm.page_inactive_count 2>/dev/null)
  speculative_pages=$(sysctl -n vm.page_speculative_count 2>/dev/null)
  if [ -n "$memory_total_bytes" ] && [ -n "$page_size" ] && [ -n "$free_pages" ] && [ -n "$inactive_pages" ]; then
    [ -n "$speculative_pages" ] || speculative_pages=0
    available_bytes=$(((free_pages + inactive_pages + speculative_pages) * page_size))
    if [ "$available_bytes" -le "$memory_total_bytes" ] 2>/dev/null; then
      memory_used_bytes=$((memory_total_bytes - available_bytes))
    fi
  fi
else
  os_name=$os_type
fi
set -- $(df -kP / 2>/dev/null | tail -n 1)
if [ "$#" -ge 6 ]; then
  root_disk_total_bytes=$(($2 * 1024))
  root_disk_used_bytes=$(($3 * 1024))
fi
printf "version=1\n"
emit hostname "$hostname_value"
emit os_name "$os_name"
emit kernel_release "$kernel_release"
emit uptime_seconds "$uptime_seconds"
emit load_average "$load_average"
emit cpu_count "$cpu_count"
emit memory_total_bytes "$memory_total_bytes"
emit memory_used_bytes "$memory_used_bytes"
emit root_disk_total_bytes "$root_disk_total_bytes"
emit root_disk_used_bytes "$root_disk_used_bytes"
printf "end=1\n"'"#;

/// Transport and parser limits intentionally agree on a small response.
pub const MAX_OVERVIEW_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_OVERVIEW_LINES: usize = 32;
const MAX_OVERVIEW_LINE_BYTES: usize = 1024;
const MAX_HOSTNAME_BYTES: usize = 255;
const MAX_OS_NAME_BYTES: usize = 512;
const MAX_KERNEL_RELEASE_BYTES: usize = 256;
const MAX_CPU_COUNT: u32 = 1_048_576;
const MAX_UPTIME_SECONDS: u64 = 3_155_760_000;
const MAX_LOAD_AVERAGE: f64 = 1_000_000.0;
// DTOs cross JSON into JavaScript numbers, so accepting a larger u64 would
// silently lose byte-count precision in the renderer.
const MAX_CAPACITY_BYTES: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemOverview {
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub kernel_release: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub load_average: Option<[f64; 3]>,
    pub cpu_count: Option<u32>,
    pub memory_total_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
    pub root_disk_total_bytes: Option<u64>,
    pub root_disk_used_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverviewParseError {
    OutputTooLarge,
    TooManyLines,
    LineTooLong { line: usize },
    InvalidLine { line: usize },
    UnknownField { line: usize },
    DuplicateField { line: usize },
    UnsupportedVersion,
    MissingEndMarker,
    InvalidField { field: &'static str },
    InconsistentField { field: &'static str },
}

impl fmt::Display for OverviewParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLarge => formatter.write_str("overview output exceeded its size limit"),
            Self::TooManyLines => formatter.write_str("overview output contained too many lines"),
            Self::LineTooLong { line } => write!(formatter, "overview line {line} was too long"),
            Self::InvalidLine { line } => write!(formatter, "overview line {line} was invalid"),
            Self::UnknownField { line } => {
                write!(formatter, "overview line {line} had an unknown field")
            }
            Self::DuplicateField { line } => {
                write!(formatter, "overview line {line} duplicated a field")
            }
            Self::UnsupportedVersion => formatter.write_str("overview version was unsupported"),
            Self::MissingEndMarker => formatter.write_str("overview end marker was missing"),
            Self::InvalidField { field } => write!(formatter, "overview {field} field was invalid"),
            Self::InconsistentField { field } => {
                write!(formatter, "overview {field} fields were inconsistent")
            }
        }
    }
}

impl std::error::Error for OverviewParseError {}

#[derive(Default)]
struct RawOverview<'a> {
    version: Option<&'a str>,
    hostname: Option<&'a str>,
    os_name: Option<&'a str>,
    kernel_release: Option<&'a str>,
    uptime_seconds: Option<&'a str>,
    load_average: Option<&'a str>,
    cpu_count: Option<&'a str>,
    memory_total_bytes: Option<&'a str>,
    memory_used_bytes: Option<&'a str>,
    root_disk_total_bytes: Option<&'a str>,
    root_disk_used_bytes: Option<&'a str>,
    end: Option<&'a str>,
}

fn set_once<'a>(
    slot: &mut Option<&'a str>,
    value: &'a str,
    line: usize,
) -> Result<(), OverviewParseError> {
    if slot.replace(value).is_some() {
        return Err(OverviewParseError::DuplicateField { line });
    }
    Ok(())
}

fn optional_text(
    value: Option<&str>,
    max_bytes: usize,
    field: &'static str,
) -> Result<Option<String>, OverviewParseError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(OverviewParseError::InvalidField { field });
    }
    Ok(Some(value.to_owned()))
}

fn optional_u64(
    value: Option<&str>,
    max: u64,
    field: &'static str,
) -> Result<Option<u64>, OverviewParseError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|_| OverviewParseError::InvalidField { field })?;
    if parsed > max {
        return Err(OverviewParseError::InvalidField { field });
    }
    Ok(Some(parsed))
}

fn optional_load(value: Option<&str>) -> Result<Option<[f64; 3]>, OverviewParseError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err(OverviewParseError::InvalidField {
            field: "load average",
        });
    }
    let mut load = [0.0; 3];
    for (index, field) in fields.into_iter().enumerate() {
        let parsed = field
            .parse::<f64>()
            .map_err(|_| OverviewParseError::InvalidField {
                field: "load average",
            })?;
        if !parsed.is_finite() || !(0.0..=MAX_LOAD_AVERAGE).contains(&parsed) {
            return Err(OverviewParseError::InvalidField {
                field: "load average",
            });
        }
        load[index] = parsed;
    }
    Ok(Some(load))
}

/// Parses the exact line protocol emitted by [`GET_SYSTEM_OVERVIEW`].
///
/// Empty values become `None`. Unknown, duplicate, oversized or internally
/// inconsistent data rejects the entire snapshot.
pub fn parse_system_overview(stdout: &str) -> Result<SystemOverview, OverviewParseError> {
    if stdout.len() > MAX_OVERVIEW_OUTPUT_BYTES {
        return Err(OverviewParseError::OutputTooLarge);
    }

    let mut raw = RawOverview::default();
    for (line_index, line) in stdout.lines().enumerate() {
        let line_number = line_index + 1;
        if line_number > MAX_OVERVIEW_LINES {
            return Err(OverviewParseError::TooManyLines);
        }
        if line.len() > MAX_OVERVIEW_LINE_BYTES {
            return Err(OverviewParseError::LineTooLong { line: line_number });
        }
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(OverviewParseError::InvalidLine { line: line_number })?;
        match key {
            "version" => set_once(&mut raw.version, value, line_number)?,
            "hostname" => set_once(&mut raw.hostname, value, line_number)?,
            "os_name" => set_once(&mut raw.os_name, value, line_number)?,
            "kernel_release" => set_once(&mut raw.kernel_release, value, line_number)?,
            "uptime_seconds" => set_once(&mut raw.uptime_seconds, value, line_number)?,
            "load_average" => set_once(&mut raw.load_average, value, line_number)?,
            "cpu_count" => set_once(&mut raw.cpu_count, value, line_number)?,
            "memory_total_bytes" => set_once(&mut raw.memory_total_bytes, value, line_number)?,
            "memory_used_bytes" => set_once(&mut raw.memory_used_bytes, value, line_number)?,
            "root_disk_total_bytes" => {
                set_once(&mut raw.root_disk_total_bytes, value, line_number)?
            }
            "root_disk_used_bytes" => set_once(&mut raw.root_disk_used_bytes, value, line_number)?,
            "end" => set_once(&mut raw.end, value, line_number)?,
            _ => return Err(OverviewParseError::UnknownField { line: line_number }),
        }
    }

    if raw.version != Some("1") {
        return Err(OverviewParseError::UnsupportedVersion);
    }
    if raw.end != Some("1") {
        return Err(OverviewParseError::MissingEndMarker);
    }

    let uptime_seconds = optional_u64(raw.uptime_seconds, MAX_UPTIME_SECONDS, "uptime seconds")?;
    let cpu_count = optional_u64(raw.cpu_count, u64::from(MAX_CPU_COUNT), "CPU count")?
        .map(|value| value as u32);
    if cpu_count == Some(0) {
        return Err(OverviewParseError::InvalidField { field: "CPU count" });
    }
    let memory_total_bytes =
        optional_u64(raw.memory_total_bytes, MAX_CAPACITY_BYTES, "memory total")?;
    let memory_used_bytes = optional_u64(raw.memory_used_bytes, MAX_CAPACITY_BYTES, "memory used")?;
    if matches!((memory_used_bytes, memory_total_bytes), (Some(used), Some(total)) if used > total)
    {
        return Err(OverviewParseError::InconsistentField { field: "memory" });
    }
    let root_disk_total_bytes = optional_u64(
        raw.root_disk_total_bytes,
        MAX_CAPACITY_BYTES,
        "root disk total",
    )?;
    let root_disk_used_bytes = optional_u64(
        raw.root_disk_used_bytes,
        MAX_CAPACITY_BYTES,
        "root disk used",
    )?;
    if matches!((root_disk_used_bytes, root_disk_total_bytes), (Some(used), Some(total)) if used > total)
    {
        return Err(OverviewParseError::InconsistentField { field: "root disk" });
    }

    Ok(SystemOverview {
        hostname: optional_text(raw.hostname, MAX_HOSTNAME_BYTES, "hostname")?,
        os_name: optional_text(raw.os_name, MAX_OS_NAME_BYTES, "OS name")?,
        kernel_release: optional_text(
            raw.kernel_release,
            MAX_KERNEL_RELEASE_BYTES,
            "kernel release",
        )?,
        uptime_seconds,
        load_average: optional_load(raw.load_average)?,
        cpu_count,
        memory_total_bytes,
        memory_used_bytes,
        root_disk_total_bytes,
        root_disk_used_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE: &str = concat!(
        "version=1\n",
        "hostname=demo-box\n",
        "os_name=Ubuntu 24.04.3 LTS\n",
        "kernel_release=6.8.0-79-generic\n",
        "uptime_seconds=12345\n",
        "load_average=0.10 0.20 0.30\n",
        "cpu_count=8\n",
        "memory_total_bytes=17179869184\n",
        "memory_used_bytes=6442450944\n",
        "root_disk_total_bytes=107374182400\n",
        "root_disk_used_bytes=26843545600\n",
        "end=1\n",
    );

    #[test]
    fn command_is_fixed_read_only_and_cross_platform() {
        assert!(GET_SYSTEM_OVERVIEW.starts_with("sh -c '"));
        assert!(GET_SYSTEM_OVERVIEW.contains("/proc/meminfo"));
        assert!(GET_SYSTEM_OVERVIEW.contains("hw.memsize"));
        assert!(GET_SYSTEM_OVERVIEW.contains("df -kP /"));
        assert!(!GET_SYSTEM_OVERVIEW.contains("sudo"));
        for mutating_verb in [
            " rm ",
            " mv ",
            " chmod ",
            " chown ",
            " kill ",
            " systemctl ",
        ] {
            assert!(!GET_SYSTEM_OVERVIEW.contains(mutating_verb));
        }
    }

    #[test]
    fn parses_complete_linux_snapshot() {
        let overview = parse_system_overview(COMPLETE).expect("valid overview");
        assert_eq!(overview.hostname.as_deref(), Some("demo-box"));
        assert_eq!(overview.os_name.as_deref(), Some("Ubuntu 24.04.3 LTS"));
        assert_eq!(overview.kernel_release.as_deref(), Some("6.8.0-79-generic"));
        assert_eq!(overview.uptime_seconds, Some(12_345));
        assert_eq!(overview.load_average, Some([0.1, 0.2, 0.3]));
        assert_eq!(overview.cpu_count, Some(8));
        assert_eq!(overview.memory_total_bytes, Some(17_179_869_184));
        assert_eq!(overview.memory_used_bytes, Some(6_442_450_944));
        assert_eq!(overview.root_disk_total_bytes, Some(107_374_182_400));
        assert_eq!(overview.root_disk_used_bytes, Some(26_843_545_600));
    }

    #[test]
    fn same_protocol_accepts_macos_values() {
        let output = COMPLETE
            .replace("Ubuntu 24.04.3 LTS", "macOS 15.6")
            .replace("6.8.0-79-generic", "24.6.0");
        let overview = parse_system_overview(&output).expect("valid macOS overview");
        assert_eq!(overview.os_name.as_deref(), Some("macOS 15.6"));
        assert_eq!(overview.kernel_release.as_deref(), Some("24.6.0"));
    }

    #[test]
    fn blank_and_absent_measurements_become_null() {
        let output = concat!(
            "version=1\n",
            "hostname=\n",
            "os_name=Minimal Linux\n",
            "uptime_seconds=\n",
            "load_average=\n",
            "memory_total_bytes=\n",
            "end=1\n",
        );
        let overview = parse_system_overview(output).expect("partial overview");
        assert_eq!(overview.hostname, None);
        assert_eq!(overview.os_name.as_deref(), Some("Minimal Linux"));
        assert_eq!(overview.uptime_seconds, None);
        assert_eq!(overview.load_average, None);
        assert_eq!(overview.cpu_count, None);
        assert_eq!(overview.memory_total_bytes, None);
        assert_eq!(overview.root_disk_total_bytes, None);
    }

    #[test]
    fn serializes_camel_case_fields_and_nulls() {
        let overview =
            parse_system_overview("version=1\nos_name=Linux\nend=1\n").expect("partial overview");
        let json = serde_json::to_value(overview).expect("serialize overview");
        assert_eq!(json["osName"], "Linux");
        assert!(json["hostname"].is_null());
        assert!(json["memoryTotalBytes"].is_null());
        assert!(json["rootDiskUsedBytes"].is_null());
    }

    #[test]
    fn rejects_oversized_output() {
        let output = "x".repeat(MAX_OVERVIEW_OUTPUT_BYTES + 1);
        assert_eq!(
            parse_system_overview(&output),
            Err(OverviewParseError::OutputTooLarge)
        );
    }

    #[test]
    fn rejects_too_many_or_overlong_lines() {
        let too_many = "\n".repeat(MAX_OVERVIEW_LINES + 1);
        assert_eq!(
            parse_system_overview(&too_many),
            Err(OverviewParseError::TooManyLines)
        );
        let long = format!("version=1\nhostname={}\nend=1\n", "a".repeat(1025));
        assert_eq!(
            parse_system_overview(&long),
            Err(OverviewParseError::LineTooLong { line: 2 })
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_malformed_fields() {
        assert_eq!(
            parse_system_overview("version=1\nsurprise=yes\nend=1\n"),
            Err(OverviewParseError::UnknownField { line: 2 })
        );
        assert_eq!(
            parse_system_overview("version=1\nhostname=a\nhostname=b\nend=1\n"),
            Err(OverviewParseError::DuplicateField { line: 3 })
        );
        assert_eq!(
            parse_system_overview("version=1\nbroken\nend=1\n"),
            Err(OverviewParseError::InvalidLine { line: 2 })
        );
    }

    #[test]
    fn requires_supported_version_and_end_marker() {
        assert_eq!(
            parse_system_overview("version=2\nend=1\n"),
            Err(OverviewParseError::UnsupportedVersion)
        );
        assert_eq!(
            parse_system_overview("version=1\nhostname=partial\n"),
            Err(OverviewParseError::MissingEndMarker)
        );
    }

    #[test]
    fn rejects_invalid_text_and_numeric_fields() {
        assert_eq!(
            parse_system_overview("version=1\nhostname=bad\u{7}host\nend=1\n"),
            Err(OverviewParseError::InvalidField { field: "hostname" })
        );
        assert_eq!(
            parse_system_overview("version=1\nuptime_seconds=-1\nend=1\n"),
            Err(OverviewParseError::InvalidField {
                field: "uptime seconds"
            })
        );
        assert_eq!(
            parse_system_overview("version=1\ncpu_count=0\nend=1\n"),
            Err(OverviewParseError::InvalidField { field: "CPU count" })
        );
    }

    #[test]
    fn rejects_invalid_load_average() {
        for load in ["0.1 0.2", "0.1 NaN 0.3", "-0.1 0.2 0.3", "0.1 0.2 inf"] {
            let output = format!("version=1\nload_average={load}\nend=1\n");
            assert_eq!(
                parse_system_overview(&output),
                Err(OverviewParseError::InvalidField {
                    field: "load average"
                })
            );
        }
    }

    #[test]
    fn rejects_used_capacity_above_total() {
        assert_eq!(
            parse_system_overview(
                "version=1\nmemory_total_bytes=100\nmemory_used_bytes=101\nend=1\n"
            ),
            Err(OverviewParseError::InconsistentField { field: "memory" })
        );
        assert_eq!(
            parse_system_overview(
                "version=1\nroot_disk_total_bytes=100\nroot_disk_used_bytes=101\nend=1\n"
            ),
            Err(OverviewParseError::InconsistentField { field: "root disk" })
        );
    }

    #[test]
    fn rejects_capacity_that_cannot_cross_json_without_precision_loss() {
        assert_eq!(
            parse_system_overview("version=1\nmemory_total_bytes=9007199254740992\nend=1\n"),
            Err(OverviewParseError::InvalidField {
                field: "memory total"
            })
        );
    }

    #[test]
    fn preserves_equals_signs_inside_text_values() {
        let overview = parse_system_overview("version=1\nos_name=Build=Stable\nend=1\n")
            .expect("equals is part of the field value");
        assert_eq!(overview.os_name.as_deref(), Some("Build=Stable"));
    }
}
