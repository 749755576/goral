//! Process, port and service inventory over a remote session.
//!
//! Each listing has a primary command and a fallback chain, because the tool
//! that reports it differs across distributions and none of them is
//! guaranteed: `ss` is absent on older systems, `lsof` is often not
//! installed, `systemctl` only exists under systemd. The chains end in
//! `|| true` so a missing tool produces empty output rather than a non-zero
//! exit that would be reported to the user as a failure.
//!
//! Parsers are tolerant by design. A single unparseable row is skipped
//! rather than failing the listing: one odd process must not blank the
//! table.

use std::collections::HashMap;

use serde::Serialize;

/// Runs the first tool that exists. `sh -c` is used explicitly so the chain
/// behaves the same under a login shell, fish, or anything else the user has
/// configured as their default.
const PROCESS_IDENTITIES_HEADER: &str = "__GORAL_PROCESS_IDENTITIES_V1__";
const PROCESS_ROWS_HEADER: &str = "__GORAL_PROCESS_ROWS_V1__";

/// Capture process identities before the human-readable process rows. On
/// Linux the identity is the kernel boot id plus `/proc/<pid>/stat` start
/// ticks, which cannot be reused by another process during the same boot. On
/// systems without procfs, the fixed-C-locale `lstart` value is the best
/// portable stable token available from `ps`.
///
/// Taking the token snapshot first is intentional. If a PID is recycled
/// between the two snapshots, the old token is paired with the new row and a
/// later mutation fails closed; the reverse ordering could authorize the new
/// process while showing the old process to the user.
pub const LIST_PROCESSES: &str = r#"sh -c 'LC_ALL=C
export LC_ALL
set -f
printf "__GORAL_PROCESS_IDENTITIES_V1__\n"
boot_id=""
if [ -r /proc/sys/kernel/random/boot_id ]; then
  boot_id=$(tr -d "\r\n" < /proc/sys/kernel/random/boot_id 2>/dev/null)
fi
case "$boot_id" in
  ""|*[!0123456789abcdefABCDEF-]*) boot_id="" ;;
esac
if [ -n "$boot_id" ]; then
  printf "mode=linux\n"
  for stat_path in /proc/[0-9]*/stat; do
    pid=${stat_path#/proc/}
    pid=${pid%/stat}
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    stat_value=$(cat "$stat_path" 2>/dev/null) || continue
    stat_tail=${stat_value##*) }
    [ "$stat_tail" != "$stat_value" ] || continue
    set -- $stat_tail
    [ "$#" -ge 20 ] || continue
    shift 19
    start_ticks=$1
    case "$start_ticks" in ""|*[!0-9]*) continue ;; esac
    printf "%s\t%s\t%s\n" "$pid" "$boot_id" "$start_ticks"
  done
else
  printf "mode=ps\n"
  ps -eo pid= -o lstart= 2>/dev/null || ps -ax -o pid= -o lstart= 2>/dev/null || true
fi
printf "__GORAL_PROCESS_ROWS_V1__\n"
ps -eo pid= -o ppid= -o user= -o stat= -o pcpu= -o pmem= -o rss= -o etime= -o args= 2>/dev/null ||
ps -ww -o pid= -o ppid= -o user= -o stat= -o pcpu= -o pmem= -o rss= -o etime= -o args= 2>/dev/null ||
ps ww 2>/dev/null || ps 2>/dev/null || true'"#;

pub const LIST_PORTS: &str = concat!(
    "sh -c \"ss -H -tulnp 2>/dev/null || ss -tulnp 2>/dev/null ",
    "|| netstat -lntup 2>/dev/null || true\""
);

pub const LIST_SERVICES: &str = concat!(
    "sh -c \"systemctl list-units --type=service --all --no-pager --no-legend --plain ",
    "2>/dev/null || true\""
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub user: String,
    pub state: String,
    pub cpu_percent: String,
    pub memory_percent: String,
    pub resident_kib: u64,
    pub elapsed: String,
    pub command: String,
    /// Opaque renderer round-trip token checked again immediately before a
    /// signal. It contains no command text or credential material.
    pub start_time_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListeningPort {
    pub protocol: String,
    pub local_address: String,
    pub port: String,
    pub process: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemService {
    pub unit: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
}

impl SystemService {
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.sub_state == "running"
    }
}

/// A systemd unit action. Only these five; anything that would install,
/// mask or edit a unit is out of scope for a session panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl ServiceAction {
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }
}

/// systemd unit names are a restricted alphabet. As with container ids, an
/// unusable name produces no command at all rather than a quoted one.
#[must_use]
pub fn is_safe_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 256
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | ':' | '\\'))
}

/// A signal a session panel may send. Deliberately not the full set: this is
/// terminate, ask-nicely, and the last resort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessSignal {
    Term,
    Hup,
    Kill,
}

impl ProcessSignal {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Term => "TERM",
            Self::Hup => "HUP",
            Self::Kill => "KILL",
        }
    }
}

/// The kind of privileged inventory mutation represented by a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryActionKind {
    ProcessSignal,
    SystemService,
}

/// The one route selected by a non-mutating probe before an action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryActionRoute {
    Plain,
    Elevated,
}

/// Exit status reserved by identity-bound signal commands. It never contains
/// remote text and lets the adapter distinguish PID reuse from permission or
/// command failure.
pub const PROCESS_IDENTITY_MISMATCH_EXIT_STATUS: u32 = 125;

/// A mutation plan built entirely in Rust.
///
/// Each route has a non-mutating probe and one mutation command. The adapter
/// chooses the first successful probe in `probe_order`, then executes exactly
/// that route once. A failed mutation is never retried through another route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryActionPlan {
    kind: InventoryActionKind,
    probe_order: [InventoryActionRoute; 2],
    plain_probe_command: String,
    elevated_probe_command: String,
    plain_command: String,
    elevated_command: String,
}

impl InventoryActionPlan {
    #[must_use]
    pub const fn kind(&self) -> InventoryActionKind {
        self.kind
    }

    #[must_use]
    pub const fn probe_order(&self) -> [InventoryActionRoute; 2] {
        self.probe_order
    }

    #[must_use]
    pub fn probe_command(&self, route: InventoryActionRoute) -> &str {
        match route {
            InventoryActionRoute::Plain => &self.plain_probe_command,
            InventoryActionRoute::Elevated => &self.elevated_probe_command,
        }
    }

    #[must_use]
    pub fn command(&self, route: InventoryActionRoute) -> &str {
        match route {
            InventoryActionRoute::Plain => &self.plain_command,
            InventoryActionRoute::Elevated => &self.elevated_command,
        }
    }
}

fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessIdentity<'a> {
    Linux { boot_id: &'a str, start_ticks: u64 },
    PosixPs { long_start: &'a str },
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

fn valid_long_start(value: &str) -> bool {
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || fields[0].len() != 3
        || fields[1].len() != 3
        || !fields[0]
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        || !fields[1]
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        || fields[2]
            .parse::<u8>()
            .ok()
            .is_none_or(|day| !(1..=31).contains(&day))
        || fields[4]
            .parse::<u16>()
            .ok()
            .is_none_or(|year| !(1970..=9999).contains(&year))
    {
        return false;
    }
    let time = fields[3].split(':').collect::<Vec<_>>();
    time.len() == 3
        && time[0].parse::<u8>().ok().is_some_and(|hour| hour <= 23)
        && time[1]
            .parse::<u8>()
            .ok()
            .is_some_and(|minute| minute <= 59)
        && time[2]
            .parse::<u8>()
            .ok()
            .is_some_and(|second| second <= 60)
}

fn parse_process_identity(token: &str) -> Option<ProcessIdentity<'_>> {
    if let Some(value) = token.strip_prefix("linux:") {
        let (boot_id, start_ticks) = value.split_once(':')?;
        let start_ticks = start_ticks.parse::<u64>().ok().filter(|value| *value > 0)?;
        return valid_boot_id(boot_id).then_some(ProcessIdentity::Linux {
            boot_id,
            start_ticks,
        });
    }
    let long_start = token.strip_prefix("ps:")?;
    valid_long_start(long_start).then_some(ProcessIdentity::PosixPs { long_start })
}

fn identity_check_script(pid: u32, identity: &ProcessIdentity<'_>) -> String {
    match identity {
        ProcessIdentity::Linux {
            boot_id,
            start_ticks,
        } => format!(
            concat!(
                "pid={pid}; expected_boot={expected_boot}; expected_start={start_ticks}; ",
                "boot=$(tr -d \"\\r\\n\" < /proc/sys/kernel/random/boot_id 2>/dev/null) ",
                "|| exit {mismatch}; [ \"$boot\" = \"$expected_boot\" ] || exit {mismatch}; ",
                "stat_value=$(cat \"/proc/$pid/stat\" 2>/dev/null) || exit {mismatch}; ",
                "stat_tail=${{stat_value##*) }}; [ \"$stat_tail\" != \"$stat_value\" ] ",
                "|| exit {mismatch}; set -- $stat_tail; [ \"$#\" -ge 20 ] || exit {mismatch}; ",
                "shift 19; [ \"$1\" = \"$expected_start\" ] || exit {mismatch}; "
            ),
            pid = pid,
            expected_boot = shell_quote(boot_id),
            start_ticks = start_ticks,
            mismatch = PROCESS_IDENTITY_MISMATCH_EXIT_STATUS,
        ),
        ProcessIdentity::PosixPs { long_start } => format!(
            concat!(
                "pid={pid}; expected_start={expected_start}; ",
                "current_start=$(ps -p \"$pid\" -o lstart= 2>/dev/null) || exit {mismatch}; ",
                "set -- $current_start; [ \"$#\" -eq 5 ] || exit {mismatch}; ",
                "current_start=\"$1 $2 $3 $4 $5\"; ",
                "[ \"$current_start\" = \"$expected_start\" ] || exit {mismatch}; "
            ),
            pid = pid,
            expected_start = shell_quote(long_start),
            mismatch = PROCESS_IDENTITY_MISMATCH_EXIT_STATUS,
        ),
    }
}

fn identity_bound_command(check: &str, command: &str) -> String {
    let script = format!("LC_ALL=C; export LC_ALL; set -f; {check}{command}");
    format!("sh -c {}", shell_quote(&script))
}

/// Builds a signal plan only for a positive PID representable by the common
/// signed remote `pid_t` boundary.
///
/// PID 0 is especially dangerous: `kill 0` targets the caller's process
/// group. Refusing it before a command exists is stronger than trying to
/// quote or validate it later. Values above `i32::MAX` are also rejected so
/// they cannot wrap or acquire platform-specific meanings remotely.
#[must_use]
pub fn signal_action_plan(
    signal: ProcessSignal,
    pid: u32,
    start_time_token: &str,
) -> Option<InventoryActionPlan> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }
    let identity = parse_process_identity(start_time_token)?;
    let check = identity_check_script(pid, &identity);
    Some(InventoryActionPlan {
        kind: InventoryActionKind::ProcessSignal,
        probe_order: [InventoryActionRoute::Plain, InventoryActionRoute::Elevated],
        plain_probe_command: identity_bound_command(&check, "kill -0 \"$pid\""),
        elevated_probe_command: identity_bound_command(&check, "sudo -n kill -0 \"$pid\""),
        plain_command: identity_bound_command(&check, &format!("kill -{} \"$pid\"", signal.name())),
        elevated_command: identity_bound_command(
            &check,
            &format!("sudo -n kill -{} \"$pid\"", signal.name()),
        ),
    })
}

/// Builds a `systemctl` action plan, or `None` for an unusable unit name.
#[must_use]
pub fn service_action_plan(action: ServiceAction, unit: &str) -> Option<InventoryActionPlan> {
    if !is_safe_unit_name(unit) {
        return None;
    }
    let quoted_unit = shell_quote(unit);
    let base = format!("systemctl {} -- {quoted_unit}", action.verb());
    Some(InventoryActionPlan {
        kind: InventoryActionKind::SystemService,
        // A successful passwordless read probe proves that the elevated route
        // is available before the mutation. Otherwise the plain route is
        // attempted once; its failure is never replayed under sudo.
        probe_order: [InventoryActionRoute::Elevated, InventoryActionRoute::Plain],
        plain_probe_command: "sh -c 'LC_ALL=C; export LC_ALL; true'".to_owned(),
        elevated_probe_command: format!(
            "sudo -n systemctl show --property=Id --value -- {quoted_unit}"
        ),
        elevated_command: format!("sudo -n {base}"),
        plain_command: base,
    })
}

/// Parses `ps -eo pid= ppid= user= stat= pcpu= pmem= rss= etime= args=`.
///
/// The command is the remainder of the line, not a fixed column, because it
/// contains spaces; splitting it off by field count is the only correct way
/// to read this output.
#[must_use]
pub fn parse_processes(stdout: &str) -> Vec<RemoteProcess> {
    #[derive(Default)]
    struct Header {
        pid: usize,
        parent_pid: Option<usize>,
        user: Option<usize>,
        state: Option<usize>,
        cpu: Option<usize>,
        memory: Option<usize>,
        resident: Option<usize>,
        elapsed: Option<usize>,
        command: usize,
    }

    fn find_column(columns: &[&str], names: &[&str]) -> Option<usize> {
        columns
            .iter()
            .position(|column| names.iter().any(|name| column.eq_ignore_ascii_case(name)))
    }

    fn header(columns: &[&str]) -> Option<Header> {
        let pid = find_column(columns, &["PID"])?;
        let command = find_column(columns, &["COMMAND", "CMD", "ARGS"])?;
        // The generic fallbacks put the free-form command last. Refuse an
        // unfamiliar layout rather than assigning later columns to it.
        if command + 1 != columns.len() {
            return None;
        }
        Some(Header {
            pid,
            parent_pid: find_column(columns, &["PPID"]),
            user: find_column(columns, &["USER", "UID"]),
            state: find_column(columns, &["STAT", "STATE", "S"]),
            cpu: find_column(columns, &["%CPU", "CPU", "PCPU"]),
            memory: find_column(columns, &["%MEM", "MEM", "PMEM"]),
            resident: find_column(columns, &["RSS", "RSZ"]),
            elapsed: find_column(columns, &["ELAPSED", "ETIME", "TIME"]),
            command,
        })
    }

    fn value(parts: &[&str], index: Option<usize>) -> String {
        index
            .and_then(|index| parts.get(index))
            .copied()
            .unwrap_or_default()
            .to_owned()
    }

    fn parse_fallback(parts: &[&str], header: &Header) -> Option<RemoteProcess> {
        let pid = parts.get(header.pid)?.parse::<u32>().ok()?;
        let command = parts.get(header.command..)?.join(" ");
        if command.is_empty() {
            return None;
        }
        Some(RemoteProcess {
            pid,
            parent_pid: header
                .parent_pid
                .and_then(|index| parts.get(index))
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0),
            user: value(parts, header.user),
            state: value(parts, header.state),
            cpu_percent: value(parts, header.cpu),
            memory_percent: value(parts, header.memory),
            resident_kib: header
                .resident
                .and_then(|index| parts.get(index))
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0),
            elapsed: value(parts, header.elapsed),
            command,
            start_time_token: String::new(),
        })
    }

    fn framed_snapshot(stdout: &str) -> Option<(HashMap<u32, String>, &str)> {
        let snapshot = stdout
            .strip_prefix(PROCESS_IDENTITIES_HEADER)?
            .strip_prefix('\n')?;
        let (identity_rows, process_rows) =
            snapshot.split_once(&format!("\n{PROCESS_ROWS_HEADER}\n"))?;
        let mut lines = identity_rows.lines();
        let mode = lines.next()?;
        let mut identities = HashMap::new();
        match mode {
            "mode=linux" => {
                for line in lines {
                    let mut fields = line.split('\t');
                    let Some(pid) = fields.next().and_then(|value| value.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let Some(boot_id) = fields.next().filter(|value| valid_boot_id(value)) else {
                        continue;
                    };
                    let Some(start_ticks) = fields
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|value| *value > 0)
                    else {
                        continue;
                    };
                    if fields.next().is_none() {
                        identities.insert(pid, format!("linux:{boot_id}:{start_ticks}"));
                    }
                }
            }
            "mode=ps" => {
                for line in lines {
                    let mut fields = line.split_ascii_whitespace();
                    let Some(pid) = fields.next().and_then(|value| value.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let long_start = fields.collect::<Vec<_>>().join(" ");
                    if valid_long_start(&long_start) {
                        identities.insert(pid, format!("ps:{long_start}"));
                    }
                }
            }
            _ => return None,
        }
        Some((identities, process_rows))
    }

    let normalized = stdout.replace("\r\n", "\n");
    let starts_with_frame = normalized.starts_with(PROCESS_IDENTITIES_HEADER);
    let (mut identities, process_rows) = match framed_snapshot(&normalized) {
        Some(snapshot) => snapshot,
        None if starts_with_frame => return Vec::new(),
        None => (HashMap::new(), normalized.as_str()),
    };
    let mut detected_header = None;
    let mut processes = Vec::new();
    for line in process_rows.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if let Some(next_header) = header(&parts) {
            detected_header = Some(next_header);
            continue;
        }
        if let Some(header) = detected_header.as_ref() {
            if let Some(process) = parse_fallback(&parts, header) {
                processes.push(process);
            }
            continue;
        }

        let mut parts = parts.into_iter();
        let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let parent_pid = parts
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let Some(user) = parts.next().map(str::to_owned) else {
            continue;
        };
        let Some(state) = parts.next().map(str::to_owned) else {
            continue;
        };
        let Some(cpu_percent) = parts.next().map(str::to_owned) else {
            continue;
        };
        let Some(memory_percent) = parts.next().map(str::to_owned) else {
            continue;
        };
        let resident_kib = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let Some(elapsed) = parts.next().map(str::to_owned) else {
            continue;
        };
        let command = parts.collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            continue;
        }
        processes.push(RemoteProcess {
            pid,
            parent_pid,
            user,
            state,
            cpu_percent,
            memory_percent,
            resident_kib,
            elapsed,
            command,
            start_time_token: String::new(),
        });
    }
    if starts_with_frame {
        processes.retain_mut(|process| {
            let Some(token) = identities.remove(&process.pid) else {
                return false;
            };
            process.start_time_token = token;
            true
        });
    }
    processes
}

/// Splits a `host:port` local address, tolerating IPv6 forms like `[::]:22`
/// and `*:22`.
fn split_port(address: &str) -> (String, String) {
    match address.rfind(':') {
        Some(index) => (address[..index].to_owned(), address[index + 1..].to_owned()),
        None => (address.to_owned(), String::new()),
    }
}

/// Extracts the process name from `ss`'s `users:(("sshd",pid=1,fd=3))`.
fn ss_process_name(field: &str) -> String {
    field
        .split_once("((\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(name, _)| name.to_owned())
        .unwrap_or_default()
}

fn netstat_process_name(parts: &[&str]) -> String {
    parts
        .iter()
        .rev()
        .find_map(|field| {
            let (pid, name) = field.split_once('/')?;
            (!name.is_empty() && pid.chars().all(|character| character.is_ascii_digit()))
                .then(|| name.to_owned())
        })
        .unwrap_or_default()
}

/// Parses `ss -H -tulnp`, whose columns are
/// `Netid State Recv-Q Send-Q Local Peer [Process]`.
#[must_use]
pub fn parse_ports(stdout: &str) -> Vec<ListeningPort> {
    stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return None;
            }
            let protocol = parts[0].to_owned();
            if !matches!(protocol.as_str(), "tcp" | "udp" | "tcp6" | "udp6") {
                return None;
            }
            let is_netstat = parts
                .get(1)
                .is_some_and(|value| value.parse::<u64>().is_ok())
                && parts
                    .get(2)
                    .is_some_and(|value| value.parse::<u64>().is_ok());
            let local_field = if is_netstat {
                parts.get(3)?
            } else {
                parts.get(4)?
            };
            let (local_address, port) = split_port(local_field);
            if port.is_empty() {
                return None;
            }
            let process = if is_netstat {
                netstat_process_name(&parts)
            } else {
                parts
                    .get(6)
                    .map(|field| ss_process_name(field))
                    .unwrap_or_default()
            };
            Some(ListeningPort {
                protocol,
                local_address,
                port,
                process,
            })
        })
        .collect()
}

/// Parses `systemctl list-units --plain --no-legend`, whose columns are
/// `UNIT LOAD ACTIVE SUB DESCRIPTION…`.
#[must_use]
pub fn parse_services(stdout: &str) -> Vec<SystemService> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            // systemd prefixes a degraded unit with a standalone bullet, so
            // the marker is its own whitespace-separated token rather than a
            // prefix of the name. Skip it and the name is still actionable.
            let mut unit = parts.next()?.to_owned();
            if matches!(unit.as_str(), "●" | "*" | "×") {
                unit = parts.next()?.to_owned();
            }
            if !unit.ends_with(".service") {
                return None;
            }
            let load_state = parts.next()?.to_owned();
            let active_state = parts.next()?.to_owned();
            let sub_state = parts.next()?.to_owned();
            let description = parts.collect::<Vec<_>>().join(" ");
            Some(SystemService {
                unit,
                load_state,
                active_state,
                sub_state,
                description,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_ps_listing_and_keeps_the_full_command() {
        let stdout = concat!(
            " 1234     1 root     S     0.5  1.2  54321 01:23:45 /usr/sbin/sshd -D -e\n",
            " 5678  1234 www-data R     12.0 3.4 123456 00:05:01 nginx: worker process\n",
        );
        let processes = parse_processes(stdout);
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].pid, 1234);
        assert_eq!(processes[0].user, "root");
        assert_eq!(processes[0].start_time_token, "");
        // The command contains spaces, so it must be the line remainder.
        assert_eq!(processes[0].command, "/usr/sbin/sshd -D -e");
        assert_eq!(processes[1].command, "nginx: worker process");
        assert_eq!(processes[1].resident_kib, 123_456);
    }

    #[test]
    fn a_row_without_a_command_is_skipped() {
        // Headers and truncated lines look like this; showing them as
        // processes would be worse than dropping them.
        assert!(parse_processes("1234 1 root S 0.0 0.0 100 00:01").is_empty());
        assert!(parse_processes("PID PPID USER STAT").is_empty());
    }

    #[test]
    fn parses_common_ps_fallback_headers_without_inventing_missing_metrics() {
        let procps = concat!(
            "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n",
            "root 42 0.1 0.2 1000 512 ? Ss 08:00 00:01 /usr/sbin/sshd -D\n",
        );
        let processes = parse_processes(procps);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 42);
        assert_eq!(processes[0].user, "root");
        assert_eq!(processes[0].resident_kib, 512);
        assert_eq!(processes[0].command, "/usr/sbin/sshd -D");

        let basic = "PID TTY TIME CMD\n7 ? 00:00 worker --once\n";
        let processes = parse_processes(basic);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 7);
        assert_eq!(processes[0].user, "");
        assert_eq!(processes[0].elapsed, "00:00");
        assert_eq!(processes[0].command, "worker --once");
    }

    #[test]
    fn parses_ss_output_including_ipv6_and_wildcards() {
        let stdout = concat!(
            "tcp   LISTEN 0 4096 0.0.0.0:22   0.0.0.0:* users:((\"sshd\",pid=1234,fd=3))\n",
            "tcp6  LISTEN 0 4096 [::]:443     [::]:*    users:((\"nginx\",pid=99,fd=6))\n",
            "udp   UNCONN 0 0    *:68         *:*\n",
        );
        let ports = parse_ports(stdout);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, "22");
        assert_eq!(ports[0].process, "sshd");
        assert_eq!(ports[1].local_address, "[::]");
        assert_eq!(ports[1].port, "443");
        // A row with no process column is still a real listening port.
        assert_eq!(ports[2].port, "68");
        assert_eq!(ports[2].process, "");
    }

    #[test]
    fn parses_netstat_fallback_and_ignores_headers() {
        let stdout = concat!(
            "Active Internet connections (only servers)\n",
            "Proto Recv-Q Send-Q Local Address Foreign Address State\n",
            "tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n",
            "tcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN 88/postgres\n",
            "udp6 0 0 :::5353 :::* 91/avahi-daemon\n",
        );
        let ports = parse_ports(stdout);
        assert_eq!(ports.len(), 3, "header rows must not become entries");
        assert_eq!(ports[1].local_address, "127.0.0.1");
        assert_eq!(ports[1].port, "5432");
        assert_eq!(ports[1].process, "postgres");
        assert_eq!(ports[2].port, "5353");
        assert_eq!(ports[2].process, "avahi-daemon");
    }

    #[test]
    fn parses_systemctl_units_and_keeps_the_description() {
        let stdout = concat!(
            "ssh.service loaded active running OpenBSD Secure Shell server\n",
            "cron.service loaded active running Regular background program processing daemon\n",
            "dead.service loaded inactive dead Some dead unit\n",
        );
        let services = parse_services(stdout);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].unit, "ssh.service");
        assert_eq!(services[0].description, "OpenBSD Secure Shell server");
        assert!(services[0].is_running());
        assert!(!services[2].is_running());
    }

    #[test]
    fn strips_the_systemd_failure_bullet_so_the_unit_stays_actionable() {
        let services = parse_services("● broken.service loaded failed failed Broken thing\n");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].unit, "broken.service");
        assert_eq!(
            service_action_plan(ServiceAction::Restart, &services[0].unit)
                .as_ref()
                .map(|plan| plan.command(InventoryActionRoute::Plain)),
            Some("systemctl restart -- 'broken.service'"),
        );
    }

    #[test]
    fn non_service_units_are_ignored() {
        let stdout =
            "network.target loaded active active Network\nssh.service loaded active running SSH\n";
        let services = parse_services(stdout);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].unit, "ssh.service");
    }

    #[test]
    fn rejects_unit_names_that_could_reach_the_shell() {
        assert!(is_safe_unit_name("ssh.service"));
        assert!(is_safe_unit_name("user@1000.service"));
        assert!(!is_safe_unit_name("ssh.service; reboot"));
        assert!(!is_safe_unit_name("$(id).service"));
        assert!(!is_safe_unit_name(""));
        assert!(service_action_plan(ServiceAction::Stop, "a; rm -rf /",).is_none());
    }

    #[test]
    fn builds_identity_bound_signal_and_preflighted_service_plans() {
        let token = "linux:01234567-89ab-cdef-0123-456789abcdef:987654";
        let signal =
            signal_action_plan(ProcessSignal::Term, 1234, token).expect("valid signal plan");
        assert_eq!(signal.kind(), InventoryActionKind::ProcessSignal);
        assert_eq!(
            signal.probe_order(),
            [InventoryActionRoute::Plain, InventoryActionRoute::Elevated]
        );
        for route in signal.probe_order() {
            let probe = signal.probe_command(route);
            let command = signal.command(route);
            assert!(probe.contains("/proc/$pid/stat"));
            assert!(probe.contains("kill -0"));
            assert!(command.contains("/proc/$pid/stat"));
            assert!(command.contains("kill -TERM"));
            assert!(command.contains("exit 125"));
        }
        assert!(!signal.command(InventoryActionRoute::Plain).contains("sudo"));
        assert!(
            signal
                .command(InventoryActionRoute::Elevated)
                .contains("sudo -n kill -TERM")
        );

        let service =
            service_action_plan(ServiceAction::Start, "ssh.service").expect("valid service plan");
        assert_eq!(
            service.probe_order(),
            [InventoryActionRoute::Elevated, InventoryActionRoute::Plain]
        );
        assert_eq!(
            service.probe_command(InventoryActionRoute::Elevated),
            "sudo -n systemctl show --property=Id --value -- 'ssh.service'"
        );
        assert_eq!(
            service.command(InventoryActionRoute::Plain),
            "systemctl start -- 'ssh.service'"
        );
        assert_eq!(
            service.command(InventoryActionRoute::Elevated),
            "sudo -n systemctl start -- 'ssh.service'"
        );
        assert_eq!(service.kind(), InventoryActionKind::SystemService);
    }

    #[test]
    fn signal_plans_reject_process_group_and_out_of_range_targets() {
        let token = "linux:01234567-89ab-cdef-0123-456789abcdef:987654";
        assert!(signal_action_plan(ProcessSignal::Term, 0, token).is_none());
        assert!(signal_action_plan(ProcessSignal::Hup, i32::MAX as u32, token).is_some());
        assert!(signal_action_plan(ProcessSignal::Kill, i32::MAX as u32 + 1, token).is_none());
        assert!(signal_action_plan(ProcessSignal::Kill, u32::MAX, token).is_none());
        for invalid in [
            "",
            "linux:bad:1",
            "linux:01234567-89ab-cdef-0123-456789abcdef:0",
            "ps:$(touch /tmp/owned)",
            "ps:Mon Aug 31 25:00:00 2026",
        ] {
            assert!(signal_action_plan(ProcessSignal::Term, 42, invalid).is_none());
        }
    }

    #[test]
    fn framed_process_snapshot_binds_only_rows_with_preceding_identities() {
        let snapshot = concat!(
            "__GORAL_PROCESS_IDENTITIES_V1__\n",
            "mode=linux\n",
            "1234\t01234567-89ab-cdef-0123-456789abcdef\t987654\n",
            "__GORAL_PROCESS_ROWS_V1__\n",
            "1234 1 root S 0.5 1.2 54321 00:10 /usr/sbin/sshd -D\n",
            "9999 1 root S 0.0 0.1 10 00:01 should-be-dropped\n",
        );
        let processes = parse_processes(snapshot);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 1234);
        assert_eq!(
            processes[0].start_time_token,
            "linux:01234567-89ab-cdef-0123-456789abcdef:987654"
        );
    }

    #[test]
    fn portable_ps_identity_is_normalized_and_bound() {
        let snapshot = concat!(
            "__GORAL_PROCESS_IDENTITIES_V1__\n",
            "mode=ps\n",
            "  77 Mon Aug 31 12:34:56 2026\n",
            "__GORAL_PROCESS_ROWS_V1__\n",
            "77 1 user S 0.0 0.1 20 00:01 worker\n",
        );
        let processes = parse_processes(snapshot);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].start_time_token, "ps:Mon Aug 31 12:34:56 2026");
        let plan = signal_action_plan(ProcessSignal::Kill, 77, &processes[0].start_time_token)
            .expect("portable identity plan");
        assert!(plan.command(InventoryActionRoute::Plain).contains("ps -p"));
        assert!(
            plan.command(InventoryActionRoute::Plain)
                .contains("kill -KILL")
        );
    }

    #[test]
    fn every_listing_command_survives_a_missing_tool() {
        // A distribution without `ss`, `lsof` or systemd must produce an
        // empty listing, not an error the user cannot act on.
        for command in [LIST_PROCESSES, LIST_PORTS, LIST_SERVICES] {
            assert!(
                command.contains("|| true"),
                "{command} must not fail closed on a missing tool"
            );
            assert!(
                command.starts_with("sh -c"),
                "{command} must not depend on the login shell"
            );
        }
    }
}
