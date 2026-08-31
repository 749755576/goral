//! Narrow tmux session management plans and parsers.
//!
//! This module is transport-free. A future desktop adapter may execute an
//! [`TmuxExecPlan`] on an already authenticated SSH connection, but it cannot
//! supply a binary, flags, socket path, shell fragment, or startup command.
//! Interactive attach is intentionally a separate terminal launch plan:
//! `exec_capture` has no PTY and must never pretend it can attach a client.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_SESSION_NAME_BYTES: usize = 64;
pub const MAX_LIST_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_LIST_LINE_BYTES: usize = 512;
pub const MAX_LISTED_SESSIONS: usize = 512;
const MAX_WINDOW_COUNT: u32 = 1_000_000;
const MAX_EPOCH_SECONDS: u64 = 253_402_300_799;
const MUTATION_OUTPUT_LIMIT_BYTES: usize = 4 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;

/// A literal tab is passed as one argv value. Unlike the legacy `\t` format,
/// this does not need `printf`, command substitution, or another shell.
pub const LIST_SESSIONS_FORMAT: &str = concat!(
    "#{session_name}\t#{session_windows}\t#{session_attached}\t",
    "#{session_created}\t#{session_activity}",
);

/// The complete first-phase operation surface accepted from a caller.
///
/// There is deliberately no free-form command, socket, environment, or
/// binary field. `deny_unknown_fields` also keeps a future renderer from
/// smuggling one beside a valid operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum TmuxOperation {
    ListSessions,
    CreateSession {
        name: String,
    },
    AttachSession {
        name: String,
    },
    KillSession {
        name: String,
    },
    RenameSession {
        name: String,
        #[serde(rename = "newName")]
        new_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmuxExecKind {
    ListSessions,
    CreateSession,
    KillSession,
    RenameSession,
}

impl TmuxExecKind {
    #[must_use]
    pub const fn mutates(self) -> bool {
        !matches!(self, Self::ListSessions)
    }
}

/// A fixed, non-interactive invocation suitable for a bounded exec channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmuxExecPlan {
    kind: TmuxExecKind,
    args: Vec<String>,
    shell_command: String,
    max_output_bytes: usize,
}

impl TmuxExecPlan {
    #[must_use]
    pub const fn kind(&self) -> TmuxExecKind {
        self.kind
    }

    #[must_use]
    pub const fn program(&self) -> &'static str {
        "tmux"
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Shell-safe rendering for the existing `exec_capture` transport.
    #[must_use]
    pub fn shell_command(&self) -> &str {
        &self.shell_command
    }

    /// Per-stream bound for both stdout and stderr.
    #[must_use]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn mutates(&self) -> bool {
        self.kind.mutates()
    }

    /// Empty output is valid for mutations and may mean an empty catalog for
    /// reads. Retrying on that signal could execute a mutation twice.
    #[must_use]
    pub const fn retry_on_empty_output(&self) -> bool {
        false
    }
}

/// Interactive attach must be launched inside a real terminal/PTY.
///
/// No shell string is exposed: the terminal runtime receives one fixed
/// program plus already validated argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmuxTerminalLaunchPlan {
    args: Vec<String>,
}

impl TmuxTerminalLaunchPlan {
    #[must_use]
    pub const fn program(&self) -> &'static str {
        "tmux"
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TmuxOperationPlan {
    Exec(TmuxExecPlan),
    TerminalAttach(TmuxTerminalLaunchPlan),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmuxPlanError {
    InvalidSessionName,
    RenameTargetUnchanged,
}

impl fmt::Display for TmuxPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionName => "tmux session name is invalid",
            Self::RenameTargetUnchanged => "tmux rename target is unchanged",
        })
    }
}

impl std::error::Error for TmuxPlanError {}

/// Builds one native-owned operation plan.
pub fn plan_operation(operation: &TmuxOperation) -> Result<TmuxOperationPlan, TmuxPlanError> {
    match operation {
        TmuxOperation::ListSessions => Ok(TmuxOperationPlan::Exec(exec_plan(
            TmuxExecKind::ListSessions,
            [
                "list-sessions".to_owned(),
                "-F".to_owned(),
                LIST_SESSIONS_FORMAT.to_owned(),
            ],
        ))),
        TmuxOperation::CreateSession { name } => {
            validate_session_name(name)?;
            Ok(TmuxOperationPlan::Exec(exec_plan(
                TmuxExecKind::CreateSession,
                [
                    "new-session".to_owned(),
                    "-d".to_owned(),
                    "-s".to_owned(),
                    name.clone(),
                ],
            )))
        }
        TmuxOperation::AttachSession { name } => {
            validate_session_name(name)?;
            Ok(TmuxOperationPlan::TerminalAttach(TmuxTerminalLaunchPlan {
                args: vec![
                    "attach-session".to_owned(),
                    "-t".to_owned(),
                    exact_target(name),
                ],
            }))
        }
        TmuxOperation::KillSession { name } => {
            validate_session_name(name)?;
            Ok(TmuxOperationPlan::Exec(exec_plan(
                TmuxExecKind::KillSession,
                [
                    "kill-session".to_owned(),
                    "-t".to_owned(),
                    exact_target(name),
                ],
            )))
        }
        TmuxOperation::RenameSession { name, new_name } => {
            validate_session_name(name)?;
            validate_session_name(new_name)?;
            if name == new_name {
                return Err(TmuxPlanError::RenameTargetUnchanged);
            }
            Ok(TmuxOperationPlan::Exec(exec_plan(
                TmuxExecKind::RenameSession,
                [
                    "rename-session".to_owned(),
                    "-t".to_owned(),
                    exact_target(name),
                    new_name.clone(),
                ],
            )))
        }
    }
}

fn exec_plan<const N: usize>(kind: TmuxExecKind, args: [String; N]) -> TmuxExecPlan {
    let args = Vec::from(args);
    let shell_command = render_shell_command(&args);
    let max_output_bytes = if matches!(kind, TmuxExecKind::ListSessions) {
        MAX_LIST_OUTPUT_BYTES
    } else {
        MUTATION_OUTPUT_LIMIT_BYTES
    };
    TmuxExecPlan {
        kind,
        args,
        shell_command,
        max_output_bytes,
    }
}

fn render_shell_command(args: &[String]) -> String {
    let mut command = String::from("tmux");
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command
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

fn exact_target(name: &str) -> String {
    format!("={name}")
}

/// Validates the UTF-8 name as data, not as a shell fragment.
///
/// The legacy application allowed quoted Unicode names, including Chinese.
/// Keep that compatibility while rejecting the tab/newline format boundary,
/// all control characters, and `:`, tmux's session/window target separator.
/// Metacharacters remain safe because every dynamic argv value is single-
/// quoted by [`shell_quote`].
pub fn validate_session_name(name: &str) -> Result<(), TmuxPlanError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_SESSION_NAME_BYTES
        || name.chars().all(char::is_whitespace)
        || name
            .chars()
            .any(|character| character.is_control() || character == ':')
    {
        return Err(TmuxPlanError::InvalidSessionName);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TmuxSession {
    pub name: String,
    pub windows: u32,
    pub attached: bool,
    pub created: Option<u64>,
    pub last_activity: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmuxParseError {
    OutputTooLarge,
    LineTooLarge,
    TooManySessions,
    MalformedRow,
    DuplicateSession,
}

impl fmt::Display for TmuxParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutputTooLarge => "tmux session output exceeds the limit",
            Self::LineTooLarge => "tmux session row exceeds the limit",
            Self::TooManySessions => "tmux session count exceeds the limit",
            Self::MalformedRow => "tmux session output is malformed",
            Self::DuplicateSession => "tmux session output contains a duplicate",
        })
    }
}

impl std::error::Error for TmuxParseError {}

/// Parses the exact output requested by [`LIST_SESSIONS_FORMAT`].
///
/// A malformed row rejects the snapshot instead of becoming a phantom or
/// partially actionable session. Empty output is a valid empty catalog.
pub fn parse_sessions(stdout: &str) -> Result<Vec<TmuxSession>, TmuxParseError> {
    if stdout.len() > MAX_LIST_OUTPUT_BYTES {
        return Err(TmuxParseError::OutputTooLarge);
    }

    let mut sessions = Vec::new();
    let mut names = HashSet::new();
    for raw_line in stdout.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LIST_LINE_BYTES {
            return Err(TmuxParseError::LineTooLarge);
        }
        if sessions.len() == MAX_LISTED_SESSIONS {
            return Err(TmuxParseError::TooManySessions);
        }

        let mut fields = line.split('\t');
        let name = fields.next().ok_or(TmuxParseError::MalformedRow)?;
        let windows = fields.next().ok_or(TmuxParseError::MalformedRow)?;
        let attached = fields.next().ok_or(TmuxParseError::MalformedRow)?;
        let created = fields.next().ok_or(TmuxParseError::MalformedRow)?;
        let activity = fields.next().ok_or(TmuxParseError::MalformedRow)?;
        if fields.next().is_some() || validate_session_name(name).is_err() {
            return Err(TmuxParseError::MalformedRow);
        }

        let windows = windows
            .parse::<u32>()
            .ok()
            .filter(|count| (1..=MAX_WINDOW_COUNT).contains(count))
            .ok_or(TmuxParseError::MalformedRow)?;
        let attached = match attached {
            "0" => false,
            "1" => true,
            _ => return Err(TmuxParseError::MalformedRow),
        };
        let created = parse_optional_epoch(created)?;
        let last_activity = parse_optional_epoch(activity)?;
        if !names.insert(name.to_owned()) {
            return Err(TmuxParseError::DuplicateSession);
        }
        sessions.push(TmuxSession {
            name: name.to_owned(),
            windows,
            attached,
            created,
            last_activity,
        });
    }
    Ok(sessions)
}

fn parse_optional_epoch(value: &str) -> Result<Option<u64>, TmuxParseError> {
    if value.is_empty() || value == "0" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|epoch| (1..=MAX_EPOCH_SECONDS).contains(epoch))
        .map(Some)
        .ok_or(TmuxParseError::MalformedRow)
}

/// tmux reports an empty server as exit status 1 rather than an empty,
/// successful listing. Recognize only its two stable bounded diagnostics;
/// other failures remain failures for the adapter to surface safely.
#[must_use]
pub fn is_no_server_message(text: &str, exit_status: Option<i32>) -> bool {
    if exit_status != Some(1) || text.len() > MAX_DIAGNOSTIC_BYTES {
        return false;
    }
    let message = text.trim().to_ascii_lowercase();
    message.contains("no server running")
        || (message.starts_with("error connecting to ")
            && message.contains("no such file or directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(operation: TmuxOperation) -> TmuxExecPlan {
        match plan_operation(&operation).expect("valid operation") {
            TmuxOperationPlan::Exec(plan) => plan,
            TmuxOperationPlan::TerminalAttach(_) => panic!("expected exec plan"),
        }
    }

    #[test]
    fn list_plan_uses_only_fixed_tmux_argv_and_bounded_output() {
        let plan = exec(TmuxOperation::ListSessions);
        assert_eq!(plan.program(), "tmux");
        assert_eq!(plan.args(), ["list-sessions", "-F", LIST_SESSIONS_FORMAT]);
        assert_eq!(plan.kind(), TmuxExecKind::ListSessions);
        assert!(!plan.mutates());
        assert!(!plan.retry_on_empty_output());
        assert_eq!(plan.max_output_bytes(), MAX_LIST_OUTPUT_BYTES);
        assert!(
            plan.shell_command()
                .starts_with("tmux 'list-sessions' '-F' ")
        );
        assert!(!plan.shell_command().contains("sudo"));
        assert!(!plan.shell_command().contains("sh -c"));
    }

    #[test]
    fn mutation_plans_are_narrow_exact_and_shell_quoted() {
        let create = exec(TmuxOperation::CreateSession {
            name: "deploy-1".to_owned(),
        });
        assert_eq!(create.args(), ["new-session", "-d", "-s", "deploy-1"]);
        assert_eq!(
            create.shell_command(),
            "tmux 'new-session' '-d' '-s' 'deploy-1'"
        );

        let kill = exec(TmuxOperation::KillSession {
            name: "deploy-1".to_owned(),
        });
        assert_eq!(kill.args(), ["kill-session", "-t", "=deploy-1"]);

        let rename = exec(TmuxOperation::RenameSession {
            name: "deploy-1".to_owned(),
            new_name: "deploy-2".to_owned(),
        });
        assert_eq!(
            rename.args(),
            ["rename-session", "-t", "=deploy-1", "deploy-2"]
        );
        for plan in [create, kill, rename] {
            assert!(plan.mutates());
            assert!(!plan.retry_on_empty_output());
            assert_eq!(plan.program(), "tmux");
            assert_eq!(plan.max_output_bytes(), MUTATION_OUTPUT_LIMIT_BYTES);
            assert!(!plan.shell_command().contains("sudo"));
        }
    }

    #[test]
    fn attach_is_a_terminal_launch_plan_not_an_exec_command() {
        let operation = TmuxOperation::AttachSession {
            name: "ops".to_owned(),
        };
        let TmuxOperationPlan::TerminalAttach(plan) =
            plan_operation(&operation).expect("valid attach")
        else {
            panic!("attach must require a PTY");
        };
        assert_eq!(plan.program(), "tmux");
        assert_eq!(plan.args(), ["attach-session", "-t", "=ops"]);
    }

    #[test]
    fn invalid_or_ambiguous_names_never_produce_a_plan() {
        for name in ["", "   ", "a\tb", "a\nb", "a\0b", "a:b"] {
            assert_eq!(
                plan_operation(&TmuxOperation::KillSession {
                    name: name.to_owned(),
                }),
                Err(TmuxPlanError::InvalidSessionName),
                "unexpectedly accepted {name:?}",
            );
        }
        assert!(validate_session_name(&"a".repeat(MAX_SESSION_NAME_BYTES)).is_ok());
        assert_eq!(
            validate_session_name(&"a".repeat(MAX_SESSION_NAME_BYTES + 1)),
            Err(TmuxPlanError::InvalidSessionName)
        );
        assert_eq!(
            plan_operation(&TmuxOperation::RenameSession {
                name: "same".to_owned(),
                new_name: "same".to_owned(),
            }),
            Err(TmuxPlanError::RenameTargetUnchanged)
        );
    }

    #[test]
    fn legacy_unicode_and_shell_metacharacter_names_are_preserved_as_data() {
        for name in [
            " leading",
            "two words",
            "a;reboot",
            "$(id)",
            "a`id`",
            "a/b",
            "中文",
            "-leading-option",
        ] {
            assert!(
                validate_session_name(name).is_ok(),
                "unexpectedly rejected {name:?}",
            );
        }

        let plan = exec(TmuxOperation::CreateSession {
            name: "发布 '$(touch nope)'".to_owned(),
        });
        assert_eq!(
            plan.args(),
            ["new-session", "-d", "-s", "发布 '$(touch nope)'"]
        );
        assert_eq!(
            plan.shell_command(),
            "tmux 'new-session' '-d' '-s' '发布 '\"'\"'$(touch nope)'\"'\"''"
        );

        assert!(validate_session_name(&"中".repeat(21)).is_ok());
        assert_eq!(
            validate_session_name(&"中".repeat(22)),
            Err(TmuxPlanError::InvalidSessionName)
        );
    }

    #[test]
    fn request_contract_rejects_unknown_fields_and_operations() {
        let list: TmuxOperation =
            serde_json::from_str(r#"{"operation":"listSessions"}"#).expect("list request");
        assert_eq!(list, TmuxOperation::ListSessions);
        assert!(
            serde_json::from_str::<TmuxOperation>(
                r#"{"operation":"createSession","name":"demo","command":"curl bad"}"#,
            )
            .is_err()
        );
        assert!(serde_json::from_str::<TmuxOperation>(r#"{"operation":"killServer"}"#).is_err());
    }

    #[test]
    fn parser_reads_the_exact_bounded_session_format() {
        let sessions = parse_sessions(concat!(
            "work\t3\t1\t1788000000\t1788000123\n",
            "idle\t1\t0\t0\t\n",
        ))
        .expect("valid listing");
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions[0],
            TmuxSession {
                name: "work".to_owned(),
                windows: 3,
                attached: true,
                created: Some(1_788_000_000),
                last_activity: Some(1_788_000_123),
            }
        );
        assert_eq!(sessions[1].created, None);
        assert_eq!(sessions[1].last_activity, None);
        assert_eq!(parse_sessions(""), Ok(Vec::new()));
    }

    #[test]
    fn session_snapshot_serializes_with_the_renderer_contract() {
        let session = TmuxSession {
            name: "中文 session".to_owned(),
            windows: 2,
            attached: false,
            created: Some(1_788_000_000),
            last_activity: None,
        };
        assert_eq!(
            serde_json::to_value(session).expect("serialize snapshot"),
            serde_json::json!({
                "name": "中文 session",
                "windows": 2,
                "attached": false,
                "created": 1_788_000_000_u64,
                "lastActivity": null,
            })
        );
    }

    #[test]
    fn parser_rejects_malformed_diagnostic_or_duplicate_rows() {
        for output in [
            "no server running on /tmp/tmux-1/default\n",
            "demo\t1\tmaybe\t1\t2\n",
            "demo\t0\t0\t1\t2\n",
            "demo\t1\t0\tnot-time\t2\n",
            "bad:name\t1\t0\t1\t2\n",
            "demo\t1\t0\t1\t2\textra\n",
            " \n",
            "demo\t1\t0\t253402300800\t2\n",
        ] {
            assert_eq!(
                parse_sessions(output),
                Err(TmuxParseError::MalformedRow),
                "unexpectedly parsed {output:?}",
            );
        }
        assert_eq!(
            parse_sessions("demo\t1\t0\t1\t2\ndemo\t2\t1\t3\t4\n"),
            Err(TmuxParseError::DuplicateSession)
        );
    }

    #[test]
    fn only_exit_one_empty_server_diagnostics_become_an_empty_catalog() {
        assert!(is_no_server_message(
            "no server running on /tmp/tmux-1000/default",
            Some(1),
        ));
        assert!(is_no_server_message(
            "error connecting to /tmp/tmux-1000/default (No such file or directory)",
            Some(1),
        ));
        assert!(!is_no_server_message(
            "error connecting to /tmp/tmux-1000/default (Permission denied)",
            Some(1),
        ));
        assert!(!is_no_server_message(
            "no server running on /tmp/tmux-1000/default",
            Some(0),
        ));
        assert!(!is_no_server_message(
            &"x".repeat(MAX_DIAGNOSTIC_BYTES + 1),
            Some(1),
        ));
    }

    #[test]
    fn parser_enforces_output_line_and_record_limits() {
        assert_eq!(
            parse_sessions(&"x".repeat(MAX_LIST_OUTPUT_BYTES + 1)),
            Err(TmuxParseError::OutputTooLarge)
        );
        let oversized_line = format!("{}\t1\t0\t1\t2", "a".repeat(MAX_LIST_LINE_BYTES));
        assert_eq!(
            parse_sessions(&oversized_line),
            Err(TmuxParseError::LineTooLarge)
        );
        let too_many = (0..=MAX_LISTED_SESSIONS)
            .map(|index| format!("s{index}\t1\t0\t1\t2\n"))
            .collect::<String>();
        assert_eq!(
            parse_sessions(&too_many),
            Err(TmuxParseError::TooManySessions)
        );
    }

    #[test]
    fn shell_quoting_is_total_even_if_a_future_fixed_argument_contains_a_quote() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }
}
