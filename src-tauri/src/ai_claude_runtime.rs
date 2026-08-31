use std::path::Path;
use std::process::Stdio;

use netcatty_ai::MAX_AI_RESPONSE_BYTES;
use serde::Deserialize;
use serde::de::IgnoredAny;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

use crate::ai_agent_discovery::{
    ResolvedAgentCommand, SUPPORTED_CLAUDE_VERSION, resolved_agent_has_exact_version,
};

const CLAUDE_SYSTEM_PROMPT: &str = "You are Goral's read-only terminal assistant. Answer only from the supplied conversation. You have no tools. Never claim to run commands, read files, access MCP, plugins, skills, project rules, or external context.";

// `--verbose` is required by Claude Code when `--print` and `stream-json` are
// combined. `--safe-mode` preserves the user's existing authentication and
// model selection while constraining project/user customization behavior.
// Claude 2.1.246 can still report installed agent/plugin metadata in its init
// event and normalizes `--permission-mode dontAsk` to `default` there. We do
// not claim that metadata is absent: the reviewed boundary requires zero
// model-visible tools and zero MCP servers, and rejects every tool-use/result
// event before it can reach the renderer. Claude's own contract keeps
// admin-managed policy active; the executable and host policy are therefore
// an explicit trust boundary, not an OS sandbox.
pub(crate) const CLAUDE_PRINT_ARGS: [&str; 20] = [
    "--print",
    "--verbose",
    "--input-format",
    "text",
    "--output-format",
    "stream-json",
    "--include-partial-messages",
    "--no-session-persistence",
    "--safe-mode",
    "--tools",
    "",
    "--permission-mode",
    "dontAsk",
    "--disable-slash-commands",
    "--no-chrome",
    "--strict-mcp-config",
    "--prompt-suggestions",
    "false",
    "--system-prompt",
    CLAUDE_SYSTEM_PROMPT,
];

const MAX_CLAUDE_JSONL_LINE_BYTES: usize = MAX_AI_RESPONSE_BYTES;
const REVIEWED_CLAUDE_PERMISSION_MODES: [&str; 2] = ["dontAsk", "default"];

const AI_LOCAL_AGENT_UNAVAILABLE: &str = "AI_LOCAL_AGENT_UNAVAILABLE";
const AI_LOCAL_AGENT_START_FAILED: &str = "AI_LOCAL_AGENT_START_FAILED";
const AI_LOCAL_AGENT_FAILED: &str = "AI_LOCAL_AGENT_FAILED";
const AI_RESPONSE_TOO_LARGE: &str = "AI_RESPONSE_TOO_LARGE";
const AI_RESPONSE_INVALID: &str = "AI_RESPONSE_INVALID";
const AI_EMPTY_RESPONSE: &str = "AI_EMPTY_RESPONSE";

fn configure_hidden_claude_command(command: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
}

fn claude_command(resolved: &ResolvedAgentCommand, cwd: &Path) -> tokio::process::Command {
    let mut command = resolved.command();
    configure_claude_command(&mut command, cwd);
    command
}

fn configure_claude_command(command: &mut tokio::process::Command, cwd: &Path) {
    command
        .args(CLAUDE_PRINT_ARGS)
        .current_dir(cwd)
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("DISABLE_BUG_COMMAND", "1")
        .env("DISABLE_ERROR_REPORTING", "1")
        .env("DISABLE_TELEMETRY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_hidden_claude_command(command);
}

#[derive(Deserialize)]
struct EnvelopeKind {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    subtype: Option<String>,
}

#[derive(Deserialize)]
struct InitEnvelope {
    #[serde(default)]
    tools: Option<Vec<IgnoredAny>>,
    #[serde(default)]
    mcp_servers: Option<Vec<IgnoredAny>>,
    #[serde(default, rename = "permissionMode")]
    permission_mode: Option<String>,
}

#[derive(Deserialize)]
struct StreamEnvelope {
    event: StreamEvent,
}

#[derive(Deserialize)]
struct StreamEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    delta: Option<StreamDelta>,
    #[serde(default)]
    content_block: Option<ContentBlockKind>,
}

#[derive(Deserialize)]
struct StreamDelta {
    // Claude 2.1.246's `message_delta.delta` contains stop metadata but no
    // `type`; only `content_block_delta` requires a typed delta below.
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct ContentBlockKind {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct AssistantEnvelope {
    message: AssistantMessage,
}

#[derive(Deserialize)]
struct AssistantMessage {
    #[serde(default)]
    content: Vec<ContentBlockKind>,
}

#[derive(Deserialize)]
struct ResultEnvelope {
    subtype: String,
    is_error: bool,
    #[serde(default)]
    result: Option<String>,
}

struct ClaudeStreamState {
    initialized: bool,
    finished: bool,
    streamed_content: String,
    final_content: Option<String>,
}

impl ClaudeStreamState {
    fn new() -> Self {
        Self {
            initialized: false,
            finished: false,
            streamed_content: String::new(),
            final_content: None,
        }
    }

    fn require_active(&self) -> Result<(), String> {
        if !self.initialized || self.finished {
            return Err(AI_RESPONSE_INVALID.to_owned());
        }
        Ok(())
    }

    fn parse_line<F>(&mut self, line: &[u8], on_delta: &mut F) -> Result<(), String>
    where
        F: FnMut(String) -> Result<(), String>,
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }

        let envelope: EnvelopeKind =
            serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        match (envelope.kind.as_str(), envelope.subtype.as_deref()) {
            ("system", Some("init")) => self.parse_init(line),
            ("system", _) => self.require_active(),
            ("stream_event", _) => self.parse_stream_event(line, on_delta),
            ("assistant", _) => self.parse_assistant(line),
            ("result", _) => self.parse_result(line),
            // Tool results are emitted as `user` records. They are impossible
            // under the zero-tool policy and therefore invalidate the turn.
            ("user", _) => Err(AI_LOCAL_AGENT_START_FAILED.to_owned()),
            _ => Err(AI_RESPONSE_INVALID.to_owned()),
        }
    }

    fn parse_init(&mut self, line: &[u8]) -> Result<(), String> {
        if self.initialized || self.finished {
            return Err(AI_RESPONSE_INVALID.to_owned());
        }
        let init: InitEnvelope =
            serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        let tools = init
            .tools
            .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        let mcp_servers = init
            .mcp_servers
            .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        let permission_mode = init
            .permission_mode
            .as_deref()
            .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        if !tools.is_empty()
            || !mcp_servers.is_empty()
            || !REVIEWED_CLAUDE_PERMISSION_MODES.contains(&permission_mode)
        {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        self.initialized = true;
        Ok(())
    }

    fn parse_stream_event<F>(&mut self, line: &[u8], on_delta: &mut F) -> Result<(), String>
    where
        F: FnMut(String) -> Result<(), String>,
    {
        self.require_active()?;
        let stream: StreamEnvelope =
            serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        match stream.event.kind.as_str() {
            "message_start" | "message_delta" | "message_stop" | "content_block_stop" | "ping" => {
                Ok(())
            }
            "content_block_start" => {
                let block = stream
                    .event
                    .content_block
                    .ok_or_else(|| AI_RESPONSE_INVALID.to_owned())?;
                if matches!(
                    block.kind.as_str(),
                    "text" | "thinking" | "redacted_thinking"
                ) {
                    Ok(())
                } else {
                    Err(AI_LOCAL_AGENT_START_FAILED.to_owned())
                }
            }
            "content_block_delta" => {
                let delta = stream
                    .event
                    .delta
                    .ok_or_else(|| AI_RESPONSE_INVALID.to_owned())?;
                match delta.kind.as_deref() {
                    Some("text_delta") => {
                        let text = delta.text.ok_or_else(|| AI_RESPONSE_INVALID.to_owned())?;
                        if text.is_empty() {
                            return Ok(());
                        }
                        let next_length = self
                            .streamed_content
                            .len()
                            .checked_add(text.len())
                            .ok_or_else(|| AI_RESPONSE_TOO_LARGE.to_owned())?;
                        if next_length > MAX_AI_RESPONSE_BYTES {
                            return Err(AI_RESPONSE_TOO_LARGE.to_owned());
                        }
                        self.streamed_content.push_str(&text);
                        on_delta(text)
                    }
                    // Reasoning is not renderer output. Signatures and
                    // citations carry no execution authority.
                    Some("thinking_delta" | "signature_delta" | "citations_delta") => Ok(()),
                    // Partial JSON is a tool invocation. No such event is
                    // legal after `--tools ""` and the init verification.
                    Some("input_json_delta") => Err(AI_LOCAL_AGENT_START_FAILED.to_owned()),
                    _ => Err(AI_RESPONSE_INVALID.to_owned()),
                }
            }
            _ => Err(AI_RESPONSE_INVALID.to_owned()),
        }
    }

    fn parse_assistant(&self, line: &[u8]) -> Result<(), String> {
        self.require_active()?;
        let assistant: AssistantEnvelope =
            serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        if assistant.message.content.iter().all(|block| {
            matches!(
                block.kind.as_str(),
                "text" | "thinking" | "redacted_thinking"
            )
        }) {
            Ok(())
        } else {
            Err(AI_LOCAL_AGENT_START_FAILED.to_owned())
        }
    }

    fn parse_result(&mut self, line: &[u8]) -> Result<(), String> {
        self.require_active()?;
        let result: ResultEnvelope =
            serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        if result.subtype != "success" || result.is_error {
            return Err(AI_LOCAL_AGENT_FAILED.to_owned());
        }
        let content = result.result.ok_or_else(|| AI_EMPTY_RESPONSE.to_owned())?;
        if content.is_empty() {
            return Err(AI_EMPTY_RESPONSE.to_owned());
        }
        if content.len() > MAX_AI_RESPONSE_BYTES {
            return Err(AI_RESPONSE_TOO_LARGE.to_owned());
        }
        self.final_content = Some(content);
        self.finished = true;
        Ok(())
    }

    fn finish(self) -> Result<String, String> {
        if !self.initialized || !self.finished {
            return Err(AI_RESPONSE_INVALID.to_owned());
        }
        self.final_content
            .filter(|content| !content.is_empty())
            .ok_or_else(|| AI_EMPTY_RESPONSE.to_owned())
    }
}

async fn parse_claude_stdout<R, F>(mut stdout: R, mut on_delta: F) -> Result<String, String>
where
    R: AsyncRead + Unpin,
    F: FnMut(String) -> Result<(), String>,
{
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    let mut line = Zeroizing::new(Vec::new());
    let mut total = 0_usize;
    let mut state = ClaudeStreamState::new();

    loop {
        let read = stdout
            .read(&mut *chunk)
            .await
            .map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read)
            .ok_or_else(|| AI_RESPONSE_TOO_LARGE.to_owned())?;
        if total > MAX_AI_RESPONSE_BYTES {
            return Err(AI_RESPONSE_TOO_LARGE.to_owned());
        }

        for byte in &chunk[..read] {
            if *byte == b'\n' {
                state.parse_line(&line, &mut on_delta)?;
                // Init records can contain local plugin/configuration paths in
                // fields this parser deliberately ignores. Erase the parsed
                // bytes before reusing the allocation; `clear()` alone would
                // leave them in spare capacity until that memory is reused.
                line.zeroize();
            } else {
                if line.len() >= MAX_CLAUDE_JSONL_LINE_BYTES {
                    return Err(AI_RESPONSE_TOO_LARGE.to_owned());
                }
                line.push(*byte);
            }
        }
    }

    if !line.is_empty() {
        state.parse_line(&line, &mut on_delta)?;
    }
    state.finish()
}

async fn drain_claude_stderr<R>(mut stderr: R) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        match stderr.read(&mut *buffer).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(_) => return Err(AI_LOCAL_AGENT_FAILED.to_owned()),
        }
    }
}

pub(crate) async fn execute_claude<F>(
    resolved: ResolvedAgentCommand,
    cwd: &Path,
    prompt: Vec<u8>,
    on_delta: F,
) -> Result<String, String>
where
    F: FnMut(String) -> Result<(), String>,
{
    let prompt = Zeroizing::new(prompt);
    // Discovery is only a UI hint. Re-probe the exact executable immediately
    // before every turn so a PATH/package change cannot bypass the one Claude
    // version whose safe-mode contract this runtime has reviewed.
    if !resolved_agent_has_exact_version(&resolved, SUPPORTED_CLAUDE_VERSION).await {
        return Err(AI_LOCAL_AGENT_UNAVAILABLE.to_owned());
    }
    let mut child = claude_command(&resolved, cwd)
        .spawn()
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;

    let write_prompt = async move {
        stdin
            .write_all(&prompt)
            .await
            .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
        stdin
            .shutdown()
            .await
            .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())
    };
    let wait = async {
        child
            .wait()
            .await
            .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())
    };
    let ((), content, (), status) = tokio::try_join!(
        write_prompt,
        parse_claude_stdout(stdout, on_delta),
        drain_claude_stderr(stderr),
        wait,
    )?;
    if !status.success() {
        return Err(AI_LOCAL_AGENT_FAILED.to_owned());
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tokio::io::AsyncWriteExt;

    fn init(tools: &str, mcp_servers: &str, permission: &str) -> String {
        format!(
            r#"{{"type":"system","subtype":"init","tools":{tools},"mcp_servers":{mcp_servers},"permissionMode":"{permission}"}}"#
        )
    }

    fn delta(text: &str) -> String {
        serde_json::json!({
            "type": "stream_event",
            "event": {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": text}
            }
        })
        .to_string()
    }

    fn result(text: &str) -> String {
        serde_json::json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "result": text
        })
        .to_string()
    }

    async fn parse_lines(lines: &[String]) -> Result<(String, Vec<String>), String> {
        let input = lines.join("\n");
        let mut deltas = Vec::new();
        let content = parse_claude_stdout(input.as_bytes(), |delta| {
            deltas.push(delta);
            Ok(())
        })
        .await?;
        Ok((content, deltas))
    }

    #[test]
    fn fixed_arguments_request_a_zero_tool_ephemeral_turn() {
        assert_eq!(
            CLAUDE_PRINT_ARGS,
            [
                "--print",
                "--verbose",
                "--input-format",
                "text",
                "--output-format",
                "stream-json",
                "--include-partial-messages",
                "--no-session-persistence",
                "--safe-mode",
                "--tools",
                "",
                "--permission-mode",
                "dontAsk",
                "--disable-slash-commands",
                "--no-chrome",
                "--strict-mcp-config",
                "--prompt-suggestions",
                "false",
                "--system-prompt",
                CLAUDE_SYSTEM_PROMPT,
            ]
        );
        assert!(!CLAUDE_PRINT_ARGS.contains(&"--bare"));
        assert!(!CLAUDE_PRINT_ARGS.contains(&"--dangerously-skip-permissions"));
        assert!(!CLAUDE_PRINT_ARGS.contains(&"--mcp-config"));
    }

    #[test]
    fn command_is_noninteractive_hidden_and_disables_background_traffic() {
        let mut command = tokio::process::Command::new("claude");
        let cwd = std::env::temp_dir().join("goral-claude-runtime-test");
        configure_claude_command(&mut command, &cwd);
        assert_eq!(
            command
                .as_std()
                .get_args()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            CLAUDE_PRINT_ARGS
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(command.as_std().get_current_dir(), Some(cwd.as_path()));
        let environment = command
            .as_std()
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect::<std::collections::BTreeMap<_, _>>();
        for name in [
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "DISABLE_AUTOUPDATER",
            "DISABLE_BUG_COMMAND",
            "DISABLE_ERROR_REPORTING",
            "DISABLE_TELEMETRY",
        ] {
            assert_eq!(
                environment.get(std::ffi::OsStr::new(name)).copied(),
                Some(std::ffi::OsStr::new("1"))
            );
        }
    }

    #[tokio::test]
    async fn stream_parser_requires_policy_init_and_handles_chunked_unicode() {
        let payload = [
            init("[]", "[]", "dontAsk"),
            r#"{"type":"system","subtype":"status","status":"requesting"}"#.into(),
            delta("你"),
            delta("好"),
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"你好"}]}}"#.into(),
            result("你好"),
        ]
        .join("\n");
        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            for chunk in payload.as_bytes().chunks(3) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut deltas = Vec::new();
        let content = parse_claude_stdout(reader, |delta| {
            deltas.push(delta);
            Ok(())
        })
        .await
        .unwrap();
        write.await.unwrap();
        assert_eq!(content, "你好");
        assert_eq!(deltas, ["你", "好"]);
    }

    #[tokio::test]
    async fn reviewed_safe_mode_init_accepts_claudes_reported_default_metadata() {
        let init = serde_json::json!({
            "type": "system",
            "subtype": "init",
            "tools": [],
            "mcp_servers": [],
            "permissionMode": "default",
            // Claude 2.1.246 reports installed metadata even in safe mode.
            // It carries no authority here because tools and MCP are empty,
            // and later tool-use/result records remain rejected.
            "agents": ["general-purpose", "statusline-setup", "Explore", "Plan"],
            "plugins": [{"name": "one"}, {"name": "two"}],
            "skills": [],
            "slash_commands": []
        })
        .to_string();
        let (content, deltas) = parse_lines(&[
            init,
            r#"{"type":"system","subtype":"status","status":"thinking_tokens"}"#.into(),
            r#"{"type":"stream_event","event":{"type":"content_block_start","content_block":{"type":"thinking"}}}"#.into(),
            r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"private"}}}"#.into(),
            delta("answer"),
            result("answer"),
        ])
        .await
        .unwrap();

        assert_eq!(content, "answer");
        assert_eq!(deltas, ["answer"]);
    }

    #[tokio::test]
    async fn reviewed_message_delta_stop_metadata_does_not_require_a_delta_type() {
        // Captured from the reviewed Claude Code 2.1.246 stream-json contract.
        // Unlike content-block deltas, the message-level delta has no `type`.
        let message_delta = serde_json::json!({
            "type": "stream_event",
            "event": {
                "type": "message_delta",
                "delta": {
                    "stop_reason": "end_turn",
                    "stop_sequence": null
                },
                "usage": { "output_tokens": 8 }
            }
        })
        .to_string();
        let (content, deltas) = parse_lines(&[
            init("[]", "[]", "dontAsk"),
            delta("Claude 验收通过"),
            message_delta,
            result("Claude 验收通过"),
        ])
        .await
        .unwrap();

        assert_eq!(content, "Claude 验收通过");
        assert_eq!(deltas, ["Claude 验收通过"]);

        let untyped_content_delta = r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"text":"must fail"}}}"#.to_owned();
        assert_eq!(
            parse_lines(&[
                init("[]", "[]", "dontAsk"),
                untyped_content_delta,
                result("ignored"),
            ])
            .await
            .unwrap_err(),
            AI_RESPONSE_INVALID
        );
    }

    #[tokio::test]
    async fn policy_init_fails_closed_for_tools_mcp_or_wrong_permission() {
        for unsafe_init in [
            init(r#"[{"name":"Read"}]"#, "[]", "dontAsk"),
            init("[]", r#"[{"name":"server"}]"#, "dontAsk"),
            init("[]", "[]", "plan"),
            init("[]", "[]", "acceptEdits"),
            init("[]", "[]", "bypassPermissions"),
        ] {
            assert_eq!(
                parse_lines(&[unsafe_init, result("ignored")])
                    .await
                    .unwrap_err(),
                AI_LOCAL_AGENT_START_FAILED
            );
        }
        assert_eq!(
            parse_lines(&[delta("before-init"), result("ignored")])
                .await
                .unwrap_err(),
            AI_RESPONSE_INVALID
        );
    }

    #[tokio::test]
    async fn tool_events_and_tool_results_fail_closed() {
        let tool_start = r#"{"type":"stream_event","event":{"type":"content_block_start","content_block":{"type":"tool_use","name":"Bash"}}}"#.to_owned();
        assert_eq!(
            parse_lines(&[init("[]", "[]", "dontAsk"), tool_start])
                .await
                .unwrap_err(),
            AI_LOCAL_AGENT_START_FAILED
        );

        let tool_result =
            r#"{"type":"user","message":{"content":[{"type":"tool_result"}]}}"#.to_owned();
        assert_eq!(
            parse_lines(&[init("[]", "[]", "dontAsk"), tool_result])
                .await
                .unwrap_err(),
            AI_LOCAL_AGENT_START_FAILED
        );
    }

    #[tokio::test]
    async fn final_result_is_authoritative_but_all_content_is_bounded() {
        let (content, deltas) = parse_lines(&[
            init("[]", "[]", "dontAsk"),
            delta("partial"),
            result("final correction"),
        ])
        .await
        .unwrap();
        assert_eq!(content, "final correction");
        assert_eq!(deltas, ["partial"]);

        assert_eq!(
            parse_lines(&[
                init("[]", "[]", "dontAsk"),
                result(&"x".repeat(MAX_AI_RESPONSE_BYTES + 1)),
            ])
            .await
            .unwrap_err(),
            AI_RESPONSE_TOO_LARGE
        );
        assert_eq!(
            parse_claude_stdout(vec![b' '; MAX_AI_RESPONSE_BYTES + 1].as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn failures_and_stderr_never_return_provider_or_configuration_text() {
        let provider_text = "provider secret body";
        let failed = serde_json::json!({
            "type": "result",
            "subtype": "error_during_execution",
            "is_error": true,
            "result": provider_text
        })
        .to_string();
        let error = parse_lines(&[init("[]", "[]", "dontAsk"), failed])
            .await
            .unwrap_err();
        assert_eq!(error, AI_LOCAL_AGENT_FAILED);
        assert!(!error.contains(provider_text));

        assert_eq!(
            drain_claude_stderr(provider_text.repeat(100_000).as_bytes()).await,
            Ok(())
        );
    }
}
