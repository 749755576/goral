use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use netcatty_ai::{
    AiChatMessage, AiChatRole, MAX_AI_MESSAGE_BYTES, MAX_AI_MESSAGES, MAX_AI_REQUEST_TEXT_BYTES,
    MAX_AI_RESPONSE_BYTES,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::ai_agent_discovery::{AiAgentId, ResolvedAgentCommand, resolve_installed_ai_agent};
use crate::ai_claude_runtime::execute_claude;

const MAX_ACTIVE_LOCAL_AGENT_REQUESTS: usize = 2;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_JSONL_LINE_BYTES: usize = 256 * 1024;
const MAX_CODEX_MCP_INVENTORY_BYTES: usize = 256 * 1024;
const MAX_CODEX_MCP_SERVERS: usize = 64;
const MAX_CODEX_MCP_SERVER_NAME_BYTES: usize = 128;
const LOCAL_AGENT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CODEX_MCP_INVENTORY_TIMEOUT: Duration = Duration::from_secs(10);
// Keep the CLI's provider/model/authentication configuration, but override all
// renderer-relevant execution authority. MCP disable overrides are derived and
// verified immediately before these fixed arguments are used.
const CODEX_EXEC_ARGS: [&str; 12] = [
    "--ask-for-approval",
    "never",
    "exec",
    "--json",
    "--ephemeral",
    "--sandbox",
    "read-only",
    "--skip-git-repo-check",
    "--ignore-rules",
    "--color",
    "never",
    "-",
];

const AI_BUSY: &str = "AI_BUSY";
const AI_REQUEST_ID_INVALID: &str = "AI_REQUEST_ID_INVALID";
const AI_REQUEST_ID_DUPLICATE: &str = "AI_REQUEST_ID_DUPLICATE";
const AI_REQUEST_CANCELED: &str = "AI_REQUEST_CANCELED";
const AI_MESSAGES_INVALID: &str = "AI_MESSAGES_INVALID";
const AI_IMAGE_INPUT_UNSUPPORTED: &str = "AI_IMAGE_INPUT_UNSUPPORTED";
const AI_REQUEST_TOO_LARGE: &str = "AI_REQUEST_TOO_LARGE";
const AI_LOCAL_AGENT_UNSUPPORTED: &str = "AI_LOCAL_AGENT_UNSUPPORTED";
const AI_LOCAL_AGENT_UNAVAILABLE: &str = "AI_LOCAL_AGENT_UNAVAILABLE";
const AI_LOCAL_AGENT_START_FAILED: &str = "AI_LOCAL_AGENT_START_FAILED";
const AI_LOCAL_AGENT_FAILED: &str = "AI_LOCAL_AGENT_FAILED";
const AI_LOCAL_AGENT_TIMEOUT: &str = "AI_LOCAL_AGENT_TIMEOUT";
const AI_RESPONSE_TOO_LARGE: &str = "AI_RESPONSE_TOO_LARGE";
const AI_RESPONSE_INVALID: &str = "AI_RESPONSE_INVALID";
const AI_EMPTY_RESPONSE: &str = "AI_EMPTY_RESPONSE";
const AI_STREAM_CHANNEL_CLOSED: &str = "AI_STREAM_CHANNEL_CLOSED";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunLocalAiAgentRequest {
    request_id: String,
    agent_id: AiAgentId,
    messages: Vec<AiChatMessage>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunLocalAiAgentResponse {
    content: String,
}

type LocalAgentCompletion =
    Pin<Box<dyn Future<Output = Result<RunLocalAiAgentResponse, String>> + Send>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum LocalAiAgentStreamEvent {
    Delta { content: String },
    Done,
}

type CancelSender = oneshot::Sender<()>;

struct RegisteredRequest {
    identity: Arc<()>,
    cancel: CancelSender,
}

struct RequestRegistration {
    request_id: String,
    identity: Arc<()>,
}

impl Drop for RequestRegistration {
    fn drop(&mut self) {
        let mut requests = lock_request_registry();
        if requests
            .get(&self.request_id)
            .is_some_and(|request| Arc::ptr_eq(&request.identity, &self.identity))
        {
            requests.remove(&self.request_id);
        }
    }
}

fn request_registry() -> &'static Mutex<HashMap<String, RegisteredRequest>> {
    static REQUESTS: OnceLock<Mutex<HashMap<String, RegisteredRequest>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_request_registry() -> MutexGuard<'static, HashMap<String, RegisteredRequest>> {
    request_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn register_request(
    request_id: String,
    cancel: CancelSender,
) -> Result<RequestRegistration, String> {
    let mut requests = lock_request_registry();
    if requests.len() >= MAX_ACTIVE_LOCAL_AGENT_REQUESTS {
        return Err(AI_BUSY.to_owned());
    }
    if requests.contains_key(&request_id) {
        return Err(AI_REQUEST_ID_DUPLICATE.to_owned());
    }

    let identity = Arc::new(());
    requests.insert(
        request_id.clone(),
        RegisteredRequest {
            identity: Arc::clone(&identity),
            cancel,
        },
    );
    Ok(RequestRegistration {
        request_id,
        identity,
    })
}

fn validate_request_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AI_REQUEST_ID_INVALID.to_owned());
    }
    Ok(())
}

fn validate_supported_agent(agent_id: AiAgentId) -> Result<(), String> {
    match agent_id {
        AiAgentId::Codex | AiAgentId::Claude => Ok(()),
        AiAgentId::Opencode => Err(AI_LOCAL_AGENT_UNSUPPORTED.to_owned()),
    }
}

fn build_prompt(messages: &[AiChatMessage]) -> Result<Vec<u8>, String> {
    if messages.is_empty() || messages.len() > MAX_AI_MESSAGES {
        return Err(AI_MESSAGES_INVALID.to_owned());
    }

    let mut prompt = Vec::new();
    for message in messages {
        if message.has_image_content() {
            return Err(AI_IMAGE_INPUT_UNSUPPORTED.to_owned());
        }
        let content = message.content.as_bytes();
        if content.is_empty() || content.len() > MAX_AI_MESSAGE_BYTES || content.contains(&b'\0') {
            return Err(AI_MESSAGES_INVALID.to_owned());
        }

        let role = match message.role {
            AiChatRole::System => b"System:\n".as_slice(),
            AiChatRole::User => b"User:\n".as_slice(),
            AiChatRole::Assistant => b"Assistant:\n".as_slice(),
        };
        let next_length = prompt
            .len()
            .checked_add(role.len())
            .and_then(|length| length.checked_add(content.len()))
            .and_then(|length| length.checked_add(2))
            .ok_or_else(|| AI_REQUEST_TOO_LARGE.to_owned())?;
        if next_length > MAX_AI_REQUEST_TEXT_BYTES {
            return Err(AI_REQUEST_TOO_LARGE.to_owned());
        }

        prompt.extend_from_slice(role);
        prompt.extend_from_slice(content);
        prompt.extend_from_slice(b"\n\n");
    }
    Ok(prompt)
}

struct NeutralWorkingDirectory {
    path: PathBuf,
}

impl NeutralWorkingDirectory {
    fn create() -> Result<Self, String> {
        let root = std::env::temp_dir().join("goral-local-ai-agent");
        std::fs::create_dir_all(&root).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        let path = root.join(Uuid::new_v4().simple().to_string());
        std::fs::create_dir(&path).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for NeutralWorkingDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[derive(Deserialize)]
struct CodexMcpListEntry {
    name: String,
    enabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct CodexMcpInventory {
    servers: BTreeMap<String, bool>,
}

fn parse_codex_mcp_inventory(output: &[u8]) -> Result<CodexMcpInventory, String> {
    if output.len() > MAX_CODEX_MCP_INVENTORY_BYTES {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    let entries: Vec<CodexMcpListEntry> =
        serde_json::from_slice(output).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    if entries.len() > MAX_CODEX_MCP_SERVERS {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }

    let mut servers = BTreeMap::new();
    for entry in entries {
        if entry.name.is_empty()
            || entry.name.len() > MAX_CODEX_MCP_SERVER_NAME_BYTES
            || !entry
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || servers.insert(entry.name, entry.enabled).is_some()
        {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
    }
    Ok(CodexMcpInventory { servers })
}

fn codex_mcp_disable_overrides(inventory: &CodexMcpInventory) -> Vec<String> {
    inventory
        .servers
        .iter()
        .filter(|(_, enabled)| **enabled)
        .map(|(name, _)| format!("mcp_servers.{name}.enabled=false"))
        .collect()
}

fn verify_codex_mcp_isolation(
    before: &CodexMcpInventory,
    after: &CodexMcpInventory,
) -> Result<(), String> {
    if before.servers.keys().ne(after.servers.keys())
        || after.servers.values().any(|enabled| *enabled)
    {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    Ok(())
}

async fn read_bounded_codex_mcp_stdout<R>(mut stdout: R) -> Result<Zeroizing<Vec<u8>>, String>
where
    R: AsyncRead + Unpin,
{
    // `mcp list --json` includes transport metadata and may include configured
    // environment values. Keep the bounded capture out of diagnostics and
    // zeroize it on every success or error path after extracting only names
    // and enabled flags.
    let mut output = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 4096]);
    loop {
        let read = stdout
            .read(&mut *chunk)
            .await
            .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        if read == 0 {
            return Ok(output);
        }
        let next_length = output
            .len()
            .checked_add(read)
            .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        if next_length > MAX_CODEX_MCP_INVENTORY_BYTES {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

fn configure_hidden_codex_command(command: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
}

async fn read_codex_mcp_inventory(
    resolved: &ResolvedAgentCommand,
    cwd: &Path,
    overrides: &[String],
) -> Result<CodexMcpInventory, String> {
    let mut command = resolved.command();
    for value in overrides {
        command.arg("-c").arg(value);
    }
    command
        .args(["mcp", "list", "--json"])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_hidden_codex_command(&mut command);

    let mut child = command
        .spawn()
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())?;

    let capture = async {
        let (output, (), status) = tokio::try_join!(
            read_bounded_codex_mcp_stdout(stdout),
            drain_stderr(stderr),
            async {
                child
                    .wait()
                    .await
                    .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())
            }
        )?;
        if !status.success() {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        parse_codex_mcp_inventory(&output)
    };
    timeout(CODEX_MCP_INVENTORY_TIMEOUT, capture)
        .await
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?
}

async fn prepare_codex_mcp_isolation(
    resolved: &ResolvedAgentCommand,
    cwd: &Path,
) -> Result<Vec<String>, String> {
    let before = read_codex_mcp_inventory(resolved, cwd, &[]).await?;
    let overrides = codex_mcp_disable_overrides(&before);
    let after = read_codex_mcp_inventory(resolved, cwd, &overrides).await?;
    verify_codex_mcp_isolation(&before, &after)?;
    Ok(overrides)
}

fn codex_command(
    resolved: &ResolvedAgentCommand,
    cwd: &Path,
    mcp_overrides: &[String],
) -> tokio::process::Command {
    let mut command = resolved.command();
    for value in mcp_overrides {
        command.arg("-c").arg(value);
    }
    command
        .args(CODEX_EXEC_ARGS)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_hidden_codex_command(&mut command);

    command
}

async fn drain_stderr<R>(mut stderr: R) -> Result<(), String>
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

fn parse_jsonl_line<F>(line: &[u8], content: &mut String, on_delta: &mut F) -> Result<(), String>
where
    F: FnMut(String) -> Result<(), String>,
{
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }

    let value: serde_json::Value =
        serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
    if value.get("type").and_then(serde_json::Value::as_str) != Some("item.completed") {
        return Ok(());
    }
    let Some(item) = value.get("item").and_then(serde_json::Value::as_object) else {
        return Err(AI_RESPONSE_INVALID.to_owned());
    };
    if item.get("type").and_then(serde_json::Value::as_str) != Some("agent_message") {
        return Ok(());
    }
    let Some(delta) = item.get("text").and_then(serde_json::Value::as_str) else {
        return Err(AI_RESPONSE_INVALID.to_owned());
    };
    if delta.is_empty() {
        return Ok(());
    }

    let next_length = content
        .len()
        .checked_add(delta.len())
        .ok_or_else(|| AI_RESPONSE_TOO_LARGE.to_owned())?;
    if next_length > MAX_AI_RESPONSE_BYTES {
        return Err(AI_RESPONSE_TOO_LARGE.to_owned());
    }
    content.push_str(delta);
    on_delta(delta.to_owned())
}

async fn parse_codex_stdout<R, F>(mut stdout: R, mut on_delta: F) -> Result<String, String>
where
    R: AsyncRead + Unpin,
    F: FnMut(String) -> Result<(), String>,
{
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    let mut line = Zeroizing::new(Vec::new());
    let mut total = 0_usize;
    let mut content = String::new();

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
                parse_jsonl_line(&line, &mut content, &mut on_delta)?;
                line.zeroize();
            } else {
                if line.len() >= MAX_JSONL_LINE_BYTES {
                    return Err(AI_RESPONSE_TOO_LARGE.to_owned());
                }
                line.push(*byte);
            }
        }
    }

    if !line.is_empty() {
        parse_jsonl_line(&line, &mut content, &mut on_delta)?;
    }
    if content.is_empty() {
        return Err(AI_EMPTY_RESPONSE.to_owned());
    }
    Ok(content)
}

async fn execute_codex(
    resolved: ResolvedAgentCommand,
    prompt: Vec<u8>,
    on_event: &Channel<LocalAiAgentStreamEvent>,
) -> Result<RunLocalAiAgentResponse, String> {
    let prompt = Zeroizing::new(prompt);
    let cwd = NeutralWorkingDirectory::create()?;
    let mcp_overrides = prepare_codex_mcp_isolation(&resolved, cwd.path()).await?;
    let mut child = codex_command(&resolved, cwd.path(), &mcp_overrides)
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

    let stdin_task = tokio::spawn(async move {
        stdin
            .write_all(&prompt)
            .await
            .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
        stdin
            .shutdown()
            .await
            .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())
    });
    let stderr_task = tokio::spawn(drain_stderr(stderr));

    let parsed = parse_codex_stdout(stdout, |content| {
        on_event
            .send(LocalAiAgentStreamEvent::Delta { content })
            .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())
    })
    .await;
    let content = match parsed {
        Ok(content) => content,
        Err(error) => {
            stdin_task.abort();
            stderr_task.abort();
            return Err(error);
        }
    };

    let status = child
        .wait()
        .await
        .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
    let stdin_result = stdin_task
        .await
        .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
    let stderr_result = stderr_task
        .await
        .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
    stdin_result?;
    stderr_result?;
    if !status.success() {
        return Err(AI_LOCAL_AGENT_FAILED.to_owned());
    }

    on_event
        .send(LocalAiAgentStreamEvent::Done)
        .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())?;
    Ok(RunLocalAiAgentResponse { content })
}

async fn run_registered<T>(
    _registration: RequestRegistration,
    canceled: oneshot::Receiver<()>,
    completion: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    run_registered_with_timeout(canceled, completion, LOCAL_AGENT_TIMEOUT).await
}

async fn run_registered_with_timeout<T>(
    canceled: oneshot::Receiver<()>,
    completion: impl Future<Output = Result<T, String>>,
    timeout_duration: Duration,
) -> Result<T, String> {
    tokio::select! {
        biased;
        _ = canceled => Err(AI_REQUEST_CANCELED.to_owned()),
        result = timeout(timeout_duration, completion) => {
            result.map_err(|_| AI_LOCAL_AGENT_TIMEOUT.to_owned())?
        }
    }
}

fn boxed_local_agent_completion(
    agent_id: AiAgentId,
    prompt: Vec<u8>,
    on_event: Channel<LocalAiAgentStreamEvent>,
) -> LocalAgentCompletion {
    // Keep the concrete Codex/Claude async state off the Tauri invoke
    // handler's 1 MiB Windows main-thread stack. In particular, Claude owns
    // several concurrent process-I/O futures. Embedding that state in this
    // command's opaque future makes Tauri move a very large value through its
    // generated main-thread dispatcher before Tokio gets a chance to poll it.
    Box::pin(async move {
        let resolved = resolve_installed_ai_agent(agent_id)
            .await
            .ok_or_else(|| AI_LOCAL_AGENT_UNAVAILABLE.to_owned())?;
        match agent_id {
            AiAgentId::Codex => execute_codex(resolved, prompt, &on_event).await,
            AiAgentId::Claude => {
                let cwd = NeutralWorkingDirectory::create()?;
                let content = execute_claude(resolved, cwd.path(), prompt, |content| {
                    on_event
                        .send(LocalAiAgentStreamEvent::Delta { content })
                        .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())
                })
                .await?;
                on_event
                    .send(LocalAiAgentStreamEvent::Done)
                    .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())?;
                Ok(RunLocalAiAgentResponse { content })
            }
            AiAgentId::Opencode => Err(AI_LOCAL_AGENT_UNSUPPORTED.to_owned()),
        }
    })
}

#[tauri::command]
pub(crate) async fn run_local_ai_agent(
    request: RunLocalAiAgentRequest,
    on_event: Channel<LocalAiAgentStreamEvent>,
) -> Result<RunLocalAiAgentResponse, String> {
    validate_request_id(&request.request_id)?;
    validate_supported_agent(request.agent_id)?;
    let agent_id = request.agent_id;
    let prompt = build_prompt(&request.messages)?;

    // Register synchronously before PATH resolution, filesystem access, or
    // process startup so an immediate cancel can never miss this request.
    let (cancel, canceled) = oneshot::channel();
    let registration = register_request(request.request_id, cancel)?;
    let completion = boxed_local_agent_completion(agent_id, prompt, on_event);
    run_registered(registration, canceled, completion).await
}

#[tauri::command]
pub(crate) async fn cancel_local_ai_agent(request_id: String) -> Result<bool, String> {
    validate_request_id(&request_id)?;
    let request = lock_request_registry().remove(&request_id);
    Ok(request.is_some_and(|request| request.cancel.send(()).is_ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_ai::AiChatContentPart;
    use tokio::io::AsyncWriteExt;

    fn message(role: AiChatRole, content: impl Into<String>) -> AiChatMessage {
        AiChatMessage {
            role,
            content: content.into(),
            content_parts: Vec::new(),
        }
    }

    fn registry_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn request_schema_rejects_renderer_paths_environment_and_secrets() {
        let base = serde_json::json!({
            "requestId": "request-1",
            "agentId": "codex",
            "messages": [{"role": "user", "content": "hello"}]
        });
        assert!(serde_json::from_value::<RunLocalAiAgentRequest>(base.clone()).is_ok());
        for field in ["cwd", "path", "environment", "apiKey"] {
            let mut value = base.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::Value::String("secret".into()));
            assert!(serde_json::from_value::<RunLocalAiAgentRequest>(value).is_err());
        }
    }

    #[test]
    fn tauri_local_agent_command_future_stays_small() {
        let request = RunLocalAiAgentRequest {
            request_id: "future-size".into(),
            agent_id: AiAgentId::Claude,
            messages: vec![message(AiChatRole::User, "hello")],
        };
        let on_event = Channel::new(|_| Ok(()));
        let future = run_local_ai_agent(request, on_event);

        assert!(
            std::mem::size_of_val(&future) <= 16 * 1024,
            "Tauri command future grew to {} bytes",
            std::mem::size_of_val(&future)
        );
    }

    #[test]
    fn prompt_is_role_preserving_and_bounded() {
        let prompt = build_prompt(&[
            message(AiChatRole::System, "be concise"),
            message(AiChatRole::User, "hello"),
        ])
        .unwrap();
        assert_eq!(prompt, b"System:\nbe concise\n\nUser:\nhello\n\n");
        assert_eq!(build_prompt(&[]).unwrap_err(), AI_MESSAGES_INVALID);
        assert_eq!(
            build_prompt(&[message(
                AiChatRole::User,
                "x".repeat(MAX_AI_MESSAGE_BYTES + 1),
            )])
            .unwrap_err(),
            AI_MESSAGES_INVALID,
        );
        let messages = (0..MAX_AI_MESSAGES)
            .map(|_| message(AiChatRole::User, "x".repeat(MAX_AI_MESSAGE_BYTES)))
            .collect::<Vec<_>>();
        assert_eq!(build_prompt(&messages).unwrap_err(), AI_REQUEST_TOO_LARGE);
    }

    #[test]
    fn local_agents_reject_image_content_before_process_discovery() {
        let mut image_message = message(AiChatRole::User, "inspect");
        image_message.content_parts = vec![AiChatContentPart::Image {
            mime_type: "image/png".to_owned(),
            data: "iVBORw0KGgo=".to_owned(),
        }];
        assert_eq!(
            build_prompt(&[image_message]).unwrap_err(),
            AI_IMAGE_INPUT_UNSUPPORTED
        );
    }

    #[test]
    fn request_ids_and_supported_agent_are_strict() {
        assert_eq!(validate_request_id("request_123-ABC"), Ok(()));
        assert_eq!(validate_request_id(""), Err(AI_REQUEST_ID_INVALID.into()));
        assert_eq!(
            validate_request_id(&"a".repeat(MAX_REQUEST_ID_BYTES + 1)),
            Err(AI_REQUEST_ID_INVALID.into()),
        );
        assert_eq!(
            validate_request_id("renderer/path"),
            Err(AI_REQUEST_ID_INVALID.into()),
        );
        assert_eq!(validate_supported_agent(AiAgentId::Codex), Ok(()));
        assert_eq!(validate_supported_agent(AiAgentId::Claude), Ok(()));
        assert_eq!(
            validate_supported_agent(AiAgentId::Opencode),
            Err(AI_LOCAL_AGENT_UNSUPPORTED.into()),
        );
    }

    #[tokio::test]
    async fn jsonl_parser_handles_chunked_unicode_and_extracts_only_agent_text() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            for part in [
                b"{\"type\":\"thread.started\"}\n".as_slice(),
                b"{\"type\":\"item.completed\",\"item\":{\"type\":\"command_execution\",\"text\":\"do not expose\"}}\n".as_slice(),
                "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"你好\"}}\n".as_bytes(),
                b"{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\" world\"}}".as_slice(),
            ] {
                for chunk in part.chunks(3) {
                    writer.write_all(chunk).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }
        });
        let mut deltas = Vec::new();
        let content = parse_codex_stdout(reader, |delta| {
            deltas.push(delta);
            Ok(())
        })
        .await
        .unwrap();
        write.await.unwrap();
        assert_eq!(content, "你好 world");
        assert_eq!(deltas, ["你好", " world"]);
    }

    #[tokio::test]
    async fn jsonl_parser_enforces_line_and_total_limits_without_echoing_input() {
        let oversized_line = vec![b'x'; MAX_JSONL_LINE_BYTES + 1];
        assert_eq!(
            parse_codex_stdout(oversized_line.as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_TOO_LARGE,
        );

        let oversized_total = vec![b'\n'; MAX_AI_RESPONSE_BYTES + 1];
        assert_eq!(
            parse_codex_stdout(oversized_total.as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_TOO_LARGE,
        );
        assert_eq!(
            parse_codex_stdout(b"not secret json\n".as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_INVALID,
        );
    }

    #[tokio::test]
    async fn cancellation_is_registered_and_two_request_limit_is_enforced() {
        let _serial = registry_test_lock();
        assert!(lock_request_registry().is_empty());
        let (cancel_a, canceled_a) = oneshot::channel();
        let registration_a = register_request("local-a".into(), cancel_a).unwrap();
        let (cancel_b, _canceled_b) = oneshot::channel();
        let registration_b = register_request("local-b".into(), cancel_b).unwrap();
        let (cancel_c, _canceled_c) = oneshot::channel();
        assert_eq!(
            register_request("local-c".into(), cancel_c).err().unwrap(),
            AI_BUSY,
        );

        assert!(cancel_local_ai_agent("local-a".into()).await.unwrap());
        let canceled_result = run_registered(
            registration_a,
            canceled_a,
            std::future::pending::<Result<(), String>>(),
        )
        .await;
        assert_eq!(canceled_result, Err(AI_REQUEST_CANCELED.into()));
        assert!(!lock_request_registry().contains_key("local-a"));
        drop(registration_b);
        assert!(lock_request_registry().is_empty());
    }

    #[tokio::test]
    async fn registered_execution_has_a_ten_minute_timeout_and_testable_expiry() {
        let _serial = registry_test_lock();
        assert_eq!(LOCAL_AGENT_TIMEOUT, Duration::from_secs(10 * 60));
        assert!(lock_request_registry().is_empty());
        let (cancel, canceled) = oneshot::channel();
        let registration = register_request("local-timeout".into(), cancel).unwrap();
        let result = run_registered_with_timeout(
            canceled,
            std::future::pending::<Result<(), String>>(),
            Duration::ZERO,
        )
        .await;
        assert_eq!(result, Err(AI_LOCAL_AGENT_TIMEOUT.into()));
        drop(registration);
        assert!(lock_request_registry().is_empty());
    }

    #[test]
    fn fixed_codex_arguments_are_exact_and_read_only() {
        assert_eq!(
            CODEX_EXEC_ARGS,
            [
                "--ask-for-approval",
                "never",
                "exec",
                "--json",
                "--ephemeral",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--ignore-rules",
                "--color",
                "never",
                "-",
            ]
        );
    }

    #[test]
    fn codex_mcp_inventory_is_bounded_and_generates_only_enabled_overrides() {
        let inventory = parse_codex_mcp_inventory(
            br#"[
                {"name":"already-disabled","enabled":false,"transport":{"type":"stdio"}},
                {"name":"safe_name-2","enabled":true,"transport":{"type":"stdio"}}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            codex_mcp_disable_overrides(&inventory),
            ["mcp_servers.safe_name-2.enabled=false"]
        );

        let too_many = (0..=MAX_CODEX_MCP_SERVERS)
            .map(|index| serde_json::json!({"name": format!("server-{index}"), "enabled": false}))
            .collect::<Vec<_>>();
        assert_eq!(
            parse_codex_mcp_inventory(&serde_json::to_vec(&too_many).unwrap()).unwrap_err(),
            AI_LOCAL_AGENT_START_FAILED
        );
        assert_eq!(
            parse_codex_mcp_inventory(&vec![b' '; MAX_CODEX_MCP_INVENTORY_BYTES + 1]).unwrap_err(),
            AI_LOCAL_AGENT_START_FAILED
        );
    }

    #[test]
    fn codex_mcp_inventory_rejects_unsafe_or_duplicate_names() {
        for name in ["", "dot.name", "quoted\"name", "line\nname"] {
            let output = serde_json::to_vec(&[serde_json::json!({
                "name": name,
                "enabled": true
            })])
            .unwrap();
            assert_eq!(
                parse_codex_mcp_inventory(&output).unwrap_err(),
                AI_LOCAL_AGENT_START_FAILED
            );
        }

        let duplicate = br#"[
            {"name":"same","enabled":true},
            {"name":"same","enabled":false}
        ]"#;
        assert_eq!(
            parse_codex_mcp_inventory(duplicate).unwrap_err(),
            AI_LOCAL_AGENT_START_FAILED
        );
    }

    #[test]
    fn codex_mcp_isolation_requires_the_same_catalog_and_every_server_disabled() {
        let before = parse_codex_mcp_inventory(
            br#"[{"name":"one","enabled":true},{"name":"two","enabled":false}]"#,
        )
        .unwrap();
        let isolated = parse_codex_mcp_inventory(
            br#"[{"name":"one","enabled":false},{"name":"two","enabled":false}]"#,
        )
        .unwrap();
        assert_eq!(verify_codex_mcp_isolation(&before, &isolated), Ok(()));

        let still_enabled = parse_codex_mcp_inventory(
            br#"[{"name":"one","enabled":true},{"name":"two","enabled":false}]"#,
        )
        .unwrap();
        assert_eq!(
            verify_codex_mcp_isolation(&before, &still_enabled),
            Err(AI_LOCAL_AGENT_START_FAILED.into())
        );

        let changed = parse_codex_mcp_inventory(br#"[{"name":"one","enabled":false}]"#).unwrap();
        assert_eq!(
            verify_codex_mcp_isolation(&before, &changed),
            Err(AI_LOCAL_AGENT_START_FAILED.into())
        );
    }

    #[tokio::test]
    async fn stderr_is_drained_without_retaining_or_returning_it() {
        let bytes = vec![b's'; 512 * 1024];
        assert_eq!(drain_stderr(bytes.as_slice()).await, Ok(()));
    }
}
