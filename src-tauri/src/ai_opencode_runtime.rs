//! Test-only OpenCode isolation prototype.
//!
//! Do not register this runtime or advertise it as supported. The current
//! prototype still lacks a Windows Job Object/process-tree boundary and an
//! executable-identity binding across metadata probes and the final run.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use netcatty_ai::{MAX_AI_REQUEST_TEXT_BYTES, MAX_AI_RESPONSE_BYTES};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::ai_agent_discovery::ResolvedAgentCommand;

const SUPPORTED_OPENCODE_VERSION: &str = "1.17.12";
const MAX_EFFECTIVE_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const MAX_AUTH_CONTENT_BYTES: usize = 24 * 1024;
const MAX_AUTH_ENTRIES: usize = 64;
const MAX_AUTH_PROVIDER_ID_BYTES: usize = 256;
const MAX_PATHS_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 128;
const MAX_MCP_SERVERS: usize = 64;
const MAX_MCP_SERVER_NAME_BYTES: usize = 256;
const MAX_JSONL_LINE_BYTES: usize = 256 * 1024;
const CONFIG_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const METADATA_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);

const AI_LOCAL_AGENT_START_FAILED: &str = "AI_LOCAL_AGENT_START_FAILED";
const AI_LOCAL_AGENT_FAILED: &str = "AI_LOCAL_AGENT_FAILED";
const AI_RESPONSE_TOO_LARGE: &str = "AI_RESPONSE_TOO_LARGE";
const AI_RESPONSE_INVALID: &str = "AI_RESPONSE_INVALID";
const AI_EMPTY_RESPONSE: &str = "AI_EMPTY_RESPONSE";

// OpenCode has no single read-only switch. Its safe observer boundary is the
// conjunction of these flags, a deny-all private Agent, an isolated XDG/home
// profile, an in-memory auth snapshot, and a verified empty effective catalog.
const FORCED_TRUE_ENV: [&str; 12] = [
    "OPENCODE_DISABLE_PROJECT_CONFIG",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS",
    "OPENCODE_DISABLE_CLAUDE_CODE",
    "OPENCODE_DISABLE_SHARE",
    "OPENCODE_DISABLE_AUTOUPDATE",
    "OPENCODE_DISABLE_AUTOCOMPACT",
    "OPENCODE_DISABLE_MODELS_FETCH",
    "OPENCODE_DISABLE_LSP_DOWNLOAD",
    "OPENCODE_DISABLE_PRUNE",
    "OPENCODE_DISABLE_TERMINAL_TITLE",
    "OPENCODE_PURE",
];
const FORCED_FALSE_ENV: [&str; 4] = [
    "OPENCODE_AUTO_SHARE",
    "OPENCODE_EXPERIMENTAL",
    "OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS",
    "OPENCODE_ENABLE_QUESTION_TOOL",
];
const REMOVED_TELEMETRY_ENV: [&str; 4] = [
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SERVICE_NAME",
];

#[derive(Debug, Eq, PartialEq)]
struct McpInventory {
    servers: BTreeMap<String, bool>,
}

#[derive(Deserialize)]
struct EffectiveMcpEntry {
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct EffectiveAgentEntry {
    mode: Option<String>,
    hidden: Option<bool>,
    steps: Option<u64>,
    permission: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct EffectiveCompaction {
    auto: Option<bool>,
    prune: Option<bool>,
}

#[derive(Deserialize)]
struct EffectiveSkills {
    paths: Option<Vec<String>>,
    urls: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct EffectiveConfigProbe {
    mcp: Option<BTreeMap<String, EffectiveMcpEntry>>,
    agent: Option<BTreeMap<String, EffectiveAgentEntry>>,
    default_agent: Option<String>,
    permission: Option<serde_json::Value>,
    plugin: Option<Vec<serde_json::Value>>,
    instructions: Option<Vec<String>>,
    skills: Option<EffectiveSkills>,
    references: Option<BTreeMap<String, serde_json::Value>>,
    reference: Option<BTreeMap<String, serde_json::Value>>,
    command: Option<BTreeMap<String, serde_json::Value>>,
    tools: Option<BTreeMap<String, serde_json::Value>>,
    lsp: Option<serde_json::Value>,
    formatter: Option<serde_json::Value>,
    snapshot: Option<bool>,
    share: Option<String>,
    autoshare: Option<bool>,
    autoupdate: Option<serde_json::Value>,
    compaction: Option<EffectiveCompaction>,
}

#[derive(Serialize)]
struct DisabledMcpEntry {
    enabled: bool,
}

#[derive(Serialize)]
struct ObserverAgentConfig {
    mode: &'static str,
    hidden: bool,
    steps: u8,
    permission: BTreeMap<&'static str, &'static str>,
}

#[derive(Serialize)]
struct ObserverConfig {
    agent: BTreeMap<String, ObserverAgentConfig>,
    default_agent: String,
    mcp: BTreeMap<String, DisabledMcpEntry>,
    plugin: Vec<String>,
    instructions: Vec<String>,
    skills: ObserverSkills,
    references: BTreeMap<String, String>,
    reference: BTreeMap<String, String>,
    command: BTreeMap<String, String>,
    tools: BTreeMap<String, bool>,
    lsp: bool,
    formatter: bool,
    snapshot: bool,
    share: &'static str,
    autoshare: bool,
    autoupdate: bool,
    compaction: ObserverCompactionConfig,
}

#[derive(Serialize)]
struct ObserverCompactionConfig {
    auto: bool,
    prune: bool,
}

#[derive(Serialize)]
struct ObserverSkills {
    paths: Vec<String>,
    urls: Vec<String>,
}

struct PreparedIsolation {
    agent_name: String,
    config_content: Zeroizing<String>,
}

struct AuthSnapshot {
    content: Zeroizing<String>,
}

#[derive(Deserialize)]
struct AuthEntryKind {
    #[serde(rename = "type")]
    kind: String,
}

struct OpenCodeUserPaths {
    data: PathBuf,
}

struct IsolatedProfile {
    home: PathBuf,
    xdg_config_home: PathBuf,
    xdg_data_home: PathBuf,
    xdg_cache_home: PathBuf,
    xdg_state_home: PathBuf,
    config_dir: PathBuf,
    managed_config_dir: PathBuf,
    temporary_dir: PathBuf,
    work_dir: PathBuf,
}

struct OpenCodeSandbox {
    root: PathBuf,
    profile: IsolatedProfile,
}

impl OpenCodeSandbox {
    fn create() -> Result<Self, String> {
        let base = std::env::temp_dir().join("goral-local-ai-agent");
        std::fs::create_dir_all(&base).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
        let root = base.join(Uuid::new_v4().simple().to_string());
        std::fs::create_dir(&root).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;

        let home = root.join("home");
        let xdg_config_home = root.join("config");
        let xdg_data_home = root.join("data");
        let xdg_cache_home = root.join("cache");
        let xdg_state_home = root.join("state");
        let config_dir = xdg_config_home.join("opencode");
        let managed_config_dir = root.join("managed");
        let temporary_dir = root.join("tmp");
        let work_dir = root.join("work");
        for directory in [
            &home,
            &xdg_config_home,
            &xdg_data_home,
            &xdg_cache_home,
            &xdg_state_home,
            &config_dir,
            &managed_config_dir,
            &temporary_dir,
            &work_dir,
        ] {
            std::fs::create_dir_all(directory)
                .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
            restrict_directory_permissions(directory)?;
        }

        Ok(Self {
            root,
            profile: IsolatedProfile {
                home,
                xdg_config_home,
                xdg_data_home,
                xdg_cache_home,
                xdg_state_home,
                config_dir,
                managed_config_dir,
                temporary_dir,
                work_dir,
            },
        })
    }

    fn profile(&self) -> &IsolatedProfile {
        &self.profile
    }
}

impl Drop for OpenCodeSandbox {
    fn drop(&mut self) {
        if self
            .root
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "goral-local-ai-agent")
        {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn parse_effective_config(output: &[u8]) -> Result<(McpInventory, EffectiveConfigProbe), String> {
    if output.len() > MAX_EFFECTIVE_CONFIG_BYTES {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    let probe: EffectiveConfigProbe =
        serde_json::from_slice(output).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    if probe.mcp.as_ref().map_or(0, BTreeMap::len) > MAX_MCP_SERVERS {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }

    let mut servers = BTreeMap::new();
    for (name, entry) in probe.mcp.as_ref().into_iter().flatten() {
        if name.is_empty()
            || name.len() > MAX_MCP_SERVER_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        servers.insert(name.clone(), entry.enabled.unwrap_or(true));
    }
    Ok((McpInventory { servers }, probe))
}

fn permission_denies_all(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::String(action)) => action == "deny",
        Some(serde_json::Value::Object(rules)) => {
            rules.len() == 1
                && rules
                    .get("*")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|action| action == "deny")
        }
        _ => false,
    }
}

fn build_isolation_config(agent_name: String) -> Result<PreparedIsolation, String> {
    let mut permission = BTreeMap::new();
    permission.insert("*", "deny");
    let mut agent = BTreeMap::new();
    agent.insert(
        agent_name.clone(),
        ObserverAgentConfig {
            mode: "primary",
            hidden: true,
            steps: 1,
            permission,
        },
    );
    let content = serde_json::to_string(&ObserverConfig {
        agent,
        default_agent: agent_name.clone(),
        mcp: BTreeMap::new(),
        plugin: Vec::new(),
        instructions: Vec::new(),
        skills: ObserverSkills {
            paths: Vec::new(),
            urls: Vec::new(),
        },
        references: BTreeMap::new(),
        reference: BTreeMap::new(),
        command: BTreeMap::new(),
        tools: BTreeMap::new(),
        lsp: false,
        formatter: false,
        snapshot: false,
        share: "disabled",
        autoshare: false,
        autoupdate: false,
        compaction: ObserverCompactionConfig {
            auto: false,
            prune: false,
        },
    })
    .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    Ok(PreparedIsolation {
        agent_name,
        config_content: Zeroizing::new(content),
    })
}

fn verify_effective_isolation(
    inventory: &McpInventory,
    probe: &EffectiveConfigProbe,
    agent_name: &str,
) -> Result<(), String> {
    let agent = probe
        .agent
        .as_ref()
        .and_then(|agents| agents.get(agent_name));
    let skills_are_empty = probe.skills.as_ref().is_some_and(|skills| {
        skills.paths.as_ref().is_some_and(Vec::is_empty)
            && skills.urls.as_ref().is_some_and(Vec::is_empty)
    });
    if !inventory.servers.is_empty()
        || !permission_denies_all(probe.permission.as_ref())
        || probe.agent.as_ref().map(BTreeMap::len) != Some(1)
        || agent.and_then(|entry| entry.mode.as_deref()) != Some("primary")
        || agent.and_then(|entry| entry.hidden) != Some(true)
        || agent.and_then(|entry| entry.steps) != Some(1)
        || !permission_denies_all(agent.and_then(|entry| entry.permission.as_ref()))
        || probe.default_agent.as_deref() != Some(agent_name)
        || !probe.plugin.as_ref().is_some_and(Vec::is_empty)
        || !probe.instructions.as_ref().is_some_and(Vec::is_empty)
        || !skills_are_empty
        || !probe.references.as_ref().is_some_and(BTreeMap::is_empty)
        || !probe.reference.as_ref().is_some_and(BTreeMap::is_empty)
        || !probe.command.as_ref().is_some_and(BTreeMap::is_empty)
        || !probe.tools.as_ref().is_some_and(BTreeMap::is_empty)
        || probe.lsp.as_ref().and_then(serde_json::Value::as_bool) != Some(false)
        || probe
            .formatter
            .as_ref()
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || probe.snapshot != Some(false)
        || probe.share.as_deref() != Some("disabled")
        || probe.autoshare != Some(false)
        || probe
            .autoupdate
            .as_ref()
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || probe.compaction.as_ref().and_then(|value| value.auto) != Some(false)
        || probe.compaction.as_ref().and_then(|value| value.prune) != Some(false)
    {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    Ok(())
}

fn remove_inherited_opencode_environment(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("OPENCODE_")
        {
            command.env_remove(name);
        }
    }
}

fn configure_safe_environment(
    command: &mut Command,
    profile: &IsolatedProfile,
    auth: &AuthSnapshot,
    config_content: &str,
) {
    remove_inherited_opencode_environment(command);
    for name in FORCED_TRUE_ENV {
        command.env(name, "1");
    }
    for name in FORCED_FALSE_ENV {
        command.env(name, "0");
    }
    for name in REMOVED_TELEMETRY_ENV {
        command.env_remove(name);
    }
    command
        .env("OPENCODE_DB", ":memory:")
        .env("OPENCODE_PERMISSION", r#"{"*":"deny"}"#)
        .env("OPENCODE_AUTH_CONTENT", &*auth.content)
        .env("OPENCODE_CONFIG_CONTENT", config_content)
        .env("OPENCODE_CONFIG_DIR", &profile.config_dir)
        .env(
            "OPENCODE_TEST_MANAGED_CONFIG_DIR",
            &profile.managed_config_dir,
        )
        .env("OPENCODE_TEST_HOME", &profile.home)
        .env("OPENCODE_CLIENT", "goral")
        .env("XDG_CONFIG_HOME", &profile.xdg_config_home)
        .env("XDG_DATA_HOME", &profile.xdg_data_home)
        .env("XDG_CACHE_HOME", &profile.xdg_cache_home)
        .env("XDG_STATE_HOME", &profile.xdg_state_home)
        .env("TEMP", &profile.temporary_dir)
        .env("TMP", &profile.temporary_dir)
        .env("TMPDIR", &profile.temporary_dir)
        .env("NO_COLOR", "1")
        .env("CI", "1");
}

fn configure_hidden_command(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
}

fn effective_config_command(
    resolved: &ResolvedAgentCommand,
    profile: &IsolatedProfile,
    auth: &AuthSnapshot,
    config_content: &str,
) -> Command {
    let mut command = resolved.command();
    command
        .args(["debug", "config", "--pure", "--log-level", "ERROR"])
        .current_dir(&profile.work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_safe_environment(&mut command, profile, auth, config_content);
    configure_hidden_command(&mut command);
    command
}

fn opencode_run_command(
    resolved: &ResolvedAgentCommand,
    profile: &IsolatedProfile,
    auth: &AuthSnapshot,
    prepared: &PreparedIsolation,
) -> Command {
    let mut command = resolved.command();
    command
        .args([
            "run",
            "--format",
            "json",
            "--pure",
            "--log-level",
            "ERROR",
            "--agent",
            &prepared.agent_name,
            "--title",
            "Goral local assistant",
        ])
        .current_dir(&profile.work_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_safe_environment(&mut command, profile, auth, &prepared.config_content);
    configure_hidden_command(&mut command);
    command
}

async fn read_bounded_secret_output<R>(
    mut reader: R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, String>
where
    R: AsyncRead + Unpin,
{
    let mut output = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    loop {
        let read = reader
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
        if next_length > limit {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

async fn drain_stderr<R>(mut stderr: R, error_code: &'static str) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    let mut total = 0_usize;
    loop {
        let read = stderr
            .read(&mut *buffer)
            .await
            .map_err(|_| error_code.to_owned())?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read)
            .ok_or_else(|| error_code.to_owned())?;
        if total > MAX_EFFECTIVE_CONFIG_BYTES {
            return Err(error_code.to_owned());
        }
    }
}

async fn terminate_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(TERMINATION_TIMEOUT, child.wait()).await;
}

async fn read_effective_config(
    resolved: &ResolvedAgentCommand,
    profile: &IsolatedProfile,
    auth: &AuthSnapshot,
    config_content: &str,
) -> Result<(McpInventory, EffectiveConfigProbe), String> {
    let mut child = effective_config_command(resolved, profile, auth, config_content)
        .spawn()
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };

    let captured = timeout(CONFIG_PROBE_TIMEOUT, async {
        let (output, (), status) = tokio::try_join!(
            read_bounded_secret_output(stdout, MAX_EFFECTIVE_CONFIG_BYTES),
            drain_stderr(stderr, AI_LOCAL_AGENT_START_FAILED),
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
        parse_effective_config(&output)
    })
    .await;
    match captured {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) | Err(_) => {
            terminate_child(&mut child).await;
            Err(AI_LOCAL_AGENT_START_FAILED.to_owned())
        }
    }
}

fn configure_metadata_command(command: &mut Command) {
    remove_inherited_opencode_environment(command);
    for name in REMOVED_TELEMETRY_ENV {
        command.env_remove(name);
    }
    command.env("NO_COLOR", "1").env("CI", "1");
    configure_hidden_command(command);
}

async fn capture_metadata_command(
    mut command: Command,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_metadata_command(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };
    let captured = timeout(METADATA_PROBE_TIMEOUT, async {
        let (output, (), status) = tokio::try_join!(
            read_bounded_secret_output(stdout, limit),
            drain_stderr(stderr, AI_LOCAL_AGENT_START_FAILED),
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
        Ok(output)
    })
    .await;
    match captured {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(_)) | Err(_) => {
            terminate_child(&mut child).await;
            Err(AI_LOCAL_AGENT_START_FAILED.to_owned())
        }
    }
}

async fn verify_supported_version(resolved: &ResolvedAgentCommand) -> Result<(), String> {
    if !resolved.is_direct_windows_native() {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    let mut command = resolved.command();
    command.arg("--version");
    let output = capture_metadata_command(command, MAX_VERSION_OUTPUT_BYTES).await?;
    let version = std::str::from_utf8(&output)
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?
        .trim();
    if version != SUPPORTED_OPENCODE_VERSION {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    Ok(())
}

fn parse_user_paths(output: &[u8]) -> Result<OpenCodeUserPaths, String> {
    let text = std::str::from_utf8(output).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let mut data = None;
    for line in text.lines() {
        let line = line.trim();
        let split = line.find(char::is_whitespace);
        let Some(split) = split else { continue };
        let (key, value) = line.split_at(split);
        if key != "data" {
            continue;
        }
        let value = value.trim();
        if value.is_empty() || value.chars().any(|character| character == '\0') {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
        data = Some(path);
    }
    data.map(|data| OpenCodeUserPaths { data })
        .ok_or_else(|| AI_LOCAL_AGENT_START_FAILED.to_owned())
}

async fn resolve_user_paths(resolved: &ResolvedAgentCommand) -> Result<OpenCodeUserPaths, String> {
    let mut command = resolved.command();
    command.args(["debug", "paths"]);
    let output = capture_metadata_command(command, MAX_PATHS_OUTPUT_BYTES).await?;
    parse_user_paths(&output)
}

fn validate_auth_content(content: &str) -> Result<(), String> {
    if content.len() > MAX_AUTH_CONTENT_BYTES {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    let entries: BTreeMap<String, AuthEntryKind> =
        serde_json::from_str(content).map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    if entries.len() > MAX_AUTH_ENTRIES {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    for (provider_id, entry) in entries {
        if provider_id.is_empty()
            || provider_id.len() > MAX_AUTH_PROVIDER_ID_BYTES
            || provider_id.chars().any(char::is_control)
            || !matches!(entry.kind.as_str(), "api" | "oauth")
        {
            // `wellknown` auth loads remote organization config before the
            // local overlay and therefore cannot participate in this runtime.
            return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
        }
    }
    Ok(())
}

async fn read_auth_snapshot(paths: &OpenCodeUserPaths) -> Result<AuthSnapshot, String> {
    if let Ok(content) = std::env::var("OPENCODE_AUTH_CONTENT") {
        let content = Zeroizing::new(content);
        validate_auth_content(&content)?;
        return Ok(AuthSnapshot { content });
    }

    let path = paths.data.join("auth.json");
    let content = match tokio::fs::File::open(path).await {
        Ok(file) => {
            let metadata = file
                .metadata()
                .await
                .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
            if !metadata.is_file() || metadata.len() > MAX_AUTH_CONTENT_BYTES as u64 {
                return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            file.take(MAX_AUTH_CONTENT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
            if bytes.len() > MAX_AUTH_CONTENT_BYTES {
                return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
            }
            Zeroizing::new(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Zeroizing::new("{}".to_owned())
        }
        Err(_) => return Err(AI_LOCAL_AGENT_START_FAILED.to_owned()),
    };
    validate_auth_content(&content)?;
    Ok(AuthSnapshot { content })
}

async fn prepare_opencode_isolation(
    resolved: &ResolvedAgentCommand,
    profile: &IsolatedProfile,
    auth: &AuthSnapshot,
) -> Result<PreparedIsolation, String> {
    let agent_name = format!("goral-observer-{}", Uuid::new_v4().simple());
    let prepared = build_isolation_config(agent_name)?;
    let (first_inventory, first_probe) =
        read_effective_config(resolved, profile, auth, &prepared.config_content).await?;
    verify_effective_isolation(&first_inventory, &first_probe, &prepared.agent_name)?;
    let (second_inventory, second_probe) =
        read_effective_config(resolved, profile, auth, &prepared.config_content).await?;
    verify_effective_isolation(&second_inventory, &second_probe, &prepared.agent_name)?;
    if first_inventory != second_inventory {
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    }
    Ok(prepared)
}

#[derive(Deserialize)]
struct OpenCodeJsonEvent<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    #[serde(default, borrow)]
    part: Option<OpenCodeJsonPart<'a>>,
}

#[derive(Deserialize)]
struct OpenCodeJsonPart<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    #[serde(default, borrow)]
    text: Option<Cow<'a, str>>,
}

fn parse_jsonl_line<F>(line: &[u8], content: &mut String, on_delta: &mut F) -> Result<(), String>
where
    F: FnMut(String) -> Result<(), String>,
{
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let event: OpenCodeJsonEvent<'_> =
        serde_json::from_slice(line).map_err(|_| AI_RESPONSE_INVALID.to_owned())?;
    match event.kind.as_ref() {
        "step_start" => {
            if event.part.as_ref().map(|part| part.kind.as_ref()) == Some("step-start") {
                Ok(())
            } else {
                Err(AI_RESPONSE_INVALID.to_owned())
            }
        }
        "step_finish" => {
            if event.part.as_ref().map(|part| part.kind.as_ref()) == Some("step-finish") {
                Ok(())
            } else {
                Err(AI_RESPONSE_INVALID.to_owned())
            }
        }
        "text" => {
            let part = event
                .part
                .filter(|part| part.kind == "text")
                .ok_or_else(|| AI_RESPONSE_INVALID.to_owned())?;
            let delta = part
                .text
                .filter(|text| !text.is_empty())
                .ok_or_else(|| AI_RESPONSE_INVALID.to_owned())?;
            let next_length = content
                .len()
                .checked_add(delta.len())
                .ok_or_else(|| AI_RESPONSE_TOO_LARGE.to_owned())?;
            if next_length > MAX_AI_RESPONSE_BYTES {
                return Err(AI_RESPONSE_TOO_LARGE.to_owned());
            }
            content.push_str(&delta);
            on_delta(delta.into_owned())
        }
        // Never expose tool inputs or provider error bodies.
        "tool_use" | "error" | "reasoning" => Err(AI_LOCAL_AGENT_FAILED.to_owned()),
        _ => Err(AI_RESPONSE_INVALID.to_owned()),
    }
}

async fn parse_opencode_stdout<R, F>(mut stdout: R, mut on_delta: F) -> Result<String, String>
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

/// Runs one OpenCode observer turn with prompt bytes on stdin only. The caller
/// owns registration, timeout, cancellation, and renderer event publication.
/// Dropping this future drops a kill-on-drop handle to the directly resolved
/// native OpenCode process; the supported Windows npm shim has no Node layer.
pub(crate) async fn execute_opencode<F>(
    resolved: ResolvedAgentCommand,
    prompt: Vec<u8>,
    on_delta: F,
) -> Result<String, String>
where
    F: FnMut(String) -> Result<(), String>,
{
    if prompt.is_empty() || prompt.len() > MAX_AI_REQUEST_TEXT_BYTES || prompt.contains(&b'\0') {
        return Err(AI_LOCAL_AGENT_FAILED.to_owned());
    }
    verify_supported_version(&resolved).await?;
    let user_paths = resolve_user_paths(&resolved).await?;
    let auth = read_auth_snapshot(&user_paths).await?;
    let sandbox = OpenCodeSandbox::create()?;
    let prepared = prepare_opencode_isolation(&resolved, sandbox.profile(), &auth).await?;
    let mut child = opencode_run_command(&resolved, sandbox.profile(), &auth, &prepared)
        .spawn()
        .map_err(|_| AI_LOCAL_AGENT_START_FAILED.to_owned())?;
    let Some(mut stdin) = child.stdin.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child).await;
        return Err(AI_LOCAL_AGENT_START_FAILED.to_owned());
    };

    let prompt = Zeroizing::new(prompt);
    let completed = tokio::try_join!(
        async move {
            stdin
                .write_all(&prompt)
                .await
                .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())?;
            stdin
                .shutdown()
                .await
                .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())
        },
        parse_opencode_stdout(stdout, on_delta),
        drain_stderr(stderr, AI_LOCAL_AGENT_FAILED),
        async {
            child
                .wait()
                .await
                .map_err(|_| AI_LOCAL_AGENT_FAILED.to_owned())
        }
    );
    let ((), content, (), status) = match completed {
        Ok(completed) => completed,
        Err(error) => {
            terminate_child(&mut child).await;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(AI_LOCAL_AGENT_FAILED.to_owned());
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use tokio::io::AsyncWriteExt;

    fn command_env(command: &Command, name: &str) -> Option<Option<OsString>> {
        command
            .as_std()
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .map(|(_, value)| value.map(OsStr::to_owned))
    }

    fn isolated_profile() -> IsolatedProfile {
        IsolatedProfile {
            home: PathBuf::from("test-home"),
            xdg_config_home: PathBuf::from("test-config"),
            xdg_data_home: PathBuf::from("test-data"),
            xdg_cache_home: PathBuf::from("test-cache"),
            xdg_state_home: PathBuf::from("test-state"),
            config_dir: PathBuf::from("test-config/opencode"),
            managed_config_dir: PathBuf::from("test-managed"),
            temporary_dir: PathBuf::from("test-temp"),
            work_dir: PathBuf::from("test-work"),
        }
    }

    #[test]
    fn command_policy_is_deny_all_in_memory_and_side_effect_bounded() {
        let mut command = Command::new("opencode");
        let profile = isolated_profile();
        let auth = AuthSnapshot {
            content: Zeroizing::new("{\"provider\":{}}".to_owned()),
        };
        configure_safe_environment(&mut command, &profile, &auth, "{\"safe\":true}");
        for name in FORCED_TRUE_ENV {
            assert_eq!(command_env(&command, name), Some(Some("1".into())));
        }
        for name in FORCED_FALSE_ENV {
            assert_eq!(command_env(&command, name), Some(Some("0".into())));
        }
        for name in REMOVED_TELEMETRY_ENV {
            assert_eq!(command_env(&command, name), Some(None));
        }
        assert_eq!(
            command_env(&command, "OPENCODE_PERMISSION"),
            Some(Some(r#"{"*":"deny"}"#.into()))
        );
        assert_eq!(
            command_env(&command, "OPENCODE_DB"),
            Some(Some(":memory:".into()))
        );
        assert_eq!(
            command_env(&command, "OPENCODE_CONFIG_CONTENT"),
            Some(Some("{\"safe\":true}".into()))
        );
        assert_eq!(
            command_env(&command, "OPENCODE_AUTH_CONTENT"),
            Some(Some("{\"provider\":{}}".into()))
        );
        assert_eq!(
            command_env(&command, "XDG_CONFIG_HOME"),
            Some(Some(profile.xdg_config_home.into_os_string()))
        );
    }

    #[test]
    fn effective_config_parser_extracts_only_bounded_mcp_state() {
        let (inventory, _) = parse_effective_config(
            br#"{
                "provider":{"private":{"options":{"apiKey":"must-not-escape"}}},
                "mcp":{
                    "disabled":{"enabled":false,"command":["secret"]},
                    "default-enabled":{"type":"remote","url":"https://private.invalid"}
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            inventory.servers,
            BTreeMap::from([
                ("default-enabled".to_owned(), true),
                ("disabled".to_owned(), false),
            ])
        );
        let too_many = (0..=MAX_MCP_SERVERS)
            .map(|index| format!(r#""m{index}":{{"enabled":false}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(r#"{{"mcp":{{{too_many}}}}}"#);
        assert_eq!(
            parse_effective_config(input.as_bytes()).err().unwrap(),
            AI_LOCAL_AGENT_START_FAILED
        );
    }

    #[test]
    fn isolation_overlay_disables_every_server_and_uses_a_private_agent() {
        let prepared = build_isolation_config("goral-observer-test".to_owned()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&prepared.config_content).unwrap();
        assert_eq!(value["mcp"], serde_json::json!({}));
        assert_eq!(
            value["agent"]["goral-observer-test"]["permission"]["*"],
            "deny"
        );
        assert_eq!(value["agent"]["goral-observer-test"]["steps"], 1);
        assert_eq!(value["share"], "disabled");
        assert_eq!(value["autoshare"], false);
        assert_eq!(value["compaction"]["auto"], false);
    }

    fn safe_probe(permission: &str, agent_permission: &str) -> EffectiveConfigProbe {
        EffectiveConfigProbe {
            mcp: Some(BTreeMap::new()),
            agent: Some(BTreeMap::from([(
                "observer".to_owned(),
                EffectiveAgentEntry {
                    mode: Some("primary".to_owned()),
                    hidden: Some(true),
                    steps: Some(1),
                    permission: Some(serde_json::json!({"*": agent_permission})),
                },
            )])),
            default_agent: Some("observer".to_owned()),
            permission: Some(serde_json::json!({"*": permission})),
            plugin: Some(Vec::new()),
            instructions: Some(Vec::new()),
            skills: Some(EffectiveSkills {
                paths: Some(Vec::new()),
                urls: Some(Vec::new()),
            }),
            references: Some(BTreeMap::new()),
            reference: Some(BTreeMap::new()),
            command: Some(BTreeMap::new()),
            tools: Some(BTreeMap::new()),
            lsp: Some(serde_json::json!(false)),
            formatter: Some(serde_json::json!(false)),
            snapshot: Some(false),
            share: Some("disabled".to_owned()),
            autoshare: Some(false),
            autoupdate: Some(serde_json::json!(false)),
            compaction: Some(EffectiveCompaction {
                auto: Some(false),
                prune: Some(false),
            }),
        }
    }

    #[test]
    fn isolation_verification_fails_closed_on_authority_change() {
        let empty = McpInventory {
            servers: BTreeMap::new(),
        };
        assert!(
            verify_effective_isolation(&empty, &safe_probe("deny", "deny"), "observer").is_ok()
        );
        assert!(
            verify_effective_isolation(&empty, &safe_probe("allow", "deny"), "observer").is_err()
        );
        assert!(
            verify_effective_isolation(&empty, &safe_probe("deny", "allow"), "observer").is_err()
        );
        let enabled = McpInventory {
            servers: BTreeMap::from([("alpha".to_owned(), true)]),
        };
        assert!(
            verify_effective_isolation(&enabled, &safe_probe("deny", "deny"), "observer").is_err()
        );
        let disabled = McpInventory {
            servers: BTreeMap::from([("alpha".to_owned(), false)]),
        };
        assert!(
            verify_effective_isolation(&disabled, &safe_probe("deny", "deny"), "observer").is_err()
        );
    }

    #[tokio::test]
    async fn json_stream_handles_chunked_unicode_and_text_parts() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            for input in [
                br#"{"type":"step_start","part":{"type":"step-start"}}
"#
                .as_slice(),
                "{\"type\":\"text\",\"part\":{\"type\":\"text\",\"text\":\"你好\"}}\n".as_bytes(),
                br#"{"type":"text","part":{"type":"text","text":" world"}}"#.as_slice(),
            ] {
                for chunk in input.chunks(3) {
                    writer.write_all(chunk).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }
        });
        let mut deltas = Vec::new();
        let content = parse_opencode_stdout(reader, |delta| {
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
    async fn json_stream_rejects_unsafe_or_unbounded_output() {
        assert_eq!(
            parse_opencode_stdout(
                br#"{"type":"tool_use","part":{"type":"tool","state":{"input":"secret"}}}
"#
                .as_slice(),
                |_| Ok(())
            )
            .await
            .unwrap_err(),
            AI_LOCAL_AGENT_FAILED
        );
        assert_eq!(
            parse_opencode_stdout(
                br#"{"type":"error","error":{"data":{"message":"provider secret"}}}
"#
                .as_slice(),
                |_| Ok(())
            )
            .await
            .unwrap_err(),
            AI_LOCAL_AGENT_FAILED
        );
        assert_eq!(
            parse_opencode_stdout(b"not-json\n".as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_INVALID
        );
        assert_eq!(
            parse_opencode_stdout(vec![b'x'; MAX_JSONL_LINE_BYTES + 1].as_slice(), |_| Ok(()))
                .await
                .unwrap_err(),
            AI_RESPONSE_TOO_LARGE
        );
    }
}
