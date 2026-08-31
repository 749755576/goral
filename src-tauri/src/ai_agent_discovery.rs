use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

const MAX_PATH_DIRECTORIES: usize = 256;
const MAX_SHIM_BYTES: u64 = 16 * 1024;
const MAX_CAPTURED_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_VERSION_BYTES: usize = 64;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const TERMINATION_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) const SUPPORTED_CLAUDE_VERSION: &str = "2.1.246";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AiAgentId {
    Codex,
    Claude,
    Opencode,
}

impl AiAgentId {
    fn implementation_supported(self) -> bool {
        matches!(self, Self::Codex | Self::Claude)
    }

    fn runtime_supported(self, installed: bool, probe: Option<&ProbeResult>) -> bool {
        if !self.implementation_supported() {
            return false;
        }
        if !installed {
            // Keep an uninstalled implementation visible as supported so the
            // renderer can distinguish "not installed" from "not compatible".
            return true;
        }
        match self {
            Self::Claude => probe.is_some_and(|probe| {
                probe.available && probe.version.as_deref() == Some(SUPPORTED_CLAUDE_VERSION)
            }),
            Self::Codex => true,
            Self::Opencode => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiscoveredAiAgent {
    id: AiAgentId,
    name: &'static str,
    installed: bool,
    available: bool,
    runtime_supported: bool,
    version: Option<String>,
}

#[derive(Clone, Copy)]
struct AgentSpec {
    id: AiAgentId,
    name: &'static str,
    command: &'static str,
}

const CODEX: AgentSpec = AgentSpec {
    id: AiAgentId::Codex,
    name: "Codex CLI",
    command: "codex",
};
const CLAUDE: AgentSpec = AgentSpec {
    id: AiAgentId::Claude,
    name: "Claude Code",
    command: "claude",
};
const OPENCODE: AgentSpec = AgentSpec {
    id: AiAgentId::Opencode,
    name: "OpenCode",
    command: "opencode",
};

#[derive(Debug)]
pub(crate) struct ResolvedAgentCommand {
    program: PathBuf,
    prefix_args: Vec<OsString>,
    managed_codex_package_root: Option<PathBuf>,
}

impl ResolvedAgentCommand {
    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.prefix_args);
        if let Some(package_root) = &self.managed_codex_package_root {
            // Mirror the official npm launcher using only the canonical path
            // derived from the validated package. Never inherit conflicting
            // package-manager markers into a directly launched binary.
            command
                .env_remove("CODEX_MANAGED_BY_BUN")
                .env_remove("CODEX_MANAGED_BY_PNPM")
                .env_remove("CODEX_MANAGED_BY_NPM")
                .env("CODEX_MANAGED_PACKAGE_ROOT", package_root)
                .env("CODEX_MANAGED_BY_NPM", "1");
        }
        command
    }

    /// OpenCode cancellation is currently supported only when PATH resolution
    /// reached its native Windows executable directly. A Node/script launcher
    /// could outlive the handle owned by the desktop runtime.
    #[cfg(test)]
    pub(crate) fn is_direct_windows_native(&self) -> bool {
        #[cfg(windows)]
        {
            self.prefix_args.is_empty()
                && self
                    .program
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|extension| {
                        matches!(extension.to_ascii_lowercase().as_str(), "exe" | "com")
                    })
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

#[derive(Debug, Default)]
struct ProbeResult {
    available: bool,
    version: Option<String>,
}

#[tauri::command]
pub(crate) async fn discover_ai_agents() -> Vec<DiscoveredAiAgent> {
    discover_ai_agents_on_path(std::env::var_os("PATH").as_deref()).await
}

async fn discover_ai_agents_on_path(path: Option<&OsStr>) -> Vec<DiscoveredAiAgent> {
    let (codex, claude, opencode) = tokio::join!(
        discover_agent(CODEX, path),
        discover_agent(CLAUDE, path),
        discover_agent(OPENCODE, path),
    );
    vec![codex, claude, opencode]
}

async fn discover_agent(spec: AgentSpec, path: Option<&OsStr>) -> DiscoveredAiAgent {
    let Some(command) = resolve_command_on_path(spec.command, path).await else {
        return DiscoveredAiAgent {
            id: spec.id,
            name: spec.name,
            installed: false,
            available: false,
            runtime_supported: spec.id.runtime_supported(false, None),
            version: None,
        };
    };

    let probe = probe_version(&command).await;
    DiscoveredAiAgent {
        id: spec.id,
        name: spec.name,
        installed: true,
        available: probe.available,
        runtime_supported: spec.id.runtime_supported(true, Some(&probe)),
        version: probe.version,
    }
}

/// Re-probe an already resolved executable through the same bounded, timed
/// `--version` path used by discovery. Runtimes call this immediately before
/// starting a turn so a PATH target changed after discovery fails closed.
pub(crate) async fn resolved_agent_has_exact_version(
    command: &ResolvedAgentCommand,
    expected: &str,
) -> bool {
    let probe = probe_version(command).await;
    probe.available && probe.version.as_deref() == Some(expected)
}

pub(crate) async fn resolve_installed_ai_agent(
    agent_id: AiAgentId,
) -> Option<ResolvedAgentCommand> {
    let spec = match agent_id {
        AiAgentId::Codex => CODEX,
        AiAgentId::Claude => CLAUDE,
        AiAgentId::Opencode => OPENCODE,
    };
    resolve_command_on_path(spec.command, std::env::var_os("PATH").as_deref()).await
}

async fn resolve_command_on_path(
    command: &str,
    path: Option<&OsStr>,
) -> Option<ResolvedAgentCommand> {
    let path = path?;
    for directory in std::env::split_paths(path).take(MAX_PATH_DIRECTORIES) {
        // Never let an empty or relative PATH segment turn the renderer or
        // process working directory into an executable search location.
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            continue;
        }

        #[cfg(windows)]
        {
            for extension in ["exe", "com"] {
                let candidate = directory.join(format!("{command}.{extension}"));
                if is_regular_file(&candidate) {
                    return Some(ResolvedAgentCommand {
                        program: candidate,
                        prefix_args: Vec::new(),
                        managed_codex_package_root: None,
                    });
                }
            }

            if let Some(command) = resolve_windows_npm_shim(command, &directory, path).await {
                return Some(command);
            }
        }

        #[cfg(unix)]
        {
            let candidate = directory.join(command);
            if is_executable_file(&candidate) {
                return Some(ResolvedAgentCommand {
                    program: candidate,
                    prefix_args: Vec::new(),
                    managed_codex_package_root: None,
                });
            }
        }
    }
    None
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
async fn resolve_windows_npm_shim(
    command: &str,
    directory: &Path,
    path: &OsStr,
) -> Option<ResolvedAgentCommand> {
    let shim_path = directory.join(format!("{command}.cmd"));
    let shim = read_bounded_shim(&shim_path).await?;
    let shim = String::from_utf8(shim).ok()?;

    for relative_target in known_windows_npm_targets(command) {
        if !shim_references_target(&shim, relative_target) {
            continue;
        }

        let Some(target) = validated_shim_target(directory, relative_target) else {
            continue;
        };
        let extension = target
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(extension.as_str(), "exe" | "com") {
            return Some(ResolvedAgentCommand {
                program: target,
                prefix_args: Vec::new(),
                managed_codex_package_root: None,
            });
        }
        if matches!(extension.as_str(), "js" | "cjs" | "mjs") {
            // The official Windows Codex npm launcher always spawns its
            // platform-native binary as a child. Starting that launcher here
            // would make cancellation kill only Node while leaving Codex
            // running. Resolve the native binary paired with this exact,
            // validated package instead, and fail closed if it is absent.
            if command == "codex" {
                let (native, package_root) = resolve_windows_codex_native(directory, &target)?;
                return Some(ResolvedAgentCommand {
                    program: native,
                    prefix_args: Vec::new(),
                    managed_codex_package_root: Some(package_root),
                });
            }

            let node = resolve_direct_windows_executable("node", path)?;
            return Some(ResolvedAgentCommand {
                program: node,
                prefix_args: vec![target.into_os_string()],
                managed_codex_package_root: None,
            });
        }
    }
    None
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsCodexNativeLayout {
    package_directory: &'static str,
    target_triple: &'static str,
}

#[cfg(windows)]
fn windows_codex_native_layout() -> Option<WindowsCodexNativeLayout> {
    match std::env::consts::ARCH {
        "x86_64" => Some(WindowsCodexNativeLayout {
            package_directory: "codex-win32-x64",
            target_triple: "x86_64-pc-windows-msvc",
        }),
        "aarch64" => Some(WindowsCodexNativeLayout {
            package_directory: "codex-win32-arm64",
            target_triple: "aarch64-pc-windows-msvc",
        }),
        _ => None,
    }
}

#[cfg(windows)]
fn resolve_windows_codex_native(directory: &Path, launcher: &Path) -> Option<(PathBuf, PathBuf)> {
    let trusted_root = std::fs::canonicalize(directory).ok()?;
    let launcher = std::fs::canonicalize(launcher).ok()?;
    if !launcher.starts_with(&trusted_root) || !is_regular_file(&launcher) {
        return None;
    }

    let package_root = launcher.parent()?.parent()?;
    let expected_launcher =
        std::fs::canonicalize(package_root.join("bin").join("codex.js")).ok()?;
    if launcher != expected_launcher {
        return None;
    }

    let layout = windows_codex_native_layout()?;
    let package_tail = Path::new("@openai").join(layout.package_directory);
    let candidate_roots = [
        // npm commonly nests the optional platform package below Codex.
        package_root.join("node_modules").join(&package_tail),
        // pnpm commonly links it beside the scoped Codex package.
        package_root.parent()?.join(layout.package_directory),
        // npm may hoist the optional platform package to the shim root.
        trusted_root.join("node_modules").join(&package_tail),
        // The upstream launcher also supports a bundled vendor fallback.
        package_root.to_path_buf(),
    ];

    for candidate_root in candidate_roots {
        let candidate = candidate_root
            .join("vendor")
            .join(layout.target_triple)
            .join("bin")
            .join("codex.exe");
        let Ok(candidate) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if candidate.starts_with(&trusted_root) && is_regular_file(&candidate) {
            return Some((candidate, package_root.to_path_buf()));
        }
    }
    None
}

#[cfg(windows)]
fn known_windows_npm_targets(command: &str) -> &'static [&'static str] {
    match command {
        "codex" => &[r"node_modules\@openai\codex\bin\codex.js"],
        "claude" => &[
            r"node_modules\@anthropic-ai\claude-code\bin\claude.exe",
            r"node_modules\@anthropic-ai\claude-code\cli.js",
        ],
        "opencode" => &[
            r"node_modules\opencode-ai\bin\opencode.exe",
            r"node_modules\opencode-ai\bin\opencode.js",
        ],
        _ => &[],
    }
}

#[cfg(windows)]
fn shim_references_target(shim: &str, relative_target: &str) -> bool {
    let normalized = shim.replace('/', "\\").to_ascii_lowercase();
    let target = format!(r"%dp0%\{}", relative_target.to_ascii_lowercase());
    normalized.contains(&target) && normalized.contains("%*")
}

#[cfg(windows)]
fn validated_shim_target(directory: &Path, relative_target: &str) -> Option<PathBuf> {
    let directory = std::fs::canonicalize(directory).ok()?;
    let target = std::fs::canonicalize(directory.join(relative_target)).ok()?;
    if !target.starts_with(&directory) || !is_regular_file(&target) {
        return None;
    }
    Some(target)
}

#[cfg(windows)]
fn resolve_direct_windows_executable(command: &str, path: &OsStr) -> Option<PathBuf> {
    for directory in std::env::split_paths(path).take(MAX_PATH_DIRECTORIES) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            continue;
        }
        for extension in ["exe", "com"] {
            let candidate = directory.join(format!("{command}.{extension}"));
            if is_regular_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
async fn read_bounded_shim(path: &Path) -> Option<Vec<u8>> {
    let file = tokio::fs::File::open(path).await.ok()?;
    if file.metadata().await.ok()?.len() > MAX_SHIM_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SHIM_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    (bytes.len() as u64 <= MAX_SHIM_BYTES).then_some(bytes)
}

async fn probe_version(spec: &ResolvedAgentCommand) -> ProbeResult {
    let mut command = spec.command();
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }

    let Ok(mut child) = command.spawn() else {
        return ProbeResult::default();
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.start_kill();
        return ProbeResult::default();
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.start_kill();
        return ProbeResult::default();
    };

    let result = timeout(PROBE_TIMEOUT, async {
        let (status, stdout, stderr) = tokio::join!(
            child.wait(),
            read_bounded_output(stdout),
            read_bounded_output(stderr),
        );
        (
            status,
            stdout.unwrap_or_default(),
            stderr.unwrap_or_default(),
        )
    })
    .await;

    let Ok((Ok(status), stdout, stderr)) = result else {
        let _ = child.start_kill();
        let _ = timeout(TERMINATION_TIMEOUT, child.wait()).await;
        return ProbeResult::default();
    };
    if !status.success() {
        return ProbeResult::default();
    }

    ProbeResult {
        available: true,
        version: extract_version(&stdout).or_else(|| extract_version(&stderr)),
    }
}

async fn read_bounded_output<R>(mut reader: R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut kept = Vec::with_capacity(MAX_CAPTURED_OUTPUT_BYTES);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(kept);
        }
        let remaining = MAX_CAPTURED_OUTPUT_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(remaining)]);
    }
}

fn extract_version(output: &[u8]) -> Option<String> {
    let output = String::from_utf8_lossy(output);
    output
        .split_ascii_whitespace()
        .filter_map(sanitize_version_token)
        .next()
}

fn sanitize_version_token(token: &str) -> Option<String> {
    let token = token.trim_matches(|character: char| {
        matches!(
            character,
            ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
        )
    });
    if token.is_empty() || token.len() > MAX_VERSION_BYTES || !token.is_ascii() {
        return None;
    }

    let body = token
        .strip_prefix('v')
        .or_else(|| token.strip_prefix('V'))
        .unwrap_or(token);
    if !body.starts_with(|character: char| character.is_ascii_digit())
        || !body.contains('.')
        || !body.ends_with(|character: char| character.is_ascii_alphanumeric())
        || !body.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
    {
        return None;
    }

    let numeric_prefix = body.split(['-', '+']).next().unwrap_or_default();
    if numeric_prefix
        .split('.')
        .any(|part| part.is_empty() || !part.chars().all(|character| character.is_ascii_digit()))
    {
        return None;
    }
    Some(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[cfg(windows)]
    fn fake_version_command(_root: &Path) -> ResolvedAgentCommand {
        ResolvedAgentCommand {
            program: PathBuf::from(std::env::var_os("ComSpec").unwrap()),
            prefix_args: vec![
                "/D".into(),
                "/S".into(),
                "/C".into(),
                format!("echo {} ClaudeCode", SUPPORTED_CLAUDE_VERSION).into(),
            ],
            managed_codex_package_root: None,
        }
    }

    #[cfg(unix)]
    fn fake_version_command(root: &Path) -> ResolvedAgentCommand {
        use std::os::unix::fs::PermissionsExt;

        let script = root.join("claude-version");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{} (Claude Code)'\n",
                SUPPORTED_CLAUDE_VERSION
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();
        ResolvedAgentCommand {
            program: script,
            prefix_args: Vec::new(),
            managed_codex_package_root: None,
        }
    }

    #[test]
    fn versions_are_short_and_do_not_accept_paths_or_messages() {
        assert_eq!(extract_version(b"codex-cli 1.2.3\n"), Some("1.2.3".into()));
        assert_eq!(
            extract_version(b"2.1.246 (Claude Code)\n"),
            Some("2.1.246".into())
        );
        assert_eq!(
            extract_version(b"OpenCode v1.17.12-beta.1\n"),
            Some("v1.17.12-beta.1".into())
        );
        assert_eq!(
            extract_version(br"failed at C:\Users\name\secret.txt"),
            None
        );
        assert_eq!(extract_version(b"API_KEY=abc.def"), None);
        assert_eq!(extract_version(&vec![b'1'; MAX_VERSION_BYTES + 1]), None);
    }

    #[test]
    fn claude_runtime_support_requires_the_exact_tested_version() {
        let supported = ProbeResult {
            available: true,
            version: Some(SUPPORTED_CLAUDE_VERSION.to_owned()),
        };
        assert!(AiAgentId::Claude.runtime_supported(true, Some(&supported)));

        for probe in [
            ProbeResult {
                available: true,
                version: Some("2.1.245".to_owned()),
            },
            ProbeResult {
                available: true,
                version: None,
            },
            ProbeResult::default(),
        ] {
            assert!(!AiAgentId::Claude.runtime_supported(true, Some(&probe)));
        }

        assert!(AiAgentId::Claude.runtime_supported(false, None));
        assert!(AiAgentId::Codex.runtime_supported(true, None));
        assert!(!AiAgentId::Opencode.runtime_supported(false, None));
    }

    #[tokio::test]
    async fn runtime_reprobe_is_bounded_and_requires_the_exact_version() {
        let temp = tempfile::tempdir().unwrap();
        let command = fake_version_command(temp.path());
        assert!(resolved_agent_has_exact_version(&command, SUPPORTED_CLAUDE_VERSION).await);
        assert!(!resolved_agent_has_exact_version(&command, "2.1.245").await);
    }

    #[tokio::test]
    async fn bounded_reader_drains_input_but_retains_only_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(MAX_CAPTURED_OUTPUT_BYTES * 2);
        let write = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_CAPTURED_OUTPUT_BYTES * 3])
                .await
                .unwrap();
        });
        let retained = read_bounded_output(reader).await.unwrap();
        write.await.unwrap();
        assert_eq!(retained.len(), MAX_CAPTURED_OUTPUT_BYTES);
        assert!(retained.iter().all(|byte| *byte == b'x'));
    }

    #[tokio::test]
    async fn missing_path_returns_the_fixed_secret_free_catalog() {
        let agents = discover_ai_agents_on_path(None).await;
        assert_eq!(agents.len(), 3);
        assert_eq!(agents[0].id, AiAgentId::Codex);
        assert_eq!(agents[1].id, AiAgentId::Claude);
        assert_eq!(agents[2].id, AiAgentId::Opencode);
        assert!(
            agents
                .iter()
                .all(|agent| { !agent.installed && !agent.available && agent.version.is_none() })
        );
        assert!(agents[0].runtime_supported);
        assert!(agents[1].runtime_supported);
        assert!(!agents[2].runtime_supported);

        let json = serde_json::to_value(agents).unwrap();
        let first = json
            .as_array()
            .unwrap()
            .first()
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            first
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "available",
                "id",
                "installed",
                "name",
                "runtimeSupported",
                "version",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
    }

    #[tokio::test]
    async fn relative_path_entries_are_never_executable_search_roots() {
        let relative = std::env::join_paths([Path::new("renderer-controlled")]).unwrap();
        assert!(
            resolve_command_on_path("codex", Some(&relative))
                .await
                .is_none()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn standard_codex_npm_shim_resolves_directly_to_its_native_binary() {
        let temp = tempfile::tempdir().unwrap();
        let node = temp.path().join("node.exe");
        let target = temp.path().join(r"node_modules\@openai\codex\bin\codex.js");
        let layout = windows_codex_native_layout().unwrap();
        let native = temp
            .path()
            .join(r"node_modules\@openai\codex\node_modules\@openai")
            .join(layout.package_directory)
            .join("vendor")
            .join(layout.target_triple)
            .join("bin")
            .join("codex.exe");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::create_dir_all(native.parent().unwrap()).unwrap();
        std::fs::write(&node, b"not executed").unwrap();
        std::fs::write(&target, b"not executed").unwrap();
        std::fs::write(&native, b"not executed").unwrap();
        std::fs::write(
            temp.path().join("codex.cmd"),
            br#"@ECHO off
"%_prog%" "%dp0%\node_modules\@openai\codex\bin\codex.js" %*
"#,
        )
        .unwrap();

        let path = std::env::join_paths([temp.path()]).unwrap();
        let resolved = resolve_command_on_path("codex", Some(&path)).await.unwrap();
        assert_eq!(resolved.program, std::fs::canonicalize(native).unwrap());
        assert!(resolved.prefix_args.is_empty());
        let expected_package_root =
            std::fs::canonicalize(target.parent().unwrap().parent().unwrap()).unwrap();
        assert_eq!(
            resolved.managed_codex_package_root.as_ref(),
            Some(&expected_package_root)
        );

        let command = resolved.command();
        let command_env = |name: &str| {
            command
                .as_std()
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| value.map(OsStr::to_owned))
        };
        assert_eq!(
            command_env("CODEX_MANAGED_PACKAGE_ROOT"),
            Some(Some(expected_package_root.into_os_string()))
        );
        assert_eq!(
            command_env("CODEX_MANAGED_BY_NPM"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(command_env("CODEX_MANAGED_BY_BUN"), Some(None));
        assert_eq!(command_env("CODEX_MANAGED_BY_PNPM"), Some(None));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn codex_npm_shim_without_a_paired_native_binary_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let node = temp.path().join("node.exe");
        let target = temp.path().join(r"node_modules\@openai\codex\bin\codex.js");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&node, b"not executed").unwrap();
        std::fs::write(&target, b"not executed").unwrap();
        std::fs::write(
            temp.path().join("codex.cmd"),
            br#"@ECHO off
"%_prog%" "%dp0%\node_modules\@openai\codex\bin\codex.js" %*
"#,
        )
        .unwrap();

        let path = std::env::join_paths([temp.path()]).unwrap();
        assert!(
            resolve_command_on_path("codex", Some(&path))
                .await
                .is_none()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn non_codex_javascript_shims_keep_the_bounded_node_adapter() {
        let temp = tempfile::tempdir().unwrap();
        let node = temp.path().join("node.exe");
        let target = temp
            .path()
            .join(r"node_modules\@anthropic-ai\claude-code\cli.js");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&node, b"not executed").unwrap();
        std::fs::write(&target, b"not executed").unwrap();
        std::fs::write(
            temp.path().join("claude.cmd"),
            br#"@ECHO off
"%_prog%" "%dp0%\node_modules\@anthropic-ai\claude-code\cli.js" %*
"#,
        )
        .unwrap();

        let path = std::env::join_paths([temp.path()]).unwrap();
        let resolved = resolve_command_on_path("claude", Some(&path))
            .await
            .unwrap();
        assert_eq!(resolved.program, node);
        assert_eq!(
            resolved.prefix_args,
            vec![std::fs::canonicalize(target).unwrap().into_os_string()]
        );
    }
}
