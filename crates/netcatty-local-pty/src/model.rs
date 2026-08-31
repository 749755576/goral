use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub const MAX_DISCOVERED_SHELLS: usize = 64;
pub const MAX_SHELL_ID_BYTES: usize = 128;
pub const MAX_SHELL_NAME_BYTES: usize = 256;
pub const MAX_SHELL_COMMAND_BYTES: usize = 32 * 1_024;
pub const MAX_SHELL_ARGUMENTS: usize = 32;
pub const MAX_SHELL_ARGUMENT_BYTES: usize = 4 * 1_024;
pub const MAX_SHELL_ICON_BYTES: usize = 64;
pub const MAX_CWD_BYTES: usize = 32 * 1_024;
pub const MAX_TERMINAL_ENV_BYTES: usize = 128;
pub const MAX_WINDOW_DIMENSION: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellField {
    Id,
    Name,
    Command,
    Argument,
    Icon,
    Default,
    WorkingDirectory,
    TerminalEnvironment,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShellDiscoveryError {
    InventoryTooLarge {
        maximum_entries: usize,
    },
    InvalidField {
        field: ShellField,
        maximum_bytes: usize,
    },
    TooManyArguments {
        maximum_entries: usize,
    },
    DuplicateId,
    MultipleDefaults,
    NoShellsFound,
    UnknownShell,
    CustomShellUnavailable,
    InvalidWindowSize {
        maximum: u32,
    },
    WorkingDirectoryUnavailable,
}

impl fmt::Display for ShellDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InventoryTooLarge { maximum_entries } => write!(
                formatter,
                "Local shell inventory exceeds {maximum_entries} entries"
            ),
            Self::InvalidField {
                field,
                maximum_bytes,
            } => write!(
                formatter,
                "Local shell {field:?} is invalid or exceeds {maximum_bytes} bytes"
            ),
            Self::TooManyArguments { maximum_entries } => write!(
                formatter,
                "Local shell argument list exceeds {maximum_entries} entries"
            ),
            Self::DuplicateId => {
                formatter.write_str("Local shell inventory contains duplicate IDs")
            }
            Self::MultipleDefaults => {
                formatter.write_str("Local shell inventory contains multiple defaults")
            }
            Self::NoShellsFound => formatter.write_str("No supported local shell was found"),
            Self::UnknownShell => formatter.write_str("The selected local shell is unavailable"),
            Self::CustomShellUnavailable => {
                formatter.write_str("The configured custom shell is unavailable")
            }
            Self::InvalidWindowSize { maximum } => write!(
                formatter,
                "Local terminal dimensions must be between 1 and {maximum}"
            ),
            Self::WorkingDirectoryUnavailable => {
                formatter.write_str("A local terminal working directory is unavailable")
            }
        }
    }
}

impl fmt::Debug for ShellDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for ShellDiscoveryError {}

/// Renderer-safe shell metadata. The command is exposed for legacy display
/// compatibility, but callers must resolve `id` through [`ShellCatalog`]
/// before spawning rather than trusting a returned copy of `command`/`args`.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredShell {
    id: String,
    name: String,
    command: String,
    args: Vec<String>,
    icon: String,
    is_default: bool,
}

impl DiscoveredShell {
    pub(crate) fn new(
        id: String,
        name: String,
        command: String,
        args: Vec<String>,
        icon: String,
        is_default: bool,
    ) -> Result<Self, ShellDiscoveryError> {
        validate_id(&id)?;
        validate_text(ShellField::Name, &name, MAX_SHELL_NAME_BYTES, false)?;
        validate_text(
            ShellField::Command,
            &command,
            MAX_SHELL_COMMAND_BYTES,
            false,
        )?;
        if args.len() > MAX_SHELL_ARGUMENTS {
            return Err(ShellDiscoveryError::TooManyArguments {
                maximum_entries: MAX_SHELL_ARGUMENTS,
            });
        }
        for argument in &args {
            validate_text(
                ShellField::Argument,
                argument,
                MAX_SHELL_ARGUMENT_BYTES,
                true,
            )?;
        }
        validate_text(ShellField::Icon, &icon, MAX_SHELL_ICON_BYTES, false)?;
        Ok(Self {
            id,
            name,
            command,
            args,
            icon,
            is_default,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn icon(&self) -> &str {
        &self.icon
    }

    pub const fn is_default(&self) -> bool {
        self.is_default
    }

    pub(crate) fn set_default(&mut self, value: bool) {
        self.is_default = value;
    }
}

impl fmt::Debug for DiscoveredShell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveredShell")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("command", &"[redacted native path]")
            .field("argument_count", &self.args.len())
            .field("icon", &self.icon)
            .field("is_default", &self.is_default)
            .finish()
    }
}

#[derive(Clone)]
pub struct ShellCatalog {
    shells: Vec<DiscoveredShell>,
    by_id: HashMap<String, usize>,
    default_index: usize,
}

impl ShellCatalog {
    pub(crate) fn new(mut shells: Vec<DiscoveredShell>) -> Result<Self, ShellDiscoveryError> {
        if shells.is_empty() {
            return Err(ShellDiscoveryError::NoShellsFound);
        }
        if shells.len() > MAX_DISCOVERED_SHELLS {
            return Err(ShellDiscoveryError::InventoryTooLarge {
                maximum_entries: MAX_DISCOVERED_SHELLS,
            });
        }

        let mut by_id = HashMap::with_capacity(shells.len());
        let mut default_index = None;
        for (index, shell) in shells.iter().enumerate() {
            if by_id.insert(shell.id.clone(), index).is_some() {
                return Err(ShellDiscoveryError::DuplicateId);
            }
            if shell.is_default {
                if default_index.replace(index).is_some() {
                    return Err(ShellDiscoveryError::MultipleDefaults);
                }
            }
        }
        let default_index = default_index.unwrap_or(0);
        for (index, shell) in shells.iter_mut().enumerate() {
            shell.set_default(index == default_index);
        }
        Ok(Self {
            shells,
            by_id,
            default_index,
        })
    }

    pub fn shells(&self) -> &[DiscoveredShell] {
        &self.shells
    }

    pub fn default_shell(&self) -> &DiscoveredShell {
        &self.shells[self.default_index]
    }

    pub fn get(&self, id: &str) -> Option<&DiscoveredShell> {
        self.by_id.get(id).map(|index| &self.shells[*index])
    }

    /// Add one user-configured shell after it has been read from native
    /// Settings custody. The registration type is intentionally not
    /// deserializable: a local-start request can select this generated ID but
    /// cannot replace its executable or argv.
    pub fn with_custom_shell(
        &self,
        custom: CustomShellRegistration,
    ) -> Result<Self, ShellDiscoveryError> {
        let mut shells = self.shells.clone();
        for shell in &mut shells {
            shell.set_default(false);
        }
        shells.retain(|shell| shell.id != CustomShellRegistration::ID);
        shells.insert(0, custom.into_discovered()?);
        Self::new(shells)
    }

    /// Select an already discovered shell as the Settings-owned default
    /// without allowing the renderer to replace its executable or argv.
    pub fn with_default_shell(&self, id: &str) -> Result<Self, ShellDiscoveryError> {
        if self.get(id).is_none() {
            return Err(ShellDiscoveryError::UnknownShell);
        }
        let mut shells = self.shells.clone();
        for shell in &mut shells {
            shell.set_default(shell.id == id);
        }
        Self::new(shells)
    }

    pub(crate) fn resolve(&self, id: Option<&str>) -> Result<ShellLaunch, ShellDiscoveryError> {
        if let Some(id) = id {
            let shell = self.get(id).ok_or(ShellDiscoveryError::UnknownShell)?;
            return Ok(Self::launch(shell));
        }
        Ok(self.default_launch())
    }

    fn launch(shell: &DiscoveredShell) -> ShellLaunch {
        ShellLaunch {
            id: shell.id.clone(),
            command: shell.command.clone(),
            args: shell.args.clone(),
        }
    }

    fn default_launch(&self) -> ShellLaunch {
        #[cfg(windows)]
        {
            // The legacy picker marks `pwsh > powershell > cmd` as its
            // display default, while a start request with no shell selection
            // uses the separate `pwsh > powershell > powershell.exe` spawn
            // fallback. Preserve that distinction. A trusted custom shell is
            // still authoritative when native Settings made it the default.
            if self.default_shell().id == CustomShellRegistration::ID {
                return Self::launch(self.default_shell());
            }
            if let Some(shell) = ["pwsh", "powershell"]
                .into_iter()
                .find_map(|id| self.get(id))
            {
                return Self::launch(shell);
            }
            return ShellLaunch {
                id: "powershell-fallback".to_owned(),
                command: "powershell.exe".to_owned(),
                args: vec!["-NoLogo".to_owned()],
            };
        }

        #[cfg(not(windows))]
        {
            Self::launch(self.default_shell())
        }
    }
}

/// A validated user-configured executable and direct argv. Construct this only
/// from native Settings-owned values, then register it in [`ShellCatalog`]. It
/// has no `Deserialize` implementation and cannot enter a local-start payload.
#[derive(Clone)]
pub struct CustomShellRegistration {
    command: String,
    args: Vec<String>,
    name: String,
    icon: String,
}

impl CustomShellRegistration {
    pub const ID: &'static str = "configured-local-shell";

    pub fn new(command: String, args: Vec<String>) -> Result<Self, ShellDiscoveryError> {
        let command = normalize_custom_command(command)?;
        if args.len() > MAX_SHELL_ARGUMENTS {
            return Err(ShellDiscoveryError::TooManyArguments {
                maximum_entries: MAX_SHELL_ARGUMENTS,
            });
        }
        for argument in &args {
            validate_text(
                ShellField::Argument,
                argument,
                MAX_SHELL_ARGUMENT_BYTES,
                true,
            )?;
        }
        let (name, icon) = custom_shell_presentation(&command);
        Ok(Self {
            command,
            args,
            name: name.to_owned(),
            icon: icon.to_owned(),
        })
    }

    pub fn with_presentation(
        mut self,
        name: String,
        icon: String,
    ) -> Result<Self, ShellDiscoveryError> {
        validate_text(ShellField::Name, &name, MAX_SHELL_NAME_BYTES, false)?;
        validate_text(ShellField::Icon, &icon, MAX_SHELL_ICON_BYTES, false)?;
        self.name = name;
        self.icon = icon;
        Ok(self)
    }

    fn into_discovered(self) -> Result<DiscoveredShell, ShellDiscoveryError> {
        DiscoveredShell::new(
            Self::ID.to_owned(),
            self.name,
            self.command,
            self.args,
            self.icon,
            true,
        )
    }
}

impl fmt::Debug for CustomShellRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomShellRegistration")
            .field("command", &"[redacted native path]")
            .field("argument_count", &self.args.len())
            .field("name", &self.name)
            .field("icon", &self.icon)
            .finish()
    }
}

impl fmt::Debug for ShellCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellCatalog")
            .field("shell_count", &self.shells.len())
            .field("default_id", &self.default_shell().id)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ShellLaunch {
    pub(crate) id: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
}

impl fmt::Debug for ShellLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellLaunch")
            .field("id", &self.id)
            .field("command", &"[redacted native path]")
            .field("argument_count", &self.args.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPtyWindowSize {
    columns: u16,
    rows: u16,
}

impl LocalPtyWindowSize {
    pub fn new(columns: u32, rows: u32) -> Result<Self, ShellDiscoveryError> {
        if columns == 0
            || rows == 0
            || columns > MAX_WINDOW_DIMENSION
            || rows > MAX_WINDOW_DIMENSION
        {
            return Err(ShellDiscoveryError::InvalidWindowSize {
                maximum: MAX_WINDOW_DIMENSION,
            });
        }
        Ok(Self {
            columns: columns as u16,
            rows: rows as u16,
        })
    }

    pub const fn columns(self) -> u16 {
        self.columns
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalEnvironmentRequest {
    #[serde(default)]
    term: Option<String>,
    #[serde(default)]
    color_term: Option<String>,
}

impl TerminalEnvironmentRequest {
    pub fn new(term: Option<String>, color_term: Option<String>) -> Self {
        Self { term, color_term }
    }

    fn validate(self) -> Result<TerminalEnvironment, ShellDiscoveryError> {
        let term = self.term.unwrap_or_else(|| "xterm-256color".to_owned());
        let color_term = self.color_term.unwrap_or_else(|| "truecolor".to_owned());
        validate_environment_value(&term)?;
        validate_environment_value(&color_term)?;
        Ok(TerminalEnvironment { term, color_term })
    }
}

impl fmt::Debug for TerminalEnvironmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalEnvironmentRequest")
            .field("term_present", &self.term.is_some())
            .field("color_term_present", &self.color_term.is_some())
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalPtyRequest {
    #[serde(default)]
    shell_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    columns: u32,
    rows: u32,
    #[serde(default)]
    environment: TerminalEnvironmentRequest,
}

impl LocalPtyRequest {
    pub fn new(shell_id: Option<String>, columns: u32, rows: u32) -> Self {
        Self {
            shell_id,
            cwd: None,
            columns,
            rows,
            environment: TerminalEnvironmentRequest::default(),
        }
    }

    pub fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }

    /// Applies a native Settings default only when this individual launch did
    /// not explicitly choose a working directory.
    pub fn with_default_cwd(mut self, cwd: Option<String>) -> Self {
        if self.cwd.is_none() {
            self.cwd = cwd;
        }
        self
    }

    pub fn with_environment(mut self, environment: TerminalEnvironmentRequest) -> Self {
        self.environment = environment;
        self
    }
}

impl fmt::Debug for LocalPtyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalPtyRequest")
            .field("shell_id", &self.shell_id)
            .field("cwd", &self.cwd.as_ref().map(|_| "[redacted native path]"))
            .field("columns", &self.columns)
            .field("rows", &self.rows)
            .field("environment", &self.environment)
            .finish()
    }
}

#[derive(Clone)]
pub struct LocalPtyConfig {
    pub(crate) shell: ShellLaunch,
    pub(crate) cwd: PathBuf,
    pub(crate) window_size: LocalPtyWindowSize,
    pub(crate) environment: TerminalEnvironment,
}

impl LocalPtyConfig {
    pub fn resolve(
        catalog: &ShellCatalog,
        request: LocalPtyRequest,
    ) -> Result<Self, ShellDiscoveryError> {
        if let Some(id) = request.shell_id.as_deref() {
            validate_id(id)?;
        }
        let shell = catalog.resolve(request.shell_id.as_deref())?;
        let cwd = resolve_working_directory(request.cwd.as_deref())?;
        let window_size = LocalPtyWindowSize::new(request.columns, request.rows)?;
        let environment = request.environment.validate()?;
        Ok(Self {
            shell,
            cwd,
            window_size,
            environment,
        })
    }

    pub fn shell_id(&self) -> &str {
        &self.shell.id
    }

    pub fn window_size(&self) -> LocalPtyWindowSize {
        self.window_size
    }
}

impl fmt::Debug for LocalPtyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalPtyConfig")
            .field("shell", &self.shell)
            .field("cwd", &"[redacted native path]")
            .field("window_size", &self.window_size)
            .field("environment", &"[redacted inherited environment]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct TerminalEnvironment {
    pub(crate) term: String,
    pub(crate) color_term: String,
}

fn validate_id(value: &str) -> Result<(), ShellDiscoveryError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_SHELL_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && value.as_bytes()[0].is_ascii_alphanumeric();
    if valid {
        Ok(())
    } else {
        Err(ShellDiscoveryError::InvalidField {
            field: ShellField::Id,
            maximum_bytes: MAX_SHELL_ID_BYTES,
        })
    }
}

fn validate_text(
    field: ShellField,
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> Result<(), ShellDiscoveryError> {
    let valid = (allow_empty || !value.is_empty())
        && value.len() <= maximum_bytes
        && !value.contains('\0')
        && !value.contains(['\r', '\n']);
    if valid {
        Ok(())
    } else {
        Err(ShellDiscoveryError::InvalidField {
            field,
            maximum_bytes,
        })
    }
}

fn validate_environment_value(value: &str) -> Result<(), ShellDiscoveryError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_TERMINAL_ENV_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if valid {
        Ok(())
    } else {
        Err(ShellDiscoveryError::InvalidField {
            field: ShellField::TerminalEnvironment,
            maximum_bytes: MAX_TERMINAL_ENV_BYTES,
        })
    }
}

fn resolve_working_directory(requested: Option<&str>) -> Result<PathBuf, ShellDiscoveryError> {
    if let Some(requested) = requested {
        validate_text(
            ShellField::WorkingDirectory,
            requested,
            MAX_CWD_BYTES,
            false,
        )?;
    }

    let home = home::home_dir().filter(|path| path.is_dir());
    let current = std::env::current_dir().ok().filter(|path| path.is_dir());
    let fallback = home
        .clone()
        .or(current.clone())
        .ok_or(ShellDiscoveryError::WorkingDirectoryUnavailable)?;

    let Some(requested) = requested else {
        return Ok(fallback);
    };
    let expanded = expand_home(requested, home.as_deref());
    let resolved = if expanded.is_absolute() {
        expanded
    } else if let Some(current) = current {
        current.join(expanded)
    } else {
        return Ok(fallback);
    };
    if resolved.is_dir() {
        Ok(resolved)
    } else {
        // Legacy behavior deliberately falls back instead of exposing the
        // rejected native path in an error message.
        Ok(fallback)
    }
}

fn expand_home(value: &str, home: Option<&Path>) -> PathBuf {
    if value == "~" {
        return home
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(value));
    }
    if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
        && let Some(home) = home
    {
        return home.join(rest);
    }
    PathBuf::from(value)
}

fn normalize_custom_command(command: String) -> Result<String, ShellDiscoveryError> {
    let command = command.trim();
    validate_text(ShellField::Command, command, MAX_SHELL_COMMAND_BYTES, false)?;
    let expanded = expand_home(command, home::home_dir().as_deref());
    let path_like = expanded.is_absolute() || command.contains(['/', '\\']);
    if path_like {
        if !is_executable_file(&expanded) {
            return Err(ShellDiscoveryError::CustomShellUnavailable);
        }
        return expanded
            .to_str()
            .map(str::to_owned)
            .ok_or(ShellDiscoveryError::InvalidField {
                field: ShellField::Command,
                maximum_bytes: MAX_SHELL_COMMAND_BYTES,
            });
    }
    let valid_bare_name = command
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if !valid_bare_name {
        return Err(ShellDiscoveryError::InvalidField {
            field: ShellField::Command,
            maximum_bytes: MAX_SHELL_COMMAND_BYTES,
        });
    }
    Ok(command.to_owned())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn custom_shell_presentation(command: &str) -> (&'static str, &'static str) {
    let basename = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    let stem = basename.strip_suffix(".exe").unwrap_or(&basename);
    match stem {
        "pwsh" => ("PowerShell 7", "pwsh"),
        "powershell" => ("Windows PowerShell", "powershell"),
        "cmd" => ("CMD", "cmd"),
        "bash" => ("Bash", "bash"),
        "zsh" => ("Zsh", "zsh"),
        "fish" => ("Fish", "fish"),
        "nu" => ("Nushell", "nushell"),
        _ => ("Local Terminal", "terminal"),
    }
}

pub(crate) fn unique_shell_id(base: &str, used: &mut HashSet<String>) -> String {
    let mut normalized = String::with_capacity(base.len().min(MAX_SHELL_ID_BYTES));
    let mut last_dash = false;
    for character in base.chars().flat_map(char::to_lowercase) {
        let mapped = if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            character
        } else {
            '-'
        };
        if mapped == '-' && last_dash {
            continue;
        }
        if normalized.len() + mapped.len_utf8() > MAX_SHELL_ID_BYTES.saturating_sub(8) {
            break;
        }
        normalized.push(mapped);
        last_dash = mapped == '-';
    }
    let normalized = normalized.trim_matches('-');
    let base = if normalized.is_empty() {
        "shell"
    } else {
        normalized
    };
    if !used.contains(base) {
        let result = base.to_owned();
        used.insert(result.clone());
        return result;
    }
    for suffix in 2..=MAX_DISCOVERED_SHELLS + 1 {
        let candidate = format!("{base}-{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    // The inventory bound makes this branch unreachable, but preserve a valid
    // deterministic ID if a future caller changes the limit.
    "shell-overflow".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(id: &str, is_default: bool) -> DiscoveredShell {
        DiscoveredShell::new(
            id.to_owned(),
            "Test shell".to_owned(),
            "test-shell".to_owned(),
            vec!["--login".to_owned()],
            "terminal".to_owned(),
            is_default,
        )
        .expect("valid shell")
    }

    #[test]
    fn shell_json_matches_legacy_camel_case_without_runtime_fields() {
        let value = serde_json::to_value(shell("test", true)).expect("serialize shell");
        assert_eq!(
            value,
            serde_json::json!({
                "id": "test",
                "name": "Test shell",
                "command": "test-shell",
                "args": ["--login"],
                "icon": "terminal",
                "isDefault": true
            })
        );
    }

    #[test]
    fn debug_redacts_native_paths_and_arguments() {
        let shell = DiscoveredShell::new(
            "private".to_owned(),
            "Private".to_owned(),
            "C:\\Users\\private-user\\secret-shell.exe".to_owned(),
            vec!["--secret=value".to_owned()],
            "terminal".to_owned(),
            true,
        )
        .expect("valid shell");
        let debug = format!("{shell:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("--secret"));
    }

    #[test]
    fn catalog_rejects_duplicates_and_multiple_defaults() {
        assert!(matches!(
            ShellCatalog::new(vec![shell("same", true), shell("same", false)]),
            Err(ShellDiscoveryError::DuplicateId)
        ));
        assert!(matches!(
            ShellCatalog::new(vec![shell("one", true), shell("two", true)]),
            Err(ShellDiscoveryError::MultipleDefaults)
        ));
    }

    #[test]
    fn catalog_promotes_first_entry_when_discovery_has_no_default() {
        let catalog =
            ShellCatalog::new(vec![shell("one", false), shell("two", false)]).expect("catalog");
        assert_eq!(catalog.default_shell().id(), "one");
        assert!(catalog.shells()[0].is_default());
        assert!(!catalog.shells()[1].is_default());
    }

    #[test]
    fn native_settings_can_select_only_an_existing_discovered_shell() {
        let catalog =
            ShellCatalog::new(vec![shell("one", true), shell("two", false)]).expect("catalog");
        let selected = catalog.with_default_shell("two").expect("known shell");
        assert_eq!(selected.default_shell().id(), "two");
        assert!(matches!(
            catalog.with_default_shell("missing"),
            Err(ShellDiscoveryError::UnknownShell)
        ));
    }

    #[test]
    fn request_accepts_only_known_shell_ids_and_bounded_dimensions() {
        let catalog = ShellCatalog::new(vec![shell("known", true)]).expect("catalog");
        let unknown = LocalPtyConfig::resolve(
            &catalog,
            LocalPtyRequest::new(Some("unknown".to_owned()), 80, 24),
        );
        assert!(matches!(unknown, Err(ShellDiscoveryError::UnknownShell)));
        assert_eq!(
            LocalPtyWindowSize::new(0, 24),
            Err(ShellDiscoveryError::InvalidWindowSize {
                maximum: MAX_WINDOW_DIMENSION
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn empty_windows_selection_preserves_the_legacy_spawn_fallback() {
        let cmd = DiscoveredShell::new(
            "cmd".to_owned(),
            "CMD".to_owned(),
            "cmd.exe".to_owned(),
            Vec::new(),
            "cmd".to_owned(),
            true,
        )
        .expect("CMD shell");
        let catalog = ShellCatalog::new(vec![cmd]).expect("catalog");

        let fallback = LocalPtyConfig::resolve(&catalog, LocalPtyRequest::new(None, 80, 24))
            .expect("legacy fallback");
        assert_eq!(fallback.shell.id, "powershell-fallback");
        assert_eq!(fallback.shell.command, "powershell.exe");
        assert_eq!(fallback.shell.args, ["-NoLogo"]);

        let selected = LocalPtyConfig::resolve(
            &catalog,
            LocalPtyRequest::new(Some("cmd".to_owned()), 80, 24),
        )
        .expect("explicit CMD selection");
        assert_eq!(selected.shell.id, "cmd");
        assert_eq!(selected.shell.command, "cmd.exe");
        assert!(selected.shell.args.is_empty());
    }

    #[test]
    fn request_deserialization_rejects_unknown_environment_keys() {
        let result = serde_json::from_value::<LocalPtyRequest>(serde_json::json!({
            "columns": 80,
            "rows": 24,
            "environment": { "PATH": "untrusted" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn invalid_cwd_falls_back_without_echoing_the_path() {
        let catalog = ShellCatalog::new(vec![shell("known", true)]).expect("catalog");
        let marker = "private-directory-that-does-not-exist-sentinel";
        let config = LocalPtyConfig::resolve(
            &catalog,
            LocalPtyRequest::new(None, 80, 24).with_cwd(Some(marker.to_owned())),
        )
        .expect("fallback config");
        assert!(config.cwd.is_dir());
        assert!(!format!("{config:?}").contains(marker));
    }

    #[test]
    fn shell_ids_are_stable_bounded_and_collision_safe() {
        let mut used = HashSet::new();
        assert_eq!(unique_shell_id("Ubuntu 24.04", &mut used), "ubuntu-24.04");
        assert_eq!(
            unique_shell_id("Ubuntu--24.04", &mut used),
            "ubuntu-24.04-2"
        );
        assert!(unique_shell_id(&"x".repeat(1024), &mut used).len() <= MAX_SHELL_ID_BYTES);
    }

    #[test]
    fn trusted_custom_shell_registration_preserves_direct_argv() {
        let catalog = ShellCatalog::new(vec![shell("known", true)]).expect("catalog");
        let custom = CustomShellRegistration::new(
            "custom-shell".to_owned(),
            vec!["--login".to_owned(), "value with spaces".to_owned()],
        )
        .expect("custom shell");
        let catalog = catalog.with_custom_shell(custom).expect("custom catalog");
        let selected = catalog.default_shell();
        assert_eq!(selected.id(), CustomShellRegistration::ID);
        assert_eq!(selected.command(), "custom-shell");
        assert_eq!(selected.args(), ["--login", "value with spaces"]);
        assert_eq!(catalog.shells().len(), 2);
    }

    #[test]
    fn custom_shell_rejects_command_injection_and_missing_paths() {
        assert!(matches!(
            CustomShellRegistration::new("shell && other".to_owned(), vec![]),
            Err(ShellDiscoveryError::InvalidField {
                field: ShellField::Command,
                ..
            })
        ));
        assert!(matches!(
            CustomShellRegistration::new(
                "C:\\missing-custom-shell-sentinel\\shell.exe".to_owned(),
                vec![]
            ),
            Err(ShellDiscoveryError::CustomShellUnavailable)
        ));
    }

    #[test]
    fn custom_shell_debug_redacts_command_and_arguments() {
        let custom = CustomShellRegistration::new(
            "custom-secret-shell".to_owned(),
            vec!["--token=secret".to_owned()],
        )
        .expect("custom shell");
        let debug = format!("{custom:?}");
        assert!(!debug.contains("custom-secret-shell"));
        assert!(!debug.contains("token"));
    }
}
