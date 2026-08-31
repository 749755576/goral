use std::collections::HashSet;

use crate::model::{
    DiscoveredShell, MAX_DISCOVERED_SHELLS, ShellCatalog, ShellDiscoveryError, unique_shell_id,
};

pub fn discover_shells() -> Result<ShellCatalog, ShellDiscoveryError> {
    #[cfg(windows)]
    let shells = windows::discover()?;
    #[cfg(unix)]
    let shells = unix::discover()?;
    #[cfg(not(any(windows, unix)))]
    let shells = Vec::new();

    ShellCatalog::new(shells)
}

fn shell(
    id: String,
    name: impl Into<String>,
    command: impl Into<String>,
    args: Vec<String>,
    icon: impl Into<String>,
) -> Result<DiscoveredShell, ShellDiscoveryError> {
    DiscoveredShell::new(id, name.into(), command.into(), args, icon.into(), false)
}

fn mark_default_by_id(shells: &mut [DiscoveredShell], priorities: &[&str]) {
    let default = priorities
        .iter()
        .find_map(|id| shells.iter().position(|shell| shell.id() == *id))
        .unwrap_or(0);
    for (index, shell) in shells.iter_mut().enumerate() {
        shell.set_default(index == default);
    }
}

#[cfg(unix)]
fn unix_shell_name(basename: &str) -> &str {
    match basename {
        "zsh" => "Zsh",
        "bash" => "Bash",
        "fish" => "Fish",
        "sh" => "sh",
        "ksh" => "Ksh",
        "tcsh" => "Tcsh",
        "csh" => "Csh",
        "dash" => "Dash",
        "nu" => "Nushell",
        "pwsh" => "PowerShell",
        other => other,
    }
}

#[cfg(unix)]
fn unix_shell_icon(basename: &str) -> &str {
    match basename {
        "zsh" => "zsh",
        "bash" => "bash",
        "fish" => "fish",
        "nu" => "nushell",
        "pwsh" => "pwsh",
        _ => "terminal",
    }
}

#[cfg(unix)]
fn unix_login_args(basename: &str) -> Vec<String> {
    if matches!(basename, "bash" | "zsh" | "fish" | "ksh" | "sh") {
        vec!["-l".to_owned()]
    } else {
        Vec::new()
    }
}

fn wsl_icon(distro: &str) -> &str {
    let lower = distro.to_ascii_lowercase();
    if lower.contains("ubuntu") {
        "ubuntu"
    } else if lower.contains("debian") {
        "debian"
    } else if lower.contains("kali") {
        "kali"
    } else if lower.contains("alpine") {
        "alpine"
    } else if lower.contains("opensuse") || lower.contains("suse") {
        "opensuse"
    } else if lower.contains("fedora") {
        "fedora"
    } else if lower.contains("arch") {
        "arch"
    } else if lower.contains("oracle") {
        "oracle"
    } else {
        "linux"
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        fs,
        io::Read,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use winreg::{HKEY, RegKey, enums::*};

    use super::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_DISCOVERY_OUTPUT_BYTES: usize = 64 * 1_024;

    pub(super) fn discover() -> Result<Vec<DiscoveredShell>, ShellDiscoveryError> {
        let mut shells = Vec::new();
        let mut ids = HashSet::new();

        if let Some(command) = detect_cmd() {
            shells.push(shell(
                unique_shell_id("cmd", &mut ids),
                "CMD",
                command,
                Vec::new(),
                "cmd",
            )?);
        }
        if let Some(command) = detect_powershell() {
            shells.push(shell(
                unique_shell_id("powershell", &mut ids),
                "Windows PowerShell",
                command,
                vec!["-NoLogo".to_owned()],
                "powershell",
            )?);
        }
        if let Some(command) = detect_pwsh() {
            shells.push(shell(
                unique_shell_id("pwsh", &mut ids),
                "PowerShell 7",
                command,
                vec!["-NoLogo".to_owned()],
                "pwsh",
            )?);
        }

        if let Some(wsl) = system_executable("wsl.exe") {
            let distros = discover_wsl_distros(&wsl);
            if shells.len().saturating_add(distros.len()) > MAX_DISCOVERED_SHELLS {
                return Err(ShellDiscoveryError::InventoryTooLarge {
                    maximum_entries: MAX_DISCOVERED_SHELLS,
                });
            }
            for distro in distros {
                let id = unique_shell_id(&format!("wsl-{distro}"), &mut ids);
                shells.push(shell(
                    id,
                    format!("{distro} (WSL)"),
                    path_string(&wsl)?,
                    vec!["-d".to_owned(), distro.clone()],
                    wsl_icon(&distro),
                )?);
            }
        }

        if let Some(command) = detect_git_bash() {
            shells.push(shell(
                unique_shell_id("git-bash", &mut ids),
                "Git Bash",
                command,
                vec!["--login".to_owned(), "-i".to_owned()],
                "git-bash",
            )?);
        }
        if let Some(command) = detect_cygwin() {
            shells.push(shell(
                unique_shell_id("cygwin", &mut ids),
                "Cygwin",
                command,
                vec!["--login".to_owned(), "-i".to_owned()],
                "cygwin",
            )?);
        }

        if shells.is_empty() {
            // `cmd.exe` is part of supported Windows. Keeping a bare program
            // name here mirrors the legacy fallback and lets CreateProcess use
            // the protected system search order when ComSpec is unavailable.
            shells.push(shell(
                unique_shell_id("cmd", &mut ids),
                "CMD",
                "cmd.exe",
                Vec::new(),
                "cmd",
            )?);
        }
        mark_default_by_id(&mut shells, &["pwsh", "powershell", "cmd"]);
        Ok(shells)
    }

    fn detect_cmd() -> Option<String> {
        std::env::var_os("ComSpec")
            .map(PathBuf::from)
            .filter(|path| is_file(path))
            .and_then(|path| path.to_str().map(str::to_owned))
            .or_else(|| find_executable("cmd.exe"))
            .or_else(|| Some("cmd.exe".to_owned()))
    }

    fn detect_powershell() -> Option<String> {
        find_executable("powershell.exe").or_else(|| {
            system_root().and_then(|root| {
                checked_path(root.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
            })
        })
    }

    fn detect_pwsh() -> Option<String> {
        find_executable("pwsh.exe")
            .or_else(|| {
                registry_string(
                    HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe",
                    "",
                )
                .and_then(checked_path)
            })
            .or_else(|| {
                std::env::var_os("ProgramFiles")
                    .map(PathBuf::from)
                    .and_then(|root| checked_path(root.join("PowerShell/7/pwsh.exe")))
            })
    }

    fn detect_git_bash() -> Option<String> {
        registry_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\GitForWindows", "InstallPath")
            .and_then(|root| checked_path(PathBuf::from(root).join("bin/bash.exe")))
            .or_else(|| {
                ["ProgramFiles", "ProgramFiles(x86)"]
                    .into_iter()
                    .filter_map(std::env::var_os)
                    .map(PathBuf::from)
                    .find_map(|root| checked_path(root.join("Git/bin/bash.exe")))
            })
    }

    fn detect_cygwin() -> Option<String> {
        registry_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Cygwin\setup", "rootdir")
            .or_else(|| {
                registry_string(
                    HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WOW6432Node\Cygwin\setup",
                    "rootdir",
                )
            })
            .and_then(|root| checked_path(PathBuf::from(root).join("bin/bash.exe")))
            .or_else(|| checked_path(PathBuf::from(r"C:\cygwin64\bin\bash.exe")))
    }

    fn system_executable(name: &str) -> Option<PathBuf> {
        system_root()
            .map(|root| root.join("System32").join(name))
            .filter(|path| is_file(path))
    }

    fn system_root() -> Option<PathBuf> {
        std::env::var_os("SystemRoot").map(PathBuf::from)
    }

    fn find_executable(name: &str) -> Option<String> {
        let local_windows_apps = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Microsoft/WindowsApps"));
        let paths = std::env::var_os("PATH")?;
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join(name);
            if !is_file(&candidate)
                || is_windows_app_alias(&candidate, local_windows_apps.as_deref())
            {
                continue;
            }
            if let Some(value) = candidate.to_str() {
                return Some(value.to_owned());
            }
        }
        None
    }

    fn is_windows_app_alias(path: &Path, windows_apps: Option<&Path>) -> bool {
        let Some(windows_apps) = windows_apps else {
            return false;
        };
        path.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&format!(
                "{}\\",
                windows_apps.to_string_lossy().to_ascii_lowercase()
            ))
    }

    fn checked_path(path: impl Into<PathBuf>) -> Option<String> {
        let path = path.into();
        is_file(&path)
            .then(|| path.to_str().map(str::to_owned))
            .flatten()
    }

    fn path_string(path: &Path) -> Result<String, ShellDiscoveryError> {
        path.to_str()
            .map(str::to_owned)
            .ok_or(ShellDiscoveryError::InvalidField {
                field: crate::ShellField::Command,
                maximum_bytes: crate::model::MAX_SHELL_COMMAND_BYTES,
            })
    }

    fn is_file(path: &Path) -> bool {
        fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    fn registry_string(root: HKEY, path: &str, name: &str) -> Option<String> {
        RegKey::predef(root)
            .open_subkey(path)
            .ok()?
            .get_value::<String, _>(name)
            .ok()
            .filter(|value| !value.is_empty())
    }

    fn discover_wsl_distros(wsl: &Path) -> Vec<String> {
        let from_command = run_bounded_output(wsl, &["-l", "-q"])
            .and_then(|bytes| decode_wsl_output(&bytes))
            .map(parse_distro_lines)
            .unwrap_or_default();
        if !from_command.is_empty() {
            return from_command;
        }
        registry_wsl_distros()
    }

    fn parse_distro_lines(value: String) -> Vec<String> {
        let mut seen = HashSet::new();
        value
            .lines()
            .map(|line| line.trim_matches(['\r', '\0', ' ']).to_owned())
            .filter(|line| {
                !line.is_empty()
                    && line.len() <= 256
                    && !line.contains(['\0', '\r', '\n'])
                    && seen.insert(line.clone())
            })
            .collect()
    }

    fn registry_wsl_distros() -> Vec<String> {
        let Ok(lxss) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Lxss")
        else {
            return Vec::new();
        };
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        for key_name in lxss.enum_keys().flatten().take(MAX_DISCOVERED_SHELLS + 1) {
            let Ok(key) = lxss.open_subkey(key_name) else {
                continue;
            };
            let Ok(name) = key.get_value::<String, _>("DistributionName") else {
                continue;
            };
            if !name.is_empty()
                && name.len() <= 256
                && !name.contains(['\0', '\r', '\n'])
                && seen.insert(name.clone())
            {
                values.push(name);
            }
        }
        values
    }

    fn run_bounded_output(program: &Path, args: &[&str]) -> Option<Vec<u8>> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().ok()?;
        let stdout = child.stdout.take()?;
        let reader = thread::Builder::new()
            .name("netcatty-shell-discovery".to_owned())
            .spawn(move || {
                let mut bytes = Vec::new();
                stdout
                    .take((MAX_DISCOVERY_OUTPUT_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .ok()?;
                Some(bytes)
            })
            .ok()?;

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().ok()? {
                break status;
            }
            if started.elapsed() >= DISCOVERY_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            let _ = reader.join();
            return None;
        }
        let bytes = reader.join().ok().flatten()?;
        (bytes.len() <= MAX_DISCOVERY_OUTPUT_BYTES).then_some(bytes)
    }

    fn decode_wsl_output(bytes: &[u8]) -> Option<String> {
        if bytes.contains(&0) {
            if !bytes.len().is_multiple_of(2) {
                return None;
            }
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units).ok()
        } else {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn wsl_output_accepts_utf8_and_utf16le() {
            assert_eq!(
                decode_wsl_output(b"Ubuntu\r\nDebian\r\n").as_deref(),
                Some("Ubuntu\r\nDebian\r\n")
            );
            let utf16 = "Ubuntu\r\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            assert_eq!(decode_wsl_output(&utf16).as_deref(), Some("Ubuntu\r\n"));
        }

        #[test]
        fn windows_default_priority_matches_legacy() {
            let mut shells = vec![
                shell("cmd".to_owned(), "CMD", "cmd.exe", vec![], "cmd").unwrap(),
                shell(
                    "powershell".to_owned(),
                    "Windows PowerShell",
                    "powershell.exe",
                    vec![],
                    "powershell",
                )
                .unwrap(),
                shell(
                    "pwsh".to_owned(),
                    "PowerShell 7",
                    "pwsh.exe",
                    vec![],
                    "pwsh",
                )
                .unwrap(),
            ];
            mark_default_by_id(&mut shells, &["pwsh", "powershell", "cmd"]);
            assert_eq!(
                shells.iter().find(|shell| shell.is_default()).unwrap().id(),
                "pwsh"
            );
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        collections::HashMap,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    use super::*;

    const MAX_ETC_SHELLS_BYTES: u64 = 1024 * 1024;

    pub(super) fn discover() -> Result<Vec<DiscoveredShell>, ShellDiscoveryError> {
        let env_shell = valid_shell_path(std::env::var_os("SHELL").map(PathBuf::from));
        let mut paths = read_etc_shells()?;
        if let Some(env_shell) = env_shell.as_ref() {
            let env_real = fs::canonicalize(env_shell).ok();
            let already_present = paths.iter().any(|path| {
                env_real
                    .as_ref()
                    .zip(fs::canonicalize(path).ok().as_ref())
                    .is_some_and(|(left, right)| left == right)
            });
            if !already_present {
                paths.insert(0, env_shell.clone());
            }
        }
        if paths.is_empty() {
            for fallback in ["/bin/zsh", "/bin/bash", "/bin/sh"] {
                if let Some(path) = valid_shell_path(Some(PathBuf::from(fallback))) {
                    paths.push(path);
                    break;
                }
            }
        }
        if paths.len() > MAX_DISCOVERED_SHELLS {
            return Err(ShellDiscoveryError::InventoryTooLarge {
                maximum_entries: MAX_DISCOVERED_SHELLS,
            });
        }

        let mut counts = HashMap::new();
        for path in &paths {
            if let Some(base) = path.file_name().and_then(|name| name.to_str()) {
                *counts.entry(base.to_owned()).or_insert(0usize) += 1;
            }
        }
        let env_real = env_shell
            .as_ref()
            .and_then(|path| fs::canonicalize(path).ok());
        let mut used_ids = HashSet::new();
        let mut shells = Vec::new();
        for path in paths {
            let Some(command) = path.to_str().map(str::to_owned) else {
                continue;
            };
            let Some(base) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let duplicated = counts.get(base).copied().unwrap_or_default() > 1;
            let raw_id = if duplicated {
                command.trim_start_matches('/').replace('/', "-")
            } else {
                base.to_owned()
            };
            let name = if duplicated {
                format!("{} ({command})", unix_shell_name(base))
            } else {
                unix_shell_name(base).to_owned()
            };
            let mut discovered = shell(
                unique_shell_id(&raw_id, &mut used_ids),
                name,
                command,
                unix_login_args(base),
                unix_shell_icon(base),
            )?;
            let is_default = env_real
                .as_ref()
                .zip(fs::canonicalize(&path).ok().as_ref())
                .is_some_and(|(left, right)| left == right);
            discovered.set_default(is_default);
            shells.push(discovered);
        }
        if !shells.iter().any(DiscoveredShell::is_default) && !shells.is_empty() {
            shells[0].set_default(true);
        }
        Ok(shells)
    }

    fn read_etc_shells() -> Result<Vec<PathBuf>, ShellDiscoveryError> {
        let path = Path::new("/etc/shells");
        let Ok(metadata) = fs::metadata(path) else {
            return Ok(Vec::new());
        };
        if metadata.len() > MAX_ETC_SHELLS_BYTES {
            return Err(ShellDiscoveryError::InventoryTooLarge {
                maximum_entries: MAX_DISCOVERED_SHELLS,
            });
        }
        let Ok(content) = fs::read_to_string(path) else {
            return Ok(Vec::new());
        };
        let mut seen = HashSet::new();
        let mut paths = Vec::new();
        for value in content.lines().map(str::trim) {
            if value.is_empty() || value.starts_with('#') || value.contains('\0') {
                continue;
            }
            let Some(path) = valid_shell_path(Some(PathBuf::from(value))) else {
                continue;
            };
            let Ok(real) = fs::canonicalize(&path) else {
                continue;
            };
            if seen.insert(real) {
                paths.push(path);
            }
            if paths.len() > MAX_DISCOVERED_SHELLS {
                return Err(ShellDiscoveryError::InventoryTooLarge {
                    maximum_entries: MAX_DISCOVERED_SHELLS,
                });
            }
        }
        Ok(paths)
    }

    fn valid_shell_path(path: Option<PathBuf>) -> Option<PathBuf> {
        let path = path?;
        if !path.is_absolute() {
            return None;
        }
        let metadata = fs::metadata(&path).ok()?;
        (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distro_icon_mapping_matches_legacy_names() {
        assert_eq!(wsl_icon("Ubuntu-24.04"), "ubuntu");
        assert_eq!(wsl_icon("openSUSE-Tumbleweed"), "opensuse");
        assert_eq!(wsl_icon("Custom"), "linux");
    }

    #[cfg(unix)]
    #[test]
    fn unix_shell_metadata_matches_legacy() {
        assert_eq!(unix_shell_name("zsh"), "Zsh");
        assert_eq!(unix_shell_icon("nu"), "nushell");
        assert_eq!(unix_login_args("bash"), ["-l"]);
        assert!(unix_login_args("nu").is_empty());
    }

    #[test]
    fn live_discovery_is_bounded_and_has_exactly_one_default() {
        let catalog = discover_shells().expect("discover local shells");
        assert!(!catalog.shells().is_empty());
        assert!(catalog.shells().len() <= MAX_DISCOVERED_SHELLS);
        assert_eq!(
            catalog
                .shells()
                .iter()
                .filter(|shell| shell.is_default())
                .count(),
            1
        );
    }
}
