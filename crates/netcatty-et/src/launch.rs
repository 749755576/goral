use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt, fs,
    path::{Path, PathBuf},
};

use crate::{
    EtConfigError, EtConfigField, EtStartRequest, EtTarget, EtWindowSize,
    MAX_ENVIRONMENT_VALUE_BYTES, MAX_NATIVE_PATH_BYTES, MAX_SSH_OPTION_BYTES,
    MAX_SSH_OPTION_TOTAL_BYTES, MAX_SSH_OPTIONS, TrustedEtClient,
};

/// Native-only filesystem path. It has no serde implementation and its Debug
/// representation never reveals the path.
#[derive(Clone, Eq, PartialEq)]
pub struct NativePath(PathBuf);

impl NativePath {
    pub fn new(path: PathBuf) -> Result<Self, EtConfigError> {
        if !path.is_absolute() {
            return Err(EtConfigError::NativePathMustBeAbsolute);
        }
        let text = path.to_str().ok_or(EtConfigError::InvalidField {
            field: EtConfigField::NativePath,
            maximum_bytes: MAX_NATIVE_PATH_BYTES,
        })?;
        if text.is_empty()
            || text.len() > MAX_NATIVE_PATH_BYTES
            || text.chars().any(|character| character == '\0')
        {
            return Err(EtConfigError::InvalidField {
                field: EtConfigField::NativePath,
                maximum_bytes: MAX_NATIVE_PATH_BYTES,
            });
        }
        Ok(Self(path))
    }

    pub fn existing_file(path: PathBuf) -> Result<Self, EtConfigError> {
        let path = Self::new(path)?;
        if !fs::metadata(&path.0).is_ok_and(|metadata| metadata.is_file()) {
            return Err(EtConfigError::NativePathUnavailable);
        }
        Ok(path)
    }

    pub fn existing_directory(path: PathBuf) -> Result<Self, EtConfigError> {
        let path = Self::new(path)?;
        if !fs::metadata(&path.0).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(EtConfigError::NativePathUnavailable);
        }
        Ok(path)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    fn normalized(&self) -> &str {
        // `new` rejects non-Unicode paths.
        self.0.to_str().unwrap_or("")
    }
}

impl fmt::Debug for NativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePath([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtHostKeyChecking {
    Yes,
    AcceptNew,
    No,
}

/// Typed SSH options accepted by the ET launch planner. There is no arbitrary
/// string/command variant, and path-bearing variants require a native-only
/// [`NativePath`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EtSshOption {
    UserKnownHostsFile(NativePath),
    GlobalKnownHostsFile(NativePath),
    StrictHostKeyChecking(EtHostKeyChecking),
    DisableKnownHostsCommand,
    LogLevelError,
    IdentityFile(NativePath),
    CertificateFile(NativePath),
    IdentityAgent(NativePath),
    DisableIdentityAgent,
    IdentitiesOnly,
    DisablePublicKeyAuthentication,
    EnableKeyboardInteractive,
    PublicKeyAuthenticationOnly,
    OnePasswordPrompt,
}

impl EtSshOption {
    fn render(&self) -> String {
        match self {
            Self::UserKnownHostsFile(path) => {
                format!("UserKnownHostsFile={}", path.normalized())
            }
            Self::GlobalKnownHostsFile(path) => {
                format!("GlobalKnownHostsFile={}", path.normalized())
            }
            Self::StrictHostKeyChecking(value) => format!(
                "StrictHostKeyChecking={}",
                match value {
                    EtHostKeyChecking::Yes => "yes",
                    EtHostKeyChecking::AcceptNew => "accept-new",
                    EtHostKeyChecking::No => "no",
                }
            ),
            Self::DisableKnownHostsCommand => "KnownHostsCommand=none".to_owned(),
            Self::LogLevelError => "LogLevel=ERROR".to_owned(),
            Self::IdentityFile(path) => format!("IdentityFile={}", path.normalized()),
            Self::CertificateFile(path) => format!("CertificateFile={}", path.normalized()),
            Self::IdentityAgent(path) => format!("IdentityAgent={}", path.normalized()),
            Self::DisableIdentityAgent => "IdentityAgent=none".to_owned(),
            Self::IdentitiesOnly => "IdentitiesOnly=yes".to_owned(),
            Self::DisablePublicKeyAuthentication => "PubkeyAuthentication=no".to_owned(),
            Self::EnableKeyboardInteractive => "KbdInteractiveAuthentication=yes".to_owned(),
            Self::PublicKeyAuthenticationOnly => "PreferredAuthentications=publickey".to_owned(),
            Self::OnePasswordPrompt => "NumberOfPasswordPrompts=1".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NativeEnvironmentKey {
    Home,
    UserProfile,
    Path,
    SshAuthSock,
    SshAskpass,
    SshAskpassRequire,
    Display,
    AskpassMap,
    AskpassHelper,
}

impl NativeEnvironmentKey {
    const fn name(self) -> &'static str {
        match self {
            Self::Home => "HOME",
            Self::UserProfile => "USERPROFILE",
            Self::Path => "PATH",
            Self::SshAuthSock => "SSH_AUTH_SOCK",
            Self::SshAskpass => "SSH_ASKPASS",
            Self::SshAskpassRequire => "SSH_ASKPASS_REQUIRE",
            Self::Display => "DISPLAY",
            Self::AskpassMap => "NETCATTY_ET_ASKPASS_MAP",
            Self::AskpassHelper => "NETCATTY_ET_ASKPASS_HELPER",
        }
    }
}

/// Native-prepared, allowlisted process environment. Values may point at
/// native askpass/config artifacts, but no secret value is accepted directly.
#[derive(Clone, Default)]
pub struct EtNativeEnvironment {
    values: BTreeMap<NativeEnvironmentKey, OsString>,
}

impl EtNativeEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_home(&mut self, value: NativePath) {
        self.insert_path(NativeEnvironmentKey::Home, value);
    }

    pub fn set_user_profile(&mut self, value: NativePath) {
        self.insert_path(NativeEnvironmentKey::UserProfile, value);
    }

    pub fn set_ssh_auth_sock(&mut self, value: NativePath) {
        self.insert_path(NativeEnvironmentKey::SshAuthSock, value);
    }

    pub fn set_ssh_askpass(&mut self, value: NativePath) {
        self.insert_path(NativeEnvironmentKey::SshAskpass, value);
        self.values.insert(
            NativeEnvironmentKey::SshAskpassRequire,
            OsString::from("force"),
        );
    }

    pub fn set_askpass_map(&mut self, value: NativePath) {
        self.insert_path(NativeEnvironmentKey::AskpassMap, value);
    }

    pub fn enable_askpass_helper(&mut self) {
        self.values
            .insert(NativeEnvironmentKey::AskpassHelper, OsString::from("1"));
    }

    pub fn set_path(&mut self, value: OsString) -> Result<(), EtConfigError> {
        validate_environment_value(&value)?;
        self.values.insert(NativeEnvironmentKey::Path, value);
        Ok(())
    }

    pub fn set_display(&mut self, value: String) -> Result<(), EtConfigError> {
        validate_environment_value(OsStr::new(&value))?;
        self.values
            .insert(NativeEnvironmentKey::Display, OsString::from(value));
        Ok(())
    }

    fn insert_path(&mut self, key: NativeEnvironmentKey, value: NativePath) {
        self.values
            .insert(key, value.as_path().as_os_str().to_os_string());
    }

    fn pairs(&self) -> impl Iterator<Item = (&'static str, &OsStr)> {
        self.values
            .iter()
            .map(|(key, value)| (key.name(), value.as_os_str()))
    }
}

impl fmt::Debug for EtNativeEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<_> = self.values.keys().map(|key| key.name()).collect();
        formatter
            .debug_struct("EtNativeEnvironment")
            .field("keys", &keys)
            .finish()
    }
}

/// Fully native-resolved ET start configuration.
pub struct EtSessionConfig {
    client: TrustedEtClient,
    target: EtTarget,
    window_size: EtWindowSize,
    ssh_options: Vec<EtSshOption>,
    environment: EtNativeEnvironment,
    forwarding_socket: Option<NativePath>,
    cwd: NativePath,
}

impl EtSessionConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        request: EtStartRequest,
        target: EtTarget,
        client: TrustedEtClient,
        cwd: NativePath,
        ssh_options: Vec<EtSshOption>,
        environment: EtNativeEnvironment,
        forwarding_socket: Option<NativePath>,
    ) -> Result<Self, EtConfigError> {
        let window_size = request.validate()?;
        if request.host_id() != target.id() {
            return Err(EtConfigError::TargetMismatch);
        }
        validate_ssh_options(&ssh_options)?;
        if !cwd.as_path().is_dir() {
            return Err(EtConfigError::NativePathUnavailable);
        }
        Ok(Self {
            client,
            target,
            window_size,
            ssh_options,
            environment,
            forwarding_socket,
            cwd,
        })
    }

    pub const fn window_size(&self) -> EtWindowSize {
        self.window_size
    }

    pub fn target(&self) -> &EtTarget {
        &self.target
    }

    pub fn into_launch_spec(self) -> EtLaunchSpec {
        let endpoint = self.target.endpoint();
        let mut arguments = Vec::new();
        if endpoint.et_port() != 2022 {
            arguments.push(OsString::from("-p"));
            arguments.push(OsString::from(endpoint.et_port().to_string()));
        }
        if let Some(socket) = self.forwarding_socket {
            arguments.push(OsString::from("-f"));
            arguments.push(OsString::from("--ssh-socket"));
            arguments.push(socket.as_path().as_os_str().to_os_string());
        }
        if endpoint.ssh_port() != 22 {
            push_ssh_option(&mut arguments, format!("Port={}", endpoint.ssh_port()));
        }
        for option in &self.ssh_options {
            push_ssh_option(&mut arguments, option.render());
        }
        if let Some(jump) = self.target.jump_host() {
            arguments.push(OsString::from("--jumphost"));
            arguments.push(OsString::from(jump.endpoint().user_host()));
            arguments.push(OsString::from("--jport"));
            arguments.push(OsString::from(jump.endpoint().et_port().to_string()));
        }
        arguments.push(OsString::from(endpoint.user_host()));

        let mut environment = BTreeMap::new();
        environment.insert(OsString::from("TERM"), OsString::from("xterm-256color"));
        environment.insert(OsString::from("COLORTERM"), OsString::from("truecolor"));
        environment.insert(OsString::from("ET_NO_TELEMETRY"), OsString::from("1"));
        for (key, value) in self.environment.pairs() {
            environment.insert(OsString::from(key), value.to_os_string());
        }

        EtLaunchSpec {
            executable: self.client.path().to_path_buf(),
            arguments,
            environment,
            cwd: self.cwd.0,
            window_size: self.window_size,
        }
    }
}

impl fmt::Debug for EtSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtSessionConfig")
            .field("client", &self.client)
            .field("target", &self.target)
            .field("window_size", &self.window_size)
            .field("ssh_option_count", &self.ssh_options.len())
            .field("environment", &self.environment)
            .field(
                "forwarding_socket",
                &self.forwarding_socket.as_ref().map(|_| "[redacted]"),
            )
            .field("cwd", &"[redacted]")
            .finish()
    }
}

pub struct EtLaunchSpec {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    cwd: PathBuf,
    window_size: EtWindowSize,
}

impl EtLaunchSpec {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }

    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub const fn window_size(&self) -> EtWindowSize {
        self.window_size
    }
}

impl fmt::Debug for EtLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let environment_keys: Vec<_> = self.environment.keys().collect();
        formatter
            .debug_struct("EtLaunchSpec")
            .field("executable", &"[redacted bundled resource path]")
            .field("argument_count", &self.arguments.len())
            .field("environment_keys", &environment_keys)
            .field("cwd", &"[redacted]")
            .field("window_size", &self.window_size)
            .finish()
    }
}

fn push_ssh_option(arguments: &mut Vec<OsString>, value: String) {
    arguments.push(OsString::from("--ssh-option"));
    arguments.push(OsString::from(value));
}

fn validate_ssh_options(options: &[EtSshOption]) -> Result<(), EtConfigError> {
    if options.len() > MAX_SSH_OPTIONS {
        return Err(EtConfigError::TooManySshOptions {
            maximum: MAX_SSH_OPTIONS,
        });
    }
    let mut total = 0usize;
    for option in options {
        let rendered = option.render();
        if rendered.is_empty() || rendered.len() > MAX_SSH_OPTION_BYTES {
            return Err(EtConfigError::InvalidField {
                field: EtConfigField::SshOption,
                maximum_bytes: MAX_SSH_OPTION_BYTES,
            });
        }
        total = total.saturating_add(rendered.len());
    }
    if total > MAX_SSH_OPTION_TOTAL_BYTES {
        return Err(EtConfigError::SshOptionsTooLarge {
            maximum_bytes: MAX_SSH_OPTION_TOTAL_BYTES,
        });
    }
    Ok(())
}

fn validate_environment_value(value: &OsStr) -> Result<(), EtConfigError> {
    let text = value.to_str().ok_or(EtConfigError::InvalidField {
        field: EtConfigField::Environment,
        maximum_bytes: MAX_ENVIRONMENT_VALUE_BYTES,
    })?;
    if text.len() > MAX_ENVIRONMENT_VALUE_BYTES || text.contains('\0') {
        return Err(EtConfigError::InvalidField {
            field: EtConfigField::Environment,
            maximum_bytes: MAX_ENVIRONMENT_VALUE_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EtArchitecture, EtClientResolver, EtEndpoint, EtJumpHost, EtPlatform};
    use uuid::Uuid;

    fn client() -> (TrustedEtClient, PathBuf) {
        let root = std::env::temp_dir().join(format!("netcatty-et-launch-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("et")).unwrap();
        let platform = EtPlatform::current().unwrap();
        let path = root.join("et").join(if platform == EtPlatform::Windows {
            "et.exe"
        } else {
            "et"
        });
        fs::write(&path, b"test").unwrap();
        #[cfg(unix)]
        if platform != EtPlatform::Windows {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let client = EtClientResolver::new(root.clone())
            .resolve_for(platform, EtArchitecture::X86_64)
            .unwrap();
        (client, root)
    }

    #[test]
    fn launch_spec_uses_direct_argv_and_fixed_environment() {
        let (client, root) = client();
        let target = EtTarget::new(
            "host-1".into(),
            EtEndpoint::new("target.example".into(), "alice".into(), 2222, 9022).unwrap(),
            vec![EtJumpHost::new(
                EtEndpoint::new("jump.example".into(), "ops".into(), 22, 3033).unwrap(),
            )],
        )
        .unwrap();
        let config = EtSessionConfig::resolve(
            EtStartRequest::new("host-1".into(), 120, 32),
            target,
            client,
            NativePath::existing_directory(root.clone()).unwrap(),
            vec![
                EtSshOption::StrictHostKeyChecking(EtHostKeyChecking::AcceptNew),
                EtSshOption::LogLevelError,
                EtSshOption::PublicKeyAuthenticationOnly,
            ],
            EtNativeEnvironment::new(),
            None,
        )
        .unwrap();
        let spec = config.into_launch_spec();
        let args: Vec<_> = spec
            .arguments()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-p",
                "9022",
                "--ssh-option",
                "Port=2222",
                "--ssh-option",
                "StrictHostKeyChecking=accept-new",
                "--ssh-option",
                "LogLevel=ERROR",
                "--ssh-option",
                "PreferredAuthentications=publickey",
                "--jumphost",
                "ops@jump.example",
                "--jport",
                "3033",
                "alice@target.example",
            ]
        );
        assert_eq!(
            spec.environment().get(OsStr::new("TERM")).unwrap(),
            "xterm-256color"
        );
        assert_eq!(
            spec.environment()
                .get(OsStr::new("ET_NO_TELEMETRY"))
                .unwrap(),
            "1"
        );
        let debug = format!("{spec:?}");
        assert!(!debug.contains("target.example"));
        assert!(!debug.contains(root.to_string_lossy().as_ref()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn renderer_id_must_match_the_native_target() {
        let (client, root) = client();
        let target = EtTarget::new(
            "host-a".into(),
            EtEndpoint::new("target".into(), "alice".into(), 22, 2022).unwrap(),
            vec![],
        )
        .unwrap();
        let result = EtSessionConfig::resolve(
            EtStartRequest::new("host-b".into(), 80, 24),
            target,
            client,
            NativePath::existing_directory(root.clone()).unwrap(),
            vec![],
            EtNativeEnvironment::new(),
            None,
        );
        assert!(matches!(result, Err(EtConfigError::TargetMismatch)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_environment_debug_redacts_values() {
        let mut environment = EtNativeEnvironment::new();
        environment
            .set_display("secret-looking-display-value".into())
            .unwrap();
        let debug = format!("{environment:?}");
        assert!(debug.contains("DISPLAY"));
        assert!(!debug.contains("secret-looking"));
    }
}
