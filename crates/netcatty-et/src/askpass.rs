use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

pub const ET_ASKPASS_HELPER_ENV: &str = "NETCATTY_ET_ASKPASS_HELPER";
pub const ET_ASKPASS_MAP_ENV: &str = "NETCATTY_ET_ASKPASS_MAP";

const MAP_MAGIC: &[u8; 8] = b"NCETAP01";
const MAX_MAP_BYTES: usize = 32 * 1_024;
const MAX_MAP_ENTRIES: usize = 16;
const MAX_MATCHER_BYTES: usize = 1_024;
const MAX_SECRET_FILE_NAME_BYTES: usize = 96;
const MAX_PROMPT_BYTES: usize = 4 * 1_024;
const MAX_ASKPASS_SECRET_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EtAskpassKind {
    Password = 1,
    Passphrase = 2,
}

impl EtAskpassKind {
    fn parse(value: u8) -> Result<Self, EtAskpassError> {
        match value {
            1 => Ok(Self::Password),
            2 => Ok(Self::Passphrase),
            _ => Err(EtAskpassError::InvalidMap),
        }
    }
}

struct EtAskpassEntry {
    kind: EtAskpassKind,
    matcher: String,
    secret_file_name: String,
}

/// Secret-free routing table for the native askpass helper.
///
/// Entries contain only prompt matchers and random, relative artifact names;
/// secret values are kept in separate private files.
#[derive(Default)]
pub struct EtAskpassMap {
    entries: Vec<EtAskpassEntry>,
}

impl EtAskpassMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn add_password(
        &mut self,
        user_host_matcher: &str,
        secret_file_name: &str,
    ) -> Result<(), EtAskpassError> {
        let matcher = normalize_matcher(user_host_matcher)?;
        let Some((username, hostname)) = matcher.split_once('@') else {
            return Err(EtAskpassError::InvalidEntry);
        };
        if username.is_empty()
            || hostname.is_empty()
            || hostname.contains('@')
            || matcher.chars().any(char::is_whitespace)
        {
            return Err(EtAskpassError::InvalidEntry);
        }
        self.add(EtAskpassKind::Password, matcher, secret_file_name)
    }

    pub fn add_passphrase(
        &mut self,
        private_key_file_name: &str,
        secret_file_name: &str,
    ) -> Result<(), EtAskpassError> {
        validate_relative_file_name(private_key_file_name)?;
        self.add(
            EtAskpassKind::Passphrase,
            normalize_matcher(private_key_file_name)?,
            secret_file_name,
        )
    }

    fn add(
        &mut self,
        kind: EtAskpassKind,
        matcher: String,
        secret_file_name: &str,
    ) -> Result<(), EtAskpassError> {
        validate_relative_file_name(secret_file_name)?;
        if self.entries.len() >= MAX_MAP_ENTRIES {
            return Err(EtAskpassError::TooManyEntries);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.kind == kind && entry.matcher == matcher)
        {
            return Err(EtAskpassError::InvalidEntry);
        }
        self.entries.push(EtAskpassEntry {
            kind,
            matcher,
            secret_file_name: secret_file_name.to_owned(),
        });
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EtAskpassError> {
        let count =
            u16::try_from(self.entries.len()).map_err(|_| EtAskpassError::TooManyEntries)?;
        let mut bytes = Vec::with_capacity(10 + self.entries.len() * 64);
        bytes.extend_from_slice(MAP_MAGIC);
        bytes.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            let matcher = entry.matcher.as_bytes();
            let matcher_length =
                u16::try_from(matcher.len()).map_err(|_| EtAskpassError::InvalidEntry)?;
            let file_name = entry.secret_file_name.as_bytes();
            let file_name_length =
                u8::try_from(file_name.len()).map_err(|_| EtAskpassError::InvalidEntry)?;
            bytes.push(entry.kind as u8);
            bytes.extend_from_slice(&matcher_length.to_be_bytes());
            bytes.extend_from_slice(matcher);
            bytes.push(file_name_length);
            bytes.extend_from_slice(file_name);
            if bytes.len() > MAX_MAP_BYTES {
                return Err(EtAskpassError::MapTooLarge);
            }
        }
        Ok(bytes)
    }
}

impl fmt::Debug for EtAskpassMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtAskpassMap")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtAskpassError {
    InvalidEntry,
    TooManyEntries,
    MapTooLarge,
    InvalidMap,
    InvalidPrompt,
    NoMatchingEntry,
    UnsafePath,
    SecretUnavailable,
    SecretNotRepresentable,
    OutputUnavailable,
}

impl fmt::Display for EtAskpassError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEntry => "invalid askpass entry",
            Self::TooManyEntries => "too many askpass entries",
            Self::MapTooLarge => "askpass map is too large",
            Self::InvalidMap => "invalid askpass map",
            Self::InvalidPrompt => "invalid askpass prompt",
            Self::NoMatchingEntry => "askpass prompt was not matched",
            Self::UnsafePath => "unsafe askpass artifact path",
            Self::SecretUnavailable => "askpass secret is unavailable",
            Self::SecretNotRepresentable => "askpass secret cannot be represented safely",
            Self::OutputUnavailable => "askpass output is unavailable",
        })
    }
}

impl std::error::Error for EtAskpassError {}

/// Runs the current desktop executable as a native askpass helper when the
/// private native environment flag is present. Normal desktop startup receives
/// `None`; helper invocations receive a redacted process exit code.
#[must_use]
pub fn run_askpass_helper_if_requested() -> Option<i32> {
    if env::var_os(ET_ASKPASS_HELPER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return None;
    }
    Some(match run_askpass_helper() {
        Ok(()) => 0,
        Err(_) => 1,
    })
}

fn run_askpass_helper() -> Result<(), EtAskpassError> {
    let map_path = env::var_os(ET_ASKPASS_MAP_ENV)
        .map(PathBuf::from)
        .ok_or(EtAskpassError::InvalidMap)?;
    let prompt = collect_prompt(env::args_os().skip(1))?;
    let entries = load_map(&map_path)?;
    let secret_file_name = select_entry(&entries, &prompt)?;
    let mut secret = read_secret_file(&map_path, secret_file_name)?;
    let result = write_secret(&secret);
    secret.zeroize();
    result
}

fn collect_prompt(arguments: impl Iterator<Item = OsString>) -> Result<String, EtAskpassError> {
    let mut prompt = String::new();
    for argument in arguments {
        let argument = argument
            .into_string()
            .map_err(|_| EtAskpassError::InvalidPrompt)?;
        if !prompt.is_empty() {
            prompt.push(' ');
        }
        prompt.push_str(&argument);
        if prompt.len() > MAX_PROMPT_BYTES {
            return Err(EtAskpassError::InvalidPrompt);
        }
    }
    normalize_prompt(&prompt)
}

fn write_secret(secret: &[u8]) -> Result<(), EtAskpassError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(secret)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.flush())
        .map_err(|_| EtAskpassError::OutputUnavailable)
}

fn load_map(path: &Path) -> Result<Vec<EtAskpassEntry>, EtAskpassError> {
    let bytes = read_bounded_regular_file(path, MAX_MAP_BYTES, EtAskpassError::InvalidMap)?;
    parse_map(&bytes)
}

fn parse_map(bytes: &[u8]) -> Result<Vec<EtAskpassEntry>, EtAskpassError> {
    if bytes.len() < MAP_MAGIC.len() + 2 || bytes.get(..MAP_MAGIC.len()) != Some(MAP_MAGIC) {
        return Err(EtAskpassError::InvalidMap);
    }
    let mut cursor = MAP_MAGIC.len();
    let count = usize::from(read_u16(bytes, &mut cursor)?);
    if count > MAX_MAP_ENTRIES {
        return Err(EtAskpassError::InvalidMap);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = EtAskpassKind::parse(read_u8(bytes, &mut cursor)?)?;
        let matcher_length = usize::from(read_u16(bytes, &mut cursor)?);
        if matcher_length == 0 || matcher_length > MAX_MATCHER_BYTES {
            return Err(EtAskpassError::InvalidMap);
        }
        let matcher = read_slice(bytes, &mut cursor, matcher_length)?;
        let matcher = std::str::from_utf8(matcher).map_err(|_| EtAskpassError::InvalidMap)?;
        let matcher = normalize_matcher(matcher).map_err(|_| EtAskpassError::InvalidMap)?;
        let file_name_length = usize::from(read_u8(bytes, &mut cursor)?);
        if file_name_length == 0 || file_name_length > MAX_SECRET_FILE_NAME_BYTES {
            return Err(EtAskpassError::InvalidMap);
        }
        let file_name = read_slice(bytes, &mut cursor, file_name_length)?;
        let secret_file_name = std::str::from_utf8(file_name)
            .map_err(|_| EtAskpassError::InvalidMap)?
            .to_owned();
        validate_relative_file_name(&secret_file_name).map_err(|_| EtAskpassError::InvalidMap)?;
        if kind == EtAskpassKind::Password {
            let Some((username, hostname)) = matcher.split_once('@') else {
                return Err(EtAskpassError::InvalidMap);
            };
            if username.is_empty()
                || hostname.is_empty()
                || hostname.contains('@')
                || matcher.chars().any(char::is_whitespace)
            {
                return Err(EtAskpassError::InvalidMap);
            }
        } else {
            validate_relative_file_name(&matcher).map_err(|_| EtAskpassError::InvalidMap)?;
        }
        if entries
            .iter()
            .any(|entry: &EtAskpassEntry| entry.kind == kind && entry.matcher == matcher)
        {
            return Err(EtAskpassError::InvalidMap);
        }
        entries.push(EtAskpassEntry {
            kind,
            matcher,
            secret_file_name,
        });
    }
    if cursor != bytes.len() {
        return Err(EtAskpassError::InvalidMap);
    }
    Ok(entries)
}

fn read_secret_file(
    map_path: &Path,
    file_name: &str,
) -> Result<Zeroizing<Vec<u8>>, EtAskpassError> {
    validate_relative_file_name(file_name)?;
    let map_parent = validated_direct_parent(map_path, EtAskpassError::UnsafePath)?;
    let secret_path = map_parent.join(file_name);
    let canonical_secret = validate_regular_direct_child(
        &secret_path,
        &map_parent,
        EtAskpassError::SecretUnavailable,
    )?;
    let bytes = read_bounded_open_file(
        &canonical_secret,
        MAX_ASKPASS_SECRET_BYTES,
        EtAskpassError::SecretUnavailable,
    )?;
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return Err(EtAskpassError::SecretNotRepresentable);
    }
    Ok(Zeroizing::new(bytes))
}

fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
    error: EtAskpassError,
) -> Result<Vec<u8>, EtAskpassError> {
    let parent = validated_direct_parent(path, error)?;
    let canonical = validate_regular_direct_child(path, &parent, error)?;
    read_bounded_open_file(&canonical, maximum, error)
}

fn read_bounded_open_file(
    path: &Path,
    maximum: usize,
    error: EtAskpassError,
) -> Result<Vec<u8>, EtAskpassError> {
    let file = File::open(path).map_err(|_| error)?;
    let metadata = file.metadata().map_err(|_| error)?;
    if !metadata.is_file() || is_reparse_point(&metadata) || metadata.len() > maximum as u64 {
        return Err(error);
    }
    let limit = u64::try_from(maximum).map_err(|_| error)?.saturating_add(1);
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    if bytes.len() > maximum {
        return Err(error);
    }
    Ok(bytes)
}

fn validated_direct_parent(path: &Path, error: EtAskpassError) -> Result<PathBuf, EtAskpassError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(error);
    }
    let parent = path.parent().ok_or(error)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| error)?;
    if !parent_metadata.is_dir() || is_reparse_point(&parent_metadata) {
        return Err(error);
    }
    let canonical_parent = fs::canonicalize(parent).map_err(|_| error)?;
    if canonical_parent != parent {
        return Err(error);
    }
    Ok(canonical_parent)
}

fn validate_regular_direct_child(
    path: &Path,
    canonical_parent: &Path,
    error: EtAskpassError,
) -> Result<PathBuf, EtAskpassError> {
    if path.parent() != Some(canonical_parent) {
        return Err(error);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(error);
    }
    let canonical = fs::canonicalize(path).map_err(|_| error)?;
    if canonical.parent() != Some(canonical_parent) || canonical != path {
        return Err(error);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn select_entry<'a>(
    entries: &'a [EtAskpassEntry],
    normalized_prompt: &str,
) -> Result<&'a str, EtAskpassError> {
    let kind = classify_prompt(normalized_prompt)?;
    let mut selected: Option<(&EtAskpassEntry, usize)> = None;
    let mut ambiguous = false;
    for entry in entries.iter().filter(|entry| entry.kind == kind) {
        if !contains_scoped_matcher(normalized_prompt, &entry.matcher) {
            continue;
        }
        let score = entry.matcher.len();
        match selected {
            Some((_, current_score)) if current_score > score => {}
            Some((current, current_score)) if current_score == score => {
                if current.secret_file_name != entry.secret_file_name {
                    ambiguous = true;
                }
            }
            _ => {
                selected = Some((entry, score));
                ambiguous = false;
            }
        }
    }
    if ambiguous {
        return Err(EtAskpassError::NoMatchingEntry);
    }
    selected
        .map(|(entry, _)| entry.secret_file_name.as_str())
        .ok_or(EtAskpassError::NoMatchingEntry)
}

fn classify_prompt(prompt: &str) -> Result<EtAskpassKind, EtAskpassError> {
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || contains_forbidden_prompt(prompt) {
        return Err(EtAskpassError::InvalidPrompt);
    }
    if contains_word(prompt, "passphrase") {
        return Ok(EtAskpassKind::Passphrase);
    }
    if contains_word(prompt, "password")
        || contains_word(prompt, "passwd")
        || prompt.contains("密码")
        || prompt.contains("口令")
    {
        return Ok(EtAskpassKind::Password);
    }
    Err(EtAskpassError::InvalidPrompt)
}

fn contains_forbidden_prompt(prompt: &str) -> bool {
    const PHRASES: &[&str] = &[
        "one-time",
        "one time",
        "one_time",
        "two-factor",
        "two factor",
        "multi-factor",
        "multi factor",
        "second factor",
        "confirm password",
        "confirm passphrase",
        "re-enter password",
        "re enter password",
        "reenter password",
        "verification",
        "passcode",
        "security code",
        "一次性",
        "验证码",
        "双因素",
        "多因素",
        "二次验证",
    ];
    if PHRASES.iter().any(|phrase| prompt.contains(phrase))
        || ["otp", "token", "pin", "mfa", "2fa", "duo", "edr"]
            .iter()
            .any(|word| contains_word(prompt, word))
    {
        return true;
    }
    let mentions_password = contains_word(prompt, "password") || contains_word(prompt, "passwd");
    mentions_password
        && (["second", "secondary", "additional", "another", "confirm"]
            .iter()
            .any(|word| contains_word(prompt, word))
            || prompt.contains("re-enter")
            || prompt.contains("re enter")
            || prompt.contains("reenter"))
}

fn contains_scoped_matcher(prompt: &str, matcher: &str) -> bool {
    prompt.match_indices(matcher).any(|(start, _)| {
        let end = start + matcher.len();
        let before = prompt[..start].chars().next_back();
        let after = prompt[end..].chars().next();
        !before.is_some_and(is_scope_character) && !after.is_some_and(is_scope_character)
    })
}

fn is_scope_character(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(character, '@' | '.' | '-' | '_' | ':' | '[' | ']' | '%')
}

fn contains_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(start, _)| {
        let end = start + word.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        !before.is_some_and(is_word_character) && !after.is_some_and(is_word_character)
    })
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

fn normalize_prompt(prompt: &str) -> Result<String, EtAskpassError> {
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.chars().any(char::is_control)
    {
        return Err(EtAskpassError::InvalidPrompt);
    }
    let normalized = prompt.to_lowercase();
    if normalized.len() > MAX_PROMPT_BYTES {
        return Err(EtAskpassError::InvalidPrompt);
    }
    Ok(normalized)
}

fn normalize_matcher(matcher: &str) -> Result<String, EtAskpassError> {
    if matcher.is_empty()
        || matcher.len() > MAX_MATCHER_BYTES
        || matcher.chars().any(char::is_control)
    {
        return Err(EtAskpassError::InvalidEntry);
    }
    let matcher = matcher.to_lowercase();
    if matcher.is_empty() || matcher.len() > MAX_MATCHER_BYTES {
        return Err(EtAskpassError::InvalidEntry);
    }
    Ok(matcher)
}

fn validate_relative_file_name(value: &str) -> Result<(), EtAskpassError> {
    if value.is_empty()
        || value.len() > MAX_SECRET_FILE_NAME_BYTES
        || value == "."
        || value == ".."
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(EtAskpassError::InvalidEntry);
    }
    Ok(())
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, EtAskpassError> {
    let value = *bytes.get(*cursor).ok_or(EtAskpassError::InvalidMap)?;
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, EtAskpassError> {
    let slice = read_slice(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], EtAskpassError> {
    let end = cursor
        .checked_add(length)
        .ok_or(EtAskpassError::InvalidMap)?;
    let slice = bytes.get(*cursor..end).ok_or(EtAskpassError::InvalidMap)?;
    *cursor = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_directory() -> PathBuf {
        let directory = env::temp_dir().join(format!("netcatty-et-askpass-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::canonicalize(directory).unwrap()
    }

    fn encode_raw(kind: EtAskpassKind, matcher: &str, file_name: &str) -> Vec<u8> {
        let mut bytes = Vec::from(MAP_MAGIC.as_slice());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(kind as u8);
        bytes.extend_from_slice(&(matcher.len() as u16).to_be_bytes());
        bytes.extend_from_slice(matcher.as_bytes());
        bytes.push(file_name.len() as u8);
        bytes.extend_from_slice(file_name.as_bytes());
        bytes
    }

    #[test]
    fn most_specific_scoped_password_match_wins() {
        let mut map = EtAskpassMap::new();
        map.add_password("alice@host", "short-secret").unwrap();
        map.add_password("alice@host.example", "long-secret")
            .unwrap();
        let entries = parse_map(&map.encode().unwrap()).unwrap();
        assert_eq!(
            select_entry(&entries, "alice@host.example's password:").unwrap(),
            "long-secret"
        );
        assert!(select_entry(&entries, "bob@host.example's password:").is_err());
    }

    #[test]
    fn prompt_kind_is_strict_and_second_factors_never_match() {
        let mut map = EtAskpassMap::new();
        map.add_password("alice@target.example", "password-secret")
            .unwrap();
        map.add_passphrase("identity-123", "passphrase-secret")
            .unwrap();
        let entries = parse_map(&map.encode().unwrap()).unwrap();

        assert_eq!(
            select_entry(&entries, "alice@target.example's password:").unwrap(),
            "password-secret"
        );
        assert_eq!(
            select_entry(&entries, "enter passphrase for key 'identity-123':").unwrap(),
            "passphrase-secret"
        );
        assert!(select_entry(&entries, "enter passphrase for key 'password-secret':").is_err());
        assert!(select_entry(&entries, "identity-123 password:").is_err());
        for prompt in [
            "alice@target.example OTP:",
            "alice@target.example one-time password:",
            "alice@target.example token:",
            "alice@target.example PIN:",
            "alice@target.example MFA password:",
            "alice@target.example 2FA password:",
            "alice@target.example verification code:",
            "alice@target.example passcode:",
            "alice@target.example second password:",
            "alice@target.example additional password:",
            "alice@target.example confirm password:",
            "Duo password for alice@target.example:",
        ] {
            let normalized = normalize_prompt(prompt).unwrap();
            assert!(select_entry(&entries, &normalized).is_err(), "{prompt}");
        }
    }

    #[test]
    fn traversal_oversize_and_debug_values_are_rejected_or_redacted() {
        let traversal = encode_raw(EtAskpassKind::Password, "alice@host", "../secret");
        assert_eq!(
            parse_map(&traversal).err().unwrap(),
            EtAskpassError::InvalidMap
        );
        assert_eq!(
            normalize_prompt(&"x".repeat(MAX_PROMPT_BYTES + 1)).unwrap_err(),
            EtAskpassError::InvalidPrompt
        );

        let sentinel = "matcher-sentinel-that-must-not-be-debugged";
        let mut map = EtAskpassMap::new();
        map.add_password(&format!("alice@{sentinel}"), "secret-file")
            .unwrap();
        let debug = format!("{map:?}");
        assert!(debug.contains("entry_count"));
        assert!(!debug.contains(sentinel));
        assert!(!format!("{:?}", EtAskpassError::InvalidMap).contains(sentinel));
    }

    #[test]
    fn bounded_file_reader_rejects_oversized_map() {
        let directory = test_directory();
        let map_path = directory.join("askpass.map");
        fs::write(&map_path, vec![0_u8; MAX_MAP_BYTES + 1]).unwrap();
        assert_eq!(
            load_map(&map_path).err().unwrap(),
            EtAskpassError::InvalidMap
        );
        fs::remove_file(map_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn secret_reader_rejects_line_delimiters() {
        let directory = test_directory();
        let map_path = directory.join("askpass.map");
        let secret_path = directory.join("secret-file");
        fs::write(&map_path, MAP_MAGIC).unwrap();
        fs::write(&secret_path, b"unsafe\nsecret").unwrap();
        assert_eq!(
            read_secret_file(&map_path, "secret-file").unwrap_err(),
            EtAskpassError::SecretNotRepresentable
        );
        fs::remove_file(secret_path).unwrap();
        fs::remove_file(map_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = test_directory();
        let map_path = directory.join("askpass.map");
        let secret_path = directory.join("real-secret");
        let link_path = directory.join("secret-link");
        fs::write(&map_path, MAP_MAGIC).unwrap();
        fs::write(&secret_path, b"secret").unwrap();
        symlink(&secret_path, &link_path).unwrap();
        assert_eq!(
            read_secret_file(&map_path, "secret-link").unwrap_err(),
            EtAskpassError::SecretUnavailable
        );
        fs::remove_file(link_path).unwrap();
        fs::remove_file(secret_path).unwrap();
        fs::remove_file(map_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn secret_reader_rejects_symlinks_when_supported() {
        use std::os::windows::fs::symlink_file;

        let directory = test_directory();
        let map_path = directory.join("askpass.map");
        let secret_path = directory.join("real-secret");
        let link_path = directory.join("secret-link");
        fs::write(&map_path, MAP_MAGIC).unwrap();
        fs::write(&secret_path, b"secret").unwrap();
        if symlink_file(&secret_path, &link_path).is_ok() {
            assert_eq!(
                read_secret_file(&map_path, "secret-link").unwrap_err(),
                EtAskpassError::SecretUnavailable
            );
            fs::remove_file(link_path).unwrap();
        }
        fs::remove_file(secret_path).unwrap();
        fs::remove_file(map_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
