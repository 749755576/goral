use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const PROMPT_TAIL_LIMIT: usize = 2_048;
pub const INPUT_CHUNK_LIMIT: usize = 64 * 1_024;
pub const LOGIN_VALUE_LIMIT: usize = 4 * 1_024;
pub const STARTUP_COMMAND_LIMIT: usize = 64 * 1_024;

/// Owned sensitive UTF-8 which is redacted from diagnostics and overwritten on drop.
pub struct SecretText(Vec<u8>);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Result<Self, AutoLoginError> {
        Self::with_limit(value.into(), LOGIN_VALUE_LIMIT)
    }

    pub fn startup_command(value: impl Into<String>) -> Result<Self, AutoLoginError> {
        Self::with_limit(value.into(), STARTUP_COMMAND_LIMIT)
    }

    fn with_limit(value: String, limit: usize) -> Result<Self, AutoLoginError> {
        if value.len() > limit {
            return Err(AutoLoginError::ValueTooLarge);
        }
        Ok(Self(value.into_bytes()))
    }

    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_str(&self) -> &str {
        // Construction only accepts String and internal mutations preserve UTF-8.
        std::str::from_utf8(&self.0).expect("SecretText invariant")
    }

    fn trim_ascii_and_unicode_whitespace(&mut self) {
        let trimmed = self.expose_str().trim().as_bytes().to_vec();
        wipe(&mut self.0);
        self.0 = trimmed;
    }

    fn append_carriage_return(mut self) -> Self {
        self.0.push(b'\r');
        self
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText([REDACTED])")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // Volatile stores and fences keep this best-effort wipe from being elided.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[derive(Debug)]
pub enum LoginValue {
    Absent,
    ExplicitEmpty,
    Present(SecretText),
}

impl LoginValue {
    pub fn present(value: impl Into<String>) -> Result<Self, AutoLoginError> {
        Ok(Self::Present(SecretText::new(value)?))
    }

    fn is_configured(&self) -> bool {
        !matches!(self, Self::Absent)
    }

    fn take_line(&mut self) -> Option<SecretText> {
        match std::mem::replace(self, Self::Absent) {
            Self::Absent => None,
            Self::ExplicitEmpty => Some(SecretText(Vec::new()).append_carriage_return()),
            Self::Present(value) => Some(value.append_carriage_return()),
        }
    }
}

#[derive(Debug)]
pub struct AutoLoginConfig {
    pub username: LoginValue,
    pub password: LoginValue,
    pub startup_command: Option<SecretText>,
    pub timeout: Duration,
}

impl Default for AutoLoginConfig {
    fn default() -> Self {
        Self {
            username: LoginValue::Absent,
            password: LoginValue::Absent,
            startup_command: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoLoginState {
    Active,
    Disabled,
    Completed,
    Cancelled,
    TimedOut,
    Faulted,
}

#[derive(Debug)]
pub enum AutoLoginAction {
    SendLine(SecretText),
    Completed { startup_command: Option<SecretText> },
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoLoginError {
    ValueTooLarge,
    InputChunkTooLarge,
}

impl fmt::Display for AutoLoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge => formatter.write_str("Telnet auto-login value exceeds its limit"),
            Self::InputChunkTooLarge => {
                formatter.write_str("Telnet auto-login input chunk exceeds its limit")
            }
        }
    }
}

impl std::error::Error for AutoLoginError {}

#[derive(Clone, Copy, Debug, Default)]
enum AnsiState {
    #[default]
    Text,
    Escape,
    Csi,
    Osc,
    OscEscape,
}

pub struct AutoLogin {
    username: LoginValue,
    password: LoginValue,
    startup_command: Option<SecretText>,
    timeout: Duration,
    started_at: Instant,
    tail: String,
    ansi_state: AnsiState,
    sent_wake: bool,
    sent_username: bool,
    sent_password: bool,
    state: AutoLoginState,
}

impl fmt::Debug for AutoLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutoLogin")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("startup_command", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl AutoLogin {
    pub fn new(config: AutoLoginConfig) -> Self {
        Self::new_at(config, Instant::now())
    }

    pub fn new_at(mut config: AutoLoginConfig, started_at: Instant) -> Self {
        if let LoginValue::Present(username) = &mut config.username {
            username.trim_ascii_and_unicode_whitespace();
        }
        let enabled = config.username.is_configured() || config.password.is_configured();
        Self {
            username: config.username,
            password: config.password,
            startup_command: config.startup_command,
            timeout: config.timeout,
            started_at,
            tail: String::with_capacity(PROMPT_TAIL_LIMIT),
            ansi_state: AnsiState::Text,
            sent_wake: false,
            sent_username: false,
            sent_password: false,
            state: if enabled {
                AutoLoginState::Active
            } else {
                AutoLoginState::Disabled
            },
        }
    }

    pub fn state(&self) -> AutoLoginState {
        self.state
    }

    pub fn handle_text(&mut self, text: &str) -> Result<Vec<AutoLoginAction>, AutoLoginError> {
        self.handle_text_at(text, Instant::now())
    }

    pub fn handle_text_at(
        &mut self,
        text: &str,
        now: Instant,
    ) -> Result<Vec<AutoLoginAction>, AutoLoginError> {
        if self.state != AutoLoginState::Active {
            return Ok(Vec::new());
        }
        if text.len() > INPUT_CHUNK_LIMIT {
            self.state = AutoLoginState::Faulted;
            return Err(AutoLoginError::InputChunkTooLarge);
        }
        if now.saturating_duration_since(self.started_at) > self.timeout {
            self.state = AutoLoginState::TimedOut;
            return Ok(vec![AutoLoginAction::TimedOut]);
        }

        self.push_text_without_ansi(text);
        let mut actions = Vec::with_capacity(2);

        if self.has_sent_credentials() && is_command_prompt(&self.tail) {
            self.complete(&mut actions);
            return Ok(actions);
        }

        if !self.sent_wake && is_continue_prompt(&self.tail) {
            self.sent_wake = true;
            actions.push(AutoLoginAction::SendLine(
                SecretText(Vec::new()).append_carriage_return(),
            ));
            return Ok(actions);
        }

        let username_prompt =
            is_username_prompt(&self.tail) || has_username_prompt_before_password(&self.tail);
        if !self.sent_username
            && (self.username.is_configured() || self.password.is_configured())
            && username_prompt
        {
            self.sent_username = true;
            let line = self
                .username
                .take_line()
                .unwrap_or_else(|| SecretText(Vec::new()).append_carriage_return());
            actions.push(AutoLoginAction::SendLine(line));
        }

        if self.state == AutoLoginState::Active
            && !self.sent_password
            && self.password.is_configured()
            && is_password_prompt(&self.tail)
        {
            self.sent_password = true;
            if let Some(line) = self.password.take_line() {
                actions.push(AutoLoginAction::SendLine(line));
            }
        }

        if self.has_sent_credentials() && is_command_prompt(&self.tail) {
            self.complete(&mut actions);
        }
        Ok(actions)
    }

    pub fn handle_user_input(&mut self) -> Vec<AutoLoginAction> {
        if self.state != AutoLoginState::Active {
            return Vec::new();
        }
        self.state = AutoLoginState::Cancelled;
        vec![AutoLoginAction::Cancelled]
    }

    fn has_sent_credentials(&self) -> bool {
        self.sent_username || self.sent_password
    }

    fn complete(&mut self, actions: &mut Vec<AutoLoginAction>) {
        if self.state != AutoLoginState::Active {
            return;
        }
        self.state = AutoLoginState::Completed;
        actions.push(AutoLoginAction::Completed {
            startup_command: self.startup_command.take(),
        });
    }

    fn push_text_without_ansi(&mut self, text: &str) {
        for ch in text.chars() {
            match self.ansi_state {
                AnsiState::Text if ch == '\u{1b}' => self.ansi_state = AnsiState::Escape,
                AnsiState::Text => push_bounded_char(&mut self.tail, normalize_cr(ch)),
                AnsiState::Escape if ch == '[' => self.ansi_state = AnsiState::Csi,
                AnsiState::Escape if ch == ']' => self.ansi_state = AnsiState::Osc,
                AnsiState::Escape => self.ansi_state = AnsiState::Text,
                AnsiState::Csi if ('@'..='~').contains(&ch) => self.ansi_state = AnsiState::Text,
                AnsiState::Csi => {}
                AnsiState::Osc if ch == '\u{7}' => self.ansi_state = AnsiState::Text,
                AnsiState::Osc if ch == '\u{1b}' => self.ansi_state = AnsiState::OscEscape,
                AnsiState::Osc => {}
                AnsiState::OscEscape if ch == '\\' => self.ansi_state = AnsiState::Text,
                AnsiState::OscEscape if ch == '\u{1b}' => {}
                AnsiState::OscEscape => self.ansi_state = AnsiState::Osc,
            }
        }
    }
}

fn normalize_cr(ch: char) -> char {
    if ch == '\r' { '\n' } else { ch }
}

fn push_bounded_char(tail: &mut String, ch: char) {
    tail.push(ch);
    if tail.len() <= PROMPT_TAIL_LIMIT {
        return;
    }
    let mut drain_to = tail.len() - PROMPT_TAIL_LIMIT;
    while !tail.is_char_boundary(drain_to) {
        drain_to += 1;
    }
    tail.drain(..drain_to);
}

fn prompt_lines(text: &str) -> impl DoubleEndedIterator<Item = &str> {
    text.split('\n').map(last_prompt_slice)
}

fn last_prompt_slice(line: &str) -> &str {
    let mut start = line.len().saturating_sub(320);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    &line[start..]
}

fn last_prompt_line(text: &str) -> &str {
    prompt_lines(text).next_back().unwrap_or_default()
}

fn prompt_core(line: &str) -> String {
    line.trim_end()
        .trim_end_matches([':', '：', '?', '？'])
        .trim_end()
        .to_lowercase()
}

fn is_last_login(line: &str) -> bool {
    let core = prompt_core(line);
    ["last login", "previous login"]
        .iter()
        .any(|value| core.ends_with(value))
}

fn ends_with_prompt_token(core: &str, token: &str) -> bool {
    let Some(prefix) = core.strip_suffix(token) else {
        return false;
    };
    prefix
        .chars()
        .next_back()
        .is_none_or(|ch| !ch.is_ascii_alphanumeric())
}

pub fn is_username_prompt(text: &str) -> bool {
    let line = last_prompt_line(text);
    if is_last_login(line) {
        return false;
    }
    let core = prompt_core(line);
    [
        "user name",
        "username",
        "login",
        "logon",
        "account",
        "userid",
        "user id",
        "user",
        "用户名",
        "帳號",
        "帐号",
        "账号",
        "登录",
        "登入",
    ]
    .iter()
    .any(|token| ends_with_prompt_token(&core, token))
}

pub fn is_password_prompt(text: &str) -> bool {
    let core = prompt_core(last_prompt_line(text));
    [
        "password",
        "passwd",
        "passcode",
        "passphrase",
        "pass phrase",
        "pin",
        "密码",
        "密碼",
        "口令",
    ]
    .iter()
    .any(|token| ends_with_prompt_token(&core, token))
}

pub fn is_continue_prompt(text: &str) -> bool {
    let line = prompt_core(last_prompt_line(text));
    let wake_verb = line.contains("press") || line.contains("hit");
    let wake_key = line.contains("return")
        || line.contains("enter")
        || line.contains("any key")
        || line.contains("space");
    wake_verb && wake_key
}

pub fn is_command_prompt(text: &str) -> bool {
    let line = last_prompt_line(text).trim_end();
    !line.is_empty()
        && line.len() <= 200
        && !is_last_login(line)
        && !is_username_prompt(line)
        && !is_password_prompt(line)
        && !is_continue_prompt(line)
        && matches!(line.chars().next_back(), Some('$' | '#' | '>'))
}

fn has_username_prompt_before_password(text: &str) -> bool {
    let lines: Vec<_> = prompt_lines(text).collect();
    let Some(password_index) = lines.iter().rposition(|line| is_password_prompt(line)) else {
        return false;
    };
    lines[..password_index]
        .iter()
        .any(|line| is_username_prompt(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(username: LoginValue, password: LoginValue) -> AutoLoginConfig {
        AutoLoginConfig {
            username,
            password,
            ..AutoLoginConfig::default()
        }
    }

    fn lines(actions: &[AutoLoginAction]) -> Vec<&str> {
        actions
            .iter()
            .filter_map(|action| match action {
                AutoLoginAction::SendLine(value) => Some(value.expose_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn split_ansi_prompts_send_credentials_once() {
        let mut login = AutoLogin::new(config(
            LoginValue::present(" admin ").unwrap(),
            LoginValue::present("secret").unwrap(),
        ));
        let mut first_actions = login.handle_text("\x1b[32mUser").unwrap();
        first_actions.extend(login.handle_text("name:\x1b[0m ").unwrap());
        assert_eq!(lines(&first_actions), ["admin\r"]);
        assert!(login.handle_text("\r\nPass").unwrap().is_empty());
        assert_eq!(lines(&login.handle_text("word: ").unwrap()), ["secret\r"]);
        assert!(login.handle_text("Password: ").unwrap().is_empty());
    }

    #[test]
    fn combined_prompts_preserve_username_then_password_order() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::present("secret").unwrap(),
        ));
        let actions = login.handle_text("Username: \r\nPassword: ").unwrap();
        assert_eq!(lines(&actions), ["admin\r", "secret\r"]);
    }

    #[test]
    fn absent_and_explicit_empty_values_have_distinct_behavior() {
        let mut password_only = AutoLogin::new(config(
            LoginValue::Absent,
            LoginValue::present("secret").unwrap(),
        ));
        assert_eq!(
            lines(&password_only.handle_text("Username: ").unwrap()),
            ["\r"]
        );
        assert_eq!(
            lines(&password_only.handle_text("\r\nPassword: ").unwrap()),
            ["secret\r"]
        );

        let mut empty =
            AutoLogin::new(config(LoginValue::ExplicitEmpty, LoginValue::ExplicitEmpty));
        assert_eq!(lines(&empty.handle_text("Username: ").unwrap()), ["\r"]);
        assert_eq!(lines(&empty.handle_text("\r\nPassword: ").unwrap()), ["\r"]);

        let disabled = AutoLogin::new(config(LoginValue::Absent, LoginValue::Absent));
        assert_eq!(disabled.state(), AutoLoginState::Disabled);
    }

    #[test]
    fn supports_kylin_and_chinese_prompts_without_colons() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("lybing").unwrap(),
            LoginValue::present("secret").unwrap(),
        ));
        assert_eq!(
            lines(
                &login
                    .handle_text("Kylin V10 SP1\r\nlybing-pc login")
                    .unwrap()
            ),
            ["lybing\r"]
        );
        assert_eq!(
            lines(&login.handle_text("\r\nInput Password").unwrap()),
            ["secret\r"]
        );

        let mut chinese = AutoLogin::new(config(
            LoginValue::present("管理员").unwrap(),
            LoginValue::ExplicitEmpty,
        ));
        assert_eq!(lines(&chinese.handle_text("用户名").unwrap()), ["管理员\r"]);
        assert_eq!(lines(&chinese.handle_text("\r\n密码").unwrap()), ["\r"]);
    }

    #[test]
    fn wake_prompts_are_sent_once() {
        for prompt in [
            "Press RETURN to get started.",
            "Press <ENTER> to continue",
            "Press [Enter] to continue",
            "Hit any key to begin",
            "Press Space",
        ] {
            let mut login = AutoLogin::new(config(
                LoginValue::present("admin").unwrap(),
                LoginValue::Absent,
            ));
            assert_eq!(lines(&login.handle_text(prompt).unwrap()), ["\r"]);
            assert!(login.handle_text(prompt).unwrap().is_empty());
        }
    }

    #[test]
    fn completion_returns_startup_command_exactly_once() {
        let mut cfg = config(LoginValue::present("admin").unwrap(), LoginValue::Absent);
        cfg.startup_command = Some(SecretText::startup_command("show version").unwrap());
        let mut login = AutoLogin::new(cfg);
        login.handle_text("login: ").unwrap();
        let actions = login.handle_text("\r\nrouter# ").unwrap();
        match actions.as_slice() {
            [
                AutoLoginAction::Completed {
                    startup_command: Some(command),
                },
            ] => assert_eq!(command.expose_str(), "show version"),
            other => panic!("unexpected actions: {other:?}"),
        }
        assert!(login.handle_text("\r\nrouter# ").unwrap().is_empty());
        assert_eq!(login.state(), AutoLoginState::Completed);
    }

    #[test]
    fn command_prompt_before_credentials_does_not_complete() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::Absent,
        ));
        assert!(login.handle_text("router# ").unwrap().is_empty());
        assert_eq!(login.state(), AutoLoginState::Active);
    }

    #[test]
    fn manual_input_permanently_cancels_once() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::present("secret").unwrap(),
        ));
        assert!(matches!(
            login.handle_user_input().as_slice(),
            [AutoLoginAction::Cancelled]
        ));
        assert!(login.handle_user_input().is_empty());
        assert!(login.handle_text("Username: ").unwrap().is_empty());
        assert_eq!(login.state(), AutoLoginState::Cancelled);
    }

    #[test]
    fn timeout_is_injectable_and_emitted_once() {
        let start = Instant::now();
        let mut cfg = config(LoginValue::present("admin").unwrap(), LoginValue::Absent);
        cfg.timeout = Duration::from_millis(10);
        let mut login = AutoLogin::new_at(cfg, start);
        assert!(
            login
                .handle_text_at("Username: ", start + Duration::from_millis(10))
                .unwrap()
                .iter()
                .any(|action| matches!(action, AutoLoginAction::SendLine(_)))
        );

        let mut cfg = config(LoginValue::present("admin").unwrap(), LoginValue::Absent);
        cfg.timeout = Duration::from_millis(10);
        let mut expired = AutoLogin::new_at(cfg, start);
        assert!(matches!(
            expired
                .handle_text_at("Username: ", start + Duration::from_millis(11))
                .unwrap()
                .as_slice(),
            [AutoLoginAction::TimedOut]
        ));
        assert!(
            expired
                .handle_text_at("Username: ", start + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn last_login_is_not_a_username_or_command_prompt() {
        assert!(!is_username_prompt("Last login:"));
        assert!(!is_username_prompt("Previous login:"));
        assert!(!is_command_prompt("Previous login:"));
    }

    #[test]
    fn safe_tail_and_input_have_hard_bounds() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::Absent,
        ));
        let prefix = "界".repeat(PROMPT_TAIL_LIMIT);
        let actions = login.handle_text(&(prefix + "\r\nUsername: ")).unwrap();
        assert_eq!(lines(&actions), ["admin\r"]);
        assert!(login.tail.len() <= PROMPT_TAIL_LIMIT);
        assert!(login.tail.is_char_boundary(0));

        let mut oversized = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::Absent,
        ));
        let error = oversized
            .handle_text(&"x".repeat(INPUT_CHUNK_LIMIT + 1))
            .unwrap_err();
        assert_eq!(error, AutoLoginError::InputChunkTooLarge);
        assert_eq!(oversized.state(), AutoLoginState::Faulted);
    }

    #[test]
    fn diagnostics_do_not_contain_secrets() {
        let secret = "never-print-this";
        let config = AutoLoginConfig {
            username: LoginValue::present(secret).unwrap(),
            password: LoginValue::present(secret).unwrap(),
            startup_command: Some(SecretText::startup_command(secret).unwrap()),
            timeout: DEFAULT_TIMEOUT,
        };
        assert!(!format!("{config:?}").contains(secret));
        let login = AutoLogin::new(config);
        assert!(!format!("{login:?}").contains(secret));
        assert!(!AutoLoginError::ValueTooLarge.to_string().contains(secret));
    }

    #[test]
    fn split_osc_sequences_are_stripped() {
        let mut login = AutoLogin::new(config(
            LoginValue::present("admin").unwrap(),
            LoginValue::Absent,
        ));
        assert!(login.handle_text("\x1b]0;secret title").unwrap().is_empty());
        assert_eq!(
            lines(&login.handle_text("\x1b\\Username: ").unwrap()),
            ["admin\r"]
        );
    }
}
