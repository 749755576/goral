use std::{error::Error, fmt, mem};

use crate::protocol::{command, is_option_command, option, suboption};

/// Maximum application input accepted by one codec operation.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Maximum retained, decoded payload for one Telnet subnegotiation.
pub const MAX_SUBNEGOTIATION_BYTES: usize = 64 * 1024;
/// Maximum terminal width or height accepted by NAWS.
pub const MAX_WINDOW_DIMENSION: u32 = 10_000;
/// Default terminal type advertised through RFC 1091.
pub const DEFAULT_TERMINAL_TYPE: &str = "XTERM-256COLOR";
const MAX_TERMINAL_TYPE_BYTES: usize = 255;

/// A validated terminal size suitable for the two-byte RFC 1073 fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowSize {
    columns: u16,
    rows: u16,
}

impl WindowSize {
    pub const DEFAULT: Self = Self {
        columns: 80,
        rows: 24,
    };

    pub fn new(columns: u32, rows: u32) -> Result<Self, CodecError> {
        if columns == 0
            || rows == 0
            || columns > MAX_WINDOW_DIMENSION
            || rows > MAX_WINDOW_DIMENSION
        {
            return Err(CodecError::InvalidWindowSize {
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

impl Default for WindowSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Configuration retained by one codec/session.
#[derive(Clone, Eq, PartialEq)]
pub struct TelnetConfig {
    terminal_type: String,
    window_size: WindowSize,
}

impl TelnetConfig {
    pub fn with_terminal_type(
        mut self,
        terminal_type: impl AsRef<str>,
    ) -> Result<Self, CodecError> {
        let terminal_type = terminal_type.as_ref();
        if terminal_type.is_empty()
            || terminal_type.len() > MAX_TERMINAL_TYPE_BYTES
            || !terminal_type
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(CodecError::InvalidTerminalType {
                maximum_bytes: MAX_TERMINAL_TYPE_BYTES,
            });
        }
        self.terminal_type.clear();
        self.terminal_type.push_str(terminal_type);
        Ok(self)
    }

    pub fn with_window_size(mut self, window_size: WindowSize) -> Self {
        self.window_size = window_size;
        self
    }

    pub fn terminal_type(&self) -> &str {
        &self.terminal_type
    }

    pub const fn window_size(&self) -> WindowSize {
        self.window_size
    }
}

impl Default for TelnetConfig {
    fn default() -> Self {
        Self {
            terminal_type: DEFAULT_TERMINAL_TYPE.to_owned(),
            window_size: WindowSize::DEFAULT,
        }
    }
}

impl fmt::Debug for TelnetConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetConfig")
            .field("terminal_type_bytes", &self.terminal_type.len())
            .field("window_size", &self.window_size)
            .finish()
    }
}

/// Bounded protocol errors. Neither `Display` nor `Debug` contains input data.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CodecError {
    InputTooLarge { maximum_bytes: usize },
    SubnegotiationTooLarge { maximum_bytes: usize },
    InvalidWindowSize { maximum: u32 },
    InvalidTerminalType { maximum_bytes: usize },
    Poisoned,
}

impl fmt::Debug for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { maximum_bytes } => {
                write!(formatter, "Telnet input exceeds {maximum_bytes} bytes")
            }
            Self::SubnegotiationTooLarge { maximum_bytes } => write!(
                formatter,
                "Telnet subnegotiation exceeds {maximum_bytes} bytes"
            ),
            Self::InvalidWindowSize { maximum } => write!(
                formatter,
                "Telnet window dimensions must be between 1 and {maximum}"
            ),
            Self::InvalidTerminalType { maximum_bytes } => write!(
                formatter,
                "Telnet terminal type must be printable ASCII up to {maximum_bytes} bytes"
            ),
            Self::Poisoned => {
                formatter.write_str("Telnet codec is unavailable after a fatal error")
            }
        }
    }
}

impl Error for CodecError {}

/// Byte storage whose diagnostic representation reports only its length.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct TelnetBytes(Vec<u8>);

impl TelnetBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for TelnetBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for TelnetBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetBytes")
            .field("bytes", &self.len())
            .finish()
    }
}

impl From<Vec<u8>> for TelnetBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Renderer/runtime-relevant protocol state changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelnetEvent {
    ProtocolActivated,
    RemoteEchoChanged { enabled: bool },
    LocalEchoChanged { enabled: bool },
}

/// The application bytes, required wire replies, and state events produced by
/// one remote frame.
#[derive(Default, Eq, PartialEq)]
pub struct DecodeResult {
    application_data: TelnetBytes,
    outbound: TelnetBytes,
    events: Vec<TelnetEvent>,
}

impl DecodeResult {
    pub fn application_data(&self) -> &[u8] {
        self.application_data.as_slice()
    }

    pub fn outbound(&self) -> &[u8] {
        self.outbound.as_slice()
    }

    pub fn events(&self) -> &[TelnetEvent] {
        &self.events
    }

    pub fn into_parts(self) -> (TelnetBytes, TelnetBytes, Vec<TelnetEvent>) {
        (self.application_data, self.outbound, self.events)
    }
}

impl fmt::Debug for DecodeResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeResult")
            .field("application_bytes", &self.application_data.len())
            .field("outbound_bytes", &self.outbound.len())
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Clone, Copy, Default)]
struct OptionState {
    enabled: bool,
    pending_enable: bool,
    rejection_sent: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ParseState {
    #[default]
    Data,
    Iac,
    Option(u8),
    SubnegotiationOption,
    SubnegotiationData(u8),
    SubnegotiationIac(u8),
}

/// Stateful RFC 854 parser and option negotiator.
///
/// It stays in raw receive mode until the peer sends its first IAC byte. At
/// that point it emits the legacy Netcatty client offer (DO SGA, WILL TTYPE,
/// WILL NAWS) and parses commands across arbitrary TCP frame boundaries.
pub struct TelnetCodec {
    config: TelnetConfig,
    active: bool,
    poisoned: bool,
    parse_state: ParseState,
    subnegotiation: Vec<u8>,
    local_options: [OptionState; 256],
    remote_options: [OptionState; 256],
    remote_echo: bool,
    remote_echo_known: bool,
    local_echo: bool,
}

impl TelnetCodec {
    pub fn new(config: TelnetConfig) -> Self {
        Self {
            config,
            active: false,
            poisoned: false,
            parse_state: ParseState::Data,
            subnegotiation: Vec::new(),
            local_options: [OptionState::default(); 256],
            remote_options: [OptionState::default(); 256],
            remote_echo: true,
            remote_echo_known: false,
            local_echo: false,
        }
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn window_size(&self) -> WindowSize {
        self.config.window_size
    }

    pub const fn remote_echo(&self) -> bool {
        self.remote_echo
    }

    pub const fn local_echo(&self) -> bool {
        self.local_echo
    }

    /// Decode one remote frame and produce application bytes plus any replies
    /// that must be written before the next read.
    pub fn receive(&mut self, input: &[u8]) -> Result<DecodeResult, CodecError> {
        self.ensure_available()?;
        check_input_size(input)?;

        let mut result = DecodeResult::default();
        let mut cursor = 0;
        if !self.active {
            let Some(iac_at) = input.iter().position(|byte| *byte == command::IAC) else {
                result.application_data.0.extend_from_slice(input);
                return Ok(result);
            };
            result
                .application_data
                .0
                .extend_from_slice(&input[..iac_at]);
            self.active = true;
            result.events.push(TelnetEvent::ProtocolActivated);
            self.start_negotiation(&mut result.outbound.0);
            cursor = iac_at;
        }

        while cursor < input.len() {
            let byte = input[cursor];
            cursor += 1;
            match self.parse_state {
                ParseState::Data => {
                    if byte == command::IAC {
                        self.parse_state = ParseState::Iac;
                    } else {
                        result.application_data.0.push(byte);
                    }
                }
                ParseState::Iac => {
                    if byte == command::IAC {
                        result.application_data.0.push(command::IAC);
                        self.parse_state = ParseState::Data;
                    } else if is_option_command(byte) {
                        self.parse_state = ParseState::Option(byte);
                    } else if byte == command::SB {
                        self.parse_state = ParseState::SubnegotiationOption;
                    } else {
                        self.parse_state = ParseState::Data;
                    }
                }
                ParseState::Option(verb) => {
                    self.handle_option(verb, byte, &mut result.outbound.0, &mut result.events);
                    self.parse_state = ParseState::Data;
                }
                ParseState::SubnegotiationOption => {
                    self.subnegotiation.clear();
                    self.parse_state = ParseState::SubnegotiationData(byte);
                }
                ParseState::SubnegotiationData(selected_option) => {
                    if byte == command::IAC {
                        self.parse_state = ParseState::SubnegotiationIac(selected_option);
                    } else {
                        self.push_subnegotiation(byte)?;
                    }
                }
                ParseState::SubnegotiationIac(selected_option) => {
                    if byte == command::SE {
                        let payload = mem::take(&mut self.subnegotiation);
                        self.handle_subnegotiation(
                            selected_option,
                            &payload,
                            &mut result.outbound.0,
                        );
                        self.parse_state = ParseState::Data;
                    } else if byte == command::IAC {
                        self.push_subnegotiation(command::IAC)?;
                        self.parse_state = ParseState::SubnegotiationData(selected_option);
                    } else {
                        // Ignore an embedded IAC command pair, matching the
                        // tolerant legacy parser without retaining its bytes.
                        self.parse_state = ParseState::SubnegotiationData(selected_option);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Apply NVT CR/LF conversion and, once Telnet is active, escape every
    /// literal IAC as IAC IAC.
    pub fn encode_input(&self, input: &[u8]) -> Result<TelnetBytes, CodecError> {
        self.ensure_available()?;
        check_input_size(input)?;
        let normalized = normalize_nvt_newlines(input);
        if !self.active || !normalized.contains(&command::IAC) {
            return Ok(normalized.into());
        }
        Ok(escape_iac(&normalized).into())
    }

    /// Update the retained terminal size. The returned bytes are empty until
    /// the protocol is active and the peer has enabled NAWS.
    pub fn resize(&mut self, columns: u32, rows: u32) -> Result<TelnetBytes, CodecError> {
        self.ensure_available()?;
        self.config.window_size = WindowSize::new(columns, rows)?;
        let mut outbound = Vec::new();
        self.append_naws_if_enabled(&mut outbound);
        Ok(outbound.into())
    }

    /// Reset all negotiated and partial-frame state for a reconnect while
    /// retaining the configured terminal type and latest window size.
    pub fn reset(&mut self) {
        self.active = false;
        self.poisoned = false;
        self.parse_state = ParseState::Data;
        self.subnegotiation.clear();
        self.local_options = [OptionState::default(); 256];
        self.remote_options = [OptionState::default(); 256];
        self.remote_echo = true;
        self.remote_echo_known = false;
        self.local_echo = false;
    }

    fn ensure_available(&self) -> Result<(), CodecError> {
        if self.poisoned {
            Err(CodecError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn push_subnegotiation(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.subnegotiation.len() == MAX_SUBNEGOTIATION_BYTES {
            self.poisoned = true;
            self.subnegotiation.clear();
            return Err(CodecError::SubnegotiationTooLarge {
                maximum_bytes: MAX_SUBNEGOTIATION_BYTES,
            });
        }
        self.subnegotiation.push(byte);
        Ok(())
    }

    fn start_negotiation(&mut self, outbound: &mut Vec<u8>) {
        self.request_remote(option::SUPPRESS_GO_AHEAD, outbound);
        self.request_local(option::TERMINAL_TYPE, outbound);
        self.request_local(option::NAWS, outbound);
    }

    fn request_remote(&mut self, selected_option: u8, outbound: &mut Vec<u8>) {
        self.remote_options[selected_option as usize].pending_enable = true;
        append_command(outbound, command::DO, selected_option);
    }

    fn request_local(&mut self, selected_option: u8, outbound: &mut Vec<u8>) {
        self.local_options[selected_option as usize].pending_enable = true;
        append_command(outbound, command::WILL, selected_option);
    }

    fn handle_option(
        &mut self,
        verb: u8,
        selected_option: u8,
        outbound: &mut Vec<u8>,
        events: &mut Vec<TelnetEvent>,
    ) {
        match verb {
            command::WILL => self.handle_will(selected_option, outbound, events),
            command::WONT => self.handle_wont(selected_option, outbound, events),
            command::DO => self.handle_do(selected_option, outbound, events),
            command::DONT => self.handle_dont(selected_option, outbound, events),
            _ => {}
        }
    }

    fn handle_will(
        &mut self,
        selected_option: u8,
        outbound: &mut Vec<u8>,
        events: &mut Vec<TelnetEvent>,
    ) {
        let index = selected_option as usize;
        let acknowledged = self.remote_options[index].pending_enable;
        self.remote_options[index].pending_enable = false;

        if !supports_remote(selected_option) {
            if !self.remote_options[index].rejection_sent {
                append_command(outbound, command::DONT, selected_option);
                self.remote_options[index].rejection_sent = true;
            }
            self.remote_options[index].enabled = false;
            return;
        }

        let was_enabled = self.remote_options[index].enabled;
        self.remote_options[index].enabled = true;
        self.remote_options[index].rejection_sent = false;

        if selected_option == option::ECHO {
            let local_echo = &mut self.local_options[option::ECHO as usize];
            if local_echo.enabled {
                local_echo.enabled = false;
                local_echo.pending_enable = false;
                local_echo.rejection_sent = true;
                self.set_local_echo(false, events);
                append_command(outbound, command::WONT, option::ECHO);
            }
            self.set_remote_echo(true, events);
        }

        if !acknowledged && !was_enabled {
            append_command(outbound, command::DO, selected_option);
        }
    }

    fn handle_wont(
        &mut self,
        selected_option: u8,
        outbound: &mut Vec<u8>,
        events: &mut Vec<TelnetEvent>,
    ) {
        let index = selected_option as usize;
        let acknowledged = self.remote_options[index].pending_enable;
        let was_enabled = self.remote_options[index].enabled;
        self.remote_options[index].pending_enable = false;
        self.remote_options[index].enabled = false;
        self.remote_options[index].rejection_sent = false;

        if selected_option == option::ECHO {
            self.set_remote_echo(false, events);
        }
        if !acknowledged && was_enabled {
            append_command(outbound, command::DONT, selected_option);
        }
    }

    fn handle_do(
        &mut self,
        selected_option: u8,
        outbound: &mut Vec<u8>,
        events: &mut Vec<TelnetEvent>,
    ) {
        let index = selected_option as usize;
        let acknowledged = self.local_options[index].pending_enable;
        self.local_options[index].pending_enable = false;

        if !supports_local(selected_option) {
            if !self.local_options[index].rejection_sent {
                append_command(outbound, command::WONT, selected_option);
                self.local_options[index].rejection_sent = true;
            }
            self.local_options[index].enabled = false;
            return;
        }

        let was_enabled = self.local_options[index].enabled;
        self.local_options[index].enabled = true;
        self.local_options[index].rejection_sent = false;
        if !acknowledged && !was_enabled {
            append_command(outbound, command::WILL, selected_option);
        }

        if selected_option == option::ECHO && !was_enabled {
            self.set_local_echo(true, events);
        }
        if selected_option == option::NAWS && !was_enabled {
            self.append_naws_if_enabled(outbound);
        }
    }

    fn handle_dont(
        &mut self,
        selected_option: u8,
        outbound: &mut Vec<u8>,
        events: &mut Vec<TelnetEvent>,
    ) {
        let index = selected_option as usize;
        let acknowledged = self.local_options[index].pending_enable;
        let was_enabled = self.local_options[index].enabled;
        self.local_options[index].pending_enable = false;
        self.local_options[index].enabled = false;
        self.local_options[index].rejection_sent = false;

        if selected_option == option::ECHO && was_enabled {
            self.set_local_echo(false, events);
        }
        if !acknowledged && was_enabled {
            append_command(outbound, command::WONT, selected_option);
        }
    }

    fn handle_subnegotiation(&self, selected_option: u8, payload: &[u8], outbound: &mut Vec<u8>) {
        if selected_option == option::TERMINAL_TYPE && payload.first() == Some(&suboption::SEND) {
            let mut response = Vec::with_capacity(self.config.terminal_type.len() + 1);
            response.push(suboption::IS);
            response.extend_from_slice(self.config.terminal_type.as_bytes());
            append_subnegotiation(outbound, option::TERMINAL_TYPE, &response);
        }
    }

    fn append_naws_if_enabled(&self, outbound: &mut Vec<u8>) -> bool {
        if !self.active || !self.local_options[option::NAWS as usize].enabled {
            return false;
        }
        let size = self.config.window_size;
        let columns = size.columns.to_be_bytes();
        let rows = size.rows.to_be_bytes();
        append_subnegotiation(
            outbound,
            option::NAWS,
            &[columns[0], columns[1], rows[0], rows[1]],
        );
        true
    }

    fn set_remote_echo(&mut self, enabled: bool, events: &mut Vec<TelnetEvent>) {
        if !self.remote_echo_known || self.remote_echo != enabled {
            self.remote_echo = enabled;
            self.remote_echo_known = true;
            events.push(TelnetEvent::RemoteEchoChanged { enabled });
        }
    }

    fn set_local_echo(&mut self, enabled: bool, events: &mut Vec<TelnetEvent>) {
        if self.local_echo != enabled {
            self.local_echo = enabled;
            events.push(TelnetEvent::LocalEchoChanged { enabled });
        }
    }
}

impl Default for TelnetCodec {
    fn default() -> Self {
        Self::new(TelnetConfig::default())
    }
}

impl fmt::Debug for TelnetCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetCodec")
            .field("active", &self.active)
            .field("poisoned", &self.poisoned)
            .field("parse_state", &self.parse_state)
            .field("subnegotiation_bytes", &self.subnegotiation.len())
            .field("window_size", &self.config.window_size)
            .field("remote_echo", &self.remote_echo)
            .field("local_echo", &self.local_echo)
            .finish()
    }
}

fn check_input_size(input: &[u8]) -> Result<(), CodecError> {
    if input.len() > MAX_INPUT_BYTES {
        Err(CodecError::InputTooLarge {
            maximum_bytes: MAX_INPUT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn supports_remote(selected_option: u8) -> bool {
    matches!(selected_option, option::ECHO | option::SUPPRESS_GO_AHEAD)
}

fn supports_local(selected_option: u8) -> bool {
    matches!(
        selected_option,
        option::ECHO | option::SUPPRESS_GO_AHEAD | option::TERMINAL_TYPE | option::NAWS
    )
}

fn append_command(outbound: &mut Vec<u8>, verb: u8, selected_option: u8) {
    outbound.extend_from_slice(&[command::IAC, verb, selected_option]);
}

fn append_subnegotiation(outbound: &mut Vec<u8>, selected_option: u8, payload: &[u8]) {
    outbound.extend_from_slice(&[command::IAC, command::SB, selected_option]);
    for byte in payload {
        outbound.push(*byte);
        if *byte == command::IAC {
            outbound.push(command::IAC);
        }
    }
    outbound.extend_from_slice(&[command::IAC, command::SE]);
}

fn escape_iac(input: &[u8]) -> Vec<u8> {
    let iac_count = input.iter().filter(|byte| **byte == command::IAC).count();
    let mut escaped = Vec::with_capacity(input.len() + iac_count);
    for byte in input {
        escaped.push(*byte);
        if *byte == command::IAC {
            escaped.push(command::IAC);
        }
    }
    escaped
}

fn normalize_nvt_newlines(input: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        match input[cursor] {
            b'\r' if matches!(input.get(cursor + 1), Some(b'\n' | b'\0')) => {
                normalized.extend_from_slice(&input[cursor..=cursor + 1]);
                cursor += 2;
            }
            b'\r' | b'\n' => {
                normalized.extend_from_slice(b"\r\n");
                cursor += 1;
            }
            byte => {
                normalized.push(byte);
                cursor += 1;
            }
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: &[u8] = &[
        command::IAC,
        command::DO,
        option::SUPPRESS_GO_AHEAD,
        command::IAC,
        command::WILL,
        option::TERMINAL_TYPE,
        command::IAC,
        command::WILL,
        option::NAWS,
    ];

    #[test]
    fn raw_data_does_not_activate_negotiation() {
        let mut codec = TelnetCodec::default();
        let result = codec.receive(b"login: ").unwrap();
        assert_eq!(result.application_data(), b"login: ");
        assert!(result.outbound().is_empty());
        assert!(!codec.is_active());
    }

    #[test]
    fn first_iac_activates_after_preserving_prefix() {
        let mut codec = TelnetCodec::default();
        let result = codec
            .receive(&[b'a', command::IAC, command::NOP, b'b'])
            .unwrap();
        assert_eq!(result.application_data(), b"ab");
        assert_eq!(result.outbound(), START);
        assert_eq!(result.events(), &[TelnetEvent::ProtocolActivated]);
    }

    #[test]
    fn split_iac_option_is_reassembled_across_three_frames() {
        let mut codec = TelnetCodec::default();
        let first = codec.receive(&[command::IAC]).unwrap();
        assert_eq!(first.outbound(), START);
        assert!(first.application_data().is_empty());
        let second = codec.receive(&[command::WILL]).unwrap();
        assert!(second.outbound().is_empty());
        let third = codec.receive(&[option::ECHO, b'x']).unwrap();
        assert_eq!(third.application_data(), b"x");
        assert_eq!(third.outbound(), &[command::IAC, command::DO, option::ECHO]);
        assert!(
            third
                .events()
                .contains(&TelnetEvent::RemoteEchoChanged { enabled: true })
        );
    }

    #[test]
    fn escaped_iac_is_application_data_even_when_split() {
        let mut codec = TelnetCodec::default();
        codec.receive(&[command::IAC]).unwrap();
        let result = codec.receive(&[command::IAC, b'x']).unwrap();
        assert_eq!(result.application_data(), &[command::IAC, b'x']);
    }

    #[test]
    fn standalone_commands_are_consumed() {
        let mut codec = TelnetCodec::default();
        let result = codec
            .receive(&[command::IAC, command::ARE_YOU_THERE, b'o', b'k'])
            .unwrap();
        assert_eq!(result.application_data(), b"ok");
    }

    #[test]
    fn initial_sga_acknowledgement_does_not_loop() {
        let mut codec = TelnetCodec::default();
        codec.receive(&[command::IAC]).unwrap();
        let result = codec
            .receive(&[command::WILL, option::SUPPRESS_GO_AHEAD])
            .unwrap();
        assert!(result.outbound().is_empty());
        let repeated = codec
            .receive(&[command::IAC, command::WILL, option::SUPPRESS_GO_AHEAD])
            .unwrap();
        assert!(repeated.outbound().is_empty());
    }

    #[test]
    fn peer_do_supported_option_is_acknowledged_once() {
        let mut codec = TelnetCodec::default();
        let first = codec
            .receive(&[command::IAC, command::DO, option::SUPPRESS_GO_AHEAD])
            .unwrap();
        assert!(first.outbound().ends_with(&[
            command::IAC,
            command::WILL,
            option::SUPPRESS_GO_AHEAD
        ]));
        let repeated = codec
            .receive(&[command::IAC, command::DO, option::SUPPRESS_GO_AHEAD])
            .unwrap();
        assert!(repeated.outbound().is_empty());
    }

    #[test]
    fn unknown_options_are_rejected_once_per_offer() {
        let mut codec = TelnetCodec::default();
        codec.receive(&[command::IAC]).unwrap();
        let do_unknown = codec
            .receive(&[command::DO, 200, command::IAC, command::DO, 200])
            .unwrap();
        assert_eq!(do_unknown.outbound(), &[command::IAC, command::WONT, 200]);

        let will_unknown = codec
            .receive(&[
                command::IAC,
                command::WILL,
                201,
                command::IAC,
                command::WILL,
                201,
            ])
            .unwrap();
        assert_eq!(will_unknown.outbound(), &[command::IAC, command::DONT, 201]);
    }

    #[test]
    fn refusal_ack_allows_a_later_offer_to_be_rejected_again() {
        let mut codec = TelnetCodec::default();
        codec.receive(&[command::IAC, command::DO, 222]).unwrap();
        codec.receive(&[command::IAC, command::DONT, 222]).unwrap();
        let result = codec.receive(&[command::IAC, command::DO, 222]).unwrap();
        assert_eq!(result.outbound(), &[command::IAC, command::WONT, 222]);
    }

    #[test]
    fn dont_and_wont_disable_without_repeating_responses() {
        let mut codec = TelnetCodec::default();
        codec
            .receive(&[command::IAC, command::DO, option::ECHO])
            .unwrap();
        let dont = codec
            .receive(&[
                command::IAC,
                command::DONT,
                option::ECHO,
                command::IAC,
                command::DONT,
                option::ECHO,
            ])
            .unwrap();
        assert_eq!(
            dont.outbound(),
            &[command::IAC, command::WONT, option::ECHO]
        );
        assert!(
            dont.events()
                .contains(&TelnetEvent::LocalEchoChanged { enabled: false })
        );

        codec
            .receive(&[command::IAC, command::WILL, option::ECHO])
            .unwrap();
        let wont = codec
            .receive(&[
                command::IAC,
                command::WONT,
                option::ECHO,
                command::IAC,
                command::WONT,
                option::ECHO,
            ])
            .unwrap();
        assert_eq!(
            wont.outbound(),
            &[command::IAC, command::DONT, option::ECHO]
        );
        assert!(
            wont.events()
                .contains(&TelnetEvent::RemoteEchoChanged { enabled: false })
        );
    }

    #[test]
    fn remote_echo_turns_off_local_echo() {
        let mut codec = TelnetCodec::default();
        codec
            .receive(&[command::IAC, command::DO, option::ECHO])
            .unwrap();
        assert!(codec.local_echo());
        let result = codec
            .receive(&[command::IAC, command::WILL, option::ECHO])
            .unwrap();
        assert!(!codec.local_echo());
        assert_eq!(
            result.outbound(),
            &[
                command::IAC,
                command::WONT,
                option::ECHO,
                command::IAC,
                command::DO,
                option::ECHO,
            ]
        );
    }

    #[test]
    fn terminal_type_send_is_split_safe_and_uses_default() {
        let mut codec = TelnetCodec::default();
        codec
            .receive(&[
                command::IAC,
                command::SB,
                option::TERMINAL_TYPE,
                suboption::SEND,
                command::IAC,
            ])
            .unwrap();
        let result = codec.receive(&[command::SE]).unwrap();
        let mut expected = vec![
            command::IAC,
            command::SB,
            option::TERMINAL_TYPE,
            suboption::IS,
        ];
        expected.extend_from_slice(DEFAULT_TERMINAL_TYPE.as_bytes());
        expected.extend_from_slice(&[command::IAC, command::SE]);
        assert_eq!(result.outbound(), expected);
    }

    #[test]
    fn subnegotiation_unescapes_iac_and_does_not_emit_payload() {
        let mut codec = TelnetCodec::default();
        let result = codec
            .receive(&[
                command::IAC,
                command::SB,
                5,
                b'a',
                command::IAC,
                command::IAC,
                b'b',
                command::IAC,
                command::SE,
            ])
            .unwrap();
        assert!(result.application_data().is_empty());
    }

    #[test]
    fn naws_waits_for_peer_enablement_and_sends_default_once() {
        let mut codec = TelnetCodec::default();
        assert!(codec.resize(90, 30).unwrap().is_empty());
        codec.receive(&[command::IAC]).unwrap();
        assert!(codec.resize(91, 31).unwrap().is_empty());
        let enabled = codec.receive(&[command::DO, option::NAWS]).unwrap();
        assert_eq!(
            enabled.outbound(),
            &[
                command::IAC,
                command::SB,
                option::NAWS,
                0,
                91,
                0,
                31,
                command::IAC,
                command::SE,
            ]
        );
        let repeated = codec
            .receive(&[command::IAC, command::DO, option::NAWS])
            .unwrap();
        assert!(repeated.outbound().is_empty());
    }

    #[test]
    fn naws_resize_escapes_ff_bytes() {
        let mut codec = TelnetCodec::default();
        codec
            .receive(&[command::IAC, command::DO, option::NAWS])
            .unwrap();
        let resized = codec.resize(255, 511).unwrap();
        assert_eq!(
            resized.as_slice(),
            &[
                command::IAC,
                command::SB,
                option::NAWS,
                0,
                command::IAC,
                command::IAC,
                1,
                command::IAC,
                command::IAC,
                command::IAC,
                command::SE,
            ]
        );
    }

    #[test]
    fn resize_enforces_boundaries_without_changing_previous_size() {
        let mut codec = TelnetCodec::default();
        assert!(codec.resize(1, MAX_WINDOW_DIMENSION).is_ok());
        let retained = codec.window_size();
        assert!(codec.resize(0, 24).is_err());
        assert!(codec.resize(MAX_WINDOW_DIMENSION + 1, 24).is_err());
        assert_eq!(codec.window_size(), retained);
    }

    #[test]
    fn nvt_newlines_and_active_iac_are_encoded() {
        let mut codec = TelnetCodec::default();
        assert_eq!(
            codec.encode_input(b"a\nb\rc\r\nd\r\0e").unwrap().as_slice(),
            b"a\r\nb\r\nc\r\nd\r\0e"
        );
        assert_eq!(
            codec.encode_input(&[command::IAC]).unwrap().as_slice(),
            &[command::IAC]
        );
        codec.receive(&[command::IAC]).unwrap();
        assert_eq!(
            codec
                .encode_input(&[b'x', command::IAC])
                .unwrap()
                .as_slice(),
            &[b'x', command::IAC, command::IAC]
        );
    }

    #[test]
    fn input_limit_is_checked_before_state_changes() {
        let mut codec = TelnetCodec::default();
        let oversized = vec![command::IAC; MAX_INPUT_BYTES + 1];
        assert_eq!(
            codec.receive(&oversized),
            Err(CodecError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES
            })
        );
        assert!(!codec.is_active());
        assert_eq!(
            codec.encode_input(&oversized),
            Err(CodecError::InputTooLarge {
                maximum_bytes: MAX_INPUT_BYTES
            })
        );
    }

    #[test]
    fn subnegotiation_limit_is_hard_and_poisons_parser() {
        let mut codec = TelnetCodec::default();
        codec.receive(&[command::IAC, command::SB, 5]).unwrap();
        codec.receive(&vec![b'x'; MAX_INPUT_BYTES]).unwrap();
        assert_eq!(
            codec.receive(&[b'y']),
            Err(CodecError::SubnegotiationTooLarge {
                maximum_bytes: MAX_SUBNEGOTIATION_BYTES
            })
        );
        assert_eq!(codec.receive(b"safe"), Err(CodecError::Poisoned));
        codec.reset();
        assert_eq!(codec.receive(b"safe").unwrap().application_data(), b"safe");
    }

    #[test]
    fn terminal_type_validation_and_debug_are_payload_safe() {
        let secret = "PRIVATE-TERM-MARKER";
        let config = TelnetConfig::default().with_terminal_type(secret).unwrap();
        assert_eq!(config.terminal_type(), secret);
        assert!(!format!("{config:?}").contains(secret));
        assert!(TelnetConfig::default().with_terminal_type("").is_err());
        assert!(
            TelnetConfig::default()
                .with_terminal_type("bad\nterm")
                .is_err()
        );
    }

    #[test]
    fn every_diagnostic_hides_payload_bytes() {
        let marker = b"highly-sensitive-payload";
        let bytes = TelnetBytes::from(marker.to_vec());
        assert!(!format!("{bytes:?}").contains("sensitive"));

        let mut codec = TelnetCodec::default();
        let result = codec.receive(marker).unwrap();
        assert!(!format!("{result:?}").contains("sensitive"));
        assert!(!format!("{codec:?}").contains("sensitive"));
        assert!(!format!("{:?}", CodecError::Poisoned).contains("sensitive"));
    }
}
