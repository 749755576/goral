//! RFC 854 command and option numbers used by the codec.

/// Telnet command bytes.
pub mod command {
    pub const SE: u8 = 240;
    pub const NOP: u8 = 241;
    pub const DATA_MARK: u8 = 242;
    pub const BREAK: u8 = 243;
    pub const INTERRUPT_PROCESS: u8 = 244;
    pub const ABORT_OUTPUT: u8 = 245;
    pub const ARE_YOU_THERE: u8 = 246;
    pub const ERASE_CHARACTER: u8 = 247;
    pub const ERASE_LINE: u8 = 248;
    pub const GO_AHEAD: u8 = 249;
    pub const SB: u8 = 250;
    pub const WILL: u8 = 251;
    pub const WONT: u8 = 252;
    pub const DO: u8 = 253;
    pub const DONT: u8 = 254;
    pub const IAC: u8 = 255;
}

/// Telnet option bytes supported by Netcatty's NVT client.
pub mod option {
    /// RFC 857 ECHO.
    pub const ECHO: u8 = 1;
    /// RFC 858 SUPPRESS-GO-AHEAD.
    pub const SUPPRESS_GO_AHEAD: u8 = 3;
    /// RFC 1091 TERMINAL-TYPE.
    pub const TERMINAL_TYPE: u8 = 24;
    /// RFC 1073 NEGOTIATE-ABOUT-WINDOW-SIZE.
    pub const NAWS: u8 = 31;
}

/// Subnegotiation selectors shared by TERMINAL-TYPE and similar options.
pub mod suboption {
    pub const IS: u8 = 0;
    pub const SEND: u8 = 1;
}

pub(crate) fn is_option_command(byte: u8) -> bool {
    matches!(
        byte,
        command::WILL | command::WONT | command::DO | command::DONT
    )
}
