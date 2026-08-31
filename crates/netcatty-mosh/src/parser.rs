use std::{error::Error, fmt, net::IpAddr};

use zeroize::Zeroizing;

pub const MAX_HANDSHAKE_CHUNK_BYTES: usize = 256 * 1_024;
pub const MAX_PENDING_HANDSHAKE_BYTES: usize = 4 * 1_024;
pub const MAX_PROTOCOL_LINE_BYTES: usize = 512;

const CONNECT_MARKER: &[u8] = b"MOSH CONNECT";
const IP_MARKER: &[u8] = b"MOSH IP";

#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum MoshParserError {
    ChunkTooLarge { maximum_bytes: usize },
    ProtocolLineTooLarge { maximum_bytes: usize },
    InvalidConnectLine,
}

impl fmt::Display for MoshParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChunkTooLarge { maximum_bytes } => write!(
                formatter,
                "Mosh handshake output chunk exceeds {maximum_bytes} bytes"
            ),
            Self::ProtocolLineTooLarge { maximum_bytes } => write!(
                formatter,
                "Mosh handshake protocol line exceeds {maximum_bytes} bytes"
            ),
            Self::InvalidConnectLine => {
                formatter.write_str("Mosh server returned an invalid connection marker")
            }
        }
    }
}

impl fmt::Debug for MoshParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for MoshParserError {}

/// The secret key announced by `mosh-server`.
///
/// It cannot be serialized or cloned and its owned storage is zeroized when
/// dropped. Debug output reports only the validated encoded length.
pub struct MoshKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl MoshKey {
    pub fn expose_secret(&self) -> &str {
        // Construction accepts ASCII base64 only.
        std::str::from_utf8(&self.bytes).expect("validated Mosh key must be UTF-8")
    }

    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }
}

impl fmt::Debug for MoshKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshKey")
            .field("encoded_len", &self.bytes.len())
            .field("value", &"[redacted MOSH_KEY]")
            .finish()
    }
}

pub struct MoshConnect {
    port: u16,
    key: MoshKey,
    announced_host: Option<String>,
}

impl MoshConnect {
    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn key(&self) -> &MoshKey {
        &self.key
    }

    pub fn announced_host(&self) -> Option<&str> {
        self.announced_host.as_deref()
    }

    pub(crate) fn into_parts(self) -> (u16, MoshKey, Option<String>) {
        (self.port, self.key, self.announced_host)
    }
}

impl fmt::Debug for MoshConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshConnect")
            .field("port", &self.port)
            .field("key", &self.key)
            .field(
                "announced_host",
                &self.announced_host.as_ref().map(|_| "[redacted endpoint]"),
            )
            .finish()
    }
}

pub struct SniffedHandshake {
    visible: Vec<u8>,
    connect: Option<MoshConnect>,
}

impl SniffedHandshake {
    fn new(visible: Vec<u8>, connect: Option<MoshConnect>) -> Self {
        Self { visible, connect }
    }

    pub fn visible(&self) -> &[u8] {
        &self.visible
    }

    pub fn into_visible(self) -> Vec<u8> {
        self.visible
    }

    pub fn connect(&self) -> Option<&MoshConnect> {
        self.connect.as_ref()
    }

    pub fn take_connect(&mut self) -> Option<MoshConnect> {
        self.connect.take()
    }
}

impl fmt::Debug for SniffedHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SniffedHandshake")
            .field("visible_bytes", &self.visible.len())
            .field("connect", &self.connect)
            .finish()
    }
}

#[derive(Default)]
pub struct MoshConnectSniffer {
    pending: Vec<u8>,
    announced_host: Option<String>,
    parsed: bool,
}

impl MoshConnectSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<SniffedHandshake, MoshParserError> {
        if chunk.len() > MAX_HANDSHAKE_CHUNK_BYTES {
            return Err(MoshParserError::ChunkTooLarge {
                maximum_bytes: MAX_HANDSHAKE_CHUNK_BYTES,
            });
        }
        if self.parsed {
            return Ok(SniffedHandshake::new(chunk.to_vec(), None));
        }

        self.pending.extend_from_slice(chunk);
        let mut visible = Vec::with_capacity(chunk.len());
        let mut consumed = 0;

        while let Some((line_end, record_end)) = next_complete_line(&self.pending, consumed) {
            let line = &self.pending[consumed..line_end];
            let newline = &self.pending[line_end..record_end];
            let has_protocol_marker = contains(line, CONNECT_MARKER) || contains(line, IP_MARKER);
            if has_protocol_marker && line.len() > MAX_PROTOCOL_LINE_BYTES {
                self.pending.clear();
                return Err(MoshParserError::ProtocolLineTooLarge {
                    maximum_bytes: MAX_PROTOCOL_LINE_BYTES,
                });
            }

            match parse_ip_line(line) {
                IpLine::Valid(host) => {
                    self.announced_host = Some(host);
                    consumed = record_end;
                    continue;
                }
                IpLine::Invalid => {
                    // Internal protocol is never displayed, even when the
                    // address is rejected. It also never gains launch authority.
                    consumed = record_end;
                    continue;
                }
                IpLine::Absent => {}
            }

            match parse_connect_line(line)? {
                Some(parsed) => {
                    visible.extend_from_slice(&line[..parsed.match_start]);
                    let suffix = &line[parsed.match_end..];
                    if !suffix.is_empty() {
                        visible.extend_from_slice(suffix);
                        visible.extend_from_slice(newline);
                    }
                    consumed = record_end;
                    visible.extend_from_slice(&self.pending[consumed..]);
                    let connect = MoshConnect {
                        port: parsed.port,
                        key: parsed.key,
                        announced_host: self.announced_host.take(),
                    };
                    self.pending.clear();
                    self.parsed = true;
                    return Ok(SniffedHandshake::new(visible, Some(connect)));
                }
                None => {
                    visible.extend_from_slice(&self.pending[consumed..record_end]);
                    consumed = record_end;
                }
            }
        }

        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        self.release_non_protocol_prefix(&mut visible)?;
        Ok(SniffedHandshake::new(visible, None))
    }

    /// Parse or release a final protocol line when the SSH bootstrap reaches
    /// EOF without CR/LF. This is intentionally the only place where a
    /// 22-character unpadded key is accepted at the end of an incomplete line.
    pub fn finish(&mut self) -> Result<SniffedHandshake, MoshParserError> {
        if self.parsed || self.pending.is_empty() {
            return Ok(SniffedHandshake::new(Vec::new(), None));
        }
        if (contains(&self.pending, CONNECT_MARKER) || contains(&self.pending, IP_MARKER))
            && self.pending.len() > MAX_PROTOCOL_LINE_BYTES
        {
            self.pending.clear();
            return Err(MoshParserError::ProtocolLineTooLarge {
                maximum_bytes: MAX_PROTOCOL_LINE_BYTES,
            });
        }

        match parse_ip_line(&self.pending) {
            IpLine::Valid(host) => {
                self.announced_host = Some(host);
                self.pending.clear();
                return Ok(SniffedHandshake::new(Vec::new(), None));
            }
            IpLine::Invalid => {
                self.pending.clear();
                return Ok(SniffedHandshake::new(Vec::new(), None));
            }
            IpLine::Absent => {}
        }

        if let Some(parsed) = parse_connect_line(&self.pending)? {
            let mut visible = Vec::new();
            visible.extend_from_slice(&self.pending[..parsed.match_start]);
            visible.extend_from_slice(&self.pending[parsed.match_end..]);
            let connect = MoshConnect {
                port: parsed.port,
                key: parsed.key,
                announced_host: self.announced_host.take(),
            };
            self.pending.clear();
            self.parsed = true;
            return Ok(SniffedHandshake::new(visible, Some(connect)));
        }

        Ok(SniffedHandshake::new(
            std::mem::take(&mut self.pending),
            None,
        ))
    }

    pub fn is_parsed(&self) -> bool {
        self.parsed
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    fn release_non_protocol_prefix(
        &mut self,
        visible: &mut Vec<u8>,
    ) -> Result<(), MoshParserError> {
        let Some(hold_index) = potential_protocol_start(&self.pending) else {
            visible.append(&mut self.pending);
            return Ok(());
        };

        if hold_index > 0 {
            visible.extend_from_slice(&self.pending[..hold_index]);
            self.pending.drain(..hold_index);
        }
        if self.pending.len() > MAX_PROTOCOL_LINE_BYTES {
            self.pending.clear();
            return Err(MoshParserError::ProtocolLineTooLarge {
                maximum_bytes: MAX_PROTOCOL_LINE_BYTES,
            });
        }
        if self.pending.len() > MAX_PENDING_HANDSHAKE_BYTES {
            self.pending.clear();
            return Err(MoshParserError::ProtocolLineTooLarge {
                maximum_bytes: MAX_PROTOCOL_LINE_BYTES,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for MoshConnectSniffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoshConnectSniffer")
            .field("pending_bytes", &self.pending.len())
            .field(
                "announced_host",
                &self.announced_host.as_ref().map(|_| "[redacted endpoint]"),
            )
            .field("parsed", &self.parsed)
            .finish()
    }
}

struct ParsedConnectLine {
    port: u16,
    key: MoshKey,
    match_start: usize,
    match_end: usize,
}

fn parse_connect_line(line: &[u8]) -> Result<Option<ParsedConnectLine>, MoshParserError> {
    let (cleaned, clean_to_original) = strip_ansi_with_map(line);
    let Some(marker_index) = find_subslice(&cleaned, CONNECT_MARKER) else {
        return Ok(None);
    };
    let mut clean_pos = marker_index + CONNECT_MARKER.len();
    if !cleaned
        .get(clean_pos)
        .is_some_and(|byte| is_horizontal_space(*byte))
    {
        return Err(MoshParserError::InvalidConnectLine);
    }
    while cleaned
        .get(clean_pos)
        .is_some_and(|byte| is_horizontal_space(*byte))
    {
        clean_pos += 1;
    }

    let port_start = clean_pos;
    while cleaned.get(clean_pos).is_some_and(u8::is_ascii_digit) {
        clean_pos += 1;
    }
    let port_digits = clean_pos.saturating_sub(port_start);
    if !(1..=5).contains(&port_digits)
        || !cleaned
            .get(clean_pos)
            .is_some_and(|byte| is_horizontal_space(*byte))
    {
        return Err(MoshParserError::InvalidConnectLine);
    }
    let port =
        parse_port(&cleaned[port_start..clean_pos]).ok_or(MoshParserError::InvalidConnectLine)?;
    while cleaned
        .get(clean_pos)
        .is_some_and(|byte| is_horizontal_space(*byte))
    {
        clean_pos += 1;
    }

    let Some(&match_start) = clean_to_original.get(marker_index) else {
        return Err(MoshParserError::InvalidConnectLine);
    };
    let Some(&key_start) = clean_to_original.get(clean_pos) else {
        return Err(MoshParserError::InvalidConnectLine);
    };
    let mut key = Vec::with_capacity(24);
    let mut pos = key_start;
    while pos < line.len() && key.len() < 22 {
        if line[pos] == 0x1b
            && let Some(end) = ansi_sequence_end(line, pos)
        {
            pos = end;
            continue;
        }
        if !is_base64_body(line[pos]) {
            return Err(MoshParserError::InvalidConnectLine);
        }
        key.push(line[pos]);
        pos += 1;
    }
    if key.len() != 22 {
        return Err(MoshParserError::InvalidConnectLine);
    }

    let before_padding = pos;
    let padding_lookahead = skip_ansi(line, pos);
    if line.get(padding_lookahead..padding_lookahead.saturating_add(2)) == Some(b"==") {
        key.extend_from_slice(b"==");
        pos = padding_lookahead + 2;
    } else if line.get(padding_lookahead) == Some(&b'=') {
        let second_padding = skip_ansi(line, padding_lookahead + 1);
        if line.get(second_padding) == Some(&b'=') {
            key.extend_from_slice(b"==");
            pos = second_padding + 1;
        } else if padding_lookahead == before_padding {
            return Err(MoshParserError::InvalidConnectLine);
        }
    } else if padding_lookahead == before_padding
        && line.get(pos).is_some_and(|byte| is_base64_token(*byte))
    {
        return Err(MoshParserError::InvalidConnectLine);
    }

    if line.get(pos).is_some_and(|byte| is_base64_token(*byte)) {
        return Err(MoshParserError::InvalidConnectLine);
    }

    let mut match_end = pos;
    loop {
        if line.get(match_end) == Some(&0x1b)
            && let Some(end) = ansi_sequence_end(line, match_end)
        {
            match_end = end;
            continue;
        }
        if line
            .get(match_end)
            .is_some_and(|byte| is_horizontal_space(*byte))
        {
            match_end += 1;
            continue;
        }
        break;
    }

    Ok(Some(ParsedConnectLine {
        port,
        key: MoshKey {
            bytes: Zeroizing::new(key),
        },
        match_start,
        match_end,
    }))
}

enum IpLine {
    Absent,
    Invalid,
    Valid(String),
}

fn parse_ip_line(line: &[u8]) -> IpLine {
    let (cleaned, _) = strip_ansi_with_map(line);
    let Some(marker_index) = find_subslice(&cleaned, IP_MARKER) else {
        return IpLine::Absent;
    };
    let mut pos = marker_index + IP_MARKER.len();
    if !cleaned
        .get(pos)
        .is_some_and(|byte| is_horizontal_space(*byte))
    {
        return IpLine::Invalid;
    }
    while cleaned
        .get(pos)
        .is_some_and(|byte| is_horizontal_space(*byte))
    {
        pos += 1;
    }
    let start = pos;
    while cleaned
        .get(pos)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        pos += 1;
    }
    let Ok(candidate) = std::str::from_utf8(&cleaned[start..pos]) else {
        return IpLine::Invalid;
    };
    match candidate.parse::<IpAddr>() {
        Ok(address) => IpLine::Valid(address.to_string()),
        Err(_) => IpLine::Invalid,
    }
}

fn parse_port(bytes: &[u8]) -> Option<u16> {
    let mut value = 0u32;
    for byte in bytes {
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    u16::try_from(value).ok().filter(|port| *port != 0)
}

fn strip_ansi_with_map(source: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut cleaned = Vec::with_capacity(source.len());
    let mut map = Vec::with_capacity(source.len() + 1);
    let mut index = 0;
    while index < source.len() {
        if source[index] == 0x1b
            && let Some(end) = ansi_sequence_end(source, index)
        {
            index = end;
            continue;
        }
        map.push(index);
        cleaned.push(source[index]);
        index += 1;
    }
    map.push(source.len());
    (cleaned, map)
}

fn ansi_sequence_end(source: &[u8], start: usize) -> Option<usize> {
    if source.get(start) != Some(&0x1b) {
        return None;
    }
    let introducer = *source.get(start + 1)?;
    match introducer {
        b'[' => {
            let limit = source.len().min(start + 128);
            let mut pos = start + 2;
            while pos < limit {
                if (0x40..=0x7e).contains(&source[pos]) {
                    return Some(pos + 1);
                }
                pos += 1;
            }
            None
        }
        b']' => terminated_escape_end(source, start + 2, true),
        b'P' | b'X' | b'^' | b'_' => terminated_escape_end(source, start + 2, false),
        _ => Some(start + 2),
    }
}

fn terminated_escape_end(source: &[u8], mut pos: usize, allow_bell: bool) -> Option<usize> {
    let limit = source.len().min(pos + MAX_PROTOCOL_LINE_BYTES);
    while pos < limit {
        if allow_bell && source[pos] == 0x07 {
            return Some(pos + 1);
        }
        if source[pos] == 0x1b && source.get(pos + 1) == Some(&b'\\') {
            return Some(pos + 2);
        }
        pos += 1;
    }
    None
}

fn skip_ansi(source: &[u8], mut pos: usize) -> usize {
    while source.get(pos) == Some(&0x1b) {
        let Some(end) = ansi_sequence_end(source, pos) else {
            break;
        };
        pos = end;
    }
    pos
}

fn next_complete_line(source: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut pos = start;
    while pos < source.len() {
        match source[pos] {
            b'\r' => {
                let record_end = if source.get(pos + 1) == Some(&b'\n') {
                    pos + 2
                } else {
                    pos + 1
                };
                return Some((pos, record_end));
            }
            b'\n' => return Some((pos, pos + 1)),
            _ => pos += 1,
        }
    }
    None
}

fn potential_protocol_start(source: &[u8]) -> Option<usize> {
    let mut best = None;
    for marker in [CONNECT_MARKER, IP_MARKER] {
        if let Some(index) = find_subslice(source, marker) {
            best = Some(best.map_or(index, |current: usize| current.min(index)));
        }
        let maximum = marker.len().saturating_sub(1).min(source.len());
        for length in (1..=maximum).rev() {
            if marker.starts_with(&source[source.len() - length..]) {
                let index = source.len() - length;
                best = Some(best.map_or(index, |current: usize| current.min(index)));
                break;
            }
        }
    }
    best
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

const fn is_horizontal_space(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

const fn is_base64_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

const fn is_base64_token(byte: u8) -> bool {
    is_base64_body(byte) || byte == b'='
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_PADDED: &str = "ABCDEFGHIJKLMNOPQRSTUV==";
    const KEY_UNPADDED: &str = "abcdefghijklmnopqrstuv";

    #[test]
    fn parses_padded_and_unpadded_keys_with_strict_ports() {
        for (line, port, key) in [
            (
                format!("welcome\r\nMOSH CONNECT 60001 {KEY_PADDED}\r\n"),
                60001,
                KEY_PADDED,
            ),
            (format!("MOSH CONNECT 7 {KEY_UNPADDED}\n"), 7, KEY_UNPADDED),
        ] {
            let mut sniffer = MoshConnectSniffer::new();
            let result = sniffer.feed(line.as_bytes()).unwrap();
            let connect = result.connect().unwrap();
            assert_eq!(connect.port(), port);
            assert_eq!(connect.key().expose_secret(), key);
            assert!(
                !result
                    .visible()
                    .windows(12)
                    .any(|value| value == b"MOSH CONNECT")
            );
        }
    }

    #[test]
    fn rejects_invalid_ports_and_key_shapes_without_echoing_them() {
        for line in [
            format!("MOSH CONNECT 0 {KEY_PADDED}\n"),
            format!("MOSH CONNECT 65536 {KEY_PADDED}\n"),
            "MOSH CONNECT 60000 short\n".to_owned(),
            format!("MOSH CONNECT 60000 {KEY_PADDED}oops\n"),
            format!("MOSH CONNECT 60000 {KEY_UNPADDED}=\n"),
        ] {
            let mut sniffer = MoshConnectSniffer::new();
            assert_eq!(
                sniffer.feed(line.as_bytes()).unwrap_err(),
                MoshParserError::InvalidConnectLine
            );
        }
    }

    #[test]
    fn accepts_and_redacts_conpty_controls_inside_key_and_padding() {
        let mut sniffer = MoshConnectSniffer::new();
        let result = sniffer
            .feed(b"MOSH CONNECT 60030 nDMmYnfKIKn2yAXiK/\x1b[?25h34eg\x1b[?25h\r\n")
            .unwrap();
        assert_eq!(
            result.connect().unwrap().key().expose_secret(),
            "nDMmYnfKIKn2yAXiK/34eg"
        );
        assert!(result.visible().is_empty());

        let mut padded = MoshConnectSniffer::new();
        let result = padded
            .feed(b"MOSH CONNECT 60031 ABCDEFGHIJKLMNOPQRSTUV=\x1b[?25h=\r\n")
            .unwrap();
        assert_eq!(result.connect().unwrap().key().expose_secret(), KEY_PADDED);
    }

    #[test]
    fn split_marker_and_key_never_enter_visible_output() {
        let mut sniffer = MoshConnectSniffer::new();
        let first = sniffer.feed(b"login banner\r\nMOSH CONNE").unwrap();
        assert_eq!(first.visible(), b"login banner\r\n");
        let second = sniffer.feed(b"CT 60002 ABCDEFGHIJ").unwrap();
        assert!(second.visible().is_empty());
        let third = sniffer.feed(b"KLMNOPQRSTUV==\r\n").unwrap();
        assert_eq!(third.connect().unwrap().key().expose_secret(), KEY_PADDED);
        assert!(third.visible().is_empty());
    }

    #[test]
    fn unterminated_key_waits_for_finish_or_padding() {
        let mut sniffer = MoshConnectSniffer::new();
        let first = sniffer
            .feed(format!("MOSH CONNECT 60003 {KEY_UNPADDED}").as_bytes())
            .unwrap();
        assert!(first.connect().is_none());
        assert!(first.visible().is_empty());
        let finished = sniffer.finish().unwrap();
        assert_eq!(
            finished.connect().unwrap().key().expose_secret(),
            KEY_UNPADDED
        );

        let mut padded = MoshConnectSniffer::new();
        padded
            .feed(format!("MOSH CONNECT 60004 {KEY_UNPADDED}").as_bytes())
            .unwrap();
        let result = padded.feed(b"==\n").unwrap();
        assert_eq!(
            result.connect().unwrap().key().expose_secret(),
            "abcdefghijklmnopqrstuv=="
        );
    }

    #[test]
    fn valid_ip_override_is_hidden_and_invalid_ip_has_no_authority() {
        let mut valid = MoshConnectSniffer::new();
        let result = valid
            .feed(
                format!("hello\r\nMOSH IP 203.0.113.8\r\nMOSH CONNECT 60002 {KEY_PADDED}\r\n")
                    .as_bytes(),
            )
            .unwrap();
        assert_eq!(result.visible(), b"hello\r\n");
        assert_eq!(
            result.connect().unwrap().announced_host(),
            Some("203.0.113.8")
        );

        let mut invalid = MoshConnectSniffer::new();
        let result = invalid
            .feed(format!("MOSH IP --help\r\nMOSH CONNECT 60002 {KEY_PADDED}\r\n").as_bytes())
            .unwrap();
        assert_eq!(result.connect().unwrap().announced_host(), None);
        assert!(result.visible().is_empty());
    }

    #[test]
    fn ordinary_prompts_stream_without_newlines() {
        let mut sniffer = MoshConnectSniffer::new();
        let result = sniffer.feed(b"alice@example password:").unwrap();
        assert_eq!(result.visible(), b"alice@example password:");
        assert_eq!(sniffer.pending_bytes(), 0);
    }

    #[test]
    fn protocol_memory_and_input_are_bounded() {
        let mut sniffer = MoshConnectSniffer::new();
        assert_eq!(
            sniffer
                .feed(&vec![b'x'; MAX_HANDSHAKE_CHUNK_BYTES + 1])
                .unwrap_err(),
            MoshParserError::ChunkTooLarge {
                maximum_bytes: MAX_HANDSHAKE_CHUNK_BYTES
            }
        );

        let mut sniffer = MoshConnectSniffer::new();
        let mut overlong = b"MOSH CONNECT ".to_vec();
        overlong.extend(vec![b'x'; MAX_PROTOCOL_LINE_BYTES]);
        assert_eq!(
            sniffer.feed(&overlong).unwrap_err(),
            MoshParserError::ProtocolLineTooLarge {
                maximum_bytes: MAX_PROTOCOL_LINE_BYTES
            }
        );
        assert_eq!(sniffer.pending_bytes(), 0);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let mut sniffer = MoshConnectSniffer::new();
        let result = sniffer
            .feed(format!("MOSH CONNECT 60002 {KEY_PADDED}\n").as_bytes())
            .unwrap();
        let debug = format!("{result:?}");
        assert!(!debug.contains(KEY_PADDED));
        assert!(debug.contains("redacted"));
    }
}
