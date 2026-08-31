//! Pure Connection Logs export formatting.
//!
//! This crate owns no dialogs, paths, files, Tauri state, Vault catalogs, or
//! replay-store locators. Callers must supply the one already-authorized replay
//! and authoritative metadata selected under their own transaction boundary.

use std::fmt;
use std::path::Path;

const DEFAULT_FOREGROUND: &str = "#d4d4d4";
const DEFAULT_BACKGROUND: &str = "#1e1e1e";
const BASIC_COLORS: [&str; 8] = [
    "#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
];
const BRIGHT_COLORS: [&str; 8] = [
    "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff",
];
// The live terminal runtime rejects dimensions above 10,000. A little headroom
// preserves legitimate cursor motion without letting a tiny CSI sequence
// materialize millions of sparse cells or empty row vectors during export.
const MAX_VIRTUAL_ROWS: usize = 16_384;
const MAX_VIRTUAL_COLUMNS: usize = 16_384;
const MAX_VIRTUAL_CELLS: usize = 1_000_000;
const MAX_RENDERED_CONTENT_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_CSI_BYTES: usize = 4_096;
const MAX_PORTABLE_FILE_NAME_UTF8_BYTES: usize = 255;
const MAX_PORTABLE_FILE_NAME_UTF16_UNITS: usize = 255;

/// The three legacy Connection Logs export representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// Apply terminal editing controls and omit ANSI styling.
    PlainText,
    /// Preserve the replay bytes exactly, including ANSI sequences.
    Raw,
    /// Apply terminal editing controls and preserve supported SGR as safe HTML.
    Html,
}

impl ExportFormat {
    /// Extension used for the native save dialog's initial suggestion.
    #[must_use]
    pub const fn default_extension(self) -> &'static str {
        match self {
            Self::PlainText => "txt",
            Self::Raw => "log",
            Self::Html => "html",
        }
    }
}

/// Static text used around the terminal body in a standalone HTML export.
///
/// Keeping these labels formatter-owned makes localization explicit without
/// coupling this pure crate to a renderer or desktop i18n implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtmlExportLabels<'a> {
    title: &'a str,
    host_prefix: &'a str,
    date_prefix: &'a str,
    unknown_host: &'a str,
}

impl<'a> HtmlExportLabels<'a> {
    #[must_use]
    pub const fn new(
        title: &'a str,
        host_prefix: &'a str,
        date_prefix: &'a str,
        unknown_host: &'a str,
    ) -> Self {
        Self {
            title,
            host_prefix,
            date_prefix,
            unknown_host,
        }
    }
}

/// Legacy English labels used by the compatibility rendering entry points.
pub const ENGLISH_HTML_EXPORT_LABELS: HtmlExportLabels<'static> =
    HtmlExportLabels::new("Session Log", "Host: ", "Date: ", "Unknown");

/// Resolve the actual formatter from the final user-selected path.
///
/// Matching is deliberately case-sensitive for legacy compatibility. A path
/// without an extension keeps the preferred format; `.html` selects HTML,
/// `.log`/`.raw` select raw ANSI, and every other extension selects plain text.
#[must_use]
pub fn export_format_for_path(path: &Path, preferred: ExportFormat) -> ExportFormat {
    match path.extension().and_then(|extension| extension.to_str()) {
        None | Some("") => preferred,
        Some("html") => ExportFormat::Html,
        Some("log" | "raw") => ExportFormat::Raw,
        Some(_) => ExportFormat::PlainText,
    }
}

/// Explicit local calendar components used in the default file name.
///
/// Conversion from an epoch timestamp and the user's timezone remains a
/// platform-adapter responsibility, making daylight-saving behavior testable
/// without consulting ambient process timezone state in this crate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalDateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl LocalDateTime {
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, LocalDateTimeError> {
        if year == 0
            || year > 9_999
            || !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(LocalDateTimeError);
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    #[must_use]
    pub fn file_name_component(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

impl fmt::Debug for LocalDateTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalDateTime([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalDateTimeError;

impl fmt::Display for LocalDateTimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("local export date and time are invalid")
    }
}

impl std::error::Error for LocalDateTimeError {}

/// Preserve valid Unicode while replacing characters unsafe in a portable
/// leaf path segment. The fallback is sanitized too, so callers cannot turn a
/// fallback into a path traversal.
#[must_use]
pub fn safe_path_segment(value: &str, fallback: &str) -> String {
    sanitize_path_segment(value)
        .unwrap_or_else(|| sanitize_path_segment(fallback).unwrap_or_else(|| "unknown".to_owned()))
}

/// Legacy-compatible default save-dialog file name.
#[must_use]
pub fn default_export_file_name(
    host_label: &str,
    hostname: &str,
    local_date_time: LocalDateTime,
    preferred: ExportFormat,
) -> String {
    let source = if host_label.is_empty() {
        hostname
    } else {
        host_label
    };
    let suffix = format!(
        "_{}.{}",
        local_date_time.file_name_component(),
        preferred.default_extension()
    );
    let safe_host_label = bounded_path_segment_for_suffix(source, "session", &suffix);
    format!("{safe_host_label}{suffix}")
}

/// Render terminal output after applying common cursor/editing controls and
/// removing escape sequences and alternate-screen TUI paint.
#[must_use]
pub fn render_plain_text(terminal_data: &str) -> String {
    let mut renderer = TerminalTextRenderer::default();
    renderer.feed(terminal_data);
    renderer.finish();
    renderer.to_plain_text()
}

/// Render the terminal body as escaped HTML with supported SGR styles.
#[must_use]
pub fn render_html_content(terminal_data: &str) -> String {
    let mut renderer = TerminalTextRenderer::default();
    renderer.feed(terminal_data);
    renderer.finish();
    renderer.to_html_content()
}

/// Render one complete, standalone safe HTML document.
///
/// `localized_date` must be produced by the desktop adapter from the
/// authoritative start time using the user's locale. Both header values and
/// all terminal text are HTML-escaped.
#[must_use]
pub fn render_html(terminal_data: &str, host_label: &str, localized_date: &str) -> String {
    render_html_with_labels(
        terminal_data,
        host_label,
        localized_date,
        ENGLISH_HTML_EXPORT_LABELS,
    )
}

/// Render one complete HTML document with caller-selected static labels.
#[must_use]
pub fn render_html_with_labels(
    terminal_data: &str,
    host_label: &str,
    localized_date: &str,
    labels: HtmlExportLabels<'_>,
) -> String {
    let body = render_html_content(terminal_data);
    let safe_host_value = escape_html(if host_label.is_empty() {
        labels.unknown_host
    } else {
        host_label
    });
    let safe_date = escape_html(localized_date);
    let safe_title = escape_html(labels.title);
    let safe_host_prefix = escape_html(labels.host_prefix);
    let safe_date_prefix = escape_html(labels.date_prefix);
    format!(
        "<!DOCTYPE html>\n\
<html>\n\
<head>\n\
  <meta charset=\"utf-8\">\n\
  <title>{safe_title} - {safe_host_value}</title>\n\
  <style>\n\
    body {{\n\
      background: #1e1e1e;\n\
      color: #d4d4d4;\n\
      font-family: 'JetBrains Mono', 'SF Mono', Monaco, Menlo, monospace;\n\
      font-size: 13px;\n\
      line-height: 1.4;\n\
      padding: 20px;\n\
      white-space: pre-wrap;\n\
      word-wrap: break-word;\n\
    }}\n\
    .header {{\n\
      border-bottom: 1px solid #444;\n\
      padding-bottom: 10px;\n\
      margin-bottom: 20px;\n\
      color: #888;\n\
    }}\n\
  </style>\n\
</head>\n\
<body>\n\
  <div class=\"header\">\n\
    {safe_host_prefix}{safe_host_value}<br>\n\
    {safe_date_prefix}{safe_date}\n\
  </div>\n\
  <div class=\"content\">{body}</div>\n\
</body>\n\
</html>"
    )
}

/// Render the final selected representation. Raw mode is byte-for-byte UTF-8
/// text preservation; the other modes apply the virtual terminal renderer.
#[must_use]
pub fn render_export(
    format: ExportFormat,
    terminal_data: &str,
    host_label: &str,
    localized_date: &str,
) -> String {
    render_export_with_html_labels(
        format,
        terminal_data,
        host_label,
        localized_date,
        ENGLISH_HTML_EXPORT_LABELS,
    )
}

/// Render the selected representation with caller-selected HTML labels.
/// Plain-text and raw exports intentionally ignore `html_labels`.
#[must_use]
pub fn render_export_with_html_labels(
    format: ExportFormat,
    terminal_data: &str,
    host_label: &str,
    localized_date: &str,
    html_labels: HtmlExportLabels<'_>,
) -> String {
    match format {
        ExportFormat::PlainText => render_plain_text(terminal_data),
        ExportFormat::Raw => terminal_data.to_owned(),
        ExportFormat::Html => {
            render_html_with_labels(terminal_data, host_label, localized_date, html_labels)
        }
    }
}

fn sanitize_path_segment(value: &str) -> Option<String> {
    let mut safe: String = value
        .chars()
        .map(|character| {
            if is_file_name_unsafe(character) || is_legacy_control(character) {
                '_'
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    if safe.is_empty() || safe == "." || safe == ".." {
        return None;
    }
    let trailing_dots = safe
        .chars()
        .rev()
        .take_while(|character| *character == '.')
        .count();
    if trailing_dots > 0 {
        safe.truncate(safe.len() - trailing_dots);
        safe.extend(std::iter::repeat_n('_', trailing_dots));
    }
    if is_windows_reserved_device_name(&safe) {
        safe.push('_');
    }
    Some(safe)
}

fn bounded_path_segment_for_suffix(value: &str, fallback: &str, suffix: &str) -> String {
    let safe = safe_path_segment(value, fallback);
    let max_utf8_bytes = MAX_PORTABLE_FILE_NAME_UTF8_BYTES
        .saturating_sub(suffix.len())
        .saturating_sub(1);
    let suffix_utf16_units = suffix.encode_utf16().count();
    let max_utf16_units = MAX_PORTABLE_FILE_NAME_UTF16_UNITS
        .saturating_sub(suffix_utf16_units)
        .saturating_sub(1);
    let truncated = truncate_unicode_component(&safe, max_utf8_bytes, max_utf16_units);

    // Truncation can expose a formerly internal trailing dot or remove the
    // underscore that protected a reserved Windows device name. Leave one
    // unit above so re-sanitizing can restore that protection without crossing
    // either portable component limit.
    sanitize_path_segment(&truncated)
        .unwrap_or_else(|| truncate_unicode_component("session", max_utf8_bytes, max_utf16_units))
}

fn truncate_unicode_component(
    value: &str,
    max_utf8_bytes: usize,
    max_utf16_units: usize,
) -> String {
    let mut truncated = String::with_capacity(value.len().min(max_utf8_bytes));
    let mut utf16_units = 0usize;
    for character in value.chars() {
        let next_utf8_bytes = truncated.len().saturating_add(character.len_utf8());
        let next_utf16_units = utf16_units.saturating_add(character.len_utf16());
        if next_utf8_bytes > max_utf8_bytes || next_utf16_units > max_utf16_units {
            break;
        }
        truncated.push(character);
        utf16_units = next_utf16_units;
    }
    truncated
}

fn is_file_name_unsafe(character: char) -> bool {
    matches!(
        character,
        '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
    )
}

fn is_legacy_control(character: char) -> bool {
    matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f)
}

fn is_windows_reserved_device_name(value: &str) -> bool {
    let base = value.split('.').next().unwrap_or(value);
    let lower = base.to_ascii_lowercase();
    if matches!(lower.as_str(), "con" | "prn" | "aux" | "nul") {
        return true;
    }
    let mut chars = lower.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let suffix: String = chars.collect();
    matches!(prefix.as_str(), "com" | "lpt")
        && matches!(
            suffix.as_str(),
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[derive(Clone, Default, PartialEq, Eq)]
struct Style {
    foreground: Option<String>,
    background: Option<String>,
    bold: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
}

#[derive(Clone)]
struct Cell {
    character: char,
    style: Style,
}

impl Cell {
    fn blank() -> Self {
        Self {
            character: ' ',
            style: Style::default(),
        }
    }
}

#[derive(Clone)]
struct PendingClearedScreen {
    lines: Vec<Vec<Cell>>,
    base_row: usize,
    cell_count: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ParserState {
    #[default]
    Normal,
    Escape,
    Csi,
    CsiDiscard,
    Osc,
    OscEscape,
}

#[derive(Default)]
struct TerminalTextRenderer {
    lines: Vec<Vec<Cell>>,
    row: usize,
    column: usize,
    screen_base_row: usize,
    state: ParserState,
    escape_buffer: String,
    style: Style,
    cursor_moved_home_by_csi: bool,
    just_started_log_screen: bool,
    has_preserved_screen_history: bool,
    pending_cleared_screen: Option<PendingClearedScreen>,
    alternate_screen_active: bool,
    stored_cell_count: usize,
}

impl TerminalTextRenderer {
    fn feed(&mut self, input: &str) {
        self.ensure_line();
        for character in input.chars() {
            self.consume(character);
        }
    }

    fn finish(&mut self) {
        self.state = ParserState::Normal;
        self.escape_buffer.clear();
        self.commit_pending_cleared_screen();
    }

    fn consume(&mut self, character: char) {
        match self.state {
            ParserState::Escape => {
                self.consume_escape(character);
                return;
            }
            ParserState::Csi => {
                if self.escape_buffer.len() >= MAX_CSI_BYTES {
                    self.escape_buffer.clear();
                    self.state = if is_csi_final(character) {
                        ParserState::Normal
                    } else {
                        ParserState::CsiDiscard
                    };
                    return;
                }
                self.escape_buffer.push(character);
                if is_csi_final(character) {
                    let sequence = std::mem::take(&mut self.escape_buffer);
                    self.apply_csi(&sequence);
                    self.state = ParserState::Normal;
                }
                return;
            }
            ParserState::CsiDiscard => {
                if is_csi_final(character) {
                    self.state = ParserState::Normal;
                }
                return;
            }
            ParserState::Osc => {
                if character == '\u{7}' {
                    self.state = ParserState::Normal;
                } else if character == '\u{1b}' {
                    self.state = ParserState::OscEscape;
                }
                return;
            }
            ParserState::OscEscape => {
                self.state = if character == '\\' {
                    ParserState::Normal
                } else {
                    ParserState::Osc
                };
                return;
            }
            ParserState::Normal => {}
        }

        match character {
            '\u{1b}' => {
                self.state = ParserState::Escape;
                self.escape_buffer.clear();
            }
            '\u{9b}' => {
                self.state = ParserState::Csi;
                self.escape_buffer.clear();
            }
            '\u{8}' if !self.alternate_screen_active => {
                self.column = self.column.saturating_sub(1);
            }
            '\r' if !self.alternate_screen_active => {
                self.column = 0;
                self.cursor_moved_home_by_csi = false;
            }
            '\n' if !self.alternate_screen_active => {
                if self.row + 1 < MAX_VIRTUAL_ROWS {
                    self.row += 1;
                    self.column = 0;
                    self.ensure_line();
                }
                self.cursor_moved_home_by_csi = false;
            }
            '\t' if !self.alternate_screen_active => {
                let spaces = 8 - (self.column % 8);
                for _ in 0..spaces {
                    self.write_character(' ');
                }
            }
            _ if self.alternate_screen_active => {}
            _ if is_terminal_printable(character) => self.write_character(character),
            _ => {}
        }
    }

    fn consume_escape(&mut self, character: char) {
        match character {
            '[' => self.state = ParserState::Csi,
            ']' => self.state = ParserState::Osc,
            'c' => {
                self.apply_ris_reset();
                self.state = ParserState::Normal;
            }
            _ => self.state = ParserState::Normal,
        }
        self.escape_buffer.clear();
    }

    fn apply_ris_reset(&mut self) {
        self.alternate_screen_active = false;
        self.style = Style::default();
        self.pending_cleared_screen = None;
        while self
            .lines
            .last()
            .is_some_and(|line| trimmed_line_length(line) == 0)
        {
            if let Some(line) = self.lines.pop() {
                self.stored_cell_count = self.stored_cell_count.saturating_sub(line.len());
            }
        }
        if self.lines.is_empty() {
            self.lines.push(Vec::new());
            self.row = 0;
            self.column = 0;
            self.screen_base_row = 0;
            self.has_preserved_screen_history = false;
        } else if self.lines.len() < MAX_VIRTUAL_ROWS {
            self.lines.push(Vec::new());
            self.screen_base_row = self.lines.len() - 1;
            self.row = self.screen_base_row;
            self.column = 0;
            self.has_preserved_screen_history = true;
        }
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
    }

    fn apply_csi(&mut self, sequence: &str) {
        let Some(final_character) = sequence.chars().last() else {
            return;
        };
        let params = &sequence[..sequence.len() - final_character.len_utf8()];
        let private_mode = params.contains('?');
        let cleaned: String = params
            .chars()
            .filter(|character| !matches!(character, '?' | '>' | '<' | '='))
            .collect();
        let values: Vec<Option<usize>> = cleaned
            .split(';')
            .map(|part| {
                if part.is_empty() {
                    None
                } else {
                    part.parse::<usize>().ok()
                }
            })
            .collect();
        let first = values
            .first()
            .copied()
            .flatten()
            .filter(|value| *value != 0)
            .unwrap_or(1);

        if matches!(final_character, 'h' | 'l')
            && private_mode
            && values
                .iter()
                .flatten()
                .any(|value| matches!(*value, 47 | 1047 | 1049))
        {
            self.alternate_screen_active = final_character == 'h';
            return;
        }
        if self.alternate_screen_active {
            return;
        }

        match final_character {
            'A' => {
                self.row = self.row.saturating_sub(first).max(self.screen_base_row);
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            'B' | 'E' => {
                if let Some(target) = self.row.checked_add(first) {
                    if target < MAX_VIRTUAL_ROWS {
                        self.row = target;
                        if final_character == 'E' {
                            self.column = 0;
                        }
                        self.ensure_line();
                    }
                }
                self.cursor_moved_home_by_csi = false;
            }
            'C' => {
                if let Some(target) = self.column.checked_add(first) {
                    if target < MAX_VIRTUAL_COLUMNS {
                        self.column = target;
                    }
                }
                self.cursor_moved_home_by_csi = false;
            }
            'D' => {
                self.column = self.column.saturating_sub(first);
                self.cursor_moved_home_by_csi = false;
            }
            'F' => {
                self.row = self.row.saturating_sub(first).max(self.screen_base_row);
                self.column = 0;
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            'G' => {
                let target = first.saturating_sub(1);
                if target < MAX_VIRTUAL_COLUMNS {
                    self.column = target;
                }
                self.cursor_moved_home_by_csi = false;
            }
            'H' | 'f' => {
                let relative_row = values
                    .first()
                    .copied()
                    .flatten()
                    .filter(|value| *value != 0)
                    .unwrap_or(1)
                    .saturating_sub(1);
                let target_row = self.screen_base_row.checked_add(relative_row);
                let target_column = values
                    .get(1)
                    .copied()
                    .flatten()
                    .filter(|value| *value != 0)
                    .unwrap_or(1)
                    .saturating_sub(1);
                if let Some(target_row) = target_row {
                    if target_row < MAX_VIRTUAL_ROWS && target_column < MAX_VIRTUAL_COLUMNS {
                        self.row = target_row;
                        self.column = target_column;
                        self.ensure_line();
                    }
                }
                self.cursor_moved_home_by_csi =
                    self.row == self.screen_base_row && self.column == 0;
            }
            'J' => self.erase_display(values.first().copied().flatten().unwrap_or(0)),
            'K' => self.erase_line(values.first().copied().flatten().unwrap_or(0)),
            'm' => self.apply_sgr(&values),
            _ => {}
        }
    }

    fn apply_sgr(&mut self, values: &[Option<usize>]) {
        let default = [Some(0)];
        let codes = if values.is_empty() {
            &default[..]
        } else {
            values
        };
        let mut index = 0;
        while index < codes.len() {
            let code = codes[index].unwrap_or(0);
            match code {
                0 => self.style = Style::default(),
                1 => self.style.bold = true,
                3 => self.style.italic = true,
                4 => self.style.underline = true,
                7 => self.style.inverse = true,
                22 => self.style.bold = false,
                23 => self.style.italic = false,
                24 => self.style.underline = false,
                27 => self.style.inverse = false,
                30..=37 => self.style.foreground = Some(BASIC_COLORS[code - 30].to_owned()),
                39 => self.style.foreground = None,
                40..=47 => self.style.background = Some(BASIC_COLORS[code - 40].to_owned()),
                49 => self.style.background = None,
                90..=97 => self.style.foreground = Some(BRIGHT_COLORS[code - 90].to_owned()),
                100..=107 => self.style.background = Some(BRIGHT_COLORS[code - 100].to_owned()),
                38 | 48 if codes.get(index + 1).copied().flatten() == Some(5) => {
                    if let Some(color) = codes
                        .get(index + 2)
                        .copied()
                        .flatten()
                        .and_then(color_from_ansi_256)
                    {
                        if code == 38 {
                            self.style.foreground = Some(color);
                        } else {
                            self.style.background = Some(color);
                        }
                    }
                    index += 2;
                }
                38 | 48 if codes.get(index + 1).copied().flatten() == Some(2) => {
                    let color = color_from_rgb(
                        codes.get(index + 2).copied().flatten(),
                        codes.get(index + 3).copied().flatten(),
                        codes.get(index + 4).copied().flatten(),
                    );
                    if let Some(color) = color {
                        if code == 38 {
                            self.style.foreground = Some(color);
                        } else {
                            self.style.background = Some(color);
                        }
                    }
                    index += 4;
                }
                _ => {}
            }
            index += 1;
        }
    }

    fn write_character(&mut self, character: char) {
        if self.column >= MAX_VIRTUAL_COLUMNS {
            return;
        }
        self.ensure_line();
        let current_line_length = self.lines[self.row].len();
        let additional_cells = self
            .column
            .saturating_add(1)
            .saturating_sub(current_line_length);
        if self.virtual_cell_count().saturating_add(additional_cells) > MAX_VIRTUAL_CELLS {
            return;
        }
        let line = &mut self.lines[self.row];
        while line.len() < self.column {
            line.push(Cell::blank());
        }
        let cell = Cell {
            character,
            style: self.style.clone(),
        };
        if self.column < line.len() {
            line[self.column] = cell;
        } else {
            line.push(cell);
        }
        self.stored_cell_count = self.stored_cell_count.saturating_add(additional_cells);
        self.column += 1;
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = false;
    }

    fn erase_line(&mut self, mode: usize) {
        self.ensure_line();
        let line = &mut self.lines[self.row];
        match mode {
            1 => {
                for cell in line.iter_mut().take(self.column.saturating_add(1)) {
                    *cell = Cell::blank();
                }
            }
            2 => {
                let removed = line.len();
                *line = Vec::new();
                self.stored_cell_count = self.stored_cell_count.saturating_sub(removed);
            }
            _ => {
                let new_length = line.len().min(self.column);
                let removed = line.len() - new_length;
                if removed > 0 {
                    *line = line[..new_length].to_vec();
                }
                self.stored_cell_count = self.stored_cell_count.saturating_sub(removed);
            }
        }
    }

    fn erase_display(&mut self, mode: usize) {
        self.ensure_line();
        if mode == 3 {
            if self.pending_cleared_screen.is_some() {
                self.commit_pending_cleared_screen();
            } else {
                self.pending_cleared_screen = None;
            }
            return;
        }
        if mode == 2 {
            if self.has_preserved_screen_history {
                self.clear_current_log_screen(true);
            } else {
                self.start_new_log_screen();
            }
            return;
        }
        if mode == 1 {
            for index in self.screen_base_row..self.row.min(self.lines.len()) {
                self.clear_line(index);
            }
            self.erase_line(1);
            return;
        }
        if self.row == self.screen_base_row
            && self.column == 0
            && self.cursor_moved_home_by_csi
            && !self.has_preserved_screen_history
        {
            self.start_new_log_screen();
            return;
        }
        self.erase_line(0);
        let removed = self
            .lines
            .iter()
            .skip(self.row.saturating_add(1))
            .map(Vec::len)
            .sum::<usize>();
        self.lines.truncate(self.row + 1);
        self.stored_cell_count = self.stored_cell_count.saturating_sub(removed);
    }

    fn clear_current_log_screen(&mut self, keep_pending: bool) {
        let target_row = self.row;
        if keep_pending && self.current_log_screen_has_content() {
            let cell_count = self
                .lines
                .iter()
                .skip(self.screen_base_row)
                .map(Vec::len)
                .sum();
            self.pending_cleared_screen = Some(PendingClearedScreen {
                lines: self.lines[self.screen_base_row..].to_vec(),
                base_row: self.screen_base_row,
                cell_count,
            });
        } else if !keep_pending {
            self.pending_cleared_screen = None;
        }
        for index in self.screen_base_row..self.lines.len() {
            self.clear_line(index);
        }
        self.row = self
            .screen_base_row
            .max(target_row)
            .min(MAX_VIRTUAL_ROWS - 1);
        self.ensure_line();
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
    }

    fn commit_pending_cleared_screen(&mut self) {
        let Some(pending) = self.pending_cleared_screen.take() else {
            return;
        };
        let relative_row = self.row.saturating_sub(pending.base_row);
        let column = self.column;
        let (lines, screen_base_row) = self.build_lines_with_pending_cleared_screen(&pending);
        self.lines = lines;
        self.screen_base_row = screen_base_row.min(MAX_VIRTUAL_ROWS - 1);
        self.row = self
            .screen_base_row
            .saturating_add(relative_row)
            .min(MAX_VIRTUAL_ROWS - 1);
        self.column = column;
        self.ensure_line();
        self.stored_cell_count = self.lines.iter().map(Vec::len).sum();
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
        self.has_preserved_screen_history = true;
    }

    fn build_lines_with_pending_cleared_screen(
        &self,
        pending: &PendingClearedScreen,
    ) -> (Vec<Vec<Cell>>, usize) {
        let prefix_end = pending.base_row.min(self.lines.len());
        let mut lines = self.lines[..prefix_end].to_vec();
        let mut pending_lines = pending.lines.clone();
        trim_trailing_blank_lines(&mut pending_lines);
        lines.extend(pending_lines);
        lines.push(Vec::new());
        let screen_base_row = lines.len();
        if pending.base_row < self.lines.len() {
            lines.extend(self.lines[pending.base_row..].iter().cloned());
        } else {
            lines.push(Vec::new());
        }
        lines.truncate(MAX_VIRTUAL_ROWS);
        (lines, screen_base_row.min(MAX_VIRTUAL_ROWS - 1))
    }

    fn start_new_log_screen(&mut self) {
        if self.just_started_log_screen {
            return;
        }
        let has_content = self.lines.iter().any(|line| trimmed_line_length(line) > 0);
        if has_content && self.lines.len() < MAX_VIRTUAL_ROWS {
            self.lines.push(Vec::new());
            self.row = self.lines.len() - 1;
        } else if !has_content {
            self.lines.clear();
            self.lines.push(Vec::new());
            self.stored_cell_count = 0;
            self.row = 0;
        }
        self.screen_base_row = self.row;
        self.column = 0;
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
        self.has_preserved_screen_history = has_content;
        self.pending_cleared_screen = None;
    }

    fn current_log_screen_has_content(&self) -> bool {
        self.lines
            .iter()
            .skip(self.screen_base_row)
            .any(|line| trimmed_line_length(line) > 0)
    }

    fn ensure_line(&mut self) {
        self.row = self.row.min(MAX_VIRTUAL_ROWS - 1);
        while self.lines.len() <= self.row {
            self.lines.push(Vec::new());
        }
    }

    fn clear_line(&mut self, index: usize) {
        let removed = self.lines[index].len();
        self.lines[index] = Vec::new();
        self.stored_cell_count = self.stored_cell_count.saturating_sub(removed);
    }

    fn virtual_cell_count(&self) -> usize {
        self.stored_cell_count.saturating_add(
            self.pending_cleared_screen
                .as_ref()
                .map_or(0, |pending| pending.cell_count),
        )
    }

    fn to_plain_text(&self) -> String {
        let mut rendered = String::new();
        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 && !push_bounded_str(&mut rendered, "\n") {
                break;
            }
            let length = line
                .iter()
                .rposition(|cell| !matches!(cell.character, ' ' | '\t'))
                .map_or(0, |position| position + 1);
            for cell in &line[..length] {
                if !push_bounded_char(&mut rendered, cell.character) {
                    break;
                }
            }
            if rendered.len() >= MAX_RENDERED_CONTENT_BYTES {
                break;
            }
        }
        while rendered.ends_with('\n') {
            rendered.pop();
        }
        rendered
    }

    fn to_html_content(&self) -> String {
        let mut rendered = String::new();
        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 && !push_bounded_str(&mut rendered, "\n") {
                break;
            }
            if !render_line_html(&mut rendered, line) {
                break;
            }
        }
        while rendered.ends_with('\n') {
            rendered.pop();
        }
        rendered
    }
}

fn is_csi_final(character: char) -> bool {
    ('@'..='~').contains(&character)
}

fn is_terminal_printable(character: char) -> bool {
    character as u32 >= 0x20 && character != '\u{7f}'
}

fn trim_trailing_blank_lines(lines: &mut Vec<Vec<Cell>>) {
    while lines
        .last()
        .is_some_and(|line| trimmed_line_length(line) == 0)
    {
        lines.pop();
    }
}

fn trimmed_line_length(line: &[Cell]) -> usize {
    let mut length = line.len();
    while length > 0 {
        let cell = &line[length - 1];
        if !matches!(cell.character, ' ' | '\t') || !style_to_css(&cell.style).is_empty() {
            break;
        }
        length -= 1;
    }
    length
}

fn render_line_html(output: &mut String, line: &[Cell]) -> bool {
    let length = trimmed_line_length(line);
    let mut start = 0;
    while start < length {
        let style = &line[start].style;
        let mut end = start + 1;
        while end < length && line[end].style == *style {
            end += 1;
        }
        if !push_html_run(output, &line[start..end], style) {
            return false;
        }
        start = end;
    }
    true
}

fn push_html_run(output: &mut String, cells: &[Cell], style: &Style) -> bool {
    let css = style_to_css(style);
    if css.is_empty() {
        for cell in cells {
            if !push_bounded_escaped_char(output, cell.character, 0) {
                return false;
            }
        }
        return true;
    }

    const CLOSE: &str = "</span>";
    let open = format!("<span style=\"{css}\">");
    let Some(first) = cells.first() else {
        return true;
    };
    let required = open
        .len()
        .saturating_add(escaped_html_char_len(first.character))
        .saturating_add(CLOSE.len());
    if output.len().saturating_add(required) > MAX_RENDERED_CONTENT_BYTES {
        return false;
    }

    output.push_str(&open);
    for cell in cells {
        if !push_bounded_escaped_char(output, cell.character, CLOSE.len()) {
            output.push_str(CLOSE);
            return false;
        }
    }
    output.push_str(CLOSE);
    true
}

fn push_bounded_str(output: &mut String, value: &str) -> bool {
    if output.len().saturating_add(value.len()) > MAX_RENDERED_CONTENT_BYTES {
        return false;
    }
    output.push_str(value);
    true
}

fn push_bounded_char(output: &mut String, character: char) -> bool {
    if output.len().saturating_add(character.len_utf8()) > MAX_RENDERED_CONTENT_BYTES {
        return false;
    }
    output.push(character);
    true
}

fn push_bounded_escaped_char(output: &mut String, character: char, reserved: usize) -> bool {
    let needed = escaped_html_char_len(character).saturating_add(reserved);
    if output.len().saturating_add(needed) > MAX_RENDERED_CONTENT_BYTES {
        return false;
    }
    match character {
        '&' => output.push_str("&amp;"),
        '<' => output.push_str("&lt;"),
        '>' => output.push_str("&gt;"),
        '"' => output.push_str("&quot;"),
        '\'' => output.push_str("&#039;"),
        _ => output.push(character),
    }
    true
}

const fn escaped_html_char_len(character: char) -> usize {
    match character {
        '&' => 5,
        '<' | '>' => 4,
        '"' | '\'' => 6,
        _ => character.len_utf8(),
    }
}

fn style_to_css(style: &Style) -> String {
    let foreground = if style.inverse {
        style.background.as_deref().or(Some(DEFAULT_BACKGROUND))
    } else {
        style.foreground.as_deref()
    };
    let background = if style.inverse {
        style.foreground.as_deref().or(Some(DEFAULT_FOREGROUND))
    } else {
        style.background.as_deref()
    };
    let mut declarations = Vec::new();
    if let Some(color) = foreground {
        declarations.push(format!("color: {color}"));
    }
    if let Some(color) = background {
        declarations.push(format!("background-color: {color}"));
    }
    if style.bold {
        declarations.push("font-weight: 700".to_owned());
    }
    if style.italic {
        declarations.push("font-style: italic".to_owned());
    }
    if style.underline {
        declarations.push("text-decoration: underline".to_owned());
    }
    declarations.join("; ")
}

fn color_from_ansi_256(value: usize) -> Option<String> {
    match value {
        0..=7 => Some(BASIC_COLORS[value].to_owned()),
        8..=15 => Some(BRIGHT_COLORS[value - 8].to_owned()),
        16..=231 => {
            let value = value - 16;
            color_from_rgb(
                Some(color_cube_value(value / 36)),
                Some(color_cube_value((value % 36) / 6)),
                Some(color_cube_value(value % 6)),
            )
        }
        232..=255 => {
            let level = 8 + (value - 232) * 10;
            color_from_rgb(Some(level), Some(level), Some(level))
        }
        _ => None,
    }
}

const fn color_cube_value(value: usize) -> usize {
    if value == 0 { 0 } else { 55 + value * 40 }
}

fn color_from_rgb(red: Option<usize>, green: Option<usize>, blue: Option<usize>) -> Option<String> {
    let (red, green, blue) = (red?, green?, blue?);
    if red > 255 || green > 255 || blue > 255 {
        return None;
    }
    Some(format!("#{red:02x}{green:02x}{blue:02x}"))
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#039;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{
        ExportFormat, HtmlExportLabels, LocalDateTime, MAX_CSI_BYTES,
        MAX_PORTABLE_FILE_NAME_UTF8_BYTES, MAX_PORTABLE_FILE_NAME_UTF16_UNITS,
        MAX_RENDERED_CONTENT_BYTES, MAX_VIRTUAL_CELLS, MAX_VIRTUAL_COLUMNS, MAX_VIRTUAL_ROWS,
        TerminalTextRenderer, default_export_file_name, export_format_for_path, render_export,
        render_export_with_html_labels, render_html, render_html_content, render_html_with_labels,
        render_plain_text, safe_path_segment,
    };
    use std::path::Path;

    #[test]
    fn final_extension_selects_format_case_sensitively() {
        assert_eq!(
            export_format_for_path(Path::new("chosen.html"), ExportFormat::PlainText),
            ExportFormat::Html
        );
        assert_eq!(
            export_format_for_path(Path::new("chosen.log"), ExportFormat::PlainText),
            ExportFormat::Raw
        );
        assert_eq!(
            export_format_for_path(Path::new("chosen.raw"), ExportFormat::Html),
            ExportFormat::Raw
        );
        assert_eq!(
            export_format_for_path(Path::new("chosen.HTML"), ExportFormat::Html),
            ExportFormat::PlainText
        );
        assert_eq!(
            export_format_for_path(Path::new("chosen"), ExportFormat::Raw),
            ExportFormat::Raw
        );
    }

    #[test]
    fn default_name_preserves_unicode_and_sanitizes_legacy_unsafe_characters() {
        let local = LocalDateTime::new(2026, 1, 2, 3, 4, 5).expect("local time");
        assert_eq!(
            default_export_file_name(
                "生产/服务器:东京*?<>|\0",
                "fallback.example",
                local,
                ExportFormat::PlainText,
            ),
            "生产_服务器_东京_______2026-01-02T03-04-05.txt"
        );
        assert_eq!(
            default_export_file_name("", "主机.example", local, ExportFormat::Raw),
            "主机.example_2026-01-02T03-04-05.log"
        );
    }

    #[test]
    fn safe_segments_replace_controls_tail_dots_and_windows_devices() {
        assert_eq!(
            safe_path_segment("\t生产服务器\n", "fallback"),
            "_生产服务器_"
        );
        assert_eq!(
            safe_path_segment("生产\u{85}服务器\u{9b}", "fallback"),
            "生产_服务器_"
        );
        assert_eq!(safe_path_segment("../name", "fallback"), ".._name");
        assert_eq!(safe_path_segment("CON", "fallback"), "CON_");
        assert_eq!(safe_path_segment("COM¹", "fallback"), "COM¹_");
        assert_eq!(safe_path_segment("LPT².txt", "fallback"), "LPT².txt_");
        assert_eq!(safe_path_segment("prod.", "fallback"), "prod_");
        assert_eq!(safe_path_segment("prod..", "fallback"), "prod__");
        assert_eq!(safe_path_segment("   ", "fallback"), "fallback");
        assert_eq!(safe_path_segment("..", "../bad"), ".._bad");
    }

    #[test]
    fn default_names_bound_long_unicode_for_windows_and_unix_components() {
        let local = LocalDateTime::new(2026, 1, 2, 3, 4, 5).expect("local time");
        let suffix = "_2026-01-02T03-04-05.html";
        for label in ["a".repeat(4_096), "界".repeat(2_000), "😀".repeat(2_000)] {
            let file_name = default_export_file_name(&label, "fallback", local, ExportFormat::Html);
            assert!(file_name.ends_with(suffix));
            assert!(file_name.len() <= MAX_PORTABLE_FILE_NAME_UTF8_BYTES);
            assert!(
                file_name.encode_utf16().count() <= MAX_PORTABLE_FILE_NAME_UTF16_UNITS,
                "file_name={file_name:?}"
            );
            assert!(file_name.is_char_boundary(file_name.len()));
        }
    }

    #[test]
    fn truncation_reapplies_trailing_dot_and_windows_device_protection() {
        let local = LocalDateTime::new(2026, 1, 2, 3, 4, 5).expect("local time");
        let suffix = "_2026-01-02T03-04-05.txt";

        let exposed_dot = format!("{}.tail", "a".repeat(229));
        let dotted =
            default_export_file_name(&exposed_dot, "fallback", local, ExportFormat::PlainText);
        let dotted_segment = dotted.strip_suffix(suffix).expect("timestamp suffix");
        assert!(dotted_segment.ends_with('_'));

        let reserved = format!("CON.{}", "a".repeat(4_096));
        let device =
            default_export_file_name(&reserved, "fallback", local, ExportFormat::PlainText);
        let device_segment = device.strip_suffix(suffix).expect("timestamp suffix");
        assert!(device_segment.ends_with('_'));
        assert!(device.len() <= MAX_PORTABLE_FILE_NAME_UTF8_BYTES);
        assert!(device.encode_utf16().count() <= MAX_PORTABLE_FILE_NAME_UTF16_UNITS);
    }

    #[test]
    fn local_date_time_is_explicit_and_calendar_checked() {
        assert_eq!(
            LocalDateTime::new(2024, 2, 29, 23, 59, 59)
                .expect("leap date")
                .file_name_component(),
            "2024-02-29T23-59-59"
        );
        assert!(LocalDateTime::new(2023, 2, 29, 0, 0, 0).is_err());
        assert!(LocalDateTime::new(2026, 1, 1, 24, 0, 0).is_err());
    }

    #[test]
    fn plain_text_applies_line_editing_and_removes_osc() {
        assert_eq!(render_plain_text("hellp\u{8}o\n"), "hello");
        assert_eq!(
            render_plain_text("progress 10%\rprogress 100%\n"),
            "progress 100%"
        );
        assert_eq!(render_plain_text("loading...\r\u{1b}[Kdone\n"), "done");
        assert_eq!(
            render_plain_text("before\u{1b}]0;secret title\u{7}after\n"),
            "beforeafter"
        );
    }

    #[test]
    fn split_csi_and_osc_sequences_remain_stateful_and_do_not_leak_payloads() {
        let mut renderer = TerminalTextRenderer::default();
        renderer.feed("red \u{1b}[");
        renderer.feed("31mtext\u{1b}[0m before\u{1b}]0;private");
        renderer.feed(" title\u{7}after\n");
        renderer.finish();
        assert_eq!(renderer.to_plain_text(), "red text beforeafter");
        let html = renderer.to_html_content();
        assert!(html.contains("color: #cd3131"));
        assert!(!html.contains("private"));
        assert!(!html.contains('\u{1b}'));
    }

    #[test]
    fn incomplete_and_overlong_escape_sequences_are_fully_discarded() {
        assert_eq!(render_plain_text("safe\u{1b}[31"), "safe");
        assert_eq!(render_plain_text("safe\u{1b}]0;private title"), "safe");

        let terminal = format!("safe\u{1b}[{}mvisible", "1".repeat(5_000));
        assert_eq!(render_plain_text(&terminal), "safevisible");

        for parameter_bytes in [MAX_CSI_BYTES - 1, MAX_CSI_BYTES, MAX_CSI_BYTES + 1] {
            let terminal = format!("safe\u{1b}[{}mvisible", "1".repeat(parameter_bytes));
            assert_eq!(
                render_plain_text(&terminal),
                "safevisible",
                "parameter_bytes={parameter_bytes}"
            );
        }
    }

    #[test]
    fn cursor_expansion_is_bounded_by_the_global_cell_and_output_budgets() {
        let mut terminal = String::new();
        let complete_rows = MAX_VIRTUAL_CELLS / MAX_VIRTUAL_COLUMNS;
        for _ in 0..(complete_rows + 2) {
            terminal.push_str(&format!("\u{1b}[{MAX_VIRTUAL_COLUMNS}Gx\n"));
        }
        assert!(terminal.len() < 2_048);

        let plain = render_plain_text(&terminal);
        assert!(plain.len() <= MAX_VIRTUAL_CELLS + MAX_VIRTUAL_ROWS);
        assert_eq!(plain.matches('x').count(), complete_rows);
        assert!(plain.len() <= MAX_RENDERED_CONTENT_BYTES);
        drop(plain);

        let html = render_html_content(&terminal);
        assert!(html.len() <= MAX_RENDERED_CONTENT_BYTES);
        assert_eq!(html.matches('x').count(), complete_rows);
    }

    #[test]
    fn sparse_cursor_axes_do_not_materialize_million_cell_or_row_gaps() {
        let wide = "\u{1b}[1000000Gx";
        assert_eq!(wide.len(), 11);
        assert_eq!(render_plain_text(wide), "x");

        let tall = "\u{1b}[100000Hrow";
        assert_eq!(render_plain_text(tall), "row");
    }

    #[test]
    fn erased_sparse_lines_release_capacity_before_the_global_budget_is_reused() {
        let mut renderer = TerminalTextRenderer::default();
        for _ in 0..4 {
            renderer.feed(&format!("\u{1b}[{MAX_VIRTUAL_COLUMNS}Gx\r\u{1b}[K\n"));
        }
        assert_eq!(renderer.stored_cell_count, 0);
        assert_eq!(renderer.lines.iter().map(Vec::capacity).sum::<usize>(), 0);
    }

    #[test]
    fn screen_clear_preserves_shell_history_without_duplicate_separator() {
        assert_eq!(
            render_plain_text("login banner\n$ tmux\n\u{1b}[H\u{1b}[2Jtmux pane\n"),
            "login banner\n$ tmux\n\ntmux pane"
        );
        assert_eq!(
            render_plain_text("login banner\n$ clear\n\u{1b}[H\u{1b}[2J\u{1b}[3Jafter clear\n"),
            "login banner\n$ clear\n\nafter clear"
        );
        assert_eq!(
            render_plain_text("before tui\n\u{1b}[H\u{1b}[Jframe one\n\u{1b}[H\u{1b}[Jframe two\n"),
            "before tui\n\nframe two"
        );
    }

    #[test]
    fn legacy_screen_editing_regression_matrix_matches_visible_log_history() {
        let cases = [
            ("progress 10%\r\u{1b}[Jprogress 20%\n", "progress 20%"),
            ("old1\nold2\n\u{1b}[2J\u{1b}[Hnew\n", "old1\nold2\n\nnew"),
            ("old\n\u{1b}[2Jnew\u{1b}[1Jafter\n", "old\n\n   after"),
            (
                "before zellij\n$ zellij\n\u{1b}[H\u{1b}[Jzellij pane\n",
                "before zellij\n$ zellij\n\nzellij pane",
            ),
            (
                "before tui\n\u{1b}[H\u{1b}[2Jframe one\n\u{1b}[H\u{1b}[2Jframe two\n",
                "before tui\n\nframe one\n\nframe two",
            ),
            (
                "before tui\n\u{1b}[2Jframe one\r\u{1b}[2Jframe two\n",
                "before tui\n\nframe one\n\nframe two",
            ),
            (
                "before\n\u{1b}[2Jfirst\u{1b}[2J\u{1b}[2Jsecond\n",
                "before\n\nfirst\n\n     second",
            ),
            (
                "before\n\u{1b}[H\u{1b}[2Jone\n\u{1b}[H\u{1b}[2Jtwo\n",
                "before\n\none\n\ntwo",
            ),
            (
                "before tui\n\u{1b}[H\u{1b}[2Jframe one\n\u{1b}[H\u{1b}[2Jframe two\n\u{1b}[H\u{1b}[2Jframe three\n",
                "before tui\n\nframe two\n\nframe three",
            ),
            (
                "before\n\u{1b}[H\u{1b}[2Jone\n\u{1b}[2J\u{1b}[10;5Htext\n",
                "before\n\none\n\n\n\n\n\n\n\n\n\n\n    text",
            ),
            (
                "before\n\u{1b}[H\u{1b}[2Jfirst screen\n\u{1b}[H\u{1b}[2J\u{1b}[3Jsecond screen\n",
                "before\n\nfirst screen\n\nsecond screen",
            ),
            (
                "before\n\u{1b}[H\u{1b}[2Jscreen\n\u{1b}[3Jafter\n",
                "before\n\nscreen\nafter",
            ),
        ];
        for (terminal, expected) in cases {
            assert_eq!(
                render_plain_text(terminal),
                expected,
                "terminal={terminal:?}"
            );
        }
    }

    #[test]
    fn alternate_screen_and_ris_keep_shell_history_only() {
        assert_eq!(
            render_plain_text("$ vim file\n\u{1b}[?1049h~\nstatus\u{1b}[?1049l$ ls\n"),
            "$ vim file\n$ ls"
        );
        assert_eq!(
            render_plain_text("before\n\u{9b}?47hTUI\n\u{9b}?47lafter\n"),
            "before\nafter"
        );
        assert_eq!(
            render_plain_text("before\u{1b}[?1049hTUI\u{1b}cshell-after\n"),
            "before\nshell-after"
        );
        assert_eq!(
            render_plain_text("shell\n\u{1b}[?47hTUI\n\u{1b}[?47lafter\n"),
            "shell\nafter"
        );
        assert_eq!(
            render_plain_text("shell\n\u{1b}[?1047hTUI\n\u{1b}[?1047lafter\n"),
            "shell\nafter"
        );
        assert_eq!(
            render_plain_text("before\n\u{9b}?1049hTUI\n\u{9b}?1049lafter\n"),
            "before\nafter"
        );
        assert_eq!(
            render_plain_text("before\u{1b}cshell\u{1b}[Hnew"),
            "before\nnewll"
        );
    }

    #[test]
    fn html_escapes_metadata_and_content_while_preserving_supported_sgr() {
        let content = render_html_content("<red> \u{1b}[1;31m&\u{1b}[0m\n");
        assert!(content.contains("&lt;red&gt; "));
        assert!(content.contains("color: #cd3131"));
        assert!(content.contains("font-weight: 700"));
        assert!(content.contains("&amp;"));
        assert!(!content.contains('\u{1b}'));

        let document = render_html("done", "host<1>", "1/2/2026 <local>");
        assert!(document.starts_with("<!DOCTYPE html>"));
        assert!(document.contains("host&lt;1&gt;"));
        assert!(document.contains("1/2/2026 &lt;local&gt;"));
        assert!(!document.contains("host<1>"));
    }

    #[test]
    fn localized_html_labels_control_title_headers_and_unknown_host_fallback() {
        let chinese = render_export_with_html_labels(
            ExportFormat::Html,
            "done",
            "",
            "2026-01-02 03:04:05 +08:00",
            HtmlExportLabels::new("会话日志", "主机：", "日期：", "未知主机"),
        );
        assert!(chinese.contains("<title>会话日志 - 未知主机</title>"));
        assert!(chinese.contains("主机：未知主机<br>"));
        assert!(chinese.contains("日期：2026-01-02 03:04:05 +08:00"));
        assert!(!chinese.contains("Session Log"));

        let english = render_export_with_html_labels(
            ExportFormat::Html,
            "done",
            "",
            "2026-01-02 03:04:05 +08:00",
            HtmlExportLabels::new("Session Log", "Host: ", "Date: ", "Unknown"),
        );
        assert!(english.contains("<title>Session Log - Unknown</title>"));
        assert!(english.contains("Host: Unknown<br>"));
        assert!(english.contains("Date: 2026-01-02 03:04:05 +08:00"));
        assert!(!english.contains("会话日志"));
    }

    #[test]
    fn localized_html_labels_are_escaped() {
        let document = render_html_with_labels(
            "done",
            "",
            "date",
            HtmlExportLabels::new("<title>", "H&: ", "D>: ", "<unknown>"),
        );
        assert!(document.contains("<title>&lt;title&gt; - &lt;unknown&gt;</title>"));
        assert!(document.contains("H&amp;: &lt;unknown&gt;<br>"));
        assert!(document.contains("D&gt;: date"));
        assert!(!document.contains("<unknown>"));
    }

    #[test]
    fn html_supports_ansi_256_rgb_inverse_and_style_resets() {
        let content = render_html_content(
            "\u{1b}[38;5;196mred\u{1b}[48;2;1;2;3m bg\u{1b}[7m inverse\u{1b}[0m plain",
        );
        assert!(content.contains("color: #ff0000"));
        assert!(content.contains("background-color: #010203"));
        assert!(content.contains("color: #010203"));
        assert!(content.contains("background-color: #ff0000"));
        assert!(content.ends_with(" plain"));
        assert!(!content.ends_with(" plain</span>"));
    }

    #[test]
    fn unified_renderer_preserves_raw_ansi_exactly() {
        let terminal = "\u{1b}[31mraw\u{1b}[0m\r\n";
        assert_eq!(
            render_export(ExportFormat::Raw, terminal, "host", "date"),
            terminal
        );
        assert_eq!(
            render_export(ExportFormat::PlainText, terminal, "host", "date"),
            "raw"
        );
        assert!(
            render_export(ExportFormat::Html, terminal, "host", "date").contains("color: #cd3131")
        );
    }

    #[test]
    fn hostile_cursor_values_are_bounded() {
        let rendered = render_plain_text("start\u{1b}[999999999;999999999Hend");
        assert!(rendered.len() <= 1_200_000);
        assert!(rendered.contains("start"));
        assert!(rendered.ends_with("end"));
    }
}
