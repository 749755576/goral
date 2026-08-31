use std::{fmt, str::FromStr};

use encoding_rs::{CoderResult, Decoder, Encoding, GB18030, GBK, UTF_8};
use zeroize::Zeroizing;

use crate::MAX_INPUT_BYTES;

/// A safe terminal charset selected from `encoding_rs` labels.
///
/// Empty, unknown, replacement-only and ASCII-incompatible labels deliberately
/// become UTF-8. This keeps terminal control bytes such as CR, ESC and CSI
/// single-byte on the wire.
#[derive(Clone, Copy)]
pub struct TelnetCharset {
    encoding: &'static Encoding,
}

impl TelnetCharset {
    #[allow(non_upper_case_globals)]
    pub const Utf8: Self = Self { encoding: UTF_8 };
    #[allow(non_upper_case_globals)]
    pub const Gb18030: Self = Self { encoding: GB18030 };

    /// Parse and normalize a user/locale charset label, falling back to UTF-8.
    pub fn parse_label(label: &str) -> Self {
        if label.len() > 256 {
            return Self::Utf8;
        }
        let raw = label.trim();
        if raw.is_empty() {
            return Self::Utf8;
        }

        let locale_codeset = raw
            .rsplit_once('.')
            .map(|(_, codeset)| codeset.split('@').next().unwrap_or(codeset));
        for candidate in [Some(raw), locale_codeset].into_iter().flatten() {
            let collapsed = candidate
                .bytes()
                .filter(u8::is_ascii_alphanumeric)
                .map(|byte| byte.to_ascii_lowercase())
                .collect::<Vec<_>>();
            if collapsed == b"utf8" {
                return Self::Utf8;
            }
            if matches!(
                collapsed.as_slice(),
                b"gb18030" | b"gbk" | b"gb2312" | b"cp936" | b"ms936"
            ) {
                return Self::Gb18030;
            }
            if let Some(encoding) = Encoding::for_label_no_replacement(candidate.as_bytes()) {
                if encoding.is_ascii_compatible() {
                    return if encoding == GBK {
                        Self::Gb18030
                    } else {
                        Self { encoding }
                    };
                }
            }
        }
        Self::Utf8
    }

    /// Canonical label suitable for renderer/native round trips.
    pub fn normalized_label(self) -> &'static str {
        if self.encoding == UTF_8 {
            "utf-8"
        } else if self.encoding == GB18030 {
            "gb18030"
        } else {
            canonical_label(self.encoding)
        }
    }

    pub fn normalize_label(label: &str) -> &'static str {
        Self::parse_label(label).normalized_label()
    }

    pub fn is_utf8(self) -> bool {
        self.encoding == UTF_8
    }

    pub(crate) fn decoder(self) -> TerminalDecoder {
        TerminalDecoder {
            decoder: self.encoding.new_decoder_without_bom_handling(),
        }
    }

    pub(crate) fn encode_input(self, utf8: &[u8]) -> Result<Zeroizing<Vec<u8>>, CharsetError> {
        if self.is_utf8() {
            return Ok(Zeroizing::new(utf8.to_vec()));
        }
        let text = std::str::from_utf8(utf8).map_err(|_| CharsetError::InvalidUtf8Input)?;
        let (encoded, _, _) = self.encoding.encode(text);
        if encoded.len() > MAX_INPUT_BYTES {
            return Err(CharsetError::OutputTooLarge);
        }
        Ok(Zeroizing::new(encoded.into_owned()))
    }
}

fn canonical_label(encoding: &'static Encoding) -> &'static str {
    match encoding.name() {
        "Big5" => "big5",
        "EUC-JP" => "euc-jp",
        "EUC-KR" => "euc-kr",
        "IBM866" => "ibm866",
        "ISO-8859-2" => "iso-8859-2",
        "ISO-8859-3" => "iso-8859-3",
        "ISO-8859-4" => "iso-8859-4",
        "ISO-8859-5" => "iso-8859-5",
        "ISO-8859-6" => "iso-8859-6",
        "ISO-8859-7" => "iso-8859-7",
        "ISO-8859-8" => "iso-8859-8",
        "ISO-8859-8-I" => "iso-8859-8-i",
        "ISO-8859-10" => "iso-8859-10",
        "ISO-8859-13" => "iso-8859-13",
        "ISO-8859-14" => "iso-8859-14",
        "ISO-8859-15" => "iso-8859-15",
        "ISO-8859-16" => "iso-8859-16",
        "KOI8-R" => "koi8-r",
        "KOI8-U" => "koi8-u",
        "Shift_JIS" => "shift_jis",
        "x-mac-cyrillic" => "x-mac-cyrillic",
        "x-user-defined" => "x-user-defined",
        // Remaining encoding_rs names are already canonical lowercase labels.
        name => name,
    }
}

impl Default for TelnetCharset {
    fn default() -> Self {
        Self::Utf8
    }
}

impl PartialEq for TelnetCharset {
    fn eq(&self, other: &Self) -> bool {
        self.encoding == other.encoding
    }
}

impl Eq for TelnetCharset {}

impl fmt::Debug for TelnetCharset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TelnetCharset")
            .field(&self.normalized_label())
            .finish()
    }
}

impl fmt::Display for TelnetCharset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.normalized_label())
    }
}

impl FromStr for TelnetCharset {
    type Err = std::convert::Infallible;

    fn from_str(label: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse_label(label))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CharsetError {
    InvalidUtf8Input,
    OutputTooLarge,
}

pub(crate) struct TerminalDecoder {
    decoder: Decoder,
}

impl TerminalDecoder {
    pub(crate) fn decode(&mut self, input: &[u8], last: bool) -> Vec<u8> {
        let capacity = self
            .decoder
            .max_utf8_buffer_length(input.len())
            .unwrap_or_else(|| input.len().saturating_mul(3).saturating_add(3));
        let mut decoded = String::with_capacity(capacity);
        let (result, read, _) = self.decoder.decode_to_string(input, &mut decoded, last);
        debug_assert_eq!(result, CoderResult::InputEmpty);
        debug_assert_eq!(read, input.len());
        decoded.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_and_locale_labels_normalize_safely() {
        for label in [
            "GB18030",
            "gbk",
            "GB2312",
            "gb-18030",
            "cp936",
            "ms936",
            "zh_CN.GBK",
            "zh_CN.GB18030@custom",
        ] {
            assert_eq!(TelnetCharset::normalize_label(label), "gb18030");
        }
        for label in ["", "UTF8", "utf-8", "unknown", "utf-16le", "ucs-2"] {
            assert_eq!(TelnetCharset::normalize_label(label), "utf-8");
        }
    }

    #[test]
    fn encoding_rs_ascii_supersets_are_supported() {
        for label in [
            "big5",
            "shift_jis",
            "euc-jp",
            "euc-kr",
            "latin1",
            "windows-1252",
            "ja_JP.Shift_JIS",
        ] {
            let charset = TelnetCharset::parse_label(label);
            assert!(!charset.is_utf8(), "{label}");
            assert_eq!(
                charset.encode_input(b"\x1b[A\r\x03").unwrap().as_slice(),
                b"\x1b[A\r\x03"
            );
        }
        assert_eq!(TelnetCharset::normalize_label("BIG5"), "big5");
        assert_eq!(TelnetCharset::normalize_label("Shift-JIS"), "shift_jis");
    }

    #[test]
    fn gb18030_is_stateful_across_frames_and_symmetric() {
        let charset = TelnetCharset::Gb18030;
        let text = "你好世界\r";
        let wire = charset.encode_input(text.as_bytes()).unwrap();
        assert_ne!(wire.as_slice(), text.as_bytes());
        let split = wire.len() - 2;
        let mut decoder = charset.decoder();
        let mut output = decoder.decode(&wire[..split], false);
        output.extend(decoder.decode(&wire[split..], false));
        assert_eq!(output, text.as_bytes());
    }

    #[test]
    fn split_four_byte_gb18030_character_is_not_corrupted() {
        let charset = TelnetCharset::Gb18030;
        let wire = charset.encode_input("💩".as_bytes()).unwrap();
        assert_eq!(wire.len(), 4);
        let mut decoder = charset.decoder();
        assert!(decoder.decode(&wire[..3], false).is_empty());
        assert_eq!(decoder.decode(&wire[3..], false), "💩".as_bytes());
    }
}
