use std::{error::Error, fmt, str::FromStr};

use encoding_rs::{CoderResult, Decoder, Encoding, GB18030, GBK, UTF_8};
use zeroize::Zeroizing;

use crate::MAX_INPUT_BYTES;

/// Safe terminal charset selected from `encoding_rs` labels.
///
/// Unknown, replacement-only, overlong, and ASCII-incompatible labels become
/// UTF-8 so terminal control bytes retain their single-byte wire semantics.
#[derive(Clone, Copy)]
pub struct SerialCharset {
    encoding: &'static Encoding,
}

impl SerialCharset {
    #[allow(non_upper_case_globals)]
    pub const Utf8: Self = Self { encoding: UTF_8 };
    #[allow(non_upper_case_globals)]
    pub const Gb18030: Self = Self { encoding: GB18030 };

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

    /// Create one stateful decoder for a single serial session. It preserves
    /// split multibyte characters and converts only lone LF bytes to CRLF,
    /// including when CR and LF arrive in different device reads.
    pub fn decoder(self) -> SerialDecoder {
        SerialDecoder {
            decoder: self.encoding.new_decoder_without_bom_handling(),
            previous_was_cr: false,
        }
    }

    pub fn encode_input(self, utf8: &[u8]) -> Result<Zeroizing<Vec<u8>>, SerialCharsetError> {
        if utf8.len() > MAX_INPUT_BYTES {
            return Err(SerialCharsetError::OutputTooLarge);
        }
        let text = std::str::from_utf8(utf8).map_err(|_| SerialCharsetError::InvalidUtf8Input)?;
        if self.is_utf8() {
            return Ok(Zeroizing::new(utf8.to_vec()));
        }
        let (encoded, _, _) = self.encoding.encode(text);
        if encoded.len() > MAX_INPUT_BYTES {
            return Err(SerialCharsetError::OutputTooLarge);
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
        name => name,
    }
}

impl Default for SerialCharset {
    fn default() -> Self {
        Self::Utf8
    }
}

impl PartialEq for SerialCharset {
    fn eq(&self, other: &Self) -> bool {
        self.encoding == other.encoding
    }
}

impl Eq for SerialCharset {}

impl fmt::Debug for SerialCharset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SerialCharset")
            .field(&self.normalized_label())
            .finish()
    }
}

impl fmt::Display for SerialCharset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.normalized_label())
    }
}

impl FromStr for SerialCharset {
    type Err = std::convert::Infallible;

    fn from_str(label: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse_label(label))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialCharsetError {
    InvalidUtf8Input,
    OutputTooLarge,
}

impl fmt::Display for SerialCharsetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8Input => formatter.write_str("Serial input is not valid UTF-8"),
            Self::OutputTooLarge => formatter.write_str("Serial encoded input is too large"),
        }
    }
}

impl Error for SerialCharsetError {}

pub struct SerialDecoder {
    decoder: Decoder,
    previous_was_cr: bool,
}

impl SerialDecoder {
    pub fn decode(&mut self, input: &[u8], last: bool) -> Vec<u8> {
        let capacity = self
            .decoder
            .max_utf8_buffer_length(input.len())
            .unwrap_or_else(|| input.len().saturating_mul(3).saturating_add(3));
        let mut decoded = String::with_capacity(capacity);
        let (result, read, _) = self.decoder.decode_to_string(input, &mut decoded, last);
        debug_assert_eq!(result, CoderResult::InputEmpty);
        debug_assert_eq!(read, input.len());
        self.normalize_line_endings(decoded.as_bytes())
    }

    fn normalize_line_endings(&mut self, decoded: &[u8]) -> Vec<u8> {
        let extra = decoded.iter().filter(|&&byte| byte == b'\n').count();
        let mut normalized = Vec::with_capacity(decoded.len().saturating_add(extra));
        for &byte in decoded {
            if byte == b'\n' && !self.previous_was_cr {
                normalized.push(b'\r');
            }
            normalized.push(byte);
            self.previous_was_cr = byte == b'\r';
        }
        normalized
    }
}

impl fmt::Debug for SerialDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialDecoder")
            .field("previous_was_cr", &self.previous_was_cr)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_locale_labels_and_ascii_supersets_normalize_safely() {
        for label in [
            "GB18030",
            "gbk",
            "GB2312",
            "gb-18030",
            "cp936",
            "ms936",
            "zh_CN.GBK",
        ] {
            assert_eq!(SerialCharset::normalize_label(label), "gb18030");
        }
        for label in ["", "UTF8", "utf-8", "unknown", "utf-16le", "ucs-2"] {
            assert_eq!(SerialCharset::normalize_label(label), "utf-8");
        }
        for label in ["big5", "shift_jis", "euc-jp", "euc-kr", "latin1"] {
            let charset = SerialCharset::parse_label(label);
            assert!(!charset.is_utf8(), "{label}");
            assert_eq!(
                charset.encode_input(b"\x1b[A\r\x03").unwrap().as_slice(),
                b"\x1b[A\r\x03"
            );
        }
    }

    #[test]
    fn split_utf8_and_gb18030_characters_are_incremental() {
        let utf8 = "用户名".as_bytes();
        let mut decoder = SerialCharset::Utf8.decoder();
        assert!(decoder.decode(&utf8[..2], false).is_empty());
        assert_eq!(decoder.decode(&utf8[2..], false), utf8);

        let wire = SerialCharset::Gb18030
            .encode_input("💩".as_bytes())
            .unwrap();
        assert_eq!(wire.len(), 4);
        let mut decoder = SerialCharset::Gb18030.decoder();
        assert!(decoder.decode(&wire[..3], false).is_empty());
        assert_eq!(decoder.decode(&wire[3..], false), "💩".as_bytes());
    }

    #[test]
    fn isolated_lf_becomes_crlf_without_corrupting_cross_frame_crlf() {
        let mut decoder = SerialCharset::Utf8.decoder();
        assert_eq!(decoder.decode(b"one\n", false), b"one\r\n");
        assert_eq!(decoder.decode(b"two\r", false), b"two\r");
        assert_eq!(decoder.decode(b"\nthree\n", false), b"\nthree\r\n");
        assert_eq!(decoder.decode(b"\r\n\n", false), b"\r\n\r\n");
    }

    #[test]
    fn input_encoding_is_symmetric_bounded_and_rejects_forged_utf8() {
        let text = "你好\r";
        let charset = SerialCharset::Gb18030;
        let wire = charset.encode_input(text.as_bytes()).unwrap();
        let mut decoder = charset.decoder();
        assert_eq!(decoder.decode(&wire, false), text.as_bytes());
        assert_eq!(
            SerialCharset::Utf8.encode_input(&[0xff]),
            Err(SerialCharsetError::InvalidUtf8Input)
        );
        assert_eq!(
            SerialCharset::Gb18030.encode_input(&vec![b'a'; MAX_INPUT_BYTES + 1]),
            Err(SerialCharsetError::OutputTooLarge)
        );
        assert_eq!(
            SerialCharset::Utf8.encode_input(&vec![b'a'; MAX_INPUT_BYTES + 1]),
            Err(SerialCharsetError::OutputTooLarge)
        );
    }
}
