use std::{error::Error, fmt, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{CodecError, TelnetBytes, TelnetCodec, TelnetConfig, TelnetEvent};

const READ_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Shutdown,
}

/// Session errors retain only the I/O category, never remote or local data.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionError {
    Protocol(CodecError),
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}

impl SessionError {
    fn io(operation: IoOperation, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

impl From<CodecError> for SessionError {
    fn from(error: CodecError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "Telnet protocol error: {error}"),
            Self::Io { operation, kind } => {
                write!(formatter, "Telnet {operation:?} failed ({kind:?})")
            }
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io { .. } => None,
        }
    }
}

/// One socket read after Telnet control bytes have been removed.
pub struct SessionRead {
    application_data: TelnetBytes,
    events: Vec<TelnetEvent>,
    closed: bool,
}

impl SessionRead {
    pub fn application_data(&self) -> &[u8] {
        self.application_data.as_slice()
    }

    pub fn events(&self) -> &[TelnetEvent] {
        &self.events
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn into_parts(self) -> (TelnetBytes, Vec<TelnetEvent>, bool) {
        (self.application_data, self.events, self.closed)
    }
}

impl fmt::Debug for SessionRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRead")
            .field("application_bytes", &self.application_data.len())
            .field("events", &self.events)
            .field("closed", &self.closed)
            .finish()
    }
}

/// Async transport wrapper around the standalone codec.
///
/// The type is generic over any Tokio `AsyncRead + AsyncWrite` stream and has
/// no dependency on Tauri or desktop state.
pub struct TelnetSession<S> {
    stream: S,
    codec: TelnetCodec,
}

impl<S> TelnetSession<S> {
    pub fn new(stream: S, config: TelnetConfig) -> Self {
        Self {
            stream,
            codec: TelnetCodec::new(config),
        }
    }

    pub fn codec(&self) -> &TelnetCodec {
        &self.codec
    }

    pub fn codec_mut(&mut self) -> &mut TelnetCodec {
        &mut self.codec
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> TelnetSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Read one transport frame, write any immediate negotiation reply, and
    /// return only application data plus state events.
    pub async fn read(&mut self) -> Result<SessionRead, SessionError> {
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        let count = self
            .stream
            .read(&mut buffer)
            .await
            .map_err(|error| SessionError::io(IoOperation::Read, error))?;
        if count == 0 {
            return Ok(SessionRead {
                application_data: TelnetBytes::default(),
                events: Vec::new(),
                closed: true,
            });
        }

        let decoded = self.codec.receive(&buffer[..count])?;
        let (application_data, outbound, events) = decoded.into_parts();
        self.write_control(outbound.as_slice()).await?;
        Ok(SessionRead {
            application_data,
            events,
            closed: false,
        })
    }

    /// Encode one bounded application input and write it in full.
    pub async fn write(&mut self, input: &[u8]) -> Result<(), SessionError> {
        let encoded = self.codec.encode_input(input)?;
        self.stream
            .write_all(encoded.as_slice())
            .await
            .map_err(|error| SessionError::io(IoOperation::Write, error))
    }

    /// Store a validated size and send NAWS only when negotiated by the peer.
    pub async fn resize(&mut self, columns: u32, rows: u32) -> Result<bool, SessionError> {
        let outbound = self.codec.resize(columns, rows)?;
        if outbound.is_empty() {
            return Ok(false);
        }
        self.write_control(outbound.as_slice()).await?;
        Ok(true)
    }

    pub async fn flush(&mut self) -> Result<(), SessionError> {
        self.stream
            .flush()
            .await
            .map_err(|error| SessionError::io(IoOperation::Flush, error))
    }

    pub async fn shutdown(&mut self) -> Result<(), SessionError> {
        self.stream
            .shutdown()
            .await
            .map_err(|error| SessionError::io(IoOperation::Shutdown, error))
    }

    async fn write_control(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.stream
            .write_all(bytes)
            .await
            .map_err(|error| SessionError::io(IoOperation::Write, error))
    }
}

impl<S> fmt::Debug for TelnetSession<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelnetSession")
            .field("codec", &self.codec)
            .field("stream", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{command, option};

    #[tokio::test]
    async fn duplex_session_negotiates_and_strips_control_bytes() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let mut session = TelnetSession::new(client, TelnetConfig::default());
        peer.write_all(&[b'h', b'i', command::IAC, command::WILL, option::ECHO])
            .await
            .unwrap();

        let read = session.read().await.unwrap();
        assert_eq!(read.application_data(), b"hi");
        assert!(!read.is_closed());

        let mut reply = [0_u8; 12];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            [
                command::IAC,
                command::DO,
                option::SUPPRESS_GO_AHEAD,
                command::IAC,
                command::WILL,
                option::TERMINAL_TYPE,
                command::IAC,
                command::WILL,
                option::NAWS,
                command::IAC,
                command::DO,
                option::ECHO,
            ]
        );
    }

    #[tokio::test]
    async fn resize_is_silent_before_naws_is_enabled() {
        let (client, _peer) = tokio::io::duplex(128);
        let mut session = TelnetSession::new(client, TelnetConfig::default());
        assert!(!session.resize(100, 40).await.unwrap());
    }

    #[tokio::test]
    async fn eof_is_explicit() {
        let (client, peer) = tokio::io::duplex(128);
        drop(peer);
        let mut session = TelnetSession::new(client, TelnetConfig::default());
        assert!(session.read().await.unwrap().is_closed());
    }

    #[test]
    fn session_diagnostics_do_not_require_or_print_stream_debug() {
        struct MarkerStream;
        let session = TelnetSession::new(MarkerStream, TelnetConfig::default());
        let debug = format!("{session:?}");
        assert!(!debug.contains("MarkerStream"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn io_error_debug_is_redacted() {
        let error = SessionError::io(
            IoOperation::Write,
            io::Error::new(io::ErrorKind::Other, "SENSITIVE-PAYLOAD"),
        );
        assert!(!format!("{error:?}").contains("SENSITIVE"));
        assert!(!error.to_string().contains("SENSITIVE"));
    }
}
