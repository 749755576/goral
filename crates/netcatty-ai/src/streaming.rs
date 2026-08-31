//! Bounded OpenAI-compatible Server-Sent Events transport.
//!
//! Transport chunks are treated as bytes until a complete SSE event is
//! available. This keeps split UTF-8 code points valid and prevents provider
//! response text from entering transport errors or diagnostics.

use std::{collections::VecDeque, fmt, str};

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    AiApiKey, AiChatRequest, AiClient, AiError, AiErrorCode, AiReasoningEffort,
    AiResponseIdleTimeout, MAX_AI_RESPONSE_BYTES, await_provider_io, is_loopback_host,
    normalize_endpoint, open_ai_provider_request_with_reasoning_effort, validate_request,
};

/// One renderer-safe step from an OpenAI-compatible streaming response.
///
/// `Debug` deliberately reports only the byte length of model output so an
/// accidental diagnostic cannot disclose terminal context or generated text.
#[derive(Eq, PartialEq)]
pub enum AiStreamEvent {
    Delta(String),
    Done,
}

impl fmt::Debug for AiStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delta(content) => formatter
                .debug_struct("AiStreamEvent::Delta")
                .field("bytes", &content.len())
                .finish(),
            Self::Done => formatter.write_str("AiStreamEvent::Done"),
        }
    }
}

/// An in-flight bounded SSE response.
///
/// Call [`AiChatStream::next_event`] until it returns `Ok(None)`. Dropping the
/// value stops reading the provider response, which gives the desktop adapter
/// a simple cancellation boundary for a closed Tauri channel.
pub struct AiChatStream {
    response: reqwest::Response,
    decoder: SseDecoder,
    pending: VecDeque<AiStreamEvent>,
    finished: bool,
    response_idle_timeout: AiResponseIdleTimeout,
}

impl fmt::Debug for AiChatStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiChatStream")
    }
}

impl AiChatStream {
    /// Returns the next text delta or terminal `Done` marker.
    ///
    /// An HTTP body, invalid SSE/JSON, incomplete stream, or provider text is
    /// never copied into the returned error. After an error the stream is
    /// terminal and subsequent calls return `Ok(None)`.
    pub async fn next_event(&mut self) -> Result<Option<AiStreamEvent>, AiError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            if self.finished || self.decoder.is_done() {
                self.finished = true;
                return Ok(None);
            }

            let chunk =
                match await_provider_io(self.response_idle_timeout, self.response.chunk()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        self.finished = true;
                        self.decoder.finish()?;
                        return Ok(None);
                    }
                    Err(error) => {
                        self.finished = true;
                        return Err(error);
                    }
                };

            match self.decoder.push(&chunk) {
                Ok(events) => self.pending.extend(events),
                Err(error) => {
                    self.finished = true;
                    return Err(error);
                }
            }
        }
    }
}

impl AiClient {
    /// Starts an OpenAI-compatible `/chat/completions` SSE request.
    ///
    /// This is independent from [`AiClient::complete`](crate::AiClient::complete)
    /// and the terminal-agent loop, so existing non-streaming behavior remains
    /// unchanged while a Tauri adapter can forward deltas as they arrive.
    pub async fn stream_chat(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
    ) -> Result<AiChatStream, AiError> {
        self.stream_chat_with_timeout(base_url, api_key, request, AiResponseIdleTimeout::default())
            .await
    }

    pub async fn stream_chat_with_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<AiChatStream, AiError> {
        self.stream_chat_with_reasoning_effort_and_timeout(
            base_url,
            api_key,
            request,
            None,
            response_idle_timeout,
        )
        .await
    }

    pub async fn stream_chat_with_reasoning_effort_and_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
        reasoning_effort: Option<AiReasoningEffort>,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<AiChatStream, AiError> {
        let endpoint = normalize_endpoint(base_url)?;
        validate_request(&request)?;
        if api_key.is_empty() && !is_loopback_host(&endpoint) {
            return Err(AiError::new(AiErrorCode::ApiKeyRequired));
        }

        let provider_request =
            open_ai_provider_request_with_reasoning_effort(&request, Some(true), reasoning_effort);
        let mut request_builder = self
            .client
            .post(endpoint)
            .header(ACCEPT, "text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .json(&provider_request);
        if !api_key.is_empty() {
            let bearer = Zeroizing::new(format!("Bearer {}", api_key.expose()));
            let mut authorization = HeaderValue::from_str(bearer.as_str())
                .map_err(|_| AiError::new(AiErrorCode::ApiKeyInvalid))?;
            authorization.set_sensitive(true);
            request_builder = request_builder.header(AUTHORIZATION, authorization);
        }

        let response = await_provider_io(response_idle_timeout, request_builder.send()).await?;
        let status = response.status();
        if !status.is_success() {
            // Never read an error body: providers may echo prompts, tokens, or
            // account details in it.
            return Err(AiError::http(status));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_AI_RESPONSE_BYTES as u64)
        {
            return Err(AiError::new(AiErrorCode::ResponseTooLarge));
        }
        let is_event_stream = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
        if !is_event_stream {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }

        Ok(AiChatStream {
            response,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            finished: false,
            response_idle_timeout,
        })
    }
}

#[derive(Default)]
struct SseDecoder {
    total_bytes: usize,
    line: Vec<u8>,
    data: Vec<u8>,
    skip_lf_after_cr: bool,
    saw_json_event: bool,
    saw_non_whitespace: bool,
    done: bool,
}

impl SseDecoder {
    fn is_done(&self) -> bool {
        self.done
    }

    fn push(&mut self, chunk: &[u8]) -> Result<Vec<AiStreamEvent>, AiError> {
        let next_total = self
            .total_bytes
            .checked_add(chunk.len())
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseTooLarge))?;
        if next_total > MAX_AI_RESPONSE_BYTES {
            return Err(AiError::new(AiErrorCode::ResponseTooLarge));
        }
        self.total_bytes = next_total;

        let mut events = Vec::new();
        for &byte in chunk {
            if self.done {
                break;
            }
            if self.skip_lf_after_cr {
                self.skip_lf_after_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\n' => self.finish_line(&mut events)?,
                b'\r' => {
                    self.finish_line(&mut events)?;
                    self.skip_lf_after_cr = true;
                }
                _ => self.line.push(byte),
            }
        }
        Ok(events)
    }

    fn finish(&self) -> Result<(), AiError> {
        if self.done {
            return Ok(());
        }
        if !self.line.is_empty() || !self.data.is_empty() || self.saw_json_event {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        Err(AiError::new(AiErrorCode::EmptyResponse))
    }

    fn finish_line(&mut self, events: &mut Vec<AiStreamEvent>) -> Result<(), AiError> {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            if !self.data.is_empty() {
                self.dispatch_event(events)?;
            }
            return Ok(());
        }
        // SSE is UTF-8 text. Validate complete physical lines even when the
        // field is a comment or otherwise ignored, while still allowing a
        // code point to be split across arbitrary transport chunks.
        str::from_utf8(&line).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        if line.first() == Some(&b':') {
            return Ok(());
        }

        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(separator) => (&line[..separator], &line[separator + 1..]),
            None => (line.as_slice(), &[][..]),
        };
        if field != b"data" {
            return Ok(());
        }
        let value = value.strip_prefix(b" ").unwrap_or(value);
        if !self.data.is_empty() {
            self.data.push(b'\n');
        }
        self.data.extend_from_slice(value);
        Ok(())
    }

    fn dispatch_event(&mut self, events: &mut Vec<AiStreamEvent>) -> Result<(), AiError> {
        let data = std::mem::take(&mut self.data);
        let text = str::from_utf8(&data).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if trimmed == "[DONE]" {
            if !self.saw_non_whitespace {
                return Err(AiError::new(AiErrorCode::EmptyResponse));
            }
            self.done = true;
            events.push(AiStreamEvent::Done);
            return Ok(());
        }

        let payload: ProviderStreamResponse =
            serde_json::from_str(text).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        self.saw_json_event = true;
        let Some(choice) = payload.choices.into_iter().next() else {
            // OpenAI may emit a final usage-only event with an empty choices
            // array before `[DONE]`.
            return Ok(());
        };
        let content = choice
            .delta
            .and_then(|message| message.content)
            .or_else(|| choice.message.and_then(|message| message.content))
            .or(choice.text);
        let Some(content) = content.filter(|content| !content.is_empty()) else {
            return Ok(());
        };
        if content.chars().any(|character| !character.is_whitespace()) {
            self.saw_non_whitespace = true;
        }
        events.push(AiStreamEvent::Delta(content));
        Ok(())
    }
}

#[derive(Deserialize)]
struct ProviderStreamResponse {
    choices: Vec<ProviderStreamChoice>,
}

#[derive(Deserialize)]
struct ProviderStreamChoice {
    #[serde(default)]
    delta: Option<ProviderStreamMessage>,
    #[serde(default)]
    message: Option<ProviderStreamMessage>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct ProviderStreamMessage {
    #[serde(default)]
    content: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        let mut expected_length = None;
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if expected_length.is_none()
                && let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
            {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                expected_length = Some(header_end + 4 + content_length);
            }
            if expected_length.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        request
    }

    fn request() -> AiChatRequest {
        AiChatRequest {
            model: "stream-model".to_owned(),
            messages: vec![crate::AiChatMessage {
                role: crate::AiChatRole::User,
                content: "stream safely".to_owned(),
                content_parts: Vec::new(),
            }],
        }
    }

    #[tokio::test]
    async fn remote_http_stream_requires_a_key_before_network_access() {
        let error = AiClient::new()
            .expect("AI client")
            .stream_chat(
                "http://api.example.test/v1",
                AiApiKey::new(String::new()).expect("empty key"),
                request(),
            )
            .await
            .expect_err("remote HTTP key requirement");
        assert_eq!(error.code(), AiErrorCode::ApiKeyRequired);
        assert_eq!(error.to_string(), "AI_API_KEY_REQUIRED");
    }

    #[test]
    fn decoder_handles_every_transport_and_utf8_boundary() {
        let body = concat!(
            ": keepalive\r\n\r\n",
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"你\"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"好\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for byte in body.as_bytes() {
            events.extend(decoder.push(std::slice::from_ref(byte)).unwrap());
        }
        decoder.finish().unwrap();
        assert_eq!(
            events,
            vec![
                AiStreamEvent::Delta("你".to_owned()),
                AiStreamEvent::Delta("好".to_owned()),
                AiStreamEvent::Done,
            ]
        );
    }

    #[test]
    fn decoder_returns_stable_empty_invalid_and_incomplete_errors() {
        let empty = SseDecoder::default().finish().unwrap_err();
        assert_eq!(empty.code(), AiErrorCode::EmptyResponse);
        assert_eq!(empty.to_string(), "AI_EMPTY_RESPONSE");

        let mut malformed = SseDecoder::default();
        let error = malformed.push(b"data: not-json\n\n").unwrap_err();
        assert_eq!(error.code(), AiErrorCode::ResponseInvalid);
        assert_eq!(error.to_string(), "AI_RESPONSE_INVALID");

        let mut invalid_utf8 = SseDecoder::default();
        let error = invalid_utf8.push(b": \xff\n\n").unwrap_err();
        assert_eq!(error.code(), AiErrorCode::ResponseInvalid);

        let mut incomplete = SseDecoder::default();
        incomplete
            .push(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
            .unwrap();
        assert_eq!(
            incomplete.finish().unwrap_err().code(),
            AiErrorCode::ResponseInvalid
        );

        let mut role_only = SseDecoder::default();
        let error = role_only
            .push(b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\ndata: [DONE]\n\n")
            .unwrap_err();
        assert_eq!(error.code(), AiErrorCode::EmptyResponse);
        assert_eq!(error.to_string(), "AI_EMPTY_RESPONSE");
    }

    #[test]
    fn decoder_enforces_the_two_mebibyte_raw_response_limit() {
        let mut decoder = SseDecoder::default();
        decoder.push(&vec![b'x'; MAX_AI_RESPONSE_BYTES]).unwrap();
        let error = decoder.push(b"x").unwrap_err();
        assert_eq!(error.code(), AiErrorCode::ResponseTooLarge);
        assert_eq!(error.to_string(), "AI_RESPONSE_TOO_LARGE");
    }

    #[tokio::test]
    async fn client_streams_openai_deltas_and_requests_stream_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(
                request_text
                    .to_ascii_lowercase()
                    .contains("accept: text/event-stream")
            );
            assert!(request_text.contains("\"stream\":true"));

            let body = concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"native \"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"流式\"}}]}\n\n",
                "data: [DONE]\n\n",
            );
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            for part in body.as_bytes().chunks(3) {
                stream.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let mut stream = AiClient::new()
            .unwrap()
            .stream_chat(
                &format!("http://{address}/v1"),
                AiApiKey::new("stream-key".to_owned()).unwrap(),
                request(),
            )
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Some(event) = stream.next_event().await.unwrap() {
            events.push(event);
        }
        provider.await.unwrap();
        assert_eq!(
            events,
            vec![
                AiStreamEvent::Delta("native ".to_owned()),
                AiStreamEvent::Delta("流式".to_owned()),
                AiStreamEvent::Done,
            ]
        );
    }

    #[tokio::test]
    async fn streaming_http_errors_never_expose_the_provider_body() {
        const PRIVATE_BODY: &str = "private-stream-error-sentinel";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PRIVATE_BODY}",
                PRIVATE_BODY.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let error = AiClient::new()
            .unwrap()
            .stream_chat(
                &format!("http://{address}/v1"),
                AiApiKey::new("private-stream-key".to_owned()).unwrap(),
                request(),
            )
            .await
            .unwrap_err();
        provider.await.unwrap();
        assert_eq!(error.code(), AiErrorCode::Http);
        assert_eq!(error.http_status(), Some(429));
        assert_eq!(error.to_string(), "AI_HTTP_ERROR:429");
        assert!(!error.to_string().contains(PRIVATE_BODY));
    }
}
