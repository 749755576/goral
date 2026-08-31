//! Bounded direct Anthropic Messages API streaming transport.
//!
//! This protocol is intentionally separate from the OpenAI-compatible
//! transport. It maps the shared chat request into Anthropic's top-level
//! `system` field and `user | assistant` messages, sends the API key only in
//! the sensitive `x-api-key` header, and emits the shared renderer-safe
//! [`AiStreamEvent`] contract.
//!
//! Anthropic ends a successful stream with `message_stop`, not `[DONE]`.
//! Unknown top-level event types, non-text content blocks, and non-text deltas
//! (including tool-use and thinking events) fail closed because this text-only
//! slice never grants those capabilities.

use std::{collections::VecDeque, fmt, str};

use reqwest::{
    Url,
    header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};

use crate::{
    AiApiKey, AiChatRequest, AiChatRole, AiClient, AiError, AiErrorCode, AiResponseIdleTimeout,
    AiStreamEvent, MAX_AI_REQUEST_TEXT_BYTES, MAX_AI_RESPONSE_BYTES, MAX_AI_URL_BYTES,
    await_provider_io, validate_request,
};

/// Anthropic's stable Messages API version used by this reviewed wire shape.
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Fixed response budget until a renderer-safe output-token setting exists.
pub const MAX_ANTHROPIC_OUTPUT_TOKENS: u32 = 4_096;

/// Maximum serialized Anthropic request body accepted by this transport.
pub const MAX_ANTHROPIC_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// Maximum text content-block index accepted from one response.
pub const MAX_ANTHROPIC_CONTENT_BLOCKS: usize = 64;

const MAX_ANTHROPIC_EVENT_NAME_BYTES: usize = 128;
const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const ANTHROPIC_VERSION: HeaderName = HeaderName::from_static("anthropic-version");

/// Normalizes a provider base URL to the direct Anthropic Messages endpoint.
///
/// A root URL becomes `/v1/messages`; a non-root base path receives a final
/// `/messages` segment. Existing `/messages` endpoints remain unchanged.
/// URL credentials/fragments and redirects are rejected by the same native
/// transport boundary as the OpenAI client. Both explicit HTTP and HTTPS
/// endpoints are accepted; the client never downgrades one scheme to another.
pub fn normalize_anthropic_endpoint(base_url: &str) -> Result<Url, AiError> {
    if base_url.len() > MAX_AI_URL_BYTES {
        return Err(AiError::new(AiErrorCode::UrlTooLong));
    }
    let mut url = Url::parse(base_url).map_err(|_| AiError::new(AiErrorCode::UrlInvalid))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(AiError::new(AiErrorCode::UrlProtocol));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(AiError::new(AiErrorCode::UrlCredentials));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    if !path.ends_with("/messages") {
        let next = if path.is_empty() {
            "/v1/messages".to_owned()
        } else {
            format!("{path}/messages")
        };
        url.set_path(&next);
    } else if path != url.path() {
        url.set_path(&path);
    }
    Ok(url)
}

/// An in-flight direct Anthropic Messages SSE response.
///
/// Call [`AiAnthropicStream::next_event`] until it returns `Ok(None)`.
/// Dropping this value drops the response body and is the cancellation
/// boundary used by the desktop adapter.
pub struct AiAnthropicStream {
    response: reqwest::Response,
    decoder: AnthropicSseDecoder,
    pending: VecDeque<AiStreamEvent>,
    finished: bool,
    response_idle_timeout: AiResponseIdleTimeout,
}

impl fmt::Debug for AiAnthropicStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiAnthropicStream")
    }
}

impl AiAnthropicStream {
    /// Returns the next text delta or terminal `Done` marker.
    ///
    /// HTTP/provider bodies, invalid SSE/JSON, and incomplete streams are
    /// reduced to fixed [`AiError`] values. After an error this stream is
    /// terminal and later calls return `Ok(None)`.
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

#[derive(Serialize)]
struct AnthropicStreamRequest<'a> {
    model: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: &'a [AnthropicRequestMessage<'a>],
    max_tokens: u32,
    stream: bool,
}

#[derive(Serialize)]
struct AnthropicRequestMessage<'a> {
    role: AnthropicRequestRole,
    content: &'a str,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum AnthropicRequestRole {
    User,
    Assistant,
}

impl AiClient {
    /// Starts a direct Anthropic `/v1/messages` streaming request.
    ///
    /// The shared chat request remains the public input contract. Leading
    /// system messages are joined into Anthropic's top-level `system` string;
    /// later system messages are rejected to avoid changing conversation
    /// chronology. Consecutive user or assistant messages remain separate and
    /// are legally coalesced by Anthropic according to the Messages contract.
    /// This text-only slice sends no tool or thinking capability.
    pub async fn stream_anthropic_messages(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
    ) -> Result<AiAnthropicStream, AiError> {
        self.stream_anthropic_messages_with_timeout(
            base_url,
            api_key,
            request,
            AiResponseIdleTimeout::default(),
        )
        .await
    }

    pub async fn stream_anthropic_messages_with_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<AiAnthropicStream, AiError> {
        let endpoint = normalize_anthropic_endpoint(base_url)?;
        validate_request(&request)?;
        if request.has_image_content() {
            return Err(AiError::new(AiErrorCode::ImageInputUnsupported));
        }
        if api_key.is_empty() {
            return Err(AiError::new(AiErrorCode::ApiKeyRequired));
        }

        let (system, messages) = prepare_anthropic_messages(&request)?;
        let provider_request = AnthropicStreamRequest {
            model: &request.model,
            system: system.as_deref(),
            messages: &messages,
            max_tokens: MAX_ANTHROPIC_OUTPUT_TOKENS,
            stream: true,
        };
        let provider_body = serde_json::to_vec(&provider_request)
            .map_err(|_| AiError::new(AiErrorCode::RequestTooLarge))?;
        if provider_body.len() > MAX_ANTHROPIC_REQUEST_BYTES {
            return Err(AiError::new(AiErrorCode::RequestTooLarge));
        }
        let mut request_builder = self
            .client
            .post(endpoint)
            .header(ACCEPT, "text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(
                ANTHROPIC_VERSION,
                HeaderValue::from_static(ANTHROPIC_API_VERSION),
            )
            .body(provider_body);
        if !api_key.is_empty() {
            let mut key = HeaderValue::from_str(api_key.expose())
                .map_err(|_| AiError::new(AiErrorCode::ApiKeyInvalid))?;
            key.set_sensitive(true);
            request_builder = request_builder.header(X_API_KEY, key);
        }

        let response = await_provider_io(response_idle_timeout, request_builder.send()).await?;
        let status = response.status();
        if !status.is_success() {
            // Never read an error body: Anthropic or a gateway may echo the
            // prompt, key, account metadata, or request identifiers.
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

        Ok(AiAnthropicStream {
            response,
            decoder: AnthropicSseDecoder::default(),
            pending: VecDeque::new(),
            finished: false,
            response_idle_timeout,
        })
    }
}

fn prepare_anthropic_messages<'a>(
    request: &'a AiChatRequest,
) -> Result<(Option<String>, Vec<AnthropicRequestMessage<'a>>), AiError> {
    if request.has_image_content() {
        return Err(AiError::new(AiErrorCode::ImageInputUnsupported));
    }
    let mut system = String::new();
    let mut messages = Vec::with_capacity(request.messages.len());
    let mut saw_conversation = false;
    let mut saw_user = false;
    let mut payload_text_bytes = 0usize;

    for message in &request.messages {
        payload_text_bytes = payload_text_bytes
            .checked_add(message.content.len())
            .ok_or_else(|| AiError::new(AiErrorCode::RequestTooLarge))?;
        match message.role {
            AiChatRole::System => {
                if saw_conversation {
                    return Err(AiError::new(AiErrorCode::MessagesInvalid));
                }
                if !system.is_empty() {
                    payload_text_bytes = payload_text_bytes
                        .checked_add(2)
                        .ok_or_else(|| AiError::new(AiErrorCode::RequestTooLarge))?;
                    system.push_str("\n\n");
                }
                system.push_str(&message.content);
            }
            AiChatRole::User => {
                saw_conversation = true;
                saw_user = true;
                messages.push(AnthropicRequestMessage {
                    role: AnthropicRequestRole::User,
                    content: &message.content,
                });
            }
            AiChatRole::Assistant => {
                saw_conversation = true;
                messages.push(AnthropicRequestMessage {
                    role: AnthropicRequestRole::Assistant,
                    content: &message.content,
                });
            }
        }
    }

    if messages.is_empty() || !saw_user {
        return Err(AiError::new(AiErrorCode::MessagesInvalid));
    }
    if payload_text_bytes > MAX_AI_REQUEST_TEXT_BYTES {
        return Err(AiError::new(AiErrorCode::RequestTooLarge));
    }
    Ok(((!system.is_empty()).then_some(system), messages))
}

struct AnthropicSseDecoder {
    total_bytes: usize,
    output_bytes: usize,
    line: Vec<u8>,
    event_name: Vec<u8>,
    data: Vec<u8>,
    skip_lf_after_cr: bool,
    saw_json_event: bool,
    saw_non_whitespace: bool,
    message_started: bool,
    block_states: [u8; MAX_ANTHROPIC_CONTENT_BLOCKS],
    done: bool,
}

impl Default for AnthropicSseDecoder {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            output_bytes: 0,
            line: Vec::new(),
            event_name: Vec::new(),
            data: Vec::new(),
            skip_lf_after_cr: false,
            saw_json_event: false,
            saw_non_whitespace: false,
            message_started: false,
            block_states: [0; MAX_ANTHROPIC_CONTENT_BLOCKS],
            done: false,
        }
    }
}

impl AnthropicSseDecoder {
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
        if !self.line.is_empty()
            || !self.event_name.is_empty()
            || !self.data.is_empty()
            || self.saw_json_event
        {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        Err(AiError::new(AiErrorCode::EmptyResponse))
    }

    fn finish_line(&mut self, events: &mut Vec<AiStreamEvent>) -> Result<(), AiError> {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            if !self.data.is_empty() {
                self.dispatch_event(events)?;
            } else {
                self.event_name.clear();
            }
            return Ok(());
        }

        str::from_utf8(&line).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        if line.first() == Some(&b':') {
            return Ok(());
        }
        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(separator) => (&line[..separator], &line[separator + 1..]),
            None => (line.as_slice(), &[][..]),
        };
        let value = value.strip_prefix(b" ").unwrap_or(value);
        match field {
            b"data" => {
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(value);
            }
            b"event" => {
                if value.is_empty()
                    || value.len() > MAX_ANTHROPIC_EVENT_NAME_BYTES
                    || value.iter().any(|byte| byte.is_ascii_control())
                {
                    return Err(AiError::new(AiErrorCode::ResponseInvalid));
                }
                self.event_name.clear();
                self.event_name.extend_from_slice(value);
            }
            _ => {}
        }
        Ok(())
    }

    fn dispatch_event(&mut self, events: &mut Vec<AiStreamEvent>) -> Result<(), AiError> {
        let data = std::mem::take(&mut self.data);
        let event_name = std::mem::take(&mut self.event_name);
        let text = str::from_utf8(&data).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        if text.trim().is_empty() {
            return Ok(());
        }
        let payload: AnthropicStreamEnvelope =
            serde_json::from_str(text).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        self.saw_json_event = true;
        if payload.kind.is_empty()
            || payload.kind.len() > MAX_ANTHROPIC_EVENT_NAME_BYTES
            || !payload
                .kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        if !event_name.is_empty()
            && str::from_utf8(&event_name)
                .map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?
                != payload.kind
        {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }

        match payload.kind.as_str() {
            "message_start" => self.accept_message_start(payload),
            "content_block_start" => self.accept_content_block_start(payload, events),
            "content_block_delta" => self.accept_content_block_delta(payload, events),
            "content_block_stop" => self.accept_content_block_stop(payload),
            "message_delta" => {
                if !self.message_started || self.has_open_blocks() {
                    return Err(AiError::new(AiErrorCode::ResponseInvalid));
                }
                Ok(())
            }
            "message_stop" => {
                if !self.message_started || self.has_open_blocks() {
                    return Err(AiError::new(AiErrorCode::ResponseInvalid));
                }
                if !self.saw_non_whitespace {
                    return Err(AiError::new(AiErrorCode::EmptyResponse));
                }
                self.done = true;
                events.push(AiStreamEvent::Done);
                Ok(())
            }
            "ping" => Ok(()),
            "error" => Err(AiError::new(AiErrorCode::RequestFailed)),
            // Unknown event payloads carry no authority in this reviewed
            // text-only protocol. Fail without exposing provider fields.
            _ => Err(AiError::new(AiErrorCode::ResponseInvalid)),
        }
    }

    fn accept_message_start(&mut self, payload: AnthropicStreamEnvelope) -> Result<(), AiError> {
        let message = payload
            .message
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        if self.message_started
            || message.kind != "message"
            || message.role != "assistant"
            || self.block_states.iter().any(|state| *state != 0)
        {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        self.message_started = true;
        Ok(())
    }

    fn accept_content_block_start(
        &mut self,
        payload: AnthropicStreamEnvelope,
        events: &mut Vec<AiStreamEvent>,
    ) -> Result<(), AiError> {
        if !self.message_started {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        let index = self.checked_index(payload.index)?;
        let block = payload
            .content_block
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        if self.block_states[index] != 0 || block.kind != "text" {
            // `tool_use`, thinking, and every other non-text capability fail
            // closed instead of being silently rendered or executed.
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        let text = block
            .text
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        self.block_states[index] = 1;
        self.emit_text(text, events)
    }

    fn accept_content_block_delta(
        &mut self,
        payload: AnthropicStreamEnvelope,
        events: &mut Vec<AiStreamEvent>,
    ) -> Result<(), AiError> {
        let index = self.checked_index(payload.index)?;
        let delta = payload
            .delta
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        if !self.message_started
            || self.block_states[index] != 1
            || delta.kind.as_deref() != Some("text_delta")
        {
            // In particular, `input_json_delta`, `thinking_delta`, and
            // `signature_delta` are outside this slice and fail closed.
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        let text = delta
            .text
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        self.emit_text(text, events)
    }

    fn accept_content_block_stop(
        &mut self,
        payload: AnthropicStreamEnvelope,
    ) -> Result<(), AiError> {
        let index = self.checked_index(payload.index)?;
        if !self.message_started || self.block_states[index] != 1 {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        self.block_states[index] = 2;
        Ok(())
    }

    fn checked_index(&self, index: Option<usize>) -> Result<usize, AiError> {
        index
            .filter(|index| *index < MAX_ANTHROPIC_CONTENT_BLOCKS)
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))
    }

    fn has_open_blocks(&self) -> bool {
        self.block_states.contains(&1)
    }

    fn emit_text(&mut self, text: String, events: &mut Vec<AiStreamEvent>) -> Result<(), AiError> {
        if text.is_empty() {
            return Ok(());
        }
        if text.contains('\0') {
            return Err(AiError::new(AiErrorCode::ResponseInvalid));
        }
        let next_output = self
            .output_bytes
            .checked_add(text.len())
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseTooLarge))?;
        if next_output > MAX_AI_RESPONSE_BYTES {
            return Err(AiError::new(AiErrorCode::ResponseTooLarge));
        }
        self.output_bytes = next_output;
        if text.chars().any(|character| !character.is_whitespace()) {
            self.saw_non_whitespace = true;
        }
        events.push(AiStreamEvent::Delta(text));
        Ok(())
    }
}

#[derive(Deserialize)]
struct AnthropicStreamEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    message: Option<AnthropicMessageMetadata>,
    #[serde(default)]
    content_block: Option<AnthropicContentBlock>,
    #[serde(default)]
    delta: Option<AnthropicContentDelta>,
}

#[derive(Deserialize)]
struct AnthropicMessageMetadata {
    #[serde(rename = "type")]
    kind: String,
    role: String,
}

#[derive(Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicContentDelta {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AiChatMessage;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.expect("provider request");
            assert!(read > 0, "request ended before headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
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
        while request.len() - header_end < content_length {
            let read = stream.read(&mut buffer).await.expect("provider body");
            assert!(read > 0, "request ended before body");
            request.extend_from_slice(&buffer[..read]);
        }
        request
    }

    fn chat_request() -> AiChatRequest {
        AiChatRequest {
            model: "claude-test".to_owned(),
            messages: vec![
                AiChatMessage {
                    role: AiChatRole::System,
                    content: "Stay bounded.".to_owned(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::System,
                    content: "Return text only.".to_owned(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::User,
                    content: "你好".to_owned(),
                    content_parts: Vec::new(),
                },
            ],
        }
    }

    fn message_start() -> &'static [u8] {
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"role\":\"assistant\"}}\n\n"
    }

    #[test]
    fn endpoint_normalization_preserves_explicit_scheme_and_origin() {
        assert_eq!(
            normalize_anthropic_endpoint("https://api.anthropic.com")
                .expect("root endpoint")
                .as_str(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            normalize_anthropic_endpoint("https://api.anthropic.com/v1")
                .expect("version base endpoint")
                .as_str(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            normalize_anthropic_endpoint("https://api.example.test/custom/v1/")
                .expect("custom endpoint")
                .as_str(),
            "https://api.example.test/custom/v1/messages"
        );
        assert_eq!(
            normalize_anthropic_endpoint("http://127.0.0.1:8080/v1/messages/?test=1")
                .expect("loopback endpoint")
                .as_str(),
            "http://127.0.0.1:8080/v1/messages?test=1"
        );
        assert_eq!(
            normalize_anthropic_endpoint("http://api.example.test")
                .expect("explicit remote HTTP")
                .as_str(),
            "http://api.example.test/v1/messages"
        );
        assert_eq!(
            normalize_anthropic_endpoint("https://key@api.example.test")
                .expect_err("URL credentials")
                .code(),
            AiErrorCode::UrlCredentials
        );
    }

    #[test]
    fn request_mapping_requires_leading_system_messages_and_a_user() {
        let request = chat_request();
        let (system, messages) = prepare_anthropic_messages(&request).expect("mapped request");
        assert_eq!(
            system.as_deref(),
            Some("Stay bounded.\n\nReturn text only.")
        );
        assert_eq!(messages.len(), 1);

        let consecutive = AiChatRequest {
            model: "claude-test".to_owned(),
            messages: vec![
                AiChatMessage {
                    role: AiChatRole::User,
                    content: "first user turn".to_owned(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::User,
                    content: "second user turn".to_owned(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::Assistant,
                    content: "assistant prefill".to_owned(),
                    content_parts: Vec::new(),
                },
            ],
        };
        let (_, consecutive_messages) =
            prepare_anthropic_messages(&consecutive).expect("consecutive roles are legal");
        assert_eq!(consecutive_messages.len(), 3);
        assert!(matches!(
            consecutive_messages[0].role,
            AnthropicRequestRole::User
        ));
        assert!(matches!(
            consecutive_messages[1].role,
            AnthropicRequestRole::User
        ));
        assert!(matches!(
            consecutive_messages[2].role,
            AnthropicRequestRole::Assistant
        ));
        assert_eq!(consecutive_messages[1].content, "second user turn");

        let late_system = AiChatRequest {
            model: "claude-test".to_owned(),
            messages: vec![
                AiChatMessage {
                    role: AiChatRole::User,
                    content: "first".to_owned(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::System,
                    content: "too late".to_owned(),
                    content_parts: Vec::new(),
                },
            ],
        };
        assert_eq!(
            prepare_anthropic_messages(&late_system)
                .err()
                .expect("late system message")
                .code(),
            AiErrorCode::MessagesInvalid
        );

        let system_only = AiChatRequest {
            model: "claude-test".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::System,
                content: "no user".to_owned(),
                content_parts: Vec::new(),
            }],
        };
        assert_eq!(
            prepare_anthropic_messages(&system_only)
                .err()
                .expect("system-only request")
                .code(),
            AiErrorCode::MessagesInvalid
        );
    }

    #[test]
    fn decoder_streams_text_across_utf8_boundaries_and_completes() {
        let body = concat!(
            "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"role\":\"assistant\"}}\r\n\r\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"你\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"好\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let mut decoder = AnthropicSseDecoder::default();
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
    fn decoder_fails_closed_for_tool_or_non_text_content() {
        let mut tool = AnthropicSseDecoder::default();
        tool.push(message_start()).unwrap();
        let error = tool
            .push(
                b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"terminal_execute\"}}\n\n",
            )
            .unwrap_err();
        assert_eq!(error.code(), AiErrorCode::ResponseInvalid);
        assert_eq!(error.to_string(), "AI_RESPONSE_INVALID");

        let mut delta = AnthropicSseDecoder::default();
        delta.push(message_start()).unwrap();
        delta
            .push(
                b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            )
            .unwrap();
        assert_eq!(
            delta
                .push(
                    b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n",
                )
                .unwrap_err()
                .code(),
            AiErrorCode::ResponseInvalid
        );

        const PRIVATE_UNKNOWN_BODY: &str = "private-unknown-event-body";
        let mut unknown = AnthropicSseDecoder::default();
        let unknown_payload = format!(
            "event: future_metadata\ndata: {{\"type\":\"future_metadata\",\"private\":\"{PRIVATE_UNKNOWN_BODY}\"}}\n\n"
        );
        let error = unknown
            .push(unknown_payload.as_bytes())
            .expect_err("unknown event must fail closed");
        let diagnostic = format!("{error:?} {error}");
        assert_eq!(error.code(), AiErrorCode::ResponseInvalid);
        assert_eq!(error.to_string(), "AI_RESPONSE_INVALID");
        assert!(!diagnostic.contains(PRIVATE_UNKNOWN_BODY));
    }

    #[test]
    fn decoder_rejects_incomplete_empty_and_over_budget_streams() {
        let empty = AnthropicSseDecoder::default().finish().unwrap_err();
        assert_eq!(empty.code(), AiErrorCode::EmptyResponse);

        let mut incomplete = AnthropicSseDecoder::default();
        incomplete.push(message_start()).unwrap();
        assert_eq!(
            incomplete.finish().unwrap_err().code(),
            AiErrorCode::ResponseInvalid
        );

        let mut raw = AnthropicSseDecoder::default();
        raw.push(&vec![b'x'; MAX_AI_RESPONSE_BYTES]).unwrap();
        assert_eq!(
            raw.push(b"x").unwrap_err().code(),
            AiErrorCode::ResponseTooLarge
        );

        let mut assembled = AnthropicSseDecoder::default();
        assembled.push(message_start()).unwrap();
        assembled
            .push(
                b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            )
            .unwrap();
        assembled.output_bytes = MAX_AI_RESPONSE_BYTES;
        assert_eq!(
            assembled
                .push(
                    b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n",
                )
                .unwrap_err()
                .code(),
            AiErrorCode::ResponseTooLarge
        );
    }

    #[tokio::test]
    async fn client_sends_anthropic_headers_and_streams_shared_events() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            let header_end = request
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .expect("request headers")
                + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            assert!(headers.starts_with("POST /v1/messages HTTP/1.1\r\n"));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("x-api-key")
                        && value.trim() == "private-anthropic-key"
                })
            }));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("accept")
                        && value.trim().eq_ignore_ascii_case("text/event-stream")
                })
            }));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("content-type")
                        && value.trim().eq_ignore_ascii_case("application/json")
                })
            }));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("anthropic-version")
                        && value.trim() == ANTHROPIC_API_VERSION
                })
            }));
            assert!(!headers.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            }));

            let payload: serde_json::Value =
                serde_json::from_slice(&request[header_end..]).expect("request JSON");
            assert_eq!(payload["model"], "claude-test");
            assert_eq!(payload["system"], "Stay bounded.\n\nReturn text only.");
            assert_eq!(payload["messages"][0]["role"], "user");
            assert_eq!(payload["messages"][0]["content"], "你好");
            assert_eq!(payload["max_tokens"], MAX_ANTHROPIC_OUTPUT_TOKENS);
            assert_eq!(payload["stream"], true);
            assert!(payload.get("tools").is_none());

            let body = concat!(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"role\":\"assistant\"}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"native \"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"流式\"}}\n\n",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            );
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .expect("response headers");
            for part in body.as_bytes().chunks(2) {
                stream.write_all(part).await.expect("response chunk");
                tokio::task::yield_now().await;
            }
        });

        let mut stream = AiClient::new()
            .expect("AI client")
            .stream_anthropic_messages(
                &format!("http://{address}"),
                AiApiKey::new("private-anthropic-key".to_owned()).expect("API key"),
                chat_request(),
            )
            .await
            .expect("Anthropic stream");
        let mut events = Vec::new();
        while let Some(event) = stream.next_event().await.expect("stream event") {
            events.push(event);
        }
        provider.await.expect("provider task");
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
    async fn http_and_stream_errors_never_expose_provider_or_key_material() {
        const PRIVATE_BODY: &str = "private-anthropic-provider-error";
        const PRIVATE_KEY: &str = "private-anthropic-api-key";
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let _ = read_http_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PRIVATE_BODY}",
                PRIVATE_BODY.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("provider response");
        });

        let error = AiClient::new()
            .expect("AI client")
            .stream_anthropic_messages(
                &format!("http://{address}"),
                AiApiKey::new(PRIVATE_KEY.to_owned()).expect("API key"),
                chat_request(),
            )
            .await
            .expect_err("HTTP error");
        provider.await.expect("provider task");
        let diagnostic = format!("{error:?} {error}");
        assert_eq!(error.http_status(), Some(401));
        assert_eq!(error.to_string(), "AI_HTTP_ERROR:401");
        assert!(!diagnostic.contains(PRIVATE_BODY));
        assert!(!diagnostic.contains(PRIVATE_KEY));

        let mut decoder = AnthropicSseDecoder::default();
        let stream_error = decoder
            .push(
                b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"private-stream-body\"}}\n\n",
            )
            .expect_err("stream error");
        assert_eq!(stream_error.to_string(), "AI_REQUEST_FAILED");
        assert!(!format!("{stream_error:?} {stream_error}").contains("private-stream-body"));
    }

    #[tokio::test]
    async fn anthropic_remote_http_requires_a_key_before_network_access() {
        let error = AiClient::new()
            .expect("AI client")
            .stream_anthropic_messages(
                "http://api.example.test/v1",
                AiApiKey::new(String::new()).expect("empty key"),
                chat_request(),
            )
            .await
            .expect_err("remote key requirement");
        assert_eq!(error.code(), AiErrorCode::ApiKeyRequired);
        assert_eq!(error.to_string(), "AI_API_KEY_REQUIRED");
    }

    #[tokio::test]
    async fn serialized_request_expansion_is_bounded_before_network_access() {
        let content = "\u{1}".repeat(crate::MAX_AI_MESSAGE_BYTES);
        let request = AiChatRequest {
            model: "claude-test".to_owned(),
            messages: vec![
                AiChatMessage {
                    role: AiChatRole::User,
                    content: content.clone(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::Assistant,
                    content: content.clone(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::User,
                    content: content.clone(),
                    content_parts: Vec::new(),
                },
                AiChatMessage {
                    role: AiChatRole::Assistant,
                    content,
                    content_parts: Vec::new(),
                },
            ],
        };
        let error = AiClient::new()
            .expect("AI client")
            .stream_anthropic_messages(
                "https://api.anthropic.test",
                AiApiKey::new("bounded-key".to_owned()).expect("API key"),
                request,
            )
            .await
            .expect_err("serialized request bound");
        assert_eq!(error.code(), AiErrorCode::RequestTooLarge);
        assert_eq!(error.to_string(), "AI_REQUEST_TOO_LARGE");
    }
}
