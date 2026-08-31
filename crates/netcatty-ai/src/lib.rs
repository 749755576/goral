//! Native, bounded OpenAI-compatible chat transport.
//!
//! The renderer supplies the API key only for one request. It is immediately
//! moved into zeroizing storage, is never serializable, and is never included
//! in diagnostics. Provider response bodies are likewise never surfaced on
//! transport or HTTP errors.

mod agent;
mod anthropic;
mod models;
mod streaming;

pub use agent::{
    AI_TERMINAL_TOOL_CAPTURE_TIMEOUT_MS, AiAgentDecision, AiAgentTurn, AiPermissionMode,
    AiReasoningEffort, AiTerminalScope, AiTerminalToolCall, AiTerminalToolResult,
    MAX_AI_AGENT_TOOL_ITERATIONS, MAX_AI_TERMINAL_COMMAND_BYTES, MAX_AI_TOOL_OUTPUT_BYTES,
};
pub use anthropic::{
    ANTHROPIC_API_VERSION, AiAnthropicStream, MAX_ANTHROPIC_CONTENT_BLOCKS,
    MAX_ANTHROPIC_OUTPUT_TOKENS, MAX_ANTHROPIC_REQUEST_BYTES, normalize_anthropic_endpoint,
};
pub use models::MAX_AI_MODELS;
pub use streaming::{AiChatStream, AiStreamEvent};

use std::{fmt, future::Future, net::IpAddr, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{
    Client, StatusCode, Url,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_AI_URL_BYTES: usize = 2 * 1024;
pub const MAX_AI_KEY_BYTES: usize = 16 * 1024;
pub const MAX_AI_MODEL_BYTES: usize = 256;
pub const MAX_AI_MESSAGES: usize = 64;
pub const MAX_AI_MESSAGE_BYTES: usize = 128 * 1024;
pub const MAX_AI_REQUEST_TEXT_BYTES: usize = 512 * 1024;
pub const MAX_AI_IMAGE_PARTS: usize = 4;
pub const MAX_AI_IMAGE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_AI_REQUEST_IMAGE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_AI_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

const MAX_AI_IMAGE_BASE64_BYTES: usize = MAX_AI_IMAGE_BYTES.div_ceil(3) * 4;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 120;
pub const MIN_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 1;
pub const MAX_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 86_400;

/// Maximum time a provider may remain silent while a native AI request is
/// waiting for headers or the next response-body chunk.
///
/// This is deliberately not a total request deadline: every received chunk
/// resets the wait, so long streaming answers remain usable while stalled
/// providers still terminate predictably.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AiResponseIdleTimeout(Duration);

impl AiResponseIdleTimeout {
    pub const fn from_seconds(seconds: u32) -> Option<Self> {
        if seconds >= MIN_AI_RESPONSE_IDLE_TIMEOUT_SECONDS
            && seconds <= MAX_AI_RESPONSE_IDLE_TIMEOUT_SECONDS
        {
            Some(Self(Duration::from_secs(seconds as u64)))
        } else {
            None
        }
    }

    pub const fn as_seconds(self) -> u32 {
        self.0.as_secs() as u32
    }

    const fn duration(self) -> Duration {
        self.0
    }
}

impl Default for AiResponseIdleTimeout {
    fn default() -> Self {
        Self(Duration::from_secs(
            DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS as u64,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiErrorCode {
    UrlTooLong,
    UrlInvalid,
    UrlProtocol,
    UrlCredentials,
    UrlInsecure,
    ApiKeyRequired,
    ApiKeyInvalid,
    ModelRequired,
    ModelInvalid,
    ModelsEmpty,
    ModelsTooMany,
    MessagesInvalid,
    ImageInputInvalid,
    ImageInputUnsupported,
    RequestTooLarge,
    ClientUnavailable,
    RequestFailed,
    Timeout,
    Http,
    ResponseTooLarge,
    ResponseInvalid,
    EmptyResponse,
    AgentIterationLimit,
    AgentStateInvalid,
    TerminalScopeInvalid,
    ToolCallInvalid,
    ToolCommandInvalid,
    ToolResultInvalid,
}

impl AiErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UrlTooLong => "AI_URL_TOO_LONG",
            Self::UrlInvalid => "AI_URL_INVALID",
            Self::UrlProtocol => "AI_URL_PROTOCOL",
            Self::UrlCredentials => "AI_URL_CREDENTIALS",
            Self::UrlInsecure => "AI_URL_INSECURE",
            Self::ApiKeyRequired => "AI_API_KEY_REQUIRED",
            Self::ApiKeyInvalid => "AI_API_KEY_INVALID",
            Self::ModelRequired => "AI_MODEL_REQUIRED",
            Self::ModelInvalid => "AI_MODEL_INVALID",
            Self::ModelsEmpty => "AI_MODELS_EMPTY",
            Self::ModelsTooMany => "AI_MODELS_TOO_MANY",
            Self::MessagesInvalid => "AI_MESSAGES_INVALID",
            Self::ImageInputInvalid => "AI_IMAGE_INPUT_INVALID",
            Self::ImageInputUnsupported => "AI_IMAGE_INPUT_UNSUPPORTED",
            Self::RequestTooLarge => "AI_REQUEST_TOO_LARGE",
            Self::ClientUnavailable => "AI_CLIENT_UNAVAILABLE",
            Self::RequestFailed => "AI_REQUEST_FAILED",
            Self::Timeout => "AI_TIMEOUT",
            Self::Http => "AI_HTTP_ERROR",
            Self::ResponseTooLarge => "AI_RESPONSE_TOO_LARGE",
            Self::ResponseInvalid => "AI_RESPONSE_INVALID",
            Self::EmptyResponse => "AI_EMPTY_RESPONSE",
            Self::AgentIterationLimit => "AI_AGENT_ITERATION_LIMIT",
            Self::AgentStateInvalid => "AI_AGENT_STATE_INVALID",
            Self::TerminalScopeInvalid => "AI_TERMINAL_SCOPE_INVALID",
            Self::ToolCallInvalid => "AI_TOOL_CALL_INVALID",
            Self::ToolCommandInvalid => "AI_TOOL_COMMAND_INVALID",
            Self::ToolResultInvalid => "AI_TOOL_RESULT_INVALID",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AiError {
    code: AiErrorCode,
    http_status: Option<u16>,
}

impl AiError {
    pub const fn new(code: AiErrorCode) -> Self {
        Self {
            code,
            http_status: None,
        }
    }

    pub const fn http(status: StatusCode) -> Self {
        Self {
            code: AiErrorCode::Http,
            http_status: Some(status.as_u16()),
        }
    }

    pub const fn code(self) -> AiErrorCode {
        self.code
    }

    pub const fn http_status(self) -> Option<u16> {
        self.http_status
    }
}

impl fmt::Display for AiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = self.http_status {
            return write!(formatter, "{}:{status}", self.code.as_str());
        }
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AiError {}

/// An API key whose allocation is cleared when the in-flight request ends.
///
/// This type intentionally implements neither `Clone`, `Display`, nor Serde.
pub struct AiApiKey(Zeroizing<String>);

impl AiApiKey {
    pub fn new(value: String) -> Result<Self, AiError> {
        let value = Zeroizing::new(value);
        let bytes = value.as_bytes();
        if bytes.len() > MAX_AI_KEY_BYTES
            || bytes
                .iter()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(AiError::new(AiErrorCode::ApiKeyInvalid));
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for AiApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiApiKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AiChatRole {
    System,
    User,
    Assistant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiChatMessage {
    pub role: AiChatRole,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_parts: Vec<AiChatContentPart>,
}

impl AiChatMessage {
    pub fn has_image_content(&self) -> bool {
        !self.content_parts.is_empty()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum AiChatContentPart {
    Image {
        #[serde(rename = "mimeType")]
        mime_type: String,
        data: String,
    },
}

impl fmt::Debug for AiChatContentPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image { mime_type, data } => formatter
                .debug_struct("AiChatContentPart::Image")
                .field("mime_type", mime_type)
                .field("base64_bytes", &data.len())
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiChatRequest {
    pub model: String,
    pub messages: Vec<AiChatMessage>,
}

impl AiChatRequest {
    pub fn has_image_content(&self) -> bool {
        self.messages.iter().any(AiChatMessage::has_image_content)
    }
}

#[derive(Serialize)]
pub(crate) struct OpenAiProviderRequest<'a> {
    model: &'a str,
    messages: Vec<OpenAiProviderMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<AiReasoningEffort>,
}

#[derive(Serialize)]
struct OpenAiProviderMessage<'a> {
    role: AiChatRole,
    content: OpenAiProviderContent<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum OpenAiProviderContent<'a> {
    Text(&'a str),
    Parts(Vec<OpenAiProviderContentPart<'a>>),
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum OpenAiProviderContentPart<'a> {
    #[serde(rename = "text")]
    Text { text: &'a str },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: OpenAiProviderImageUrl },
}

#[derive(Serialize)]
struct OpenAiProviderImageUrl {
    url: String,
}

pub(crate) fn open_ai_provider_request(
    request: &AiChatRequest,
    stream: Option<bool>,
) -> OpenAiProviderRequest<'_> {
    open_ai_provider_request_with_reasoning_effort(request, stream, None)
}

pub(crate) fn open_ai_provider_request_with_reasoning_effort(
    request: &AiChatRequest,
    stream: Option<bool>,
    reasoning_effort: Option<AiReasoningEffort>,
) -> OpenAiProviderRequest<'_> {
    let messages = request
        .messages
        .iter()
        .map(|message| {
            let content = if message.content_parts.is_empty() {
                OpenAiProviderContent::Text(&message.content)
            } else {
                let mut parts = Vec::with_capacity(
                    message.content_parts.len() + usize::from(!message.content.is_empty()),
                );
                if !message.content.is_empty() {
                    parts.push(OpenAiProviderContentPart::Text {
                        text: &message.content,
                    });
                }
                parts.extend(message.content_parts.iter().map(|part| match part {
                    AiChatContentPart::Image { mime_type, data } => {
                        OpenAiProviderContentPart::ImageUrl {
                            image_url: OpenAiProviderImageUrl {
                                url: format!("data:{mime_type};base64,{data}"),
                            },
                        }
                    }
                }));
                OpenAiProviderContent::Parts(parts)
            };
            OpenAiProviderMessage {
                role: message.role,
                content,
            }
        })
        .collect();
    OpenAiProviderRequest {
        model: &request.model,
        messages,
        stream,
        reasoning_effort,
    }
}

#[derive(Clone)]
pub struct AiClient {
    client: Client,
}

impl fmt::Debug for AiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiClient")
    }
}

impl AiClient {
    pub fn new() -> Result<Self, AiError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|_| AiError::new(AiErrorCode::ClientUnavailable))?;
        Ok(Self { client })
    }

    pub async fn complete(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
    ) -> Result<String, AiError> {
        self.complete_with_timeout(base_url, api_key, request, AiResponseIdleTimeout::default())
            .await
    }

    pub async fn complete_with_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<String, AiError> {
        self.complete_with_reasoning_effort_and_timeout(
            base_url,
            api_key,
            request,
            None,
            response_idle_timeout,
        )
        .await
    }

    pub async fn complete_with_reasoning_effort_and_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        request: AiChatRequest,
        reasoning_effort: Option<AiReasoningEffort>,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<String, AiError> {
        let endpoint = normalize_endpoint(base_url)?;
        validate_request(&request)?;
        let loopback = is_loopback_host(&endpoint);
        if api_key.is_empty() && !loopback {
            return Err(AiError::new(AiErrorCode::ApiKeyRequired));
        }

        let provider_request =
            open_ai_provider_request_with_reasoning_effort(&request, None, reasoning_effort);
        let mut request_builder = self
            .client
            .post(endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&provider_request);
        if !api_key.is_empty() {
            let mut authorization = HeaderValue::from_str(&format!("Bearer {}", api_key.expose()))
                .map_err(|_| AiError::new(AiErrorCode::ApiKeyInvalid))?;
            authorization.set_sensitive(true);
            request_builder = request_builder.header(AUTHORIZATION, authorization);
        }

        let response = await_provider_io(response_idle_timeout, request_builder.send()).await?;

        let status = response.status();
        if !status.is_success() {
            // Never read or surface an error body: providers may echo prompts,
            // tokens, account identifiers, or other private material.
            return Err(AiError::http(status));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_AI_RESPONSE_BYTES as u64)
        {
            return Err(AiError::new(AiErrorCode::ResponseTooLarge));
        }

        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = await_provider_io(response_idle_timeout, response.chunk()).await? {
            let next_length = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| AiError::new(AiErrorCode::ResponseTooLarge))?;
            if next_length > MAX_AI_RESPONSE_BYTES {
                return Err(AiError::new(AiErrorCode::ResponseTooLarge));
            }
            body.extend_from_slice(&chunk);
        }

        let payload: ProviderResponse = serde_json::from_slice(&body)
            .map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))?;
        let content = payload
            .choices
            .into_iter()
            .next()
            .and_then(|choice| {
                choice
                    .message
                    .map(|message| message.content)
                    .or(choice.text)
            })
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
        if content.trim().is_empty() {
            return Err(AiError::new(AiErrorCode::EmptyResponse));
        }
        Ok(content)
    }
}

pub(crate) async fn await_provider_io<F, T>(
    response_idle_timeout: AiResponseIdleTimeout,
    operation: F,
) -> Result<T, AiError>
where
    F: Future<Output = Result<T, reqwest::Error>>,
{
    tokio::time::timeout(response_idle_timeout.duration(), operation)
        .await
        .map_err(|_| AiError::new(AiErrorCode::Timeout))?
        .map_err(map_request_error)
}

fn map_request_error(error: reqwest::Error) -> AiError {
    if error.is_timeout() {
        AiError::new(AiErrorCode::Timeout)
    } else {
        AiError::new(AiErrorCode::RequestFailed)
    }
}

pub fn normalize_endpoint(base_url: &str) -> Result<Url, AiError> {
    if base_url.as_bytes().len() > MAX_AI_URL_BYTES {
        return Err(AiError::new(AiErrorCode::UrlTooLong));
    }
    let mut url = Url::parse(base_url).map_err(|_| AiError::new(AiErrorCode::UrlInvalid))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(AiError::new(AiErrorCode::UrlProtocol));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(AiError::new(AiErrorCode::UrlCredentials));
    }
    let path = url.path().trim_end_matches('/');
    if !path.ends_with("/chat/completions") {
        let next = if path.is_empty() {
            "/chat/completions".to_owned()
        } else {
            format!("{path}/chat/completions")
        };
        url.set_path(&next);
    }
    Ok(url)
}

fn is_loopback_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn validate_request(request: &AiChatRequest) -> Result<(), AiError> {
    let model = request.model.trim();
    if model.is_empty() {
        return Err(AiError::new(AiErrorCode::ModelRequired));
    }
    if model.as_bytes().len() > MAX_AI_MODEL_BYTES || model.chars().any(char::is_control) {
        return Err(AiError::new(AiErrorCode::ModelInvalid));
    }
    if request.messages.is_empty() || request.messages.len() > MAX_AI_MESSAGES {
        return Err(AiError::new(AiErrorCode::MessagesInvalid));
    }
    let mut total = 0usize;
    let mut image_count = 0usize;
    let mut image_bytes = 0usize;
    for message in &request.messages {
        let length = message.content.as_bytes().len();
        if (length == 0 && message.content_parts.is_empty())
            || length > MAX_AI_MESSAGE_BYTES
            || message.content.contains('\0')
        {
            return Err(AiError::new(AiErrorCode::MessagesInvalid));
        }
        total = total
            .checked_add(length)
            .ok_or_else(|| AiError::new(AiErrorCode::RequestTooLarge))?;
        if total > MAX_AI_REQUEST_TEXT_BYTES {
            return Err(AiError::new(AiErrorCode::RequestTooLarge));
        }
        if !message.content_parts.is_empty() && message.role != AiChatRole::User {
            return Err(AiError::new(AiErrorCode::ImageInputInvalid));
        }
        for part in &message.content_parts {
            image_count = image_count
                .checked_add(1)
                .ok_or_else(|| AiError::new(AiErrorCode::RequestTooLarge))?;
            if image_count > MAX_AI_IMAGE_PARTS {
                return Err(AiError::new(AiErrorCode::RequestTooLarge));
            }
            let decoded_bytes = validate_image_part(part)?;
            image_bytes = image_bytes
                .checked_add(decoded_bytes)
                .ok_or_else(|| AiError::new(AiErrorCode::RequestTooLarge))?;
            if image_bytes > MAX_AI_REQUEST_IMAGE_BYTES {
                return Err(AiError::new(AiErrorCode::RequestTooLarge));
            }
        }
    }
    Ok(())
}

fn validate_image_part(part: &AiChatContentPart) -> Result<usize, AiError> {
    let AiChatContentPart::Image { mime_type, data } = part;
    if data.is_empty() || data.len() > MAX_AI_IMAGE_BASE64_BYTES {
        return Err(AiError::new(AiErrorCode::RequestTooLarge));
    }
    if !matches!(
        mime_type.as_str(),
        "image/png" | "image/jpeg" | "image/webp"
    ) {
        return Err(AiError::new(AiErrorCode::ImageInputInvalid));
    }
    let decoded = BASE64_STANDARD
        .decode(data)
        .map_err(|_| AiError::new(AiErrorCode::ImageInputInvalid))?;
    if decoded.is_empty()
        || decoded.len() > MAX_AI_IMAGE_BYTES
        || BASE64_STANDARD.encode(&decoded) != *data
        || !image_signature_matches(mime_type, &decoded)
    {
        return Err(AiError::new(AiErrorCode::ImageInputInvalid));
    }
    Ok(decoded.len())
}

fn image_signature_matches(mime_type: &str, decoded: &[u8]) -> bool {
    match mime_type {
        "image/png" => decoded.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => decoded.starts_with(&[0xff, 0xd8, 0xff]),
        "image/webp" => {
            decoded.len() >= 12 && decoded.starts_with(b"RIFF") && &decoded[8..12] == b"WEBP"
        }
        _ => false,
    }
}

#[derive(Deserialize)]
struct ProviderResponse {
    choices: Vec<ProviderChoice>,
}

#[derive(Deserialize)]
struct ProviderChoice {
    message: Option<ProviderMessage>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct ProviderMessage {
    content: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn endpoint_accepts_explicit_http_and_https_without_scheme_downgrade() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(AiResponseIdleTimeout::default().as_seconds(), 120);
        assert_eq!(
            normalize_endpoint("https://api.example.test/v1")
                .unwrap()
                .as_str(),
            "https://api.example.test/v1/chat/completions"
        );
        assert_eq!(
            normalize_endpoint("http://example.test/v1")
                .expect("explicit remote HTTP")
                .as_str(),
            "http://example.test/v1/chat/completions"
        );
        assert!(normalize_endpoint("http://localhost:8080/v1").is_ok());
        assert!(normalize_endpoint("http://127.0.0.1:8080/v1").is_ok());
        assert!(normalize_endpoint("http://[::1]:8080/v1").is_ok());
        assert!(
            normalize_endpoint("file:///tmp/private")
                .is_err_and(|error| { error.code() == AiErrorCode::UrlProtocol })
        );
        assert!(
            normalize_endpoint("https://user:pass@example.test/v1")
                .is_err_and(|error| { error.code() == AiErrorCode::UrlCredentials })
        );
    }

    #[test]
    fn response_idle_timeout_accepts_only_the_persisted_settings_range() {
        assert_eq!(AiResponseIdleTimeout::from_seconds(0), None);
        assert_eq!(
            AiResponseIdleTimeout::from_seconds(1)
                .expect("minimum response timeout")
                .as_seconds(),
            1
        );
        assert_eq!(
            AiResponseIdleTimeout::from_seconds(86_400)
                .expect("maximum response timeout")
                .as_seconds(),
            86_400
        );
        assert_eq!(AiResponseIdleTimeout::from_seconds(86_401), None);
    }

    #[tokio::test]
    async fn provider_io_maps_a_silent_wait_to_the_stable_timeout_error() {
        let timeout = AiResponseIdleTimeout(Duration::from_millis(10));
        let operation = std::future::pending::<Result<(), reqwest::Error>>();
        let error = await_provider_io(timeout, operation)
            .await
            .expect_err("silent provider I/O must time out");
        assert_eq!(error.code(), AiErrorCode::Timeout);
        assert_eq!(error.to_string(), "AI_TIMEOUT");
    }

    #[test]
    fn request_bounds_and_secret_diagnostics_are_fixed() {
        let key = AiApiKey::new("private-sentinel".to_owned()).unwrap();
        assert_eq!(format!("{key:?}"), "AiApiKey([REDACTED])");
        assert!(!format!("{key:?}").contains("private-sentinel"));
        assert!(AiApiKey::new(String::new()).is_ok());

        let invalid = AiChatRequest {
            model: "gpt-test".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "\0".to_owned(),
                content_parts: Vec::new(),
            }],
        };
        assert_eq!(
            validate_request(&invalid).unwrap_err().code(),
            AiErrorCode::MessagesInvalid
        );
    }

    #[test]
    fn bounded_image_contract_serializes_only_the_openai_data_url_schema() {
        let data = BASE64_STANDARD.encode(b"\x89PNG\r\n\x1a\n");
        let decoded: AiChatMessage = serde_json::from_value(json!({
            "role": "user",
            "content": "Describe this image.",
            "contentParts": [{
                "type": "image",
                "mimeType": "image/png",
                "data": data
            }]
        }))
        .expect("camelCase renderer contract");
        let request = AiChatRequest {
            model: "vision-model".to_owned(),
            messages: vec![decoded],
        };
        validate_request(&request).expect("valid image request");

        assert_eq!(
            serde_json::to_value(open_ai_provider_request(&request, None)).expect("provider JSON"),
            json!({
                "model": "vision-model",
                "messages": [{
                    "role": "user",
                    "content": [
                        { "type": "text", "text": "Describe this image." },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": format!("data:image/png;base64,{data}")
                            }
                        }
                    ]
                }]
            })
        );
        let debug = format!("{:?}", request.messages[0].content_parts[0]);
        assert!(!debug.contains(&data));
        assert!(debug.contains("base64_bytes"));
    }

    #[test]
    fn ordinary_openai_chat_serializes_optional_reasoning_effort() {
        let request = AiChatRequest {
            model: "reasoning-model".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "inspect the evidence".to_owned(),
                content_parts: Vec::new(),
            }],
        };

        let disabled = serde_json::to_value(open_ai_provider_request(&request, Some(true)))
            .expect("default provider JSON");
        assert_eq!(disabled.get("reasoning_effort"), None);

        let enabled = serde_json::to_value(open_ai_provider_request_with_reasoning_effort(
            &request,
            Some(true),
            Some(AiReasoningEffort::High),
        ))
        .expect("reasoning provider JSON");
        assert_eq!(enabled["reasoning_effort"], "high");
        assert_eq!(enabled["stream"], true);
    }

    #[test]
    fn image_contract_rejects_paths_urls_bad_base64_mime_spoofing_and_wrong_roles() {
        let valid_data = BASE64_STANDARD.encode(b"\x89PNG\r\n\x1a\n");
        for forbidden in [
            json!({
                "role": "user",
                "content": "inspect",
                "contentParts": [{
                    "type": "image",
                    "mimeType": "image/png",
                    "data": valid_data,
                    "path": "C:\\private\\screen.png"
                }]
            }),
            json!({
                "role": "user",
                "content": "inspect",
                "contentParts": [{
                    "type": "image",
                    "mimeType": "image/png",
                    "data": valid_data,
                    "url": "https://example.test/private.png"
                }]
            }),
        ] {
            assert!(serde_json::from_value::<AiChatMessage>(forbidden).is_err());
        }

        for (role, mime_type, data) in [
            (AiChatRole::User, "image/gif", valid_data.clone()),
            (
                AiChatRole::User,
                "image/png",
                "data:image/png;base64,AAAA".to_owned(),
            ),
            (
                AiChatRole::User,
                "image/png",
                BASE64_STANDARD.encode([0xff, 0xd8, 0xff]),
            ),
            (AiChatRole::Assistant, "image/png", valid_data),
        ] {
            let request = AiChatRequest {
                model: "vision-model".to_owned(),
                messages: vec![AiChatMessage {
                    role,
                    content: String::new(),
                    content_parts: vec![AiChatContentPart::Image {
                        mime_type: mime_type.to_owned(),
                        data,
                    }],
                }],
            };
            assert_eq!(
                validate_request(&request).unwrap_err().code(),
                AiErrorCode::ImageInputInvalid
            );
        }
    }

    #[test]
    fn image_count_is_bounded_independently_from_text() {
        let part = AiChatContentPart::Image {
            mime_type: "image/png".to_owned(),
            data: BASE64_STANDARD.encode(b"\x89PNG\r\n\x1a\n"),
        };
        let request = AiChatRequest {
            model: "vision-model".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: String::new(),
                content_parts: vec![part; MAX_AI_IMAGE_PARTS + 1],
            }],
        };
        assert_eq!(
            validate_request(&request).unwrap_err().code(),
            AiErrorCode::RequestTooLarge
        );
    }

    #[tokio::test]
    async fn native_transport_completes_against_a_loopback_provider() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(
                request_text
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-key")
            );
            let body = br#"{"choices":[{"message":{"content":"native answer"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });

        let answer = AiClient::new()
            .unwrap()
            .complete(
                &format!("http://{address}/v1"),
                AiApiKey::new("test-key".to_owned()).unwrap(),
                AiChatRequest {
                    model: "test-model".to_owned(),
                    messages: vec![AiChatMessage {
                        role: AiChatRole::User,
                        content: "hello".to_owned(),
                        content_parts: Vec::new(),
                    }],
                },
            )
            .await
            .unwrap();
        provider.await.unwrap();
        assert_eq!(answer, "native answer");
    }

    #[tokio::test]
    async fn loopback_provider_without_api_key_receives_no_authorization_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(!request_text.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            }));

            let body = br#"{"choices":[{"message":{"content":"local answer"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });

        let answer = AiClient::new()
            .unwrap()
            .complete(
                &format!("http://{address}/v1"),
                AiApiKey::new(String::new()).unwrap(),
                AiChatRequest {
                    model: "local-model".to_owned(),
                    messages: vec![AiChatMessage {
                        role: AiChatRole::User,
                        content: "hello locally".to_owned(),
                        content_parts: Vec::new(),
                    }],
                },
            )
            .await
            .unwrap();
        provider.await.unwrap();
        assert_eq!(answer, "local answer");
    }

    #[tokio::test]
    async fn remote_provider_requires_an_api_key_after_endpoint_normalization() {
        let request = AiChatRequest {
            model: "remote-model".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "hello remotely".to_owned(),
                content_parts: Vec::new(),
            }],
        };
        let client = AiClient::new().unwrap();
        let error = client
            .complete(
                "http://api.example.test/v1",
                AiApiKey::new(String::new()).unwrap(),
                request.clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), AiErrorCode::ApiKeyRequired);

        let error = client
            .complete(
                "file:///not-an-http-provider",
                AiApiKey::new(String::new()).unwrap(),
                request,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), AiErrorCode::UrlProtocol);
    }

    #[tokio::test]
    async fn provider_error_body_is_never_exposed() {
        const PRIVATE_PROVIDER_BODY: &str = "private-provider-error-sentinel";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PRIVATE_PROVIDER_BODY}",
                PRIVATE_PROVIDER_BODY.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let error = AiClient::new()
            .unwrap()
            .complete(
                &format!("http://{address}/v1"),
                AiApiKey::new("private-key-sentinel".to_owned()).unwrap(),
                AiChatRequest {
                    model: "test-model".to_owned(),
                    messages: vec![AiChatMessage {
                        role: AiChatRole::User,
                        content: "private-prompt-sentinel".to_owned(),
                        content_parts: Vec::new(),
                    }],
                },
            )
            .await
            .unwrap_err();
        provider.await.unwrap();

        assert_eq!(error.to_string(), "AI_HTTP_ERROR:401");
        assert!(!error.to_string().contains(PRIVATE_PROVIDER_BODY));
        assert!(!error.to_string().contains("private-key-sentinel"));
        assert!(!error.to_string().contains("private-prompt-sentinel"));
    }
}
