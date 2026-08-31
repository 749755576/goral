//! Bounded OpenAI-compatible and Anthropic model catalog discovery.
//!
//! Each models endpoint is derived only by replacing its normalized chat
//! suffix (`/chat/completions` or `/messages`). Scheme, host, port, and query
//! remain under the same native authority, and the shared client rejects every
//! redirect.

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderName, HeaderValue};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    ANTHROPIC_API_VERSION, AiApiKey, AiClient, AiError, AiErrorCode, AiResponseIdleTimeout,
    MAX_AI_MODEL_BYTES, MAX_AI_RESPONSE_BYTES, MAX_AI_URL_BYTES, await_provider_io,
    is_loopback_host, normalize_anthropic_endpoint, normalize_endpoint,
};

/// Maximum number of provider model entries accepted before de-duplication.
pub const MAX_AI_MODELS: usize = 512;

const MAX_ANTHROPIC_MODEL_PAGES: usize = 64;
const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const ANTHROPIC_VERSION: HeaderName = HeaderName::from_static("anthropic-version");

impl AiClient {
    /// Lists a bounded, sorted, de-duplicated OpenAI-compatible model catalog.
    ///
    /// `base_url` uses the same accepted forms as chat completion. The
    /// resulting request always targets the same origin at the sibling
    /// `/models` path. A successful provider response with no models returns
    /// [`AiErrorCode::ModelsEmpty`] so connection testing can distinguish it
    /// from a usable catalog.
    pub async fn list_models(
        &self,
        base_url: &str,
        api_key: AiApiKey,
    ) -> Result<Vec<String>, AiError> {
        self.list_models_with_timeout(base_url, api_key, AiResponseIdleTimeout::default())
            .await
    }

    pub async fn list_models_with_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<Vec<String>, AiError> {
        let endpoint = models_endpoint(base_url)?;
        if api_key.is_empty() && !is_loopback_host(&endpoint) {
            return Err(AiError::new(AiErrorCode::ApiKeyRequired));
        }

        let mut request = self.client.get(endpoint).header(ACCEPT, "application/json");
        if !api_key.is_empty() {
            let bearer = Zeroizing::new(format!("Bearer {}", api_key.expose()));
            let mut authorization = HeaderValue::from_str(bearer.as_str())
                .map_err(|_| AiError::new(AiErrorCode::ApiKeyInvalid))?;
            authorization.set_sensitive(true);
            request = request.header(AUTHORIZATION, authorization);
        }

        let response = await_provider_io(response_idle_timeout, request.send()).await?;
        parse_models_response(response, response_idle_timeout).await
    }

    /// Lists a bounded, sorted, de-duplicated direct Anthropic model catalog.
    ///
    /// The endpoint is the same-origin sibling of the normalized Messages
    /// endpoint (`/v1/messages` becomes `/v1/models`). Authentication uses
    /// only Anthropic's sensitive `x-api-key` header and the fixed reviewed
    /// API version. Pagination is followed only on the same normalized origin
    /// and remains inside the shared response/model bounds; redirects and
    /// provider error bodies remain rejected.
    pub async fn list_anthropic_models(
        &self,
        base_url: &str,
        api_key: AiApiKey,
    ) -> Result<Vec<String>, AiError> {
        self.list_anthropic_models_with_timeout(base_url, api_key, AiResponseIdleTimeout::default())
            .await
    }

    pub async fn list_anthropic_models_with_timeout(
        &self,
        base_url: &str,
        api_key: AiApiKey,
        response_idle_timeout: AiResponseIdleTimeout,
    ) -> Result<Vec<String>, AiError> {
        let mut endpoint = anthropic_models_endpoint(base_url)?;
        if api_key.is_empty() {
            return Err(AiError::new(AiErrorCode::ApiKeyRequired));
        }

        let mut key = HeaderValue::from_str(api_key.expose())
            .map_err(|_| AiError::new(AiErrorCode::ApiKeyInvalid))?;
        key.set_sensitive(true);
        let mut response_budget = MAX_AI_RESPONSE_BYTES;
        let mut page_count = 0_usize;
        let mut models = Vec::new();
        let mut seen_cursors = std::collections::HashSet::new();
        loop {
            if page_count >= MAX_ANTHROPIC_MODEL_PAGES {
                return Err(AiError::new(AiErrorCode::ResponseInvalid));
            }
            if response_budget == 0 {
                return Err(AiError::new(AiErrorCode::ResponseTooLarge));
            }
            page_count += 1;

            let request = self
                .client
                .get(endpoint.clone())
                .header(ACCEPT, "application/json")
                .header(
                    ANTHROPIC_VERSION,
                    HeaderValue::from_static(ANTHROPIC_API_VERSION),
                )
                .header(X_API_KEY, key.clone());
            let body = read_models_body(
                await_provider_io(response_idle_timeout, request.send()).await?,
                response_budget,
                response_idle_timeout,
            )
            .await?;
            response_budget -= body.len();

            let page = parse_models_payload(&body)?;
            let has_more = page.has_more;
            let last_id = page.last_id;
            append_provider_models(&mut models, page.data)?;
            if !has_more {
                return finalize_models(models);
            }

            let cursor = last_id.ok_or_else(|| AiError::new(AiErrorCode::ResponseInvalid))?;
            if !valid_model_id(&cursor) {
                return Err(AiError::new(AiErrorCode::ModelInvalid));
            }
            if !seen_cursors.insert(cursor.clone()) {
                return Err(AiError::new(AiErrorCode::ResponseInvalid));
            }
            endpoint = anthropic_models_page_endpoint(&endpoint, &cursor)?;
        }
    }
}

async fn parse_models_response(
    response: reqwest::Response,
    response_idle_timeout: AiResponseIdleTimeout,
) -> Result<Vec<String>, AiError> {
    let body = read_models_body(response, MAX_AI_RESPONSE_BYTES, response_idle_timeout).await?;
    parse_models(&body)
}

async fn read_models_body(
    mut response: reqwest::Response,
    max_bytes: usize,
    response_idle_timeout: AiResponseIdleTimeout,
) -> Result<Vec<u8>, AiError> {
    let status = response.status();
    if !status.is_success() {
        // Never read an error body. Providers and gateways may echo API keys,
        // account data, or request details in it.
        return Err(AiError::http(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(AiError::new(AiErrorCode::ResponseTooLarge));
    }

    let mut body = Vec::new();
    while let Some(chunk) = await_provider_io(response_idle_timeout, response.chunk()).await? {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AiError::new(AiErrorCode::ResponseTooLarge))?;
        if next_length > max_bytes {
            return Err(AiError::new(AiErrorCode::ResponseTooLarge));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

fn models_endpoint(base_url: &str) -> Result<reqwest::Url, AiError> {
    let mut endpoint = normalize_endpoint(base_url)?;
    let normalized_path = endpoint.path().trim_end_matches('/');
    let prefix = normalized_path
        .strip_suffix("/chat/completions")
        .ok_or_else(|| AiError::new(AiErrorCode::UrlInvalid))?;
    let models_path = if prefix.is_empty() {
        "/models".to_owned()
    } else {
        format!("{prefix}/models")
    };
    endpoint.set_path(&models_path);
    Ok(endpoint)
}

fn anthropic_models_endpoint(base_url: &str) -> Result<reqwest::Url, AiError> {
    let mut endpoint = normalize_anthropic_endpoint(base_url)?;
    let normalized_path = endpoint.path().trim_end_matches('/');
    let prefix = normalized_path
        .strip_suffix("/messages")
        .ok_or_else(|| AiError::new(AiErrorCode::UrlInvalid))?;
    let models_path = if prefix.is_empty() {
        "/models".to_owned()
    } else {
        format!("{prefix}/models")
    };
    endpoint.set_path(&models_path);
    Ok(endpoint)
}

fn anthropic_models_page_endpoint(
    endpoint: &reqwest::Url,
    after_id: &str,
) -> Result<reqwest::Url, AiError> {
    let preserved_query = endpoint
        .query_pairs()
        .filter(|(name, _)| name != "after_id")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut next = endpoint.clone();
    next.set_query(None);
    {
        let mut query = next.query_pairs_mut();
        for (name, value) in preserved_query {
            query.append_pair(&name, &value);
        }
        query.append_pair("after_id", after_id);
    }
    if next.as_str().len() > MAX_AI_URL_BYTES {
        return Err(AiError::new(AiErrorCode::UrlTooLong));
    }
    Ok(next)
}

fn parse_models(body: &[u8]) -> Result<Vec<String>, AiError> {
    let payload = parse_models_payload(body)?;
    let mut models = Vec::with_capacity(payload.data.len());
    append_provider_models(&mut models, payload.data)?;
    finalize_models(models)
}

fn parse_models_payload(body: &[u8]) -> Result<ProviderModelsResponse, AiError> {
    serde_json::from_slice(body).map_err(|_| AiError::new(AiErrorCode::ResponseInvalid))
}

fn append_provider_models(
    models: &mut Vec<String>,
    provider_models: Vec<ProviderModel>,
) -> Result<(), AiError> {
    if models
        .len()
        .checked_add(provider_models.len())
        .is_none_or(|count| count > MAX_AI_MODELS)
    {
        return Err(AiError::new(AiErrorCode::ModelsTooMany));
    }

    for model in provider_models {
        let id = model.id;
        if !valid_model_id(&id) {
            return Err(AiError::new(AiErrorCode::ModelInvalid));
        }
        models.push(id);
    }
    Ok(())
}

fn valid_model_id(id: &str) -> bool {
    !id.trim().is_empty() && id.len() <= MAX_AI_MODEL_BYTES && !id.chars().any(char::is_control)
}

fn finalize_models(mut models: Vec<String>) -> Result<Vec<String>, AiError> {
    models.sort();
    models.dedup();
    if models.is_empty() {
        return Err(AiError::new(AiErrorCode::ModelsEmpty));
    }
    Ok(models)
}

#[derive(Deserialize)]
struct ProviderModelsResponse {
    data: Vec<ProviderModel>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    last_id: Option<String>,
}

#[derive(Deserialize)]
struct ProviderModel {
    id: String,
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
        let mut buffer = [0_u8; 4_096];
        loop {
            let read = stream.read(&mut buffer).await.expect("provider request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|part| part == b"\r\n\r\n") {
                break;
            }
        }
        request
    }

    async fn write_chunked_response(stream: &mut TcpStream, body: &[u8]) {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("provider response headers");
        for part in body.chunks(3) {
            stream
                .write_all(format!("{:X}\r\n", part.len()).as_bytes())
                .await
                .expect("chunk header");
            stream.write_all(part).await.expect("chunk body");
            stream.write_all(b"\r\n").await.expect("chunk suffix");
            tokio::task::yield_now().await;
        }
        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("chunk terminator");
    }

    fn assert_authorization(request: &str, expected: Option<&str>) {
        let actual = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then_some(value.trim())
        });
        assert_eq!(actual, expected);
    }

    fn header_value<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim())
        })
    }

    #[test]
    fn models_endpoint_replaces_only_the_normalized_chat_path() {
        let endpoint = models_endpoint(
            "https://API.EXAMPLE.TEST:443/v1/chat/completions/?api-version=2026-01-01",
        )
        .expect("models endpoint");
        assert_eq!(endpoint.scheme(), "https");
        assert_eq!(endpoint.host_str(), Some("api.example.test"));
        assert_eq!(endpoint.port_or_known_default(), Some(443));
        assert_eq!(endpoint.path(), "/v1/models");
        assert_eq!(endpoint.query(), Some("api-version=2026-01-01"));

        assert_eq!(
            models_endpoint("https://api.example.test")
                .expect("root models endpoint")
                .as_str(),
            "https://api.example.test/models"
        );
        assert_eq!(
            models_endpoint("http://192.0.2.10/v1")
                .expect("explicit remote HTTP")
                .as_str(),
            "http://192.0.2.10/v1/models"
        );
    }

    #[test]
    fn anthropic_models_endpoint_replaces_only_the_normalized_messages_path() {
        let endpoint = anthropic_models_endpoint(
            "https://API.ANTHROPIC.TEST:443/v1/messages/?api-version=2026-01-01",
        )
        .expect("Anthropic models endpoint");
        assert_eq!(endpoint.scheme(), "https");
        assert_eq!(endpoint.host_str(), Some("api.anthropic.test"));
        assert_eq!(endpoint.port_or_known_default(), Some(443));
        assert_eq!(endpoint.path(), "/v1/models");
        assert_eq!(endpoint.query(), Some("api-version=2026-01-01"));

        let custom = anthropic_models_endpoint(
            "https://gateway.anthropic.test/tenant/api/messages/?region=cn",
        )
        .expect("custom-prefix Anthropic models endpoint");
        assert_eq!(custom.path(), "/tenant/api/models");
        assert_eq!(custom.query(), Some("region=cn"));

        assert_eq!(
            anthropic_models_endpoint("https://api.anthropic.test")
                .expect("root Anthropic models endpoint")
                .as_str(),
            "https://api.anthropic.test/v1/models"
        );
        assert_eq!(
            anthropic_models_endpoint("http://192.0.2.10/v1/messages")
                .expect("explicit remote HTTP")
                .as_str(),
            "http://192.0.2.10/v1/models"
        );
    }

    #[tokio::test]
    async fn lists_fragmented_models_with_authorization_and_stable_ordering() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /v1/models?source=settings HTTP/1.1\r\n"));
            assert_authorization(&request, Some("Bearer private-model-key"));
            assert!(request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("accept")
                        && value.trim().eq_ignore_ascii_case("application/json")
                })
            }));
            let body = serde_json::json!({
                "object": "list",
                "data": [
                    {"id": "zeta", "object": "model"},
                    {"id": "alpha"},
                    {"id": "zeta"},
                    {"id": "中文模型"}
                ]
            })
            .to_string();
            write_chunked_response(&mut stream, body.as_bytes()).await;
        });

        let models = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1/chat/completions/?source=settings"),
                AiApiKey::new("private-model-key".to_owned()).expect("API key"),
            )
            .await
            .expect("model catalog");
        provider.await.expect("provider task");
        assert_eq!(models, vec!["alpha", "zeta", "中文模型"]);
    }

    #[tokio::test]
    async fn lists_anthropic_models_with_protocol_headers_and_no_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /v1/models?source=settings HTTP/1.1\r\n"));
            assert_eq!(
                header_value(&request, "x-api-key"),
                Some("private-anthropic-model-key")
            );
            assert_eq!(
                header_value(&request, "anthropic-version"),
                Some(ANTHROPIC_API_VERSION)
            );
            assert_authorization(&request, None);

            let body = serde_json::json!({
                "data": [
                    {"type": "model", "id": "claude-z"},
                    {"type": "model", "id": "claude-a"},
                    {"type": "model", "id": "claude-z"}
                ],
                "has_more": false
            })
            .to_string();
            write_chunked_response(&mut stream, body.as_bytes()).await;
        });

        let models = AiClient::new()
            .expect("AI client")
            .list_anthropic_models(
                &format!("http://{address}/v1/messages/?source=settings"),
                AiApiKey::new("private-anthropic-model-key".to_owned()).expect("API key"),
            )
            .await
            .expect("Anthropic model catalog");
        provider.await.expect("provider task");
        assert_eq!(models, vec!["claude-a", "claude-z"]);
    }

    #[tokio::test]
    async fn lists_all_anthropic_model_pages_with_one_bounded_same_origin_cursor() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            for page in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("provider accept");
                let request = read_http_request(&mut stream).await;
                let request = String::from_utf8_lossy(&request);
                let expected_target = if page == 0 {
                    "/v1/models?source=settings"
                } else {
                    "/v1/models?source=settings&after_id=claude-z"
                };
                assert!(request.starts_with(&format!("GET {expected_target} HTTP/1.1\r\n")));
                assert_eq!(
                    header_value(&request, "x-api-key"),
                    Some("private-anthropic-pagination-key")
                );
                assert_eq!(
                    header_value(&request, "anthropic-version"),
                    Some(ANTHROPIC_API_VERSION)
                );
                assert_authorization(&request, None);

                let body = if page == 0 {
                    serde_json::json!({
                        "data": [
                            {"type": "model", "id": "claude-z"},
                            {"type": "model", "id": "claude-b"}
                        ],
                        "has_more": true,
                        "last_id": "claude-z"
                    })
                } else {
                    serde_json::json!({
                        "data": [
                            {"type": "model", "id": "claude-a"},
                            {"type": "model", "id": "claude-b"}
                        ],
                        "has_more": false,
                        "last_id": "claude-b"
                    })
                }
                .to_string();
                write_chunked_response(&mut stream, body.as_bytes()).await;
            }
        });

        let models = AiClient::new()
            .expect("AI client")
            .list_anthropic_models(
                &format!("http://{address}/v1/messages/?source=settings"),
                AiApiKey::new("private-anthropic-pagination-key".to_owned()).expect("API key"),
            )
            .await
            .expect("complete Anthropic model catalog");
        provider.await.expect("provider task");
        assert_eq!(models, vec!["claude-a", "claude-b", "claude-z"]);
    }

    #[tokio::test]
    async fn anthropic_empty_key_is_rejected_before_loopback_network_io() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let error = AiClient::new()
            .expect("AI client")
            .list_anthropic_models(
                &format!("http://{address}/v1/messages"),
                AiApiKey::new(String::new()).expect("empty API key"),
            )
            .await
            .expect_err("Anthropic model discovery requires a key");
        assert_eq!(error.code(), AiErrorCode::ApiKeyRequired);
        assert!(
            listener
                .accept()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "empty-key discovery must not contact the provider"
        );
    }

    #[tokio::test]
    async fn loopback_without_a_key_is_allowed_but_an_empty_catalog_is_explicit() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
            assert_authorization(&request, None);
            let body = br#"{"data":[]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("provider headers");
            stream.write_all(body).await.expect("provider body");
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1"),
                AiApiKey::new(String::new()).expect("empty loopback key"),
            )
            .await
            .expect_err("empty model catalog");
        provider.await.expect("provider task");
        assert_eq!(error.code(), AiErrorCode::ModelsEmpty);
        assert_eq!(error.to_string(), "AI_MODELS_EMPTY");

        let remote_error = AiClient::new()
            .expect("AI client")
            .list_models(
                "http://api.example.test/v1",
                AiApiKey::new(String::new()).expect("empty remote key"),
            )
            .await
            .expect_err("remote key requirement");
        assert_eq!(remote_error.code(), AiErrorCode::ApiKeyRequired);
    }

    #[tokio::test]
    async fn malformed_fragmented_response_never_enters_the_error() {
        const PRIVATE_BODY: &str = "private-malformed-model-sentinel";
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let _ = read_http_request(&mut stream).await;
            let body = format!(r#"{{"data":{{"id":"{PRIVATE_BODY}"}}}}"#);
            write_chunked_response(&mut stream, body.as_bytes()).await;
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1"),
                AiApiKey::new("private-malformed-key".to_owned()).expect("API key"),
            )
            .await
            .expect_err("malformed model response");
        provider.await.expect("provider task");
        let diagnostic = format!("{error:?} {error}");
        assert_eq!(error.code(), AiErrorCode::ResponseInvalid);
        assert_eq!(error.to_string(), "AI_RESPONSE_INVALID");
        assert!(!diagnostic.contains(PRIVATE_BODY));
        assert!(!diagnostic.contains("private-malformed-key"));
    }

    #[tokio::test]
    async fn streamed_response_over_the_two_mebibyte_limit_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let _ = read_http_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
                .await
                .expect("provider headers");
            let body = vec![b'x'; MAX_AI_RESPONSE_BYTES + 1];
            for part in body.chunks(32 * 1024) {
                if stream.write_all(part).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1"),
                AiApiKey::new(String::new()).expect("empty loopback key"),
            )
            .await
            .expect_err("oversized response");
        provider.await.expect("provider task");
        assert_eq!(error.code(), AiErrorCode::ResponseTooLarge);
        assert_eq!(error.to_string(), "AI_RESPONSE_TOO_LARGE");
    }

    #[tokio::test]
    async fn http_error_body_and_api_key_are_never_exposed() {
        const PRIVATE_BODY: &str = "private-model-http-error";
        const PRIVATE_KEY: &str = "private-model-http-key";
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            assert_authorization(
                &String::from_utf8_lossy(&request),
                Some("Bearer private-model-http-key"),
            );
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PRIVATE_BODY}",
                        PRIVATE_BODY.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("provider error");
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1"),
                AiApiKey::new(PRIVATE_KEY.to_owned()).expect("API key"),
            )
            .await
            .expect_err("HTTP error");
        provider.await.expect("provider task");
        let diagnostic = format!("{error:?} {error}");
        assert_eq!(error.http_status(), Some(401));
        assert_eq!(error.to_string(), "AI_HTTP_ERROR:401");
        assert!(!diagnostic.contains(PRIVATE_BODY));
        assert!(!diagnostic.contains(PRIVATE_KEY));
    }

    #[tokio::test]
    async fn anthropic_http_error_body_and_api_key_are_never_exposed() {
        const PRIVATE_BODY: &str = "private-anthropic-model-http-error";
        const PRIVATE_KEY: &str = "private-anthropic-model-http-key";
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let request = read_http_request(&mut stream).await;
            let request = String::from_utf8_lossy(&request);
            assert_eq!(header_value(&request, "x-api-key"), Some(PRIVATE_KEY));
            assert_authorization(&request, None);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PRIVATE_BODY}",
                        PRIVATE_BODY.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("provider error");
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_anthropic_models(
                &format!("http://{address}/v1/messages"),
                AiApiKey::new(PRIVATE_KEY.to_owned()).expect("API key"),
            )
            .await
            .expect_err("Anthropic HTTP error");
        provider.await.expect("provider task");
        let diagnostic = format!("{error:?} {error}");
        assert_eq!(error.http_status(), Some(401));
        assert_eq!(error.to_string(), "AI_HTTP_ERROR:401");
        assert!(!diagnostic.contains(PRIVATE_BODY));
        assert!(!diagnostic.contains(PRIVATE_KEY));
    }

    #[tokio::test]
    async fn cross_origin_redirect_is_returned_without_being_followed() {
        let redirect_target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect target reservation");
        let redirect_address = redirect_target
            .local_addr()
            .expect("redirect target address");
        drop(redirect_target);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("provider accept");
            let _ = read_http_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{redirect_address}/private-models\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("redirect response");
        });

        let error = AiClient::new()
            .expect("AI client")
            .list_models(
                &format!("http://{address}/v1"),
                AiApiKey::new(String::new()).expect("empty loopback key"),
            )
            .await
            .expect_err("redirect rejection");
        provider.await.expect("provider task");
        assert_eq!(error.http_status(), Some(302));
        assert_eq!(error.to_string(), "AI_HTTP_ERROR:302");
    }

    #[test]
    fn parser_enforces_model_count_and_identifier_bounds() {
        let too_many = serde_json::json!({
            "data": (0..=MAX_AI_MODELS)
                .map(|_| serde_json::json!({"id": "duplicate"}))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            parse_models(&serde_json::to_vec(&too_many).expect("too many JSON"))
                .expect_err("raw provider count"),
            AiError::new(AiErrorCode::ModelsTooMany)
        );

        let too_long = serde_json::json!({
            "data": [{"id": "x".repeat(MAX_AI_MODEL_BYTES + 1)}]
        });
        assert_eq!(
            parse_models(&serde_json::to_vec(&too_long).expect("long ID JSON"))
                .expect_err("long model ID"),
            AiError::new(AiErrorCode::ModelInvalid)
        );

        let exact = "x".repeat(MAX_AI_MODEL_BYTES);
        let exact_body = serde_json::json!({"data": [{"id": exact.clone()}]});
        assert_eq!(
            parse_models(&serde_json::to_vec(&exact_body).expect("exact ID JSON"))
                .expect("exact model ID"),
            vec![exact]
        );
    }
}
