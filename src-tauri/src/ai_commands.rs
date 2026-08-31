use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Duration, Instant},
};

use netcatty_ai::{
    AiAgentDecision, AiAgentTurn, AiAnthropicStream, AiApiKey, AiChatMessage, AiChatRequest,
    AiChatStream, AiClient, AiPermissionMode, AiReasoningEffort, AiResponseIdleTimeout,
    AiStreamEvent as NativeAiStreamEvent, AiTerminalScope, AiTerminalToolCall,
    AiTerminalToolResult, MAX_AI_KEY_BYTES, MAX_AI_RESPONSE_BYTES, normalize_anthropic_endpoint,
    normalize_endpoint,
};
use netcatty_credentials::{
    CredentialErrorCode, CredentialKind, MAX_PERSISTENT_SECRET_BYTES, OsCredentialStore,
    SecretValue, StoredCredentialReference,
};
use serde::{Deserialize, Serialize};
use tauri::{State, ipc::Channel};
use tokio::sync::oneshot;
use zeroize::Zeroize;

use crate::settings_catalog::{
    AiCommandPermissionMode, AiProviderAuthoritySettings, AiProviderProtocol,
    RendererSafeSettingsStore,
};

const MAX_ACTIVE_AI_REQUESTS: usize = 8;
const MAX_PENDING_AI_TURNS: usize = 8;
const AI_PENDING_APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
const AI_REQUEST_ID_MAX_BYTES: usize = 128;
const AI_PROVIDER_INVALID: &str = "AI_PROVIDER_INVALID";
const AI_KEY_SOURCE_INVALID: &str = "AI_KEY_SOURCE_INVALID";
const AI_STORED_KEY_NOT_FOUND: &str = "AI_STORED_KEY_NOT_FOUND";
const AI_CREDENTIAL_STORE_FAILED: &str = "AI_CREDENTIAL_STORE_FAILED";
const AI_STREAM_CHANNEL_CLOSED: &str = "AI_STREAM_CHANNEL_CLOSED";
const AI_AGENT_PROTOCOL_UNSUPPORTED: &str = "AI_AGENT_PROTOCOL_UNSUPPORTED";
const AI_REASONING_PROTOCOL_UNSUPPORTED: &str = "AI_REASONING_PROTOCOL_UNSUPPORTED";
const AI_IMAGE_INPUT_UNSUPPORTED: &str = "AI_IMAGE_INPUT_UNSUPPORTED";
const LEGACY_DEEPSEEK_CONSOLE_BASE_URL: &str = "https://platform.deepseek.com/v1";
const DEEPSEEK_API_BASE_URL: &str = "https://api.deepseek.com/v1";

#[derive(Clone, Eq, PartialEq)]
struct NativeAiAuthority {
    profile_id: String,
    provider_id: String,
    protocol: AiProviderProtocol,
    canonical_endpoint: String,
    model: String,
    permission_mode: AiPermissionMode,
    response_idle_timeout: AiResponseIdleTimeout,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompleteAiChatRequest {
    request_id: String,
    provider_profile_id: String,
    messages: Vec<AiChatMessage>,
    reasoning_effort: Option<AiReasoningEffort>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SaveAiApiKeyRequest {
    provider_profile_id: String,
    api_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartAiAgentTurnRequest {
    turn_id: String,
    provider_profile_id: String,
    messages: Vec<AiChatMessage>,
    terminal_scope: Option<AiTerminalScope>,
    reasoning_effort: Option<AiReasoningEffort>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContinueAiAgentTurnRequest {
    turn_id: String,
    tool_call_id: String,
    terminal_scope: AiTerminalScope,
    result: AiTerminalToolResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorizeAiAgentToolRequest {
    turn_id: String,
    tool_call_id: String,
    terminal_scope: AiTerminalScope,
    user_approved: bool,
}

impl Drop for SaveAiApiKeyRequest {
    fn drop(&mut self) {
        self.api_key.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompleteAiChatResponse {
    content: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum AiChatStreamEvent {
    Delta { content: String },
    Done,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum AiAgentTurnResponse {
    Completed {
        content: String,
    },
    ToolCall {
        turn_id: String,
        call: AiTerminalToolCall,
        approval_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<String>,
    },
}

type CancelSender = oneshot::Sender<()>;

struct RegisteredRequest {
    identity: Arc<()>,
    cancel: CancelSender,
}

struct RequestRegistration {
    request_id: String,
    identity: Arc<()>,
}

impl Drop for RequestRegistration {
    fn drop(&mut self) {
        let mut requests = lock_request_registry();
        if requests
            .get(&self.request_id)
            .is_some_and(|request| Arc::ptr_eq(&request.identity, &self.identity))
        {
            requests.remove(&self.request_id);
        }
    }
}

fn request_registry() -> &'static Mutex<HashMap<String, RegisteredRequest>> {
    static REQUESTS: OnceLock<Mutex<HashMap<String, RegisteredRequest>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct PendingAgentTurn {
    base_url: String,
    api_key: AiApiKey,
    turn: AiAgentTurn,
    response_idle_timeout: AiResponseIdleTimeout,
}

struct RegisteredPendingAgentTurn {
    identity: Arc<()>,
    expires_at: Instant,
    execution_authorized: bool,
    pending: PendingAgentTurn,
}

fn pending_agent_turns() -> &'static Mutex<HashMap<String, RegisteredPendingAgentTurn>> {
    static TURNS: OnceLock<Mutex<HashMap<String, RegisteredPendingAgentTurn>>> = OnceLock::new();
    TURNS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_pending_agent_turns() -> MutexGuard<'static, HashMap<String, RegisteredPendingAgentTurn>> {
    pending_agent_turns()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn prune_expired_pending_agent_turns(turns: &mut HashMap<String, RegisteredPendingAgentTurn>) {
    let now = Instant::now();
    turns.retain(|_, turn| turn.expires_at > now);
}

fn remove_pending_agent_turn_if_identity(turn_id: &str, identity: &Arc<()>) -> bool {
    let mut turns = lock_pending_agent_turns();
    if turns
        .get(turn_id)
        .is_some_and(|turn| Arc::ptr_eq(&turn.identity, identity))
    {
        turns.remove(turn_id);
        true
    } else {
        false
    }
}

fn lock_request_registry() -> MutexGuard<'static, HashMap<String, RegisteredRequest>> {
    request_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn register_request(
    request_id: String,
    cancel: CancelSender,
) -> Result<RequestRegistration, String> {
    let mut requests = lock_request_registry();
    if requests.len() >= MAX_ACTIVE_AI_REQUESTS {
        return Err("AI_BUSY".to_owned());
    }
    if requests.contains_key(&request_id) {
        return Err("AI_REQUEST_ID_DUPLICATE".to_owned());
    }

    let identity = Arc::new(());
    requests.insert(
        request_id.clone(),
        RegisteredRequest {
            identity: Arc::clone(&identity),
            cancel,
        },
    );
    Ok(RequestRegistration {
        request_id,
        identity,
    })
}

fn shared_client() -> Result<&'static AiClient, String> {
    static CLIENT: OnceLock<Result<AiClient, netcatty_ai::AiError>> = OnceLock::new();
    CLIENT
        .get_or_init(AiClient::new)
        .as_ref()
        .map_err(ToString::to_string)
}

fn validate_request_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.as_bytes().len() > AI_REQUEST_ID_MAX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("AI_REQUEST_ID_INVALID".to_owned());
    }
    Ok(())
}

fn legacy_ai_provider_reference(provider_id: &str) -> Result<StoredCredentialReference, String> {
    StoredCredentialReference::for_ai_provider(provider_id)
        .map_err(|_| AI_PROVIDER_INVALID.to_owned())
}

fn endpoint_ai_provider_reference(
    authority: &NativeAiAuthority,
) -> Result<StoredCredentialReference, String> {
    StoredCredentialReference::for_ai_provider_endpoint(
        &authority.profile_id,
        &authority.canonical_endpoint,
    )
    .map_err(|_| AI_PROVIDER_INVALID.to_owned())
}

fn legacy_endpoint_ai_provider_reference(
    authority: &NativeAiAuthority,
) -> Option<StoredCredentialReference> {
    if authority.protocol != AiProviderProtocol::OpenAiChatCompletions
        || authority.provider_id != "deepseek"
    {
        return None;
    }
    let current = normalize_endpoint(DEEPSEEK_API_BASE_URL).ok()?;
    let configured = normalize_endpoint(&authority.canonical_endpoint).ok()?;
    if configured != current {
        return None;
    }
    let legacy = normalize_endpoint(LEGACY_DEEPSEEK_CONSOLE_BASE_URL)
        .ok()?
        .to_string();
    StoredCredentialReference::for_ai_provider_endpoint(&authority.profile_id, &legacy).ok()
}

fn credential_store_error(error: netcatty_credentials::CredentialError) -> String {
    match error.code() {
        CredentialErrorCode::NotFound => AI_STORED_KEY_NOT_FOUND.to_owned(),
        CredentialErrorCode::TooLarge => "AI_API_KEY_TOO_LARGE".to_owned(),
        _ => AI_CREDENTIAL_STORE_FAILED.to_owned(),
    }
}

fn native_ai_authority(
    settings: AiProviderAuthoritySettings,
    require_enabled: bool,
) -> Result<NativeAiAuthority, String> {
    legacy_ai_provider_reference(&settings.profile_id)?;
    legacy_ai_provider_reference(&settings.provider_id)?;
    if require_enabled && !settings.enabled {
        return Err(AI_KEY_SOURCE_INVALID.to_owned());
    }
    let canonical_endpoint = match settings.protocol {
        AiProviderProtocol::OpenAiChatCompletions => normalize_endpoint(&settings.base_url),
        AiProviderProtocol::AnthropicMessages => normalize_anthropic_endpoint(&settings.base_url),
    }
    .map_err(|_| AI_KEY_SOURCE_INVALID.to_owned())?
    .to_string();
    let permission_mode = match settings.command_permission_mode {
        AiCommandPermissionMode::Observer => AiPermissionMode::Observer,
        AiCommandPermissionMode::Confirm => AiPermissionMode::Confirm,
        AiCommandPermissionMode::Auto => AiPermissionMode::Auto,
    };
    let response_idle_timeout =
        AiResponseIdleTimeout::from_seconds(settings.response_idle_timeout_seconds)
            .ok_or_else(|| AI_KEY_SOURCE_INVALID.to_owned())?;
    Ok(NativeAiAuthority {
        profile_id: settings.profile_id,
        provider_id: settings.provider_id,
        protocol: settings.protocol,
        canonical_endpoint,
        model: settings.model,
        permission_mode,
        response_idle_timeout,
    })
}

async fn load_native_ai_authority(
    settings: RendererSafeSettingsStore,
    provider_profile_id: &str,
    require_enabled: bool,
) -> Result<NativeAiAuthority, String> {
    legacy_ai_provider_reference(provider_profile_id)?;
    let provider_profile_id = provider_profile_id.to_owned();
    let snapshot = tokio::task::spawn_blocking(move || settings.load())
        .await
        .map_err(|_| AI_KEY_SOURCE_INVALID.to_owned())?
        .map_err(|_| AI_KEY_SOURCE_INVALID.to_owned())?;
    let settings = snapshot
        .ai_provider_authority(&provider_profile_id)
        .ok_or_else(|| AI_KEY_SOURCE_INVALID.to_owned())?;
    native_ai_authority(settings, require_enabled)
}

async fn load_current_ai_permission_mode(
    settings: RendererSafeSettingsStore,
) -> Result<AiPermissionMode, String> {
    let snapshot = tokio::task::spawn_blocking(move || settings.load())
        .await
        .map_err(|_| AI_KEY_SOURCE_INVALID.to_owned())?
        .map_err(|_| AI_KEY_SOURCE_INVALID.to_owned())?;
    Ok(match snapshot.ai_command_permission_mode() {
        AiCommandPermissionMode::Observer => AiPermissionMode::Observer,
        AiCommandPermissionMode::Confirm => AiPermissionMode::Confirm,
        AiCommandPermissionMode::Auto => AiPermissionMode::Auto,
    })
}

fn validate_request_profile(profile_id: &str, authority: &NativeAiAuthority) -> Result<(), String> {
    legacy_ai_provider_reference(profile_id)?;
    if profile_id != authority.profile_id {
        return Err(AI_KEY_SOURCE_INVALID.to_owned());
    }
    Ok(())
}

fn ensure_chat_content_supported(
    authority: &NativeAiAuthority,
    messages: &[AiChatMessage],
) -> Result<(), String> {
    if authority.protocol != AiProviderProtocol::OpenAiChatCompletions
        && messages.iter().any(AiChatMessage::has_image_content)
    {
        return Err(AI_IMAGE_INPUT_UNSUPPORTED.to_owned());
    }
    Ok(())
}

fn endpoint_allows_missing_key(authority: &NativeAiAuthority) -> bool {
    if authority.protocol != AiProviderProtocol::OpenAiChatCompletions {
        return false;
    }
    let Ok(endpoint) = normalize_endpoint(&authority.canonical_endpoint) else {
        return false;
    };
    if endpoint.scheme() != "http" {
        return false;
    }
    let Some(host) = endpoint.host_str() else {
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

async fn resolve_stored_api_key(
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<Option<SecretValue>, String> {
    let reference = endpoint_ai_provider_reference(authority)?;
    match credentials
        .resolve(&reference, CredentialKind::AiApiKey)
        .await
    {
        Ok(stored) => return Ok(Some(stored)),
        Err(error) if error.code() == CredentialErrorCode::NotFound => {}
        Err(error) => return Err(credential_store_error(error)),
    }

    let Some(legacy_reference) = legacy_endpoint_ai_provider_reference(authority) else {
        return Ok(None);
    };
    let stored = match credentials
        .resolve(&legacy_reference, CredentialKind::AiApiKey)
        .await
    {
        Ok(stored) => stored,
        Err(error) if error.code() == CredentialErrorCode::NotFound => return Ok(None),
        Err(error) => return Err(credential_store_error(error)),
    };
    let replacement = SecretValue::new(stored.as_bytes().to_vec())
        .map_err(|_| AI_CREDENTIAL_STORE_FAILED.to_owned())?;
    credentials
        .upsert(&reference, CredentialKind::AiApiKey, replacement)
        .await
        .map_err(credential_store_error)?;
    let _ = credentials.delete(&legacy_reference).await;
    Ok(Some(stored))
}

async fn resolve_api_key(
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<AiApiKey, String> {
    let Some(stored) = resolve_stored_api_key(authority, credentials).await? else {
        if endpoint_allows_missing_key(authority) {
            return AiApiKey::new(String::new()).map_err(|error| error.to_string());
        }
        return Err(AI_STORED_KEY_NOT_FOUND.to_owned());
    };
    let key = stored
        .as_utf8()
        .map_err(|_| AI_CREDENTIAL_STORE_FAILED.to_owned())?
        .to_owned();
    AiApiKey::new(key).map_err(|_| AI_CREDENTIAL_STORE_FAILED.to_owned())
}

enum NativeAiProviderStream {
    OpenAi(AiChatStream),
    Anthropic(AiAnthropicStream),
}

impl NativeAiProviderStream {
    async fn next_event(&mut self) -> Result<Option<NativeAiStreamEvent>, netcatty_ai::AiError> {
        match self {
            Self::OpenAi(stream) => stream.next_event().await,
            Self::Anthropic(stream) => stream.next_event().await,
        }
    }
}

async fn start_native_ai_stream(
    client: &AiClient,
    authority: &NativeAiAuthority,
    api_key: AiApiKey,
    request: AiChatRequest,
    reasoning_effort: Option<AiReasoningEffort>,
) -> Result<NativeAiProviderStream, String> {
    match authority.protocol {
        AiProviderProtocol::OpenAiChatCompletions => client
            .stream_chat_with_reasoning_effort_and_timeout(
                &authority.canonical_endpoint,
                api_key,
                request,
                reasoning_effort,
                authority.response_idle_timeout,
            )
            .await
            .map(NativeAiProviderStream::OpenAi),
        AiProviderProtocol::AnthropicMessages => client
            .stream_anthropic_messages_with_timeout(
                &authority.canonical_endpoint,
                api_key,
                request,
                authority.response_idle_timeout,
            )
            .await
            .map(NativeAiProviderStream::Anthropic),
    }
    .map_err(|error| error.to_string())
}

fn ensure_chat_reasoning_supported(
    authority: &NativeAiAuthority,
    reasoning_effort: Option<AiReasoningEffort>,
) -> Result<(), String> {
    if reasoning_effort.is_some() && authority.protocol != AiProviderProtocol::OpenAiChatCompletions
    {
        return Err(AI_REASONING_PROTOCOL_UNSUPPORTED.to_owned());
    }
    Ok(())
}

async fn consume_native_ai_stream(
    mut stream: NativeAiProviderStream,
    on_event: Option<&Channel<AiChatStreamEvent>>,
) -> Result<CompleteAiChatResponse, String> {
    let mut content = String::new();
    while let Some(event) = stream
        .next_event()
        .await
        .map_err(|error| error.to_string())?
    {
        match event {
            NativeAiStreamEvent::Delta(delta) => {
                append_stream_delta(&mut content, &delta)?;
                if let Some(on_event) = on_event {
                    on_event
                        .send(AiChatStreamEvent::Delta { content: delta })
                        .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())?;
                }
            }
            NativeAiStreamEvent::Done => {
                if let Some(on_event) = on_event {
                    on_event
                        .send(AiChatStreamEvent::Done)
                        .map_err(|_| AI_STREAM_CHANNEL_CLOSED.to_owned())?;
                }
                return Ok(CompleteAiChatResponse { content });
            }
        }
    }

    // Both native transports require their protocol-specific terminal event.
    // Never publish a partial response if a provider closes early.
    Err("AI_RESPONSE_INVALID".to_owned())
}

async fn complete_ai_chat_inner(
    mut request: CompleteAiChatRequest,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<CompleteAiChatResponse, String> {
    validate_request_profile(&request.provider_profile_id, authority)?;
    ensure_chat_content_supported(authority, &request.messages)?;
    ensure_chat_reasoning_supported(authority, request.reasoning_effort)?;
    let api_key = resolve_api_key(authority, credentials).await?;
    let client = shared_client()?;
    let chat_request = AiChatRequest {
        model: authority.model.clone(),
        messages: std::mem::take(&mut request.messages),
    };
    match authority.protocol {
        AiProviderProtocol::OpenAiChatCompletions => client
            .complete_with_reasoning_effort_and_timeout(
                &authority.canonical_endpoint,
                api_key,
                chat_request,
                request.reasoning_effort,
                authority.response_idle_timeout,
            )
            .await
            .map(|content| CompleteAiChatResponse { content })
            .map_err(|error| error.to_string()),
        AiProviderProtocol::AnthropicMessages => {
            let stream =
                start_native_ai_stream(client, authority, api_key, chat_request, None).await?;
            consume_native_ai_stream(stream, None).await
        }
    }
}

async fn list_ai_models_inner(
    provider_profile_id: &str,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<Vec<String>, String> {
    validate_request_profile(provider_profile_id, authority)?;
    let api_key = resolve_api_key(authority, credentials).await?;
    let client = shared_client()?;
    match authority.protocol {
        AiProviderProtocol::OpenAiChatCompletions => {
            client
                .list_models_with_timeout(
                    &authority.canonical_endpoint,
                    api_key,
                    authority.response_idle_timeout,
                )
                .await
        }
        AiProviderProtocol::AnthropicMessages => {
            client
                .list_anthropic_models_with_timeout(
                    &authority.canonical_endpoint,
                    api_key,
                    authority.response_idle_timeout,
                )
                .await
        }
    }
    .map_err(|error| error.to_string())
}

async fn stream_ai_chat_inner(
    mut request: CompleteAiChatRequest,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
    on_event: &Channel<AiChatStreamEvent>,
) -> Result<CompleteAiChatResponse, String> {
    validate_request_profile(&request.provider_profile_id, authority)?;
    ensure_chat_content_supported(authority, &request.messages)?;
    ensure_chat_reasoning_supported(authority, request.reasoning_effort)?;
    let api_key = resolve_api_key(authority, credentials).await?;
    let client = shared_client()?;
    let stream = start_native_ai_stream(
        client,
        authority,
        api_key,
        AiChatRequest {
            model: authority.model.clone(),
            messages: std::mem::take(&mut request.messages),
        },
        request.reasoning_effort,
    )
    .await?;
    consume_native_ai_stream(stream, Some(on_event)).await
}

fn append_stream_delta(content: &mut String, delta: &str) -> Result<(), String> {
    let next_length = content
        .len()
        .checked_add(delta.len())
        .ok_or_else(|| "AI_RESPONSE_TOO_LARGE".to_owned())?;
    if next_length > MAX_AI_RESPONSE_BYTES {
        return Err("AI_RESPONSE_TOO_LARGE".to_owned());
    }
    content.push_str(delta);
    Ok(())
}

#[cfg(test)]
async fn complete_ai_chat_with_store(
    request: CompleteAiChatRequest,
    authority: NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<CompleteAiChatResponse, String> {
    let request_id = request.request_id.clone();
    run_registered_request(
        request_id,
        complete_ai_chat_inner(request, &authority, credentials),
    )
    .await
}

#[cfg(test)]
async fn stream_ai_chat_with_store(
    request: CompleteAiChatRequest,
    authority: NativeAiAuthority,
    credentials: &OsCredentialStore,
    on_event: Channel<AiChatStreamEvent>,
) -> Result<CompleteAiChatResponse, String> {
    let request_id = request.request_id.clone();
    run_registered_request(
        request_id,
        stream_ai_chat_inner(request, &authority, credentials, &on_event),
    )
    .await
}

#[cfg(test)]
async fn list_ai_models_with_store(
    provider_profile_id: &str,
    settings: AiProviderAuthoritySettings,
    credentials: &OsCredentialStore,
) -> Result<Vec<String>, String> {
    let authority = native_ai_authority(settings, false)?;
    list_ai_models_inner(provider_profile_id, &authority, credentials).await
}

async fn run_registered_request<T>(
    request_id: String,
    completion: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    validate_request_id(&request_id)?;
    let (cancel, canceled) = oneshot::channel();
    let registration = register_request(request_id, cancel)?;
    await_registered_request(registration, canceled, completion).await
}

async fn await_registered_request<T>(
    _registration: RequestRegistration,
    canceled: oneshot::Receiver<()>,
    completion: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    // Register before the first asynchronous credential operation. Otherwise
    // a fast Stop click can arrive while the OS keyring is still resolving,
    // miss the registry entry, and allow an unwanted provider request to run.
    tokio::select! {
        result = completion => result,
        _ = canceled => Err("AI_REQUEST_CANCELED".to_owned()),
    }
}

#[tauri::command]
pub(crate) async fn complete_ai_chat(
    state: State<'_, crate::DesktopState>,
    request: CompleteAiChatRequest,
) -> Result<CompleteAiChatResponse, String> {
    let request_id = request.request_id.clone();
    let provider_profile_id = request.provider_profile_id.clone();
    let settings = state.settings.clone();
    run_registered_request(request_id, async {
        let authority = load_native_ai_authority(settings, &provider_profile_id, true).await?;
        complete_ai_chat_inner(request, &authority, &state.persistent_credentials).await
    })
    .await
}

#[tauri::command]
pub(crate) async fn stream_ai_chat(
    state: State<'_, crate::DesktopState>,
    request: CompleteAiChatRequest,
    on_event: Channel<AiChatStreamEvent>,
) -> Result<CompleteAiChatResponse, String> {
    let request_id = request.request_id.clone();
    let provider_profile_id = request.provider_profile_id.clone();
    let settings = state.settings.clone();
    run_registered_request(request_id, async {
        let authority = load_native_ai_authority(settings, &provider_profile_id, true).await?;
        stream_ai_chat_inner(
            request,
            &authority,
            &state.persistent_credentials,
            &on_event,
        )
        .await
    })
    .await
}

#[tauri::command]
pub(crate) async fn list_ai_models(
    state: State<'_, crate::DesktopState>,
    provider_profile_id: String,
) -> Result<Vec<String>, String> {
    let authority =
        load_native_ai_authority(state.settings.clone(), &provider_profile_id, false).await?;
    list_ai_models_inner(
        &provider_profile_id,
        &authority,
        &state.persistent_credentials,
    )
    .await
}

#[tauri::command]
pub(crate) async fn cancel_ai_chat(request_id: String) -> Result<bool, String> {
    validate_request_id(&request_id)?;
    let request = lock_request_registry().remove(&request_id);
    Ok(request.is_some_and(|request| request.cancel.send(()).is_ok()))
}

type PendingInsertionTracker = Arc<Mutex<Option<(String, Arc<()>)>>>;

fn insert_pending_agent_turn(
    turn_id: String,
    pending: PendingAgentTurn,
) -> Result<Arc<()>, String> {
    let mut turns = lock_pending_agent_turns();
    prune_expired_pending_agent_turns(&mut turns);
    if turns.len() >= MAX_PENDING_AI_TURNS {
        return Err("AI_BUSY".to_owned());
    }
    if turns.contains_key(&turn_id) {
        return Err("AI_REQUEST_ID_DUPLICATE".to_owned());
    }
    let identity = Arc::new(());
    turns.insert(
        turn_id.clone(),
        RegisteredPendingAgentTurn {
            identity: Arc::clone(&identity),
            expires_at: Instant::now() + AI_PENDING_APPROVAL_TTL,
            execution_authorized: false,
            pending,
        },
    );
    drop(turns);
    schedule_pending_agent_turn_expiry(turn_id, Arc::clone(&identity));
    Ok(identity)
}

fn schedule_pending_agent_turn_expiry(turn_id: String, expiry_identity: Arc<()>) {
    tokio::spawn(async move {
        tokio::time::sleep(AI_PENDING_APPROVAL_TTL).await;
        remove_pending_agent_turn_if_identity(&turn_id, &expiry_identity);
    });
}

fn has_pending_agent_turn(turn_id: &str) -> bool {
    let mut turns = lock_pending_agent_turns();
    prune_expired_pending_agent_turns(&mut turns);
    turns.contains_key(turn_id)
}

fn take_pending_agent_turn(turn_id: &str) -> Option<RegisteredPendingAgentTurn> {
    let mut turns = lock_pending_agent_turns();
    prune_expired_pending_agent_turns(&mut turns);
    turns.remove(turn_id)
}

fn authorize_pending_agent_tool(
    request: &AuthorizeAiAgentToolRequest,
    permission_mode: AiPermissionMode,
) -> Result<(), String> {
    validate_request_id(&request.turn_id)?;
    let (identity, turn_id) = {
        let mut turns = lock_pending_agent_turns();
        prune_expired_pending_agent_turns(&mut turns);
        if permission_mode == AiPermissionMode::Observer {
            if turns.remove(&request.turn_id).is_none() {
                return Err("AI_AGENT_TURN_NOT_FOUND".to_owned());
            }
            return Err("AI_TOOL_OBSERVER_DENIED".to_owned());
        }
        let registered = turns
            .get_mut(&request.turn_id)
            .ok_or_else(|| "AI_AGENT_TURN_NOT_FOUND".to_owned())?;
        registered.pending.turn.set_permission_mode(permission_mode);
        if permission_mode == AiPermissionMode::Confirm && !request.user_approved {
            return Err("AI_TOOL_APPROVAL_REQUIRED".to_owned());
        }
        registered
            .pending
            .turn
            .authorize_tool_execution(&request.tool_call_id, &request.terminal_scope)
            .map_err(|error| error.to_string())?;
        if registered.execution_authorized {
            return Err("AI_TOOL_ALREADY_AUTHORIZED".to_owned());
        }
        let identity = Arc::new(());
        registered.identity = Arc::clone(&identity);
        registered.expires_at = Instant::now() + AI_PENDING_APPROVAL_TTL;
        registered.execution_authorized = true;
        (identity, request.turn_id.clone())
    };
    schedule_pending_agent_turn_expiry(turn_id, identity);
    Ok(())
}

fn remove_tracked_pending_agent_turn(tracker: &PendingInsertionTracker) {
    let tracked = tracker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((turn_id, identity)) = tracked {
        remove_pending_agent_turn_if_identity(&turn_id, &identity);
    }
}

async fn drive_agent_turn(
    turn_id: String,
    mut pending: PendingAgentTurn,
    insertion_tracker: PendingInsertionTracker,
) -> Result<AiAgentTurnResponse, String> {
    let client = shared_client()?;
    loop {
        let decision = pending
            .turn
            .advance_with_timeout(
                client,
                &pending.base_url,
                &pending.api_key,
                pending.response_idle_timeout,
            )
            .await
            .map_err(|error| error.to_string())?;
        match decision {
            AiAgentDecision::Continue => continue,
            AiAgentDecision::Completed(content) => {
                return Ok(AiAgentTurnResponse::Completed { content });
            }
            AiAgentDecision::ToolCall {
                call,
                approval_required,
                content,
            } => {
                let response = AiAgentTurnResponse::ToolCall {
                    turn_id: turn_id.clone(),
                    call,
                    approval_required,
                    content,
                };
                let identity = insert_pending_agent_turn(turn_id.clone(), pending)?;
                *insertion_tracker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((turn_id, identity));
                return Ok(response);
            }
        }
    }
}

fn ensure_agent_protocol_supported(authority: &NativeAiAuthority) -> Result<(), String> {
    if authority.protocol == AiProviderProtocol::OpenAiChatCompletions {
        Ok(())
    } else {
        Err(AI_AGENT_PROTOCOL_UNSUPPORTED.to_owned())
    }
}

async fn start_ai_agent_turn_with_store(
    mut request: StartAiAgentTurnRequest,
    settings: RendererSafeSettingsStore,
    credentials: &OsCredentialStore,
) -> Result<AiAgentTurnResponse, String> {
    let turn_id = request.turn_id.clone();
    validate_request_id(&turn_id)?;
    if has_pending_agent_turn(&turn_id) {
        return Err("AI_REQUEST_ID_DUPLICATE".to_owned());
    }
    let insertion_tracker: PendingInsertionTracker = Arc::default();
    let result = run_registered_request(turn_id.clone(), async {
        let authority =
            load_native_ai_authority(settings, &request.provider_profile_id, true).await?;
        validate_request_profile(&request.provider_profile_id, &authority)?;
        // AiAgentTurn currently serializes the OpenAI tools schema. Reject
        // every other provider protocol before key lookup or network I/O.
        ensure_agent_protocol_supported(&authority)?;
        if request
            .messages
            .iter()
            .any(AiChatMessage::has_image_content)
        {
            return Err(AI_IMAGE_INPUT_UNSUPPORTED.to_owned());
        }
        let api_key = resolve_api_key(&authority, credentials).await?;
        let turn = AiAgentTurn::new_with_reasoning_effort(
            AiChatRequest {
                model: authority.model.clone(),
                messages: std::mem::take(&mut request.messages),
            },
            authority.permission_mode,
            request.terminal_scope.take(),
            request.reasoning_effort,
        )
        .map_err(|error| error.to_string())?;
        drive_agent_turn(
            turn_id.clone(),
            PendingAgentTurn {
                base_url: authority.canonical_endpoint,
                api_key,
                turn,
                response_idle_timeout: authority.response_idle_timeout,
            },
            Arc::clone(&insertion_tracker),
        )
        .await
    })
    .await;
    if result.is_err() {
        remove_tracked_pending_agent_turn(&insertion_tracker);
    }
    result
}

#[tauri::command]
pub(crate) async fn start_ai_agent_turn(
    state: State<'_, crate::DesktopState>,
    request: StartAiAgentTurnRequest,
) -> Result<AiAgentTurnResponse, String> {
    start_ai_agent_turn_with_store(
        request,
        state.settings.clone(),
        &state.persistent_credentials,
    )
    .await
}

#[tauri::command]
pub(crate) async fn authorize_ai_agent_tool(
    state: State<'_, crate::DesktopState>,
    request: AuthorizeAiAgentToolRequest,
) -> Result<bool, String> {
    let permission_mode = load_current_ai_permission_mode(state.settings.clone()).await?;
    authorize_pending_agent_tool(&request, permission_mode)?;
    Ok(true)
}

async fn continue_ai_agent_turn_inner(
    request: ContinueAiAgentTurnRequest,
) -> Result<AiAgentTurnResponse, String> {
    validate_request_id(&request.turn_id)?;
    let turn_id = request.turn_id.clone();
    // Register the active cancellation receiver before removing the pending
    // approval. Thus cancel always sees at least one authoritative state during
    // the pending -> provider transition.
    let (cancel, canceled) = oneshot::channel();
    let registration = register_request(turn_id.clone(), cancel)?;
    let registered =
        take_pending_agent_turn(&turn_id).ok_or_else(|| "AI_AGENT_TURN_NOT_FOUND".to_owned())?;
    let approval_rejected =
        request.result.error_code.as_deref() == Some("AI_TOOL_APPROVAL_REJECTED");
    if !registered.execution_authorized && !approval_rejected {
        return Err("AI_TOOL_NOT_AUTHORIZED".to_owned());
    }
    let mut pending = registered.pending;
    let insertion_tracker: PendingInsertionTracker = Arc::default();
    let result = await_registered_request(registration, canceled, async {
        pending
            .turn
            .submit_tool_result(
                &request.tool_call_id,
                &request.terminal_scope,
                request.result,
            )
            .map_err(|error| error.to_string())?;
        drive_agent_turn(turn_id.clone(), pending, Arc::clone(&insertion_tracker)).await
    })
    .await;
    if result.is_err() {
        remove_tracked_pending_agent_turn(&insertion_tracker);
    }
    result
}

#[tauri::command]
pub(crate) async fn continue_ai_agent_turn(
    request: ContinueAiAgentTurnRequest,
) -> Result<AiAgentTurnResponse, String> {
    continue_ai_agent_turn_inner(request).await
}

#[tauri::command]
pub(crate) async fn cancel_ai_agent_turn(turn_id: String) -> Result<bool, String> {
    validate_request_id(&turn_id)?;
    let pending = {
        let mut turns = lock_pending_agent_turns();
        prune_expired_pending_agent_turns(&mut turns);
        turns.remove(&turn_id).is_some()
    };
    let active = lock_request_registry()
        .remove(&turn_id)
        .is_some_and(|request| request.cancel.send(()).is_ok());
    Ok(pending || active)
}

async fn has_saved_ai_api_key_with_store(
    provider_profile_id: &str,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<bool, String> {
    validate_request_profile(provider_profile_id, authority)?;
    resolve_stored_api_key(authority, credentials)
        .await
        .map(|stored| stored.is_some())
}

#[tauri::command]
pub(crate) async fn has_saved_ai_api_key(
    state: State<'_, crate::DesktopState>,
    provider_profile_id: String,
) -> Result<bool, String> {
    let authority =
        load_native_ai_authority(state.settings.clone(), &provider_profile_id, false).await?;
    has_saved_ai_api_key_with_store(
        &provider_profile_id,
        &authority,
        &state.persistent_credentials,
    )
    .await
}

async fn save_ai_api_key_with_store(
    mut request: SaveAiApiKeyRequest,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<bool, String> {
    validate_request_profile(&request.provider_profile_id, authority)?;
    let reference = endpoint_ai_provider_reference(authority)?;
    if request.api_key.is_empty()
        || request.api_key.len() > MAX_AI_KEY_BYTES
        || request.api_key.len() > MAX_PERSISTENT_SECRET_BYTES
        || request.api_key.contains(['\0', '\r', '\n'])
    {
        return Err(
            if request.api_key.len() > MAX_AI_KEY_BYTES
                || request.api_key.len() > MAX_PERSISTENT_SECRET_BYTES
            {
                "AI_API_KEY_TOO_LARGE".to_owned()
            } else {
                "AI_API_KEY_INVALID".to_owned()
            },
        );
    }
    let secret = SecretValue::from_utf8(std::mem::take(&mut request.api_key))
        .map_err(credential_store_error)?;
    credentials
        .upsert(&reference, CredentialKind::AiApiKey, secret)
        .await
        .map_err(credential_store_error)?;
    if let Some(legacy) = legacy_endpoint_ai_provider_reference(authority) {
        let _ = credentials.delete(&legacy).await;
    }
    // A legacy provider-only key is never read. An explicit save is the only
    // point at which it is safe to attempt cleanup after the endpoint-bound
    // replacement is durable.
    if authority.profile_id == authority.provider_id {
        if let Ok(legacy) = legacy_ai_provider_reference(&authority.provider_id) {
            let _ = credentials.delete(&legacy).await;
        }
    }
    Ok(true)
}

#[tauri::command]
pub(crate) async fn save_ai_api_key(
    state: State<'_, crate::DesktopState>,
    request: SaveAiApiKeyRequest,
) -> Result<bool, String> {
    let authority =
        load_native_ai_authority(state.settings.clone(), &request.provider_profile_id, false)
            .await?;
    save_ai_api_key_with_store(request, &authority, &state.persistent_credentials).await
}

async fn delete_ai_api_key_with_store(
    provider_profile_id: &str,
    authority: &NativeAiAuthority,
    credentials: &OsCredentialStore,
) -> Result<bool, String> {
    validate_request_profile(provider_profile_id, authority)?;
    let reference = endpoint_ai_provider_reference(authority)?;
    credentials
        .delete(&reference)
        .await
        .map_err(credential_store_error)?;
    if let Some(legacy) = legacy_endpoint_ai_provider_reference(authority) {
        let _ = credentials.delete(&legacy).await;
    }
    if authority.profile_id == authority.provider_id {
        if let Ok(legacy) = legacy_ai_provider_reference(&authority.provider_id) {
            let _ = credentials.delete(&legacy).await;
        }
    }
    Ok(true)
}

#[tauri::command]
pub(crate) async fn delete_ai_api_key(
    state: State<'_, crate::DesktopState>,
    provider_profile_id: String,
) -> Result<bool, String> {
    let authority =
        load_native_ai_authority(state.settings.clone(), &provider_profile_id, false).await?;
    delete_ai_api_key_with_store(
        &provider_profile_id,
        &authority,
        &state.persistent_credentials,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_ai::{AiChatContentPart, AiChatRole};
    use netcatty_credentials::test_support::in_memory_credential_store;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    fn test_authority_settings(
        profile_id: &str,
        base_url: &str,
        enabled: bool,
    ) -> AiProviderAuthoritySettings {
        test_authority_settings_for_protocol(
            profile_id,
            base_url,
            enabled,
            AiProviderProtocol::OpenAiChatCompletions,
        )
    }

    fn test_authority_settings_for_protocol(
        profile_id: &str,
        base_url: &str,
        enabled: bool,
        protocol: AiProviderProtocol,
    ) -> AiProviderAuthoritySettings {
        AiProviderAuthoritySettings {
            profile_id: profile_id.to_owned(),
            provider_id: "openai-compatible".to_owned(),
            protocol,
            base_url: base_url.to_owned(),
            model: "test-model".to_owned(),
            enabled,
            command_permission_mode: AiCommandPermissionMode::Confirm,
            response_idle_timeout_seconds: 120,
        }
    }

    fn test_authority(profile_id: &str, base_url: &str) -> NativeAiAuthority {
        native_ai_authority(test_authority_settings(profile_id, base_url, true), true)
            .expect("native AI authority")
    }

    fn test_anthropic_authority(profile_id: &str, base_url: &str) -> NativeAiAuthority {
        native_ai_authority(
            test_authority_settings_for_protocol(
                profile_id,
                base_url,
                true,
                AiProviderProtocol::AnthropicMessages,
            ),
            true,
        )
        .expect("native Anthropic authority")
    }

    fn spawn_stream_provider(
        body: String,
        expected_authorization: Option<&'static str>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "AI provider was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            let mut expected_length = None;
            loop {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its body");
                request.extend_from_slice(&buffer[..read]);
                if expected_length.is_none()
                    && let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
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
                        .expect("request content length");
                    expected_length = Some(header_end + 4 + content_length);
                }
                if expected_length.is_some_and(|length| request.len() >= length) {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(request.contains("\"stream\":true"));
            assert!(request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("accept")
                        && value.trim().eq_ignore_ascii_case("text/event-stream")
                })
            }));
            match expected_authorization {
                Some(expected) => assert!(request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("authorization") && value.trim() == expected
                    })
                })),
                None => assert!(!request.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                })),
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("provider response headers");
            stream
                .write_all(body.as_bytes())
                .expect("provider response body");
        });
        (format!("http://{address}/v1"), provider)
    }

    fn anthropic_sse_body(first: &str, second: &str) -> String {
        [
            (
                "message_start",
                serde_json::json!({
                    "type": "message_start",
                    "message": {"type": "message", "role": "assistant"}
                }),
            ),
            (
                "content_block_start",
                serde_json::json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""}
                }),
            ),
            (
                "content_block_delta",
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": first}
                }),
            ),
            (
                "content_block_delta",
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": second}
                }),
            ),
            (
                "content_block_stop",
                serde_json::json!({"type": "content_block_stop", "index": 0}),
            ),
            ("message_stop", serde_json::json!({"type": "message_stop"})),
        ]
        .into_iter()
        .map(|(event, payload)| format!("event: {event}\ndata: {payload}\n\n"))
        .collect()
    }

    fn spawn_anthropic_stream_provider(
        body: String,
        expected_key: &'static str,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "Anthropic provider was not contacted"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            let mut expected_length = None;
            let mut header_end = None;
            loop {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its body");
                request.extend_from_slice(&buffer[..read]);
                if expected_length.is_none()
                    && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
                {
                    let end = index + 4;
                    let headers = String::from_utf8_lossy(&request[..index]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .expect("request content length");
                    header_end = Some(end);
                    expected_length = Some(end + content_length);
                }
                if expected_length.is_some_and(|length| request.len() >= length) {
                    break;
                }
            }
            let header_end = header_end.expect("request header boundary");
            let headers = String::from_utf8_lossy(&request[..header_end]);
            assert!(headers.starts_with("POST /v1/messages HTTP/1.1\r\n"));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("x-api-key") && value.trim() == expected_key
                })
            }));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("anthropic-version")
                        && value.trim() == netcatty_ai::ANTHROPIC_API_VERSION
                })
            }));
            assert!(!headers.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            }));
            let payload: serde_json::Value =
                serde_json::from_slice(&request[header_end..]).expect("Anthropic request JSON");
            assert_eq!(payload["model"], "test-model");
            assert_eq!(payload["stream"], true);
            assert_eq!(payload["messages"][0]["role"], "user");
            assert_eq!(
                payload["messages"][0]["content"],
                "private anthropic prompt"
            );
            assert!(payload.get("tools").is_none());

            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("provider response headers");
            stream
                .write_all(body.as_bytes())
                .expect("provider response body");
        });
        (format!("http://{address}/v1"), provider)
    }

    fn spawn_models_provider(
        status: &'static str,
        body: String,
        expected_authorization: Option<&'static str>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "AI provider was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
            let authorization = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then_some(value.trim())
            });
            assert_eq!(authorization, expected_authorization);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("provider response headers");
            stream
                .write_all(body.as_bytes())
                .expect("provider response body");
        });
        (format!("http://{address}/v1"), provider)
    }

    fn spawn_anthropic_models_provider(
        status: &'static str,
        body: String,
        expected_key: &'static str,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "AI provider was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
            let header = |expected_name: &str| {
                request.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case(expected_name)
                        .then_some(value.trim())
                })
            };
            assert_eq!(header("x-api-key"), Some(expected_key));
            assert_eq!(
                header("anthropic-version"),
                Some(netcatty_ai::ANTHROPIC_API_VERSION)
            );
            assert_eq!(header("authorization"), None);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("provider response headers");
            stream
                .write_all(body.as_bytes())
                .expect("provider response body");
        });
        (format!("http://{address}/v1/messages"), provider)
    }

    fn test_pending_agent_turn() -> PendingAgentTurn {
        PendingAgentTurn {
            base_url: "http://127.0.0.1:1/v1".to_owned(),
            api_key: AiApiKey::new(String::new()).expect("empty loopback key"),
            turn: AiAgentTurn::new(
                AiChatRequest {
                    model: "test-model".to_owned(),
                    messages: vec![AiChatMessage {
                        role: AiChatRole::User,
                        content: "hello".to_owned(),
                        content_parts: Vec::new(),
                    }],
                },
                AiPermissionMode::Confirm,
                Some(AiTerminalScope {
                    route_id: "terminal-1".to_owned(),
                    generation: 1,
                    protocol: "ssh".to_owned(),
                }),
            )
            .expect("agent turn"),
            response_idle_timeout: AiResponseIdleTimeout::default(),
        }
    }

    async fn advance_test_turn_to_tool(
        pending: &mut PendingAgentTurn,
        call_id: &str,
    ) -> AiAgentDecision {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let response = serde_json::json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": "terminal_execute",
                            "arguments": r#"{"command":"pwd"}"#,
                        },
                    }],
                },
            }],
        })
        .to_string();
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "AI provider was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .expect("provider response headers");
            stream
                .write_all(response.as_bytes())
                .expect("provider response body");
        });

        pending.base_url = format!("http://{address}/v1");
        let decision = pending
            .turn
            .advance(
                shared_client().expect("AI client"),
                &pending.base_url,
                &pending.api_key,
            )
            .await
            .expect("agent tool step");
        provider.join().expect("provider thread");
        decision
    }

    async fn pending_authorization_fixture(
        turn_id: &str,
        user_approved: bool,
    ) -> (AuthorizeAiAgentToolRequest, PendingAgentTurn) {
        let mut pending = test_pending_agent_turn();
        let AiAgentDecision::ToolCall { call, .. } =
            advance_test_turn_to_tool(&mut pending, &format!("{turn_id}-call")).await
        else {
            panic!("expected pending terminal tool call")
        };
        let request = AuthorizeAiAgentToolRequest {
            turn_id: turn_id.to_owned(),
            tool_call_id: call.id,
            terminal_scope: call.scope,
            user_approved,
        };
        (request, pending)
    }

    #[test]
    fn request_ids_are_bounded_and_log_safe() {
        assert!(validate_request_id("ai-550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_request_id("").is_err());
        assert!(validate_request_id("private host\nname").is_err());
        assert!(validate_request_id(&"a".repeat(AI_REQUEST_ID_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn stream_events_use_the_stable_tagged_renderer_contract() {
        assert_eq!(
            serde_json::to_value(AiChatStreamEvent::Delta {
                content: "increment".to_owned(),
            })
            .expect("delta JSON"),
            serde_json::json!({"kind": "delta", "content": "increment"})
        );
        assert_eq!(
            serde_json::to_value(AiChatStreamEvent::Done).expect("done JSON"),
            serde_json::json!({"kind": "done"})
        );
    }

    #[test]
    fn agent_tool_calls_use_camel_case_renderer_fields() {
        let response = AiAgentTurnResponse::ToolCall {
            turn_id: "ai-turn-1".to_owned(),
            call: AiTerminalToolCall {
                id: "call-1".to_owned(),
                command: "free -h".to_owned(),
                scope: AiTerminalScope {
                    route_id: "route-1".to_owned(),
                    generation: 7,
                    protocol: "ssh".to_owned(),
                },
            },
            approval_required: false,
            content: Some("I will inspect memory usage first.".to_owned()),
        };
        assert_eq!(
            serde_json::to_value(response).expect("agent tool-call JSON"),
            serde_json::json!({
                "kind": "toolCall",
                "turnId": "ai-turn-1",
                "call": {
                    "id": "call-1",
                    "command": "free -h",
                    "scope": {
                        "routeId": "route-1",
                        "generation": 7,
                        "protocol": "ssh"
                    }
                },
                "approvalRequired": false,
                "content": "I will inspect memory usage first."
            })
        );

        let response_without_content = AiAgentTurnResponse::ToolCall {
            turn_id: "ai-turn-2".to_owned(),
            call: AiTerminalToolCall {
                id: "call-2".to_owned(),
                command: "pwd".to_owned(),
                scope: AiTerminalScope {
                    route_id: "route-2".to_owned(),
                    generation: 1,
                    protocol: "local".to_owned(),
                },
            },
            approval_required: true,
            content: None,
        };
        let serialized =
            serde_json::to_value(response_without_content).expect("agent tool-call JSON");
        assert_eq!(serialized.get("content"), None);
    }

    #[test]
    fn stream_accumulator_keeps_the_two_mebibyte_output_limit() {
        let mut content = "a".repeat(MAX_AI_RESPONSE_BYTES - 1);
        append_stream_delta(&mut content, "b").expect("exact response limit");
        let error = append_stream_delta(&mut content, "c").expect_err("response overflow");
        assert_eq!(error, "AI_RESPONSE_TOO_LARGE");
        assert_eq!(content.len(), MAX_AI_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn streaming_bridge_emits_deltas_and_returns_the_complete_content() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"native \"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"stream\"}}]}\n\n",
            "data: [DONE]\n\n",
        )
        .to_owned();
        let (base_url, provider) = spawn_stream_provider(body, Some("Bearer stored-stream-key"));
        let profile_id = "stream-profile";
        let authority = test_authority(profile_id, &base_url);
        let (credentials, _controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-stream-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save stream key");

        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_events = std::sync::Arc::clone(&events);
        let on_event: Channel<AiChatStreamEvent> = Channel::new(move |body| {
            let event = body.deserialize::<serde_json::Value>()?;
            captured_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
            Ok(())
        });
        let request_id = "stream-bridge-request".to_owned();
        let response = stream_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: request_id.clone(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "private prompt".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
            on_event,
        )
        .await
        .expect("stream completion");
        provider.join().expect("provider thread");

        assert_eq!(response.content, "native stream");
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![
                serde_json::json!({"kind": "delta", "content": "native "}),
                serde_json::json!({"kind": "delta", "content": "stream"}),
                serde_json::json!({"kind": "done"}),
            ]
        );
        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[tokio::test]
    async fn stored_key_reaches_the_anthropic_sse_streaming_bridge() {
        let body = anthropic_sse_body("native ", "anthropic");
        let (base_url, provider) =
            spawn_anthropic_stream_provider(body, "stored-anthropic-stream-key");
        let profile_id = "anthropic-stream-profile";
        let authority = test_anthropic_authority(profile_id, &base_url);
        assert_eq!(authority.protocol, AiProviderProtocol::AnthropicMessages);
        assert!(authority.canonical_endpoint.ends_with("/v1/messages"));
        let (credentials, _controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-anthropic-stream-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save Anthropic stream key");

        let events = Arc::new(Mutex::new(Vec::new()));
        let captured_events = Arc::clone(&events);
        let on_event: Channel<AiChatStreamEvent> = Channel::new(move |body| {
            let event = body.deserialize::<serde_json::Value>()?;
            captured_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
            Ok(())
        });
        let response = stream_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: "anthropic-stream-bridge-request".to_owned(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "private anthropic prompt".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
            on_event,
        )
        .await
        .expect("Anthropic stream completion");
        provider.join().expect("provider thread");

        assert_eq!(response.content, "native anthropic");
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![
                serde_json::json!({"kind": "delta", "content": "native "}),
                serde_json::json!({"kind": "delta", "content": "anthropic"}),
                serde_json::json!({"kind": "done"}),
            ]
        );
    }

    #[tokio::test]
    async fn complete_command_consumes_anthropic_sse_with_the_same_boundary() {
        let body = anthropic_sse_body("complete ", "anthropic");
        let (base_url, provider) =
            spawn_anthropic_stream_provider(body, "stored-anthropic-complete-key");
        let profile_id = "anthropic-complete-profile";
        let authority = test_anthropic_authority(profile_id, &base_url);
        let (credentials, _controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-anthropic-complete-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save Anthropic completion key");

        let response = complete_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: "anthropic-complete-request".to_owned(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "private anthropic prompt".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
        )
        .await
        .expect("Anthropic completion");
        provider.join().expect("provider thread");
        assert_eq!(response.content, "complete anthropic");
    }

    #[tokio::test]
    async fn closed_stream_channel_stops_with_a_stable_secret_safe_error() {
        const PRIVATE_DELTA: &str = "private-provider-delta-sentinel";
        let body = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{PRIVATE_DELTA}\"}}}}]}}\n\ndata: [DONE]\n\n"
        );
        let (base_url, provider) = spawn_stream_provider(body, None);
        let profile_id = "closed-channel-profile";
        let authority = test_authority(profile_id, &base_url);
        let (credentials, _controller) = in_memory_credential_store();
        let on_event: Channel<AiChatStreamEvent> = Channel::new(|_| {
            Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed renderer stream")
                    .into(),
            )
        });
        let request_id = "closed-stream-channel-request".to_owned();
        let error = match stream_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: request_id.clone(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "private-prompt-sentinel".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
            on_event,
        )
        .await
        {
            Ok(_) => panic!("closed channel must fail"),
            Err(error) => error,
        };
        provider.join().expect("provider thread");

        assert_eq!(error, AI_STREAM_CHANNEL_CLOSED);
        assert!(!error.contains(PRIVATE_DELTA));
        assert!(!error.contains("private-prompt-sentinel"));
        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[test]
    fn native_authority_accepts_remote_http_but_keeps_the_loopback_key_boundary() {
        let disabled =
            test_authority_settings("disabled-profile", "https://api.example.test/v1", false);
        assert_eq!(
            native_ai_authority(disabled.clone(), true)
                .err()
                .expect("disabled execution must fail"),
            AI_KEY_SOURCE_INVALID
        );
        assert!(native_ai_authority(disabled, false).is_ok());

        for endpoint in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:11434/v1",
            "http://[::1]:11434/v1",
        ] {
            assert!(endpoint_allows_missing_key(&test_authority(
                "local-profile",
                endpoint
            )));
        }
        for endpoint in ["https://localhost:11434/v1", "https://api.example.test/v1"] {
            assert!(!endpoint_allows_missing_key(&test_authority(
                "remote-profile",
                endpoint
            )));
        }
        let remote_http = native_ai_authority(
            test_authority_settings("remote-http-profile", "http://192.0.2.1:11434/v1", true),
            true,
        )
        .expect("explicit remote HTTP authority");
        assert_eq!(
            remote_http.canonical_endpoint,
            "http://192.0.2.1:11434/v1/chat/completions"
        );
        assert!(!endpoint_allows_missing_key(&remote_http));

        let anthropic =
            test_anthropic_authority("anthropic-local-profile", "http://127.0.0.1:11434/v1/");
        assert_eq!(anthropic.protocol, AiProviderProtocol::AnthropicMessages);
        assert_eq!(
            anthropic.canonical_endpoint,
            "http://127.0.0.1:11434/v1/messages"
        );
        assert!(!endpoint_allows_missing_key(&anthropic));
    }

    #[tokio::test]
    async fn model_discovery_rejects_profile_mismatch_but_accepts_disabled_profiles() {
        let (credentials, controller) = in_memory_credential_store();
        let mismatch = list_ai_models_with_store(
            "renderer-profile",
            test_authority_settings("settings-profile", "https://api.example.test/v1", true),
            &credentials,
        )
        .await
        .expect_err("profile mismatch");
        assert_eq!(mismatch, AI_KEY_SOURCE_INVALID);
        assert!(controller.operation_log().is_empty());

        let body = serde_json::json!({
            "data": [{"id": "disabled-profile-model"}]
        })
        .to_string();
        let (base_url, provider) = spawn_models_provider("200 OK", body, None);
        let disabled_models = list_ai_models_with_store(
            "disabled-profile",
            test_authority_settings("disabled-profile", &base_url, false),
            &credentials,
        )
        .await
        .expect("disabled profile model discovery");
        provider.join().expect("provider thread");
        assert_eq!(disabled_models, vec!["disabled-profile-model"]);
    }

    #[tokio::test]
    async fn anthropic_model_discovery_uses_disabled_persisted_authority_and_bound_key() {
        let profile_id = "anthropic-model-profile";
        let body = serde_json::json!({
            "data": [
                {"type": "model", "id": "claude-z"},
                {"type": "model", "id": "claude-a"},
                {"type": "model", "id": "claude-z"}
            ],
            "has_more": false
        })
        .to_string();
        let (base_url, provider) =
            spawn_anthropic_models_provider("200 OK", body, "stored-anthropic-model-key");
        let settings = test_authority_settings_for_protocol(
            profile_id,
            &base_url,
            false,
            AiProviderProtocol::AnthropicMessages,
        );
        let authority = native_ai_authority(settings.clone(), false)
            .expect("disabled Anthropic model authority");
        let (credentials, _controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-anthropic-model-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save endpoint-bound Anthropic model key");

        let models = list_ai_models_with_store(profile_id, settings, &credentials)
            .await
            .expect("Anthropic model discovery");
        provider.join().expect("provider thread");
        assert_eq!(models, vec!["claude-a", "claude-z"]);
    }

    #[tokio::test]
    async fn anthropic_model_discovery_without_stored_key_never_contacts_provider() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let profile_id = "anthropic-model-missing-key";
        let settings = test_authority_settings_for_protocol(
            profile_id,
            &format!("http://{address}/v1/messages"),
            false,
            AiProviderProtocol::AnthropicMessages,
        );
        let (credentials, _controller) = in_memory_credential_store();

        let error = list_ai_models_with_store(profile_id, settings, &credentials)
            .await
            .expect_err("missing stored Anthropic key");
        assert_eq!(error, AI_STORED_KEY_NOT_FOUND);
        assert!(
            listener
                .accept()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "missing-key discovery must not contact the provider"
        );
    }

    #[tokio::test]
    async fn model_discovery_uses_the_endpoint_bound_stored_key() {
        let body = serde_json::json!({
            "data": [
                {"id": "model-z"},
                {"id": "model-a"},
                {"id": "model-z"}
            ]
        })
        .to_string();
        let (base_url, provider) =
            spawn_models_provider("200 OK", body, Some("Bearer stored-model-key"));
        let profile_id = "stored-model-profile";
        let settings = test_authority_settings(profile_id, &base_url, true);
        let authority = native_ai_authority(settings.clone(), true).expect("model authority");
        let (credentials, _controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-model-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save model key");

        let models = list_ai_models_with_store(profile_id, settings, &credentials)
            .await
            .expect("model catalog");
        provider.join().expect("provider thread");
        assert_eq!(models, vec!["model-a", "model-z"]);
    }

    #[tokio::test]
    async fn model_discovery_propagates_stable_secret_safe_provider_errors() {
        const PRIVATE_EMPTY_MARKER: &str = "private-empty-model-marker";
        const PRIVATE_MALFORMED_MARKER: &str = "private-malformed-model-marker";
        const PRIVATE_HTTP_MARKER: &str = "private-http-model-marker";

        let cases = [
            (
                "models-empty-profile",
                "200 OK",
                format!(r#"{{"data":[],"private":"{PRIVATE_EMPTY_MARKER}"}}"#),
                "AI_MODELS_EMPTY",
                PRIVATE_EMPTY_MARKER,
            ),
            (
                "models-malformed-profile",
                "200 OK",
                format!(r#"{{"data":{{"private":"{PRIVATE_MALFORMED_MARKER}"}}}}"#),
                "AI_RESPONSE_INVALID",
                PRIVATE_MALFORMED_MARKER,
            ),
            (
                "models-http-profile",
                "429 Too Many Requests",
                PRIVATE_HTTP_MARKER.to_owned(),
                "AI_HTTP_ERROR:429",
                PRIVATE_HTTP_MARKER,
            ),
        ];

        for (profile_id, status, body, expected_error, private_marker) in cases {
            let (base_url, provider) = spawn_models_provider(status, body, None);
            let (credentials, _controller) = in_memory_credential_store();
            let error = list_ai_models_with_store(
                profile_id,
                test_authority_settings(profile_id, &base_url, true),
                &credentials,
            )
            .await
            .expect_err("provider model error");
            provider.join().expect("provider thread");
            assert_eq!(error, expected_error);
            assert!(!error.contains(private_marker));
        }
    }

    #[test]
    fn completion_wire_accepts_profile_only_and_rejects_authority_overrides() {
        let valid = serde_json::json!({
            "requestId": "profile-only-completion",
            "providerProfileId": "openai-work",
            "messages": [{"role": "user", "content": "hello"}]
        });
        assert!(serde_json::from_value::<CompleteAiChatRequest>(valid.clone()).is_ok());

        for field in [
            "providerId",
            "baseUrl",
            "apiKey",
            "useStoredKey",
            "model",
            "permissionMode",
            "responseIdleTimeoutSeconds",
        ] {
            let mut malicious = valid.clone();
            malicious[field] = serde_json::json!("renderer-override");
            let error = match serde_json::from_value::<CompleteAiChatRequest>(malicious) {
                Ok(_) => panic!("renderer authority override {field} must be rejected"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`"))
            );
        }
    }

    #[test]
    fn dropped_command_registration_releases_its_request_slot() {
        let request_id = "drop-guard-request".to_owned();
        let (cancel, _canceled) = oneshot::channel();
        let registration = register_request(request_id.clone(), cancel).unwrap();
        assert!(lock_request_registry().contains_key(&request_id));

        drop(registration);

        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[test]
    fn stale_registration_cannot_remove_a_reused_request_id() {
        let request_id = "reused-request".to_owned();
        let (first_cancel, _first_canceled) = oneshot::channel();
        let first = register_request(request_id.clone(), first_cancel).unwrap();
        lock_request_registry().remove(&request_id);

        let (second_cancel, _second_canceled) = oneshot::channel();
        let second = register_request(request_id.clone(), second_cancel).unwrap();
        let second_identity = Arc::clone(&second.identity);
        drop(first);

        assert!(
            lock_request_registry()
                .get(&request_id)
                .is_some_and(|request| Arc::ptr_eq(&request.identity, &second_identity))
        );
        drop(second);
        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[tokio::test]
    async fn cancellation_is_registered_before_the_request_pipeline_is_polled() {
        let request_id = "cancel-before-credential-resolution".to_owned();
        let (started, started_rx) = oneshot::channel();
        let pending = tokio::spawn(run_registered_request(request_id.clone(), async move {
            let _ = started.send(());
            std::future::pending::<Result<(), String>>().await
        }));

        started_rx.await.expect("request pipeline started");
        assert!(cancel_ai_chat(request_id.clone()).await.expect("cancel"));
        assert_eq!(
            pending.await.expect("request task").expect_err("canceled"),
            "AI_REQUEST_CANCELED"
        );
        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[tokio::test]
    async fn remote_profile_without_api_key_returns_stable_error_and_releases_slot() {
        let request_id = "remote-no-key".to_owned();
        let (credentials, _controller) = in_memory_credential_store();
        let profile_id = "openai-work";
        let authority = test_authority(profile_id, "https://api.example.test/v1");
        let error = complete_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: request_id.clone(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "private prompt".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
        )
        .await
        .err()
        .unwrap();

        assert_eq!(error, AI_STORED_KEY_NOT_FOUND);
        assert!(!lock_request_registry().contains_key(&request_id));
    }

    #[tokio::test]
    async fn saved_api_key_lifecycle_is_isolated_by_provider_profile() {
        let (credentials, controller) = in_memory_credential_store();
        let profile_id = "openai-work";
        let other_profile_id = "openai-personal";
        let authority = test_authority(profile_id, "https://api.example.test/v1");
        let other_authority = test_authority(other_profile_id, "https://api.example.test/v1");
        assert!(
            !has_saved_ai_api_key_with_store(profile_id, &authority, &credentials)
                .await
                .expect("initial presence")
        );

        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "saved-ai-key-marker".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save key");

        assert!(
            has_saved_ai_api_key_with_store(profile_id, &authority, &credentials)
                .await
                .expect("saved presence")
        );
        assert!(
            !has_saved_ai_api_key_with_store(other_profile_id, &other_authority, &credentials)
                .await
                .expect("other profile presence")
        );
        assert_eq!(
            has_saved_ai_api_key_with_store(other_profile_id, &authority, &credentials)
                .await
                .expect_err("isolated profile authority"),
            AI_KEY_SOURCE_INVALID
        );
        delete_ai_api_key_with_store(profile_id, &authority, &credentials)
            .await
            .expect("delete key");
        assert!(
            !has_saved_ai_api_key_with_store(profile_id, &authority, &credentials)
                .await
                .expect("deleted presence")
        );

        let diagnostic = format!("{controller:?} {:?}", controller.operation_log());
        assert!(!diagnostic.contains("saved-ai-key-marker"));
        assert!(!diagnostic.contains(profile_id));
    }

    #[tokio::test]
    async fn saved_key_commands_reject_profile_mismatch_before_keyring_access() {
        let (credentials, controller) = in_memory_credential_store();
        let authority = test_authority("openai-work", "https://api.example.test/v1");
        let mismatched_profile_id = "unknown-profile";

        let has_error =
            has_saved_ai_api_key_with_store(mismatched_profile_id, &authority, &credentials)
                .await
                .expect_err("presence profile mismatch");
        assert_eq!(has_error, AI_KEY_SOURCE_INVALID);

        let save_error = save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: mismatched_profile_id.to_owned(),
                api_key: "must-not-reach-keyring".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect_err("save profile mismatch");
        assert_eq!(save_error, AI_KEY_SOURCE_INVALID);

        let delete_error =
            delete_ai_api_key_with_store(mismatched_profile_id, &authority, &credentials)
                .await
                .expect_err("delete profile mismatch");
        assert_eq!(delete_error, AI_KEY_SOURCE_INVALID);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test]
    async fn legacy_provider_only_key_is_never_read() {
        let (credentials, controller) = in_memory_credential_store();
        let provider_id = "openai-compatible";
        let authority = test_authority(provider_id, "https://api.example.test/v1");
        let legacy = legacy_ai_provider_reference(provider_id).expect("legacy AI reference");
        credentials
            .upsert(
                &legacy,
                CredentialKind::AiApiKey,
                SecretValue::from_utf8("legacy-provider-only-secret".to_owned())
                    .expect("legacy secret"),
            )
            .await
            .expect("seed legacy provider-only key");
        controller.clear_operation_log();

        assert!(
            !has_saved_ai_api_key_with_store(provider_id, &authority, &credentials)
                .await
                .expect("profile-bound presence")
        );
        let error = resolve_api_key(&authority, &credentials)
            .await
            .expect_err("legacy key must not be selected");
        assert_eq!(error, AI_STORED_KEY_NOT_FOUND);
        let diagnostic = format!("{controller:?} {:?}", controller.operation_log());
        assert!(!diagnostic.contains("legacy-provider-only-secret"));
        assert!(!diagnostic.contains(provider_id));
    }

    #[tokio::test]
    async fn known_deepseek_console_endpoint_key_moves_to_the_api_endpoint() {
        let (credentials, _controller) = in_memory_credential_store();
        let profile_id = "deepseek";
        let mut settings = test_authority_settings(profile_id, DEEPSEEK_API_BASE_URL, true);
        settings.provider_id = "deepseek".to_owned();
        let authority = native_ai_authority(settings, true).expect("DeepSeek authority");
        let legacy = legacy_endpoint_ai_provider_reference(&authority)
            .expect("known legacy DeepSeek endpoint");
        credentials
            .upsert(
                &legacy,
                CredentialKind::AiApiKey,
                SecretValue::from_utf8("deepseek-migrated-key".to_owned())
                    .expect("legacy endpoint key"),
            )
            .await
            .expect("seed legacy endpoint key");

        assert!(
            has_saved_ai_api_key_with_store(profile_id, &authority, &credentials)
                .await
                .expect("migrated key presence")
        );
        let current = endpoint_ai_provider_reference(&authority).expect("current endpoint key");
        let migrated = credentials
            .resolve(&current, CredentialKind::AiApiKey)
            .await
            .expect("migrated current key");
        assert_eq!(
            migrated.as_utf8().expect("UTF-8 key"),
            "deepseek-migrated-key"
        );
        let legacy_error = match credentials.resolve(&legacy, CredentialKind::AiApiKey).await {
            Ok(_) => panic!("legacy endpoint key must be removed"),
            Err(error) => error,
        };
        assert_eq!(legacy_error.code(), CredentialErrorCode::NotFound);
    }

    #[test]
    fn agent_start_wire_accepts_profile_only_and_rejects_authority_overrides() {
        let valid = serde_json::json!({
            "turnId": "permission-authority-turn",
            "providerProfileId": "openai-work",
            "messages": [{"role": "user", "content": "hello"}]
        });
        assert!(serde_json::from_value::<StartAiAgentTurnRequest>(valid.clone()).is_ok());

        for field in [
            "providerId",
            "baseUrl",
            "apiKey",
            "useStoredKey",
            "model",
            "permissionMode",
            "responseIdleTimeoutSeconds",
        ] {
            let mut malicious = valid.clone();
            malicious[field] = serde_json::json!("renderer-override");
            let error = match serde_json::from_value::<StartAiAgentTurnRequest>(malicious) {
                Ok(_) => panic!("renderer authority override {field} must be rejected"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`"))
            );
        }
    }

    #[tokio::test]
    async fn anthropic_agent_tool_loop_is_rejected_before_keyring_or_network_io() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let base_url = format!(
            "http://{}/v1",
            listener.local_addr().expect("listener address")
        );
        let profile_id = "openai-compatible";

        let directory = tempfile::tempdir().expect("settings directory");
        let settings_store =
            RendererSafeSettingsStore::open(directory.path()).expect("settings store");
        let current = settings_store.load().expect("default settings");
        let mut value = serde_json::to_value(&current.settings).expect("settings JSON");
        value["ai"]["providers"][0]["protocol"] = serde_json::json!("anthropicMessages");
        value["ai"]["providers"][0]["baseUrl"] = serde_json::json!(base_url);
        value["ai"]["providers"][0]["model"] = serde_json::json!("claude-test");
        let anthropic_settings: crate::settings_catalog::RendererSafeSettings =
            serde_json::from_value(value).expect("Anthropic settings");
        settings_store
            .replace(current.inventory_revision, anthropic_settings)
            .expect("publish Anthropic settings");

        let authority = test_anthropic_authority(profile_id, &base_url);
        let (credentials, controller) = in_memory_credential_store();
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "must-not-be-read-anthropic-agent-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("seed Anthropic key");
        controller.clear_operation_log();

        let error = match start_ai_agent_turn_with_store(
            StartAiAgentTurnRequest {
                turn_id: "anthropic-agent-rejected".to_owned(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "must not reach provider".to_owned(),
                    content_parts: Vec::new(),
                }],
                terminal_scope: Some(AiTerminalScope {
                    route_id: "terminal-anthropic".to_owned(),
                    generation: 1,
                    protocol: "ssh".to_owned(),
                }),
                reasoning_effort: None,
            },
            settings_store,
            &credentials,
        )
        .await
        {
            Ok(_) => panic!("Anthropic tool loop must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, AI_AGENT_PROTOCOL_UNSUPPORTED);
        assert!(controller.operation_log().is_empty());
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn agent_tool_authorization_wire_requires_an_explicit_user_decision() {
        let valid = serde_json::json!({
            "turnId": "permission-authority-turn",
            "toolCallId": "tool-call-1",
            "terminalScope": {
                "routeId": "terminal-1",
                "generation": 1,
                "protocol": "ssh"
            },
            "userApproved": true
        });
        assert!(serde_json::from_value::<AuthorizeAiAgentToolRequest>(valid.clone()).is_ok());

        let mut missing_decision = valid.clone();
        missing_decision
            .as_object_mut()
            .expect("authorization object")
            .remove("userApproved");
        assert!(serde_json::from_value::<AuthorizeAiAgentToolRequest>(missing_decision).is_err());

        let mut renderer_policy = valid;
        renderer_policy["permissionMode"] = serde_json::json!("auto");
        assert!(serde_json::from_value::<AuthorizeAiAgentToolRequest>(renderer_policy).is_err());
    }

    #[tokio::test]
    async fn every_tool_authorization_enforces_the_latest_native_permission() {
        let observer_turn = "native-observer-authorization";
        let (observer_request, observer_pending) =
            pending_authorization_fixture(observer_turn, true).await;
        insert_pending_agent_turn(observer_turn.to_owned(), observer_pending)
            .expect("observer pending turn");
        assert_eq!(
            authorize_pending_agent_tool(&observer_request, AiPermissionMode::Observer)
                .expect_err("observer must reject"),
            "AI_TOOL_OBSERVER_DENIED"
        );
        assert!(!has_pending_agent_turn(observer_turn));

        let confirm_auto_turn = "native-confirm-auto-authorization";
        let (confirm_auto_request, confirm_auto_pending) =
            pending_authorization_fixture(confirm_auto_turn, false).await;
        insert_pending_agent_turn(confirm_auto_turn.to_owned(), confirm_auto_pending)
            .expect("confirm automatic pending turn");
        assert_eq!(
            authorize_pending_agent_tool(&confirm_auto_request, AiPermissionMode::Confirm)
                .expect_err("confirm must reject automatic authorization"),
            "AI_TOOL_APPROVAL_REQUIRED"
        );
        assert!(has_pending_agent_turn(confirm_auto_turn));
        take_pending_agent_turn(confirm_auto_turn).expect("confirm automatic cleanup");

        let confirm_user_turn = "native-confirm-user-authorization";
        let (confirm_user_request, confirm_user_pending) =
            pending_authorization_fixture(confirm_user_turn, true).await;
        insert_pending_agent_turn(confirm_user_turn.to_owned(), confirm_user_pending)
            .expect("confirm user pending turn");
        authorize_pending_agent_tool(&confirm_user_request, AiPermissionMode::Confirm)
            .expect("explicit user approval");
        let confirmed = take_pending_agent_turn(confirm_user_turn).expect("confirmed pending turn");
        assert!(confirmed.execution_authorized);

        let auto_turn = "native-auto-authorization";
        let (auto_request, auto_pending) = pending_authorization_fixture(auto_turn, true).await;
        insert_pending_agent_turn(auto_turn.to_owned(), auto_pending).expect("auto pending turn");
        authorize_pending_agent_tool(&auto_request, AiPermissionMode::Auto)
            .expect("auto authorization");
        let mut authorized = take_pending_agent_turn(auto_turn).expect("authorized auto turn");
        assert!(authorized.execution_authorized);
        authorized
            .pending
            .turn
            .submit_tool_result(
                &auto_request.tool_call_id,
                &auto_request.terminal_scope,
                AiTerminalToolResult {
                    output: "/srv/project".to_owned(),
                    timed_out: false,
                    error_code: None,
                },
            )
            .expect("first auto tool result");
        let decision =
            advance_test_turn_to_tool(&mut authorized.pending, "native-auto-next-call").await;
        assert!(matches!(
            decision,
            AiAgentDecision::ToolCall {
                approval_required: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stored_key_reaches_a_real_loopback_openai_compatible_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let provider = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "AI provider was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking provider connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("provider read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("provider request");
                assert!(read > 0, "provider request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(request.lines().any(|line| {
                line.eq_ignore_ascii_case("authorization: Bearer stored-loopback-key")
            }));
            let body = br#"{"choices":[{"message":{"content":"stored key answer"}}]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("provider response headers");
            stream.write_all(body).expect("provider response body");
        });

        let (credentials, _controller) = in_memory_credential_store();
        let base_url = format!("http://{address}/v1");
        let profile_id = "local-profile";
        let authority = test_authority(profile_id, &base_url);
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: profile_id.to_owned(),
                api_key: "stored-loopback-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save stored key");
        let response = complete_ai_chat_with_store(
            CompleteAiChatRequest {
                request_id: "stored-loopback-request".to_owned(),
                provider_profile_id: profile_id.to_owned(),
                messages: vec![AiChatMessage {
                    role: AiChatRole::User,
                    content: "hello".to_owned(),
                    content_parts: Vec::new(),
                }],
                reasoning_effort: None,
            },
            authority,
            &credentials,
        )
        .await
        .expect("stored-key completion");
        provider.join().expect("provider thread");
        assert_eq!(response.content, "stored key answer");
    }

    #[tokio::test]
    async fn completion_profile_mismatch_is_rejected_before_keyring_access() {
        let (credentials, controller) = in_memory_credential_store();
        let request = CompleteAiChatRequest {
            request_id: "profile-mismatch-request".to_owned(),
            provider_profile_id: "unknown-profile".to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "hello".to_owned(),
                content_parts: Vec::new(),
            }],
            reasoning_effort: None,
        };
        let authority = test_authority("openai-work", "https://api.example.test/v1");
        let error = complete_ai_chat_with_store(request, authority, &credentials)
            .await
            .err()
            .expect("profile mismatch");
        assert_eq!(error, AI_KEY_SOURCE_INVALID);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test]
    async fn anthropic_image_content_is_rejected_before_keyring_access() {
        let (credentials, controller) = in_memory_credential_store();
        let profile_id = "anthropic-images";
        let authority = test_anthropic_authority(profile_id, "https://api.anthropic.test");
        let request = CompleteAiChatRequest {
            request_id: "anthropic-image-request".to_owned(),
            provider_profile_id: profile_id.to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "inspect".to_owned(),
                content_parts: vec![AiChatContentPart::Image {
                    mime_type: "image/png".to_owned(),
                    data: "iVBORw0KGgo=".to_owned(),
                }],
            }],
            reasoning_effort: None,
        };
        let error = match complete_ai_chat_with_store(request, authority, &credentials).await {
            Ok(_) => panic!("Anthropic image input must fail before completion"),
            Err(error) => error,
        };
        assert_eq!(error, AI_IMAGE_INPUT_UNSUPPORTED);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test]
    async fn anthropic_reasoning_effort_is_rejected_before_keyring_access() {
        let (credentials, controller) = in_memory_credential_store();
        let profile_id = "anthropic-reasoning";
        let authority = test_anthropic_authority(profile_id, "https://api.anthropic.test");
        let request = CompleteAiChatRequest {
            request_id: "anthropic-reasoning-request".to_owned(),
            provider_profile_id: profile_id.to_owned(),
            messages: vec![AiChatMessage {
                role: AiChatRole::User,
                content: "inspect".to_owned(),
                content_parts: Vec::new(),
            }],
            reasoning_effort: Some(AiReasoningEffort::High),
        };
        let error = match complete_ai_chat_with_store(request, authority, &credentials).await {
            Ok(_) => panic!("Anthropic reasoning effort must fail before completion"),
            Err(error) => error,
        };
        assert_eq!(error, AI_REASONING_PROTOCOL_UNSUPPORTED);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test]
    async fn stored_credentials_remain_bound_to_profile_and_canonical_endpoint() {
        let (credentials, _controller) = in_memory_credential_store();
        let authority = test_authority("openai-work", "https://API.EXAMPLE.TEST:443/v1/");
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: "openai-work".to_owned(),
                api_key: "canonical-authority-key".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect("save key");
        let key = resolve_api_key(&authority, &credentials)
            .await
            .expect("canonical endpoint match");
        drop(key);

        let moved_endpoint = test_authority("openai-work", "https://other.example.test/v1");
        assert_eq!(
            resolve_api_key(&moved_endpoint, &credentials)
                .await
                .expect_err("changed endpoint must not reuse key"),
            AI_STORED_KEY_NOT_FOUND
        );
        let other_profile = test_authority("openai-personal", "https://api.example.test/v1");
        assert_eq!(
            resolve_api_key(&other_profile, &credentials)
                .await
                .expect_err("other profile must not reuse key"),
            AI_STORED_KEY_NOT_FOUND
        );

        let anthropic =
            test_anthropic_authority("anthropic-work", "https://API.ANTHROPIC.EXAMPLE:443/v1/");
        save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: "anthropic-work".to_owned(),
                api_key: "canonical-anthropic-key".to_owned(),
            },
            &anthropic,
            &credentials,
        )
        .await
        .expect("save Anthropic key");
        drop(
            resolve_api_key(&anthropic, &credentials)
                .await
                .expect("canonical Anthropic endpoint match"),
        );
        let moved_anthropic =
            test_anthropic_authority("anthropic-work", "https://api.anthropic.example/proxy/v1");
        assert_eq!(
            resolve_api_key(&moved_anthropic, &credentials)
                .await
                .expect_err("changed Anthropic endpoint must not reuse key"),
            AI_STORED_KEY_NOT_FOUND
        );
    }

    #[tokio::test]
    async fn saved_api_key_rejects_invalid_profile_and_persistent_size_overflow() {
        let (credentials, _controller) = in_memory_credential_store();
        let authority = test_authority("openai-work", "https://api.example.test/v1");
        let invalid_profile = save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: "Private Profile".to_owned(),
                api_key: "secret".to_owned(),
            },
            &authority,
            &credentials,
        )
        .await
        .expect_err("invalid profile");
        assert_eq!(invalid_profile, AI_PROVIDER_INVALID);

        let too_large = save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: "openai-work".to_owned(),
                api_key: "x".repeat(MAX_PERSISTENT_SECRET_BYTES + 1),
            },
            &authority,
            &credentials,
        )
        .await
        .expect_err("persistent key limit");
        assert_eq!(too_large, "AI_API_KEY_TOO_LARGE");

        let above_transport_limit = save_ai_api_key_with_store(
            SaveAiApiKeyRequest {
                provider_profile_id: "openai-work".to_owned(),
                api_key: "x".repeat(MAX_AI_KEY_BYTES + 1),
            },
            &authority,
            &credentials,
        )
        .await
        .expect_err("key larger than the request transport limit");
        assert_eq!(above_transport_limit, "AI_API_KEY_TOO_LARGE");
    }

    #[tokio::test]
    async fn pending_approval_expiry_identity_cannot_remove_a_reused_turn_id() {
        let turn_id = "pending-reuse-agent-turn".to_owned();
        let old_identity = insert_pending_agent_turn(turn_id.clone(), test_pending_agent_turn())
            .expect("first pending turn");
        let first = take_pending_agent_turn(&turn_id)
            .expect("take first turn")
            .pending;
        let new_identity =
            insert_pending_agent_turn(turn_id.clone(), first).expect("reused pending turn");

        assert!(!remove_pending_agent_turn_if_identity(
            &turn_id,
            &old_identity
        ));
        assert!(has_pending_agent_turn(&turn_id));
        assert!(remove_pending_agent_turn_if_identity(
            &turn_id,
            &new_identity
        ));
    }

    #[test]
    fn expired_pending_approval_is_pruned_before_it_occupies_a_slot() {
        let turn_id = "expired-agent-turn".to_owned();
        lock_pending_agent_turns().insert(
            turn_id.clone(),
            RegisteredPendingAgentTurn {
                identity: Arc::new(()),
                expires_at: Instant::now(),
                execution_authorized: false,
                pending: test_pending_agent_turn(),
            },
        );
        assert!(!has_pending_agent_turn(&turn_id));
    }

    #[tokio::test]
    async fn cancel_cannot_miss_the_pending_to_active_transition() {
        let turn_id = "cancel-agent-handoff".to_owned();
        insert_pending_agent_turn(turn_id.clone(), test_pending_agent_turn())
            .expect("pending turn");
        let (cancel, canceled) = oneshot::channel();
        let registration = register_request(turn_id.clone(), cancel).expect("active handoff");

        assert!(cancel_ai_agent_turn(turn_id.clone()).await.expect("cancel"));
        assert!(take_pending_agent_turn(&turn_id).is_none());
        canceled.await.expect("active cancel signal");
        drop(registration);
        assert!(!lock_request_registry().contains_key(&turn_id));
    }
}
