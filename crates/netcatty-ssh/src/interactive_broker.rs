use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::{
    AuthenticationPrompt, AuthenticationPrompts, InteractiveAuthResponder, SecretText,
    TransportError, TransportErrorCode,
};

const INTERACTIVE_REQUEST_TTL: Duration = Duration::from_secs(5 * 60);
const INTERACTIVE_EVENT_BUFFER: usize = 64;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractivePrompt {
    pub request_id: String,
    pub owner_id: String,
    pub session_id: String,
    pub client_attempt_id: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<AuthenticationPrompt>,
}

pub type InteractivePromptReceiver = broadcast::Receiver<InteractivePrompt>;

struct PendingRequest {
    owner_id: String,
    response: oneshot::Sender<Option<Vec<SecretText>>>,
}

#[derive(Clone)]
pub struct InteractiveAuthBroker {
    pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    prompts: broadcast::Sender<InteractivePrompt>,
    ttl: Duration,
}

impl InteractiveAuthBroker {
    #[must_use]
    pub fn new() -> Self {
        let (prompts, _) = broadcast::channel(INTERACTIVE_EVENT_BUFFER);
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            prompts,
            ttl: INTERACTIVE_REQUEST_TTL,
        }
    }

    pub fn subscribe(&self) -> InteractivePromptReceiver {
        self.prompts.subscribe()
    }

    pub async fn respond(
        &self,
        owner_id: &str,
        request_id: &str,
        answers: Vec<SecretText>,
    ) -> Result<(), InteractiveBrokerError> {
        self.finish(owner_id, request_id, Some(answers)).await
    }

    pub async fn cancel(
        &self,
        owner_id: &str,
        request_id: &str,
    ) -> Result<(), InteractiveBrokerError> {
        self.finish(owner_id, request_id, None).await
    }

    pub async fn reject_owner(&self, owner_id: &str) {
        let mut pending = self.pending.lock().await;
        let request_ids: Vec<_> = pending
            .iter()
            .filter(|(_, request)| request.owner_id == owner_id)
            .map(|(request_id, _)| request_id.clone())
            .collect();
        for request_id in request_ids {
            if let Some(request) = pending.remove(&request_id) {
                let _ = request.response.send(None);
            }
        }
    }

    async fn finish(
        &self,
        owner_id: &str,
        request_id: &str,
        answers: Option<Vec<SecretText>>,
    ) -> Result<(), InteractiveBrokerError> {
        let mut pending = self.pending.lock().await;
        let request = pending
            .get(request_id)
            .ok_or(InteractiveBrokerError::NotFound)?;
        if request.owner_id != owner_id {
            return Err(InteractiveBrokerError::WrongOwner);
        }
        pending
            .remove(request_id)
            .ok_or(InteractiveBrokerError::NotFound)?
            .response
            .send(answers)
            .map_err(|_| InteractiveBrokerError::Expired)
    }

    async fn request(
        &self,
        owner_id: String,
        session_id: String,
        client_attempt_id: String,
        request: AuthenticationPrompts,
    ) -> Option<Vec<SecretText>> {
        let request_id = next_request_id();
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(
            request_id.clone(),
            PendingRequest {
                owner_id: owner_id.clone(),
                response: sender,
            },
        );
        if self
            .prompts
            .send(InteractivePrompt {
                request_id: request_id.clone(),
                owner_id,
                session_id,
                client_attempt_id,
                name: request.name,
                instructions: request.instructions,
                prompts: request.prompts,
            })
            .is_err()
        {
            self.pending.lock().await.remove(&request_id);
            return None;
        }
        let answers = tokio::time::timeout(self.ttl, receiver)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        self.pending.lock().await.remove(&request_id);
        answers
    }
}

impl Default for InteractiveAuthBroker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PromptingInteractiveAuthResponder {
    broker: InteractiveAuthBroker,
    owner_id: String,
    session_id: String,
    client_attempt_id: String,
}

impl PromptingInteractiveAuthResponder {
    #[must_use]
    pub fn new(
        broker: InteractiveAuthBroker,
        owner_id: impl Into<String>,
        session_id: impl Into<String>,
        client_attempt_id: impl Into<String>,
    ) -> Self {
        Self {
            broker,
            owner_id: owner_id.into(),
            session_id: session_id.into(),
            client_attempt_id: client_attempt_id.into(),
        }
    }
}

#[async_trait]
impl InteractiveAuthResponder for PromptingInteractiveAuthResponder {
    async fn respond(
        &self,
        request: AuthenticationPrompts,
    ) -> Result<Vec<SecretText>, TransportError> {
        self.broker
            .request(
                self.owner_id.clone(),
                self.session_id.clone(),
                self.client_attempt_id.clone(),
                request,
            )
            .await
            .ok_or_else(|| {
                TransportError::new(
                    TransportErrorCode::InteractiveAuthFailed,
                    "SSH interactive authentication was cancelled",
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveBrokerError {
    NotFound,
    WrongOwner,
    Expired,
}

impl fmt::Display for InteractiveBrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "SSH interactive request does not exist",
            Self::WrongOwner => "SSH interactive request belongs to another window",
            Self::Expired => "SSH interactive request has expired",
        })
    }
}

impl std::error::Error for InteractiveBrokerError {}

fn next_request_id() -> String {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("interactive-{}-{sequence}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{InteractiveAuthBroker, PromptingInteractiveAuthResponder};
    use crate::{
        AuthenticationPrompt, AuthenticationPrompts, InteractiveAuthResponder, SecretText,
    };

    #[tokio::test]
    async fn owning_window_can_answer_without_serializing_secrets() {
        let broker = InteractiveAuthBroker::new();
        let mut prompts = broker.subscribe();
        let responder = PromptingInteractiveAuthResponder::new(
            broker.clone(),
            "window-1",
            "session-1",
            "attempt-interactive-1",
        );
        let response = tokio::spawn(async move {
            responder
                .respond(AuthenticationPrompts {
                    name: "MFA".to_owned(),
                    instructions: String::new(),
                    prompts: vec![AuthenticationPrompt {
                        text: "Code: ".to_owned(),
                        echo: false,
                    }],
                })
                .await
        });
        let prompt = prompts.recv().await.expect("prompt");
        assert_eq!(prompt.client_attempt_id, "attempt-interactive-1");
        let serialized = serde_json::to_string(&prompt).expect("prompt JSON");
        let serialized_value = serde_json::to_value(&prompt).expect("prompt value");
        assert_eq!(
            serialized_value["clientAttemptId"],
            serde_json::json!("attempt-interactive-1")
        );
        assert!(serialized_value.get("client_attempt_id").is_none());
        assert!(!serialized.contains("123456"));
        broker
            .respond(
                "window-1",
                &prompt.request_id,
                vec![SecretText::new("123456")],
            )
            .await
            .expect("response");
        assert_eq!(response.await.expect("task").expect("answers").len(), 1);
    }
}
