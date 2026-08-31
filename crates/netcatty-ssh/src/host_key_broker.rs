use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::{
    HostKeyClassification, HostKeyStatus, HostKeyVerifier, KnownHost, LiveHostKey, TransportError,
    TransportErrorCode, classify_host_key,
};

const HOST_KEY_REQUEST_TTL: Duration = Duration::from_secs(2 * 60);
const HOST_KEY_EVENT_BUFFER: usize = 64;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPrompt {
    pub request_id: String,
    pub owner_id: String,
    pub session_id: String,
    pub client_attempt_id: String,
    pub hostname: String,
    pub port: u16,
    pub status: HostKeyStatus,
    pub key_type: String,
    pub fingerprint: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_fingerprint: Option<String>,
}

pub type HostKeyPromptReceiver = broadcast::Receiver<HostKeyPrompt>;

struct PendingRequest {
    owner_id: String,
    response: oneshot::Sender<bool>,
}

#[derive(Clone)]
pub struct HostKeyBroker {
    pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    prompts: broadcast::Sender<HostKeyPrompt>,
    ttl: Duration,
}

impl HostKeyBroker {
    #[must_use]
    pub fn new() -> Self {
        let (prompts, _) = broadcast::channel(HOST_KEY_EVENT_BUFFER);
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            prompts,
            ttl: HOST_KEY_REQUEST_TTL,
        }
    }

    pub fn subscribe(&self) -> HostKeyPromptReceiver {
        self.prompts.subscribe()
    }

    pub async fn respond(
        &self,
        owner_id: &str,
        request_id: &str,
        accept: bool,
    ) -> Result<(), HostKeyBrokerError> {
        let mut pending = self.pending.lock().await;
        let request = pending
            .get(request_id)
            .ok_or(HostKeyBrokerError::NotFound)?;
        if request.owner_id != owner_id {
            return Err(HostKeyBrokerError::WrongOwner);
        }
        let request = pending
            .remove(request_id)
            .ok_or(HostKeyBrokerError::NotFound)?;
        request
            .response
            .send(accept)
            .map_err(|_| HostKeyBrokerError::Expired)
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
                let _ = request.response.send(false);
            }
        }
    }

    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    async fn request(&self, mut prompt: HostKeyPrompt) -> bool {
        let request_id = next_request_id();
        prompt.request_id.clone_from(&request_id);
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(
            request_id.clone(),
            PendingRequest {
                owner_id: prompt.owner_id.clone(),
                response: sender,
            },
        );
        if self.prompts.send(prompt).is_err() {
            self.pending.lock().await.remove(&request_id);
            return false;
        }
        let accepted = tokio::time::timeout(self.ttl, receiver)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        self.pending.lock().await.remove(&request_id);
        accepted
    }
}

impl Default for HostKeyBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyBrokerError {
    NotFound,
    WrongOwner,
    Expired,
}

impl fmt::Display for HostKeyBrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "主机密钥确认请求不存在",
            Self::WrongOwner => "主机密钥确认请求不属于当前窗口",
            Self::Expired => "主机密钥确认请求已经过期",
        })
    }
}

impl std::error::Error for HostKeyBrokerError {}

pub struct PromptingHostKeyVerifier {
    broker: HostKeyBroker,
    owner_id: String,
    session_id: String,
    client_attempt_id: String,
    hostname: String,
    port: u16,
    known_hosts: Vec<KnownHost>,
    verification_enabled: bool,
}

impl PromptingHostKeyVerifier {
    #[must_use]
    pub fn new(
        broker: HostKeyBroker,
        owner_id: impl Into<String>,
        session_id: impl Into<String>,
        client_attempt_id: impl Into<String>,
        hostname: impl Into<String>,
        port: u16,
        known_hosts: Vec<KnownHost>,
    ) -> Self {
        Self {
            broker,
            owner_id: owner_id.into(),
            session_id: session_id.into(),
            client_attempt_id: client_attempt_id.into(),
            hostname: hostname.into(),
            port,
            known_hosts,
            verification_enabled: true,
        }
    }

    #[must_use]
    pub fn with_verification_enabled(mut self, enabled: bool) -> Self {
        self.verification_enabled = enabled;
        self
    }

    fn classify(&self, key: &LiveHostKey) -> HostKeyClassification {
        classify_host_key(&self.known_hosts, &self.hostname, self.port, key)
    }
}

#[async_trait]
impl HostKeyVerifier for PromptingHostKeyVerifier {
    async fn verify(&self, key: &LiveHostKey) -> Result<bool, TransportError> {
        if !self.verification_enabled {
            return Ok(true);
        }
        let classification = self.classify(key);
        if classification.status == HostKeyStatus::Trusted {
            return Ok(true);
        }
        let accepted = self
            .broker
            .request(HostKeyPrompt {
                request_id: String::new(),
                owner_id: self.owner_id.clone(),
                session_id: self.session_id.clone(),
                client_attempt_id: self.client_attempt_id.clone(),
                hostname: self.hostname.clone(),
                port: self.port,
                status: classification.status,
                key_type: key.key_type.clone(),
                fingerprint: key.fingerprint.clone(),
                public_key: key.public_key.clone(),
                known_host_id: classification.known_host_id,
                known_fingerprint: classification.expected_fingerprint,
            })
            .await;
        if accepted {
            Ok(true)
        } else {
            Err(TransportError::new(
                TransportErrorCode::HostKeyRejected,
                "SSH 主机密钥未被信任",
            ))
        }
    }
}

fn next_request_id() -> String {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("hostkey-{}-{sequence}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{HostKeyBroker, HostKeyBrokerError, PromptingHostKeyVerifier};
    use crate::{HostKeyStatus, HostKeyVerifier, LiveHostKey};

    fn live_key() -> LiveHostKey {
        LiveHostKey {
            key_type: "ssh-ed25519".to_owned(),
            fingerprint: "new-fingerprint".to_owned(),
            public_key: "ssh-ed25519 AAAATEST".to_owned(),
        }
    }

    #[tokio::test]
    async fn unknown_key_waits_for_the_owning_window_response() {
        let broker = HostKeyBroker::new();
        let mut prompts = broker.subscribe();
        let verifier = PromptingHostKeyVerifier::new(
            broker.clone(),
            "window-1",
            "session-1",
            "attempt-host-key-1",
            "host.example",
            22,
            Vec::new(),
        );
        let verification = tokio::spawn(async move { verifier.verify(&live_key()).await });
        let prompt = prompts.recv().await.expect("prompt");

        assert_eq!(prompt.status, HostKeyStatus::Unknown);
        assert_eq!(prompt.client_attempt_id, "attempt-host-key-1");
        let serialized = serde_json::to_value(&prompt).expect("prompt JSON");
        assert_eq!(
            serialized["clientAttemptId"],
            serde_json::json!("attempt-host-key-1")
        );
        assert!(serialized.get("client_attempt_id").is_none());
        assert_eq!(
            broker.respond("window-2", &prompt.request_id, true).await,
            Err(HostKeyBrokerError::WrongOwner)
        );
        broker
            .respond("window-1", &prompt.request_id, true)
            .await
            .expect("owner response");
        assert!(verification.await.expect("verification task").is_ok());
        assert_eq!(broker.pending_count().await, 0);
    }

    #[tokio::test]
    async fn closing_an_owner_rejects_all_pending_requests() {
        let broker = HostKeyBroker::new();
        let mut prompts = broker.subscribe();
        let verifier = PromptingHostKeyVerifier::new(
            broker.clone(),
            "window-1",
            "session-1",
            "attempt-host-key-2",
            "host.example",
            22,
            Vec::new(),
        );
        let verification = tokio::spawn(async move { verifier.verify(&live_key()).await });
        prompts.recv().await.expect("prompt");

        broker.reject_owner("window-1").await;
        assert!(verification.await.expect("verification task").is_err());
        assert_eq!(broker.pending_count().await, 0);
    }
}
