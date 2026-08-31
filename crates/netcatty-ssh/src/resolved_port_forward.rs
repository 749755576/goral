use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tokio::sync::Mutex;

use crate::{
    DirectConnector, HostChainResolver, NormalizedPortForwardRule, PortForwardError,
    PortForwardEvent, PortForwardKind, PortForwardManager, PortForwardStart, ResolvedSshEndpoint,
    SshConnection, TransportError, TransportErrorCode,
};

/// Process-owned phase for one resolved SavedHost port-forward attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResolvedPortForwardPhase {
    Connecting,
    Active,
    Error,
}

/// Secret-free runtime projection. Durable rule configuration stays in the
/// Vault and never acquires these process-lifetime fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedPortForwardRuntime {
    pub rule_id: String,
    pub phase: ResolvedPortForwardPhase,
    pub tunnel_id: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub error: Option<String>,
}

struct ResolvedForwardState {
    phase: ResolvedPortForwardPhase,
    tunnel_id: Option<String>,
    address: Option<String>,
    port: Option<u16>,
    error: Option<String>,
}

impl Default for ResolvedForwardState {
    fn default() -> Self {
        Self {
            phase: ResolvedPortForwardPhase::Connecting,
            tunnel_id: None,
            address: None,
            port: None,
            error: None,
        }
    }
}

struct ResolvedForwardEntry {
    connector: DirectConnector,
    cancelled: AtomicBool,
    state: Mutex<ResolvedForwardState>,
    connection: Mutex<Option<Arc<SshConnection>>>,
}

impl ResolvedForwardEntry {
    fn new() -> Self {
        Self {
            connector: DirectConnector::new(),
            cancelled: AtomicBool::new(false),
            state: Mutex::new(ResolvedForwardState::default()),
            connection: Mutex::new(None),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.connector.cancel();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Establishes and owns the SSH transport used by each port-forward rule.
///
/// A forwarding transport is intentionally independent from terminal shells:
/// closing a shell cannot tear down a configured tunnel, and stopping the
/// tunnel disconnects its target plus every owned jump-hop connection. Both
/// direct and chain-aware entry points consume the same resolved endpoint
/// contract as managed terminal sessions.
#[derive(Clone, Default)]
pub struct ResolvedPortForwardManager {
    forwards: PortForwardManager,
    entries: Arc<Mutex<HashMap<String, Arc<ResolvedForwardEntry>>>>,
}

impl ResolvedPortForwardManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(
        &self,
        rule: NormalizedPortForwardRule,
        target: ResolvedSshEndpoint,
    ) -> Result<PortForwardStart, PortForwardError> {
        if !target.config.jump_hosts.is_empty() {
            return Err(PortForwardError::InvalidRule);
        }
        self.start_resolved(rule, target, None).await
    }

    pub async fn start_chain(
        &self,
        rule: NormalizedPortForwardRule,
        target: ResolvedSshEndpoint,
        resolver: Arc<dyn HostChainResolver>,
    ) -> Result<PortForwardStart, PortForwardError> {
        if target.config.jump_hosts.is_empty() {
            return Err(PortForwardError::InvalidRule);
        }
        self.start_resolved(rule, target, Some(resolver)).await
    }

    async fn start_resolved(
        &self,
        rule: NormalizedPortForwardRule,
        target: ResolvedSshEndpoint,
        resolver: Option<Arc<dyn HostChainResolver>>,
    ) -> Result<PortForwardStart, PortForwardError> {
        let rule_id = rule.id.clone();
        let entry = Arc::new(ResolvedForwardEntry::new());
        {
            let mut entries = self.entries.lock().await;
            if entries.get(&rule_id).is_some_and(|existing| {
                existing
                    .state
                    .try_lock()
                    .map_or(true, |state| state.phase != ResolvedPortForwardPhase::Error)
            }) {
                return Err(PortForwardError::DuplicateRule);
            }
            if let Some(previous) = entries.insert(rule_id.clone(), entry.clone()) {
                previous.cancel();
            }
        }

        let connected = match resolver {
            Some(resolver) => {
                entry
                    .connector
                    .connect_chain(target, resolver.as_ref())
                    .await
            }
            None => {
                entry
                    .connector
                    .connect(
                        &target.config,
                        &target.auth,
                        &target.credentials,
                        target.verifier,
                        target.interactive,
                    )
                    .await
            }
        };
        let connection = match connected {
            Ok(connection) if !entry.is_cancelled() => Arc::new(connection),
            Ok(connection) => {
                let _ = connection.disconnect().await;
                self.remove_if_current(&rule_id, &entry).await;
                return Err(cancelled_error());
            }
            Err(error) => {
                self.record_error(&entry, error.to_string()).await;
                return Err(PortForwardError::Transport(error));
            }
        };
        *entry.connection.lock().await = Some(connection.clone());

        let started = match rule.kind {
            PortForwardKind::Remote => self.forwards.start_remote(rule, connection.clone()).await,
            PortForwardKind::Local | PortForwardKind::Dynamic => {
                self.forwards.start(rule, connection.clone()).await
            }
        };
        let started = match started {
            Ok(started) if !entry.is_cancelled() => started,
            Ok(started) => {
                let _ = self.forwards.stop(&rule_id).await;
                let _ = connection.disconnect().await;
                *entry.connection.lock().await = None;
                self.remove_if_current(&rule_id, &entry).await;
                let _ = started;
                return Err(cancelled_error());
            }
            Err(error) => {
                let _ = connection.disconnect().await;
                *entry.connection.lock().await = None;
                self.record_error(&entry, error.to_string()).await;
                return Err(error);
            }
        };

        {
            let mut state = entry.state.lock().await;
            state.phase = ResolvedPortForwardPhase::Active;
            state.tunnel_id = Some(started.tunnel_id.clone());
            state.address = Some(started.address.clone());
            state.port = Some(started.port);
            state.error = None;
        }
        let watcher_events = started.events.resubscribe();
        self.spawn_lifecycle_watcher(rule_id, entry, watcher_events);
        Ok(started)
    }

    pub async fn runtime_snapshot(&self) -> Vec<ResolvedPortForwardRuntime> {
        let entries = self
            .entries
            .lock()
            .await
            .iter()
            .map(|(rule_id, entry)| (rule_id.clone(), entry.clone()))
            .collect::<Vec<_>>();
        let mut snapshot = Vec::with_capacity(entries.len());
        for (rule_id, entry) in entries {
            let state = entry.state.lock().await;
            snapshot.push(ResolvedPortForwardRuntime {
                rule_id,
                phase: state.phase,
                tunnel_id: state.tunnel_id.clone(),
                address: state.address.clone(),
                port: state.port,
                error: state.error.clone(),
            });
        }
        snapshot.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        snapshot
    }

    pub async fn stop(&self, rule_id: &str) -> Result<(), PortForwardError> {
        let entry = self.entries.lock().await.remove(rule_id);
        let primitive = self.forwards.stop(rule_id).await;
        let Some(entry) = entry else {
            return primitive;
        };
        entry.cancel();
        if let Some(connection) = entry.connection.lock().await.take() {
            let _ = connection.disconnect().await;
        }
        match primitive {
            Ok(()) | Err(PortForwardError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub async fn stop_all(&self) {
        let entries = self
            .entries
            .lock()
            .await
            .drain()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        for entry in &entries {
            entry.cancel();
        }
        self.forwards.stop_all().await;
        for entry in entries {
            if let Some(connection) = entry.connection.lock().await.take() {
                let _ = connection.disconnect().await;
            }
        }
    }

    async fn record_error(&self, entry: &ResolvedForwardEntry, error: String) {
        let mut state = entry.state.lock().await;
        state.phase = ResolvedPortForwardPhase::Error;
        state.tunnel_id = None;
        state.address = None;
        state.port = None;
        state.error = Some(error);
    }

    async fn remove_if_current(&self, rule_id: &str, entry: &Arc<ResolvedForwardEntry>) {
        let mut entries = self.entries.lock().await;
        if entries
            .get(rule_id)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(rule_id);
        }
    }

    fn spawn_lifecycle_watcher(
        &self,
        rule_id: String,
        entry: Arc<ResolvedForwardEntry>,
        mut events: crate::PortForwardEventReceiver,
    ) {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(PortForwardEvent::Active { .. }) => {}
                    Ok(PortForwardEvent::ConnectionError { message }) => {
                        entry.state.lock().await.error = Some(message);
                    }
                    Ok(PortForwardEvent::Stopped)
                    | Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            let _ = manager.forwards.stop(&rule_id).await;
            if let Some(connection) = entry.connection.lock().await.take() {
                let _ = connection.disconnect().await;
            }
            manager.remove_if_current(&rule_id, &entry).await;
        });
    }
}

fn cancelled_error() -> PortForwardError {
    PortForwardError::Transport(TransportError::new(
        TransportErrorCode::Cancelled,
        "SSH connection cancelled",
    ))
}
