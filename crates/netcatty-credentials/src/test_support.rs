//! Opt-in, secret-safe support for testing cross-store credential transactions.
//!
//! This module exists only when the `test-support` Cargo feature is enabled
//! (and while this crate's own unit tests are being compiled). Production
//! builds use the operating-system keyring backend and do not include this
//! in-memory backend.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use crate::os_store::{BlockingCredentialBackend, SecretBlob};
use crate::{CredentialError, CredentialErrorCode, OsCredentialStore, OsMasterKeyStore};

/// A keyring operation that can be observed or fault-injected by tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialOperation {
    Resolve,
    Upsert,
    Delete,
}

impl CredentialOperation {
    const fn index(self) -> usize {
        match self {
            Self::Resolve => 0,
            Self::Upsert => 1,
            Self::Delete => 2,
        }
    }
}

/// Selects whether an injected error happens before or after the in-memory
/// backend applies the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureTiming {
    BeforeSideEffect,
    AfterSideEffect,
}

/// A deliberately minimal operation record.
///
/// It contains neither an account/reference nor credential bytes. Its `Debug`
/// representation is therefore safe to use in failed test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationLogEntry {
    operation: CredentialOperation,
    operation_call: usize,
}

impl OperationLogEntry {
    #[must_use]
    pub const fn operation(self) -> CredentialOperation {
        self.operation
    }

    /// Returns the per-operation call number since the controller was created.
    #[must_use]
    pub const fn operation_call(self) -> usize {
        self.operation_call
    }
}

/// A snapshot of the safe in-memory-backend operation log.
///
/// This type intentionally has no Serde implementation. Its custom `Debug`
/// implementation can only render operation kinds and call numbers.
#[derive(Clone, PartialEq, Eq)]
pub struct OperationLog {
    entries: Vec<OperationLogEntry>,
}

impl OperationLog {
    #[must_use]
    pub fn entries(&self) -> &[OperationLogEntry] {
        &self.entries
    }

    #[must_use]
    pub fn count(&self, operation: CredentialOperation) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.operation == operation)
            .count()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for OperationLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationLog")
            .field("entries", &self.entries)
            .finish()
    }
}

/// Controls and observes the opt-in in-memory credential backend.
///
/// Clones control the same backend. Its `Debug` output is intentionally opaque,
/// and the type has no Serde implementation, because the backend owns account
/// strings and zeroizing credential envelopes internally.
#[derive(Clone)]
pub struct InMemoryCredentialController {
    backend: Arc<InMemoryCredentialBackend>,
}

impl InMemoryCredentialController {
    /// Replaces pending failures for `operation` with one failure on its Nth
    /// future call. Rules for other operation kinds are retained, so an upsert
    /// failure and a compensation-delete failure can be scheduled together.
    /// `nth_call` is relative to this method call and starts at 1.
    ///
    /// # Panics
    ///
    /// Panics when `nth_call` is zero.
    pub fn set_failure(
        &self,
        operation: CredentialOperation,
        nth_call: usize,
        timing: FailureTiming,
        error: CredentialErrorCode,
    ) {
        let mut state = self.backend.state();
        state
            .failures
            .retain(|failure| failure.operation != operation);
        state.add_failure(operation, nth_call, timing, error);
    }

    /// Adds another independently scheduled failure. This is useful when a
    /// test needs both a primary operation and its compensation to fail.
    ///
    /// # Panics
    ///
    /// Panics when `nth_call` is zero.
    pub fn add_failure(
        &self,
        operation: CredentialOperation,
        nth_call: usize,
        timing: FailureTiming,
        error: CredentialErrorCode,
    ) {
        self.backend
            .state()
            .add_failure(operation, nth_call, timing, error);
    }

    /// Removes every pending injected failure without changing stored values
    /// or operation counters.
    pub fn clear_failures(&self) {
        self.backend.state().failures.clear();
    }

    /// Removes pending injected failures for one operation kind.
    pub fn clear_failures_for(&self, operation: CredentialOperation) {
        self.backend
            .state()
            .failures
            .retain(|failure| failure.operation != operation);
    }

    /// Returns a snapshot containing only operation kinds and per-kind counts.
    #[must_use]
    pub fn operation_log(&self) -> OperationLog {
        OperationLog {
            entries: self.backend.state().log.clone(),
        }
    }

    /// Clears recorded log entries. Lifetime operation counters and scheduled
    /// failures are deliberately retained.
    pub fn clear_operation_log(&self) {
        self.backend.state().log.clear();
    }

    /// Returns the lifetime number of calls of one operation kind.
    #[must_use]
    pub fn operation_count(&self, operation: CredentialOperation) -> usize {
        self.backend.state().operation_counts[operation.index()]
    }

    /// Returns the highest number of backend calls observed at the same time.
    /// `OsCredentialStore` should keep this at one even under concurrent use.
    #[must_use]
    pub fn max_concurrent_operations(&self) -> usize {
        self.backend.max_active.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn replace_raw_value(&self, service: &str, account: String, value: Vec<u8>) {
        self.backend
            .state()
            .values
            .insert((service.to_owned(), account), SecretBlob::new(value));
    }

    #[cfg(test)]
    pub(crate) fn raw_value(&self, service: &str, account: &str) -> Option<SecretBlob> {
        self.backend
            .state()
            .values
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
    }
}

impl fmt::Debug for InMemoryCredentialController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryCredentialController")
            .finish_non_exhaustive()
    }
}

/// Creates an `OsCredentialStore` backed by an isolated in-memory keyring and
/// a controller for safe observation and deterministic fault injection.
#[must_use]
pub fn in_memory_credential_store() -> (OsCredentialStore, InMemoryCredentialController) {
    let backend = Arc::new(InMemoryCredentialBackend::default());
    let store = OsCredentialStore::with_backend(backend.clone());
    let controller = InMemoryCredentialController { backend };
    (store, controller)
}

/// Creates an `OsMasterKeyStore` backed by the same fault-injectable in-memory
/// keyring implementation used by [`in_memory_credential_store`].
#[must_use]
pub fn in_memory_master_key_store() -> (OsMasterKeyStore, InMemoryCredentialController) {
    let backend = Arc::new(InMemoryCredentialBackend::default());
    let store = OsMasterKeyStore::with_backend(backend.clone());
    let controller = InMemoryCredentialController { backend };
    (store, controller)
}

#[derive(Clone, Copy)]
struct FailurePlan {
    operation: CredentialOperation,
    target_call: usize,
    timing: FailureTiming,
    error: CredentialErrorCode,
}

#[derive(Default)]
struct BackendState {
    values: HashMap<(String, String), SecretBlob>,
    operation_counts: [usize; 3],
    log: Vec<OperationLogEntry>,
    failures: Vec<FailurePlan>,
}

impl BackendState {
    fn add_failure(
        &mut self,
        operation: CredentialOperation,
        nth_call: usize,
        timing: FailureTiming,
        error: CredentialErrorCode,
    ) {
        assert!(nth_call > 0, "nth_call must start at one");
        let target_call = self.operation_counts[operation.index()]
            .checked_add(nth_call)
            .expect("operation call number overflow");
        self.failures.push(FailurePlan {
            operation,
            target_call,
            timing,
            error,
        });
    }

    fn begin_operation(&mut self, operation: CredentialOperation) -> Option<FailurePlan> {
        let count = &mut self.operation_counts[operation.index()];
        *count = count
            .checked_add(1)
            .expect("operation call number overflow");
        let operation_call = *count;
        self.log.push(OperationLogEntry {
            operation,
            operation_call,
        });
        self.failures
            .iter()
            .position(|failure| {
                failure.operation == operation && failure.target_call == operation_call
            })
            .map(|index| self.failures.remove(index))
    }
}

#[derive(Default)]
struct InMemoryCredentialBackend {
    state: StdMutex<BackendState>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl InMemoryCredentialBackend {
    fn state(&self) -> MutexGuard<'_, BackendState> {
        self.state.lock().expect("in-memory credential backend")
    }

    fn enter(&self) -> ActiveCall<'_> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        // Make overlapping backend calls reliably observable if the outer
        // OsCredentialStore serialization is ever removed.
        std::thread::sleep(Duration::from_millis(2));
        ActiveCall(self)
    }

    fn injected_before(
        failure: Option<FailurePlan>,
    ) -> Result<Option<FailurePlan>, CredentialError> {
        match failure {
            Some(failure) if failure.timing == FailureTiming::BeforeSideEffect => {
                Err(CredentialError::new(failure.error))
            }
            other => Ok(other),
        }
    }

    fn injected_after<T>(
        result: Result<T, CredentialError>,
        failure: Option<FailurePlan>,
    ) -> Result<T, CredentialError> {
        match failure {
            Some(failure) if failure.timing == FailureTiming::AfterSideEffect => {
                Err(CredentialError::new(failure.error))
            }
            _ => result,
        }
    }
}

struct ActiveCall<'a>(&'a InMemoryCredentialBackend);

impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BlockingCredentialBackend for InMemoryCredentialBackend {
    fn upsert(
        &self,
        service: &'static str,
        account: String,
        secret: SecretBlob,
    ) -> Result<(), CredentialError> {
        let _active = self.enter();
        let mut state = self.state();
        let failure = Self::injected_before(state.begin_operation(CredentialOperation::Upsert))?;
        state.values.insert((service.to_owned(), account), secret);
        Self::injected_after(Ok(()), failure)
    }

    fn resolve(
        &self,
        service: &'static str,
        account: String,
    ) -> Result<SecretBlob, CredentialError> {
        let _active = self.enter();
        let mut state = self.state();
        let failure = Self::injected_before(state.begin_operation(CredentialOperation::Resolve))?;
        let result = state
            .values
            .get(&(service.to_owned(), account))
            .cloned()
            .ok_or_else(|| CredentialError::new(CredentialErrorCode::NotFound));
        Self::injected_after(result, failure)
    }

    fn delete(&self, service: &'static str, account: String) -> Result<(), CredentialError> {
        let _active = self.enter();
        let mut state = self.state();
        let failure = Self::injected_before(state.begin_operation(CredentialOperation::Delete))?;
        let result = state
            .values
            .remove(&(service.to_owned(), account))
            .map(|_| ())
            .ok_or_else(|| CredentialError::new(CredentialErrorCode::NotFound));
        Self::injected_after(result, failure)
    }
}
