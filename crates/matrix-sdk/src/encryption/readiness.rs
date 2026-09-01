use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// Closed lifecycle state for the current application-owned encryption sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionSyncReadinessState {
    /// No generation has started.
    NotStarted,
    /// Waiting for the first committed response.
    Pending,
    /// At least one response committed.
    Received,
    /// The generation ended with an error.
    Failed,
    /// The generation ended or was dropped.
    Cancelled,
}

/// Privacy-safe encryption-sync lifecycle snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionSyncReadinessSnapshot {
    /// Monotonic process-local generation.
    pub generation: u64,
    /// Closed lifecycle state.
    pub state: EncryptionSyncReadinessState,
}

impl Default for EncryptionSyncReadinessSnapshot {
    fn default() -> Self {
        Self { generation: 0, state: EncryptionSyncReadinessState::NotStarted }
    }
}

#[derive(Debug)]
struct EncryptionSyncReadinessInner {
    snapshot: Mutex<EncryptionSyncReadinessSnapshot>,
    sender: watch::Sender<EncryptionSyncReadinessSnapshot>,
}

/// Client-owned observation state for the application-owned encryption sync.
#[derive(Clone, Debug)]
pub(crate) struct EncryptionSyncReadiness {
    inner: Arc<EncryptionSyncReadinessInner>,
}

impl EncryptionSyncReadiness {
    pub(crate) fn new() -> Self {
        let snapshot = EncryptionSyncReadinessSnapshot::default();
        Self {
            inner: Arc::new(EncryptionSyncReadinessInner {
                snapshot: Mutex::new(snapshot),
                sender: watch::Sender::new(snapshot),
            }),
        }
    }

    pub(crate) fn begin(&self) -> EncryptionSyncGenerationGuard {
        let snapshot = {
            let mut current = self.inner.snapshot.lock().expect("readiness mutex not poisoned");
            *current = EncryptionSyncReadinessSnapshot {
                generation: current.generation.saturating_add(1),
                state: EncryptionSyncReadinessState::Pending,
            };
            *current
        };
        self.inner.sender.send_replace(snapshot);
        EncryptionSyncGenerationGuard {
            readiness: self.clone(),
            generation: snapshot.generation,
            terminal: false,
        }
    }

    pub(crate) fn snapshot(&self) -> EncryptionSyncReadinessSnapshot {
        *self.inner.snapshot.lock().expect("readiness mutex not poisoned")
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<EncryptionSyncReadinessSnapshot> {
        self.inner.sender.subscribe()
    }

    fn transition(&self, generation: u64, state: EncryptionSyncReadinessState) {
        let snapshot = {
            let mut current = self.inner.snapshot.lock().expect("readiness mutex not poisoned");
            if current.generation != generation {
                return;
            }
            current.state = state;
            *current
        };
        self.inner.sender.send_replace(snapshot);
    }
}

/// Exact-generation observer guard owned by one encryption-sync stream.
#[derive(Debug)]
pub struct EncryptionSyncGenerationGuard {
    readiness: EncryptionSyncReadiness,
    generation: u64,
    terminal: bool,
}

impl EncryptionSyncGenerationGuard {
    /// Return the process-local generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Mark a committed response.
    pub fn mark_received(&mut self) {
        self.readiness.transition(self.generation, EncryptionSyncReadinessState::Received);
    }

    /// Mark failure.
    pub fn mark_failed(&mut self) {
        self.readiness.transition(self.generation, EncryptionSyncReadinessState::Failed);
        self.terminal = true;
    }

    /// Mark normal end or cancellation.
    pub fn mark_cancelled(&mut self) {
        self.readiness.transition(self.generation, EncryptionSyncReadinessState::Cancelled);
        self.terminal = true;
    }
}

impl Drop for EncryptionSyncGenerationGuard {
    fn drop(&mut self) {
        if !self.terminal {
            self.readiness.transition(self.generation, EncryptionSyncReadinessState::Cancelled);
        }
    }
}
