use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use ruma::{OwnedRoomId, RoomId};
use tokio::sync::watch;

pub(crate) const MAX_OUTBOUND_SESSION_READINESS_ENTRIES: usize = 128;

/// Closed lifecycle state for the current encryption-sync generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionSyncReadinessState {
    /// No enabled encryption-sync generation has started.
    NotStarted,
    /// The generation is waiting for its first committed response.
    Pending,
    /// The generation committed at least one response.
    Received,
    /// The generation ended with an error.
    Failed,
    /// The generation ended or was dropped without an error.
    Cancelled,
}

/// Privacy-safe snapshot of encryption-sync readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionSyncReadinessSnapshot {
    /// Monotonic process-local generation, or zero before the first generation.
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
    enabled: bool,
    snapshot: Mutex<EncryptionSyncReadinessSnapshot>,
    sender: watch::Sender<EncryptionSyncReadinessSnapshot>,
}

/// Client-owned generation state shared with the encryption-sync service.
#[derive(Clone, Debug)]
pub(crate) struct EncryptionSyncReadiness {
    inner: Arc<EncryptionSyncReadinessInner>,
}

impl EncryptionSyncReadiness {
    pub(crate) fn new(enabled: bool) -> Self {
        let snapshot = EncryptionSyncReadinessSnapshot::default();
        Self {
            inner: Arc::new(EncryptionSyncReadinessInner {
                enabled,
                snapshot: Mutex::new(snapshot),
                sender: watch::Sender::new(snapshot),
            }),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.inner.enabled
    }

    pub(crate) fn begin(&self) -> Option<EncryptionSyncGenerationGuard> {
        if !self.inner.enabled {
            return None;
        }
        let snapshot = {
            let mut current = self.inner.snapshot.lock().expect("readiness mutex not poisoned");
            let generation = current.generation.saturating_add(1);
            *current = EncryptionSyncReadinessSnapshot {
                generation,
                state: EncryptionSyncReadinessState::Pending,
            };
            *current
        };
        self.inner.sender.send_replace(snapshot);
        Some(EncryptionSyncGenerationGuard {
            readiness: self.clone(),
            generation: snapshot.generation,
            terminal: false,
        })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundSessionReadinessState {
    Unfenced,
    Fencing,
    Ready,
}

pub(crate) fn outbound_session_requires_fence(
    session_changed: bool,
    state: Option<OutboundSessionReadinessState>,
    message_index: Option<u32>,
) -> bool {
    message_index == Some(0)
        && (session_changed || state != Some(OutboundSessionReadinessState::Ready))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OutboundSessionReadinessKey {
    room_id: OwnedRoomId,
    session_id: String,
}

#[derive(Debug, Default)]
struct OutboundSessionReadinessRegistryInner {
    entries: BTreeMap<OutboundSessionReadinessKey, OutboundSessionReadinessState>,
    order: VecDeque<OutboundSessionReadinessKey>,
    evictions: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct OutboundSessionReadinessRegistry {
    enabled: bool,
    inner: Arc<Mutex<OutboundSessionReadinessRegistryInner>>,
}

impl OutboundSessionReadinessRegistry {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled, inner: Arc::new(Mutex::new(Default::default())) }
    }

    fn key(room_id: &RoomId, session_id: &str) -> OutboundSessionReadinessKey {
        OutboundSessionReadinessKey {
            room_id: room_id.to_owned(),
            session_id: session_id.to_owned(),
        }
    }

    fn set(&self, key: OutboundSessionReadinessKey, state: OutboundSessionReadinessState) {
        let mut inner = self.inner.lock().expect("outbound readiness mutex not poisoned");
        if inner.entries.contains_key(&key) {
            inner.order.retain(|entry| entry != &key);
        } else if inner.entries.len() == MAX_OUTBOUND_SESSION_READINESS_ENTRIES {
            if let Some(evicted) = inner.order.pop_front() {
                inner.entries.remove(&evicted);
                inner.evictions = inner.evictions.saturating_add(1);
            }
        }
        inner.entries.insert(key.clone(), state);
        inner.order.push_back(key);
    }

    pub(crate) fn state(
        &self,
        room_id: &RoomId,
        session_id: &str,
    ) -> Option<OutboundSessionReadinessState> {
        if !self.enabled {
            return None;
        }
        self.inner
            .lock()
            .expect("outbound readiness mutex not poisoned")
            .entries
            .get(&Self::key(room_id, session_id))
            .copied()
    }

    pub(crate) fn begin(
        &self,
        room_id: &RoomId,
        session_id: &str,
    ) -> Option<OutboundSessionReadinessAttempt> {
        if !self.enabled {
            return None;
        }
        let key = Self::key(room_id, session_id);
        self.set(key.clone(), OutboundSessionReadinessState::Fencing);
        Some(OutboundSessionReadinessAttempt { registry: self.clone(), key, ready: false })
    }

    pub(crate) fn evictions(&self) -> u64 {
        self.inner.lock().expect("outbound readiness mutex not poisoned").evictions
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("outbound readiness mutex not poisoned").entries.len()
    }
}

#[derive(Debug)]
pub(crate) struct OutboundSessionReadinessAttempt {
    registry: OutboundSessionReadinessRegistry,
    key: OutboundSessionReadinessKey,
    ready: bool,
}

impl OutboundSessionReadinessAttempt {
    pub(crate) fn mark_ready(&mut self) {
        self.registry.set(self.key.clone(), OutboundSessionReadinessState::Ready);
        self.ready = true;
    }
}

impl Drop for OutboundSessionReadinessAttempt {
    fn drop(&mut self) {
        if !self.ready {
            self.registry.set(self.key.clone(), OutboundSessionReadinessState::Unfenced);
        }
    }
}

/// Exact-generation guard owned by one encryption-sync stream.
#[derive(Debug)]
pub struct EncryptionSyncGenerationGuard {
    readiness: EncryptionSyncReadiness,
    generation: u64,
    terminal: bool,
}

impl EncryptionSyncGenerationGuard {
    /// Return the process-local generation owned by this guard.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Mark a committed encryption response for this exact generation.
    pub fn mark_received(&mut self) {
        self.readiness.transition(self.generation, EncryptionSyncReadinessState::Received);
    }

    /// Mark this exact generation as failed.
    pub fn mark_failed(&mut self) {
        self.readiness.transition(self.generation, EncryptionSyncReadinessState::Failed);
        self.terminal = true;
    }

    /// Mark this exact generation as cancelled or normally ended.
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

#[cfg(test)]
mod tests {
    use super::{EncryptionSyncReadiness, EncryptionSyncReadinessState};

    #[test]
    fn replacement_generation_rejects_stale_completion_and_drop() {
        let readiness = EncryptionSyncReadiness::new(true);
        let mut first = readiness.begin().expect("enabled generation");
        let first_generation = first.generation();
        let mut second = readiness.begin().expect("replacement generation");
        let second_generation = second.generation();

        first.mark_received();
        first.mark_failed();
        drop(first);
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::Pending);
        assert_eq!(readiness.snapshot().generation, second_generation);

        second.mark_received();
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::Received);
        assert_ne!(first_generation, second_generation);
    }

    #[test]
    fn live_generation_reports_failure_and_drop_cancellation() {
        let readiness = EncryptionSyncReadiness::new(true);
        let mut failed = readiness.begin().expect("enabled generation");
        failed.mark_failed();
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::Failed);
        drop(failed);
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::Failed);

        let cancelled = readiness.begin().expect("replacement generation");
        drop(cancelled);
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::Cancelled);
    }

    #[test]
    fn disabled_readiness_creates_no_generation() {
        let readiness = EncryptionSyncReadiness::new(false);
        assert!(readiness.begin().is_none());
        assert_eq!(readiness.snapshot().state, EncryptionSyncReadinessState::NotStarted);
    }

    #[test]
    fn unregistered_restored_index_zero_session_requires_a_fence() {
        use super::{OutboundSessionReadinessState as State, outbound_session_requires_fence};

        assert!(outbound_session_requires_fence(false, None, Some(0)));
        assert!(outbound_session_requires_fence(false, Some(State::Unfenced), Some(0)));
        assert!(!outbound_session_requires_fence(false, Some(State::Ready), Some(0)));
        assert!(!outbound_session_requires_fence(false, None, Some(1)));
    }

    #[test]
    fn failed_fence_attempt_stays_unfenced_for_retry() {
        let registry = super::OutboundSessionReadinessRegistry::new(true);
        let room_id = ruma::room_id!("!room:example.org");
        {
            let _attempt = registry.begin(room_id, "session").expect("enabled fence");
            assert_eq!(
                registry.state(room_id, "session"),
                Some(super::OutboundSessionReadinessState::Fencing)
            );
        }
        assert_eq!(
            registry.state(room_id, "session"),
            Some(super::OutboundSessionReadinessState::Unfenced)
        );
    }

    #[test]
    fn completed_fence_is_ready_and_registry_is_bounded() {
        let registry = super::OutboundSessionReadinessRegistry::new(true);
        for index in 0..=super::MAX_OUTBOUND_SESSION_READINESS_ENTRIES {
            let room_id = ruma::OwnedRoomId::try_from(format!("!room{index}:example.org"))
                .expect("valid room id");
            let mut attempt = registry.begin(&room_id, "session").expect("enabled fence");
            attempt.mark_ready();
        }
        assert_eq!(registry.len(), super::MAX_OUTBOUND_SESSION_READINESS_ENTRIES);
        assert_eq!(registry.evictions(), 1);
    }
}
