// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[cfg(test)]
use std::sync::{
    Mutex as StdMutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use eyeball::{ObservableWriteGuard, SharedObservable, Subscriber};
use eyeball_im::{ObservableVector, VectorDiff, VectorSubscriberBatchedStream};
use futures_util::future::join_all;
use imbl::Vector;
use matrix_sdk::{
    Result, Room, check_validity_of_replacement_events,
    deserialized_responses::TimelineEvent,
    event_cache::{RoomEventCache, RoomEventCacheSubscriber, RoomEventCacheUpdate},
    locks::Mutex,
    paginators::PaginationToken,
    room::ListThreadsOptions,
    task_monitor::BackgroundTaskHandle,
};
use matrix_sdk_base::event_cache::Event;
use matrix_sdk_common::serde_helpers::{extract_relation, extract_thread_root, extract_timestamp};
use ruma::{
    MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedUserId,
    events::{MessageLikeEventType, relation::RelationType},
};
use tokio::sync::Mutex as AsyncMutex;
#[cfg(test)]
use tokio::sync::watch;
use tracing::{error, trace, warn};

use crate::timeline::{Profile, TimelineDetails, TimelineItemContent, traits::RoomDataProvider};

/// Each `ThreadListItem` represents one thread root event in the room. The
/// fields are pre-resolved from the raw homeserver response: the sender's
/// profile is fetched eagerly and the event content is parsed into a
/// [`TimelineItemContent`] so that consumers can render the item without any
/// additional work.
///
/// `ThreadListItem`s are accumulated inside
/// [`super::thread_list_service::ThreadListService`] as pages are fetched via
/// [`super::thread_list_service::ThreadListService::paginate`].
#[derive(Clone, Debug)]
pub struct ThreadListItem {
    /// The thread root event.
    pub root_event: ThreadListItemEvent,

    /// The latest event in the thread (i.e. the most recent reply), if
    /// available.
    ///
    /// This is initially populated from the server's bundled thread summary
    /// and is updated in real time as new events arrive via sync.
    pub latest_event: Option<ThreadListItemEvent>,

    /// The number of replies in this thread (excluding the root event).
    ///
    /// This is initially populated from the server's bundled thread summary
    /// and is updated in real time as new events arrive via sync.
    pub num_replies: u32,
}

/// Information about an event in a thread (either the root or the latest
/// reply).
#[derive(Clone, Debug)]
pub struct ThreadListItemEvent {
    /// The event ID.
    pub event_id: OwnedEventId,

    /// The timestamp of the event.
    pub timestamp: MilliSecondsSinceUnixEpoch,

    /// The sender of the event.
    pub sender: OwnedUserId,

    /// Whether the event was sent by the current user.
    pub is_own: bool,

    /// The sender's profile (display name and avatar URL).
    pub sender_profile: TimelineDetails<Profile>,

    /// The parsed content of the event, if available.
    ///
    /// `None` when the event could not be deserialized into a known
    /// [`TimelineItemContent`] variant (e.g. an unsupported or redacted event
    /// type).
    pub content: Option<TimelineItemContent>,
}

/// The pagination state of a [`ThreadListService`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreadListPaginationState {
    /// The list is idle (not currently loading).
    Idle {
        /// Whether the end of the thread list has been reached (no more pages
        /// to load).
        end_reached: bool,
    },
    /// The list is currently loading the next page.
    Loading,
}

/// An error that occurred while using a [`ThreadListService`].
#[derive(Debug, thiserror::Error)]
pub enum ThreadListServiceError {
    /// An error from the underlying Matrix SDK.
    #[error(transparent)]
    Sdk(#[from] matrix_sdk::Error),

    /// An error from the room event cache relation index.
    #[error(transparent)]
    EventCache(#[from] matrix_sdk::event_cache::EventCacheError),
}

/// The local relation aggregate for one thread root.
///
/// The latest event keeps the original reply identity while carrying the
/// latest valid effective edit content.
#[derive(Clone)]
pub struct ThreadRelationAggregate {
    /// The latest valid original reply, if one is available.
    pub latest_event: Option<ThreadListItemEvent>,

    /// The number of valid original thread replies.
    pub num_replies: u32,
}

#[derive(Clone)]
struct BundledThreadProof {
    latest_event: Option<ThreadListItemEvent>,
    num_replies: u32,
}

#[derive(Clone)]
struct ThreadRelationProof {
    bundled: Option<BundledThreadProof>,
    complete: bool,
}

#[cfg(test)]
struct ResolverTestGate {
    root_event_id: OwnedEventId,
    entered: watch::Sender<bool>,
    release: watch::Receiver<bool>,
    claimed: AtomicBool,
}

#[cfg(test)]
static RESOLVER_TEST_GATE: OnceLock<StdMutex<Option<Arc<ResolverTestGate>>>> = OnceLock::new();

#[cfg(test)]
fn resolver_test_gate_slot() -> &'static StdMutex<Option<Arc<ResolverTestGate>>> {
    RESOLVER_TEST_GATE.get_or_init(|| StdMutex::new(None))
}

#[cfg(test)]
fn claim_resolver_test_gate(root_event_id: &ruma::EventId) -> Option<Arc<ResolverTestGate>> {
    let slot = resolver_test_gate_slot();
    let guard = slot.lock().expect("resolver test gate lock poisoned");
    let gate = guard.as_ref()?;
    if gate.root_event_id.as_str() != root_event_id.as_str()
        || gate.claimed.swap(true, Ordering::SeqCst)
    {
        return None;
    }
    Some(Arc::clone(gate))
}

/// A paginated list of threads for a given room.
///
/// `ThreadListService` provides an observable, paginated list of
/// [`ThreadListItem`]s. It exposes methods to paginate forward through the
/// thread list as well as subscribe to state changes.
///
/// When created, the service automatically starts a background task that
/// listens to room event cache updates (from `/sync` and other sources).
/// Whenever a new event belonging to a known thread arrives, the service
/// updates that thread's `latest_event` and `num_replies` fields in real time,
/// emitting observable diffs to all subscribers.
///
/// # Example
///
/// ```no_run
/// use matrix_sdk::Room;
/// use matrix_sdk_ui::timeline::thread_list_service::{
///     ThreadListPaginationState, ThreadListService,
/// };
///
/// # async {
/// # let room: Room = todo!();
/// let service = ThreadListService::new(room);
///
/// assert_eq!(
///     service.pagination_state(),
///     ThreadListPaginationState::Idle { end_reached: false }
/// );
///
/// service.paginate().await.unwrap();
///
/// let items = service.items();
/// # anyhow::Ok(()) };
/// ```
pub struct ThreadListService {
    /// The room whose threads are being listed.
    room: Room,

    /// Local proof state for bundled versus relation-derived summaries.
    proofs: Arc<Mutex<HashMap<OwnedEventId, ThreadRelationProof>>>,

    /// The pagination token used to fetch subsequent pages.
    token: AsyncMutex<PaginationToken>,

    /// The current pagination state.
    pagination_state: SharedObservable<ThreadListPaginationState>,

    /// The current list of thread items.
    items: Arc<Mutex<ObservableVector<ThreadListItem>>>,

    /// Handle to the background task listening for event cache updates.
    /// Dropping this aborts the task.
    _event_cache_task: BackgroundTaskHandle,
}

impl ThreadListService {
    /// Creates a new [`ThreadListService`] for the given room.
    ///
    /// This immediately spawns a background task that listens to the room's
    /// event cache for live updates. The task self-bootstraps by performing
    /// the async event cache subscription internally.
    pub fn new(room: Room) -> Self {
        let items: Arc<Mutex<ObservableVector<ThreadListItem>>> =
            Arc::new(Mutex::new(ObservableVector::new()));
        let proofs = Arc::new(Mutex::new(HashMap::new()));

        // Eagerly subscribe the event cache to sync responses (this is a cheap,
        // synchronous, idempotent call).
        if let Err(e) = room.client().event_cache().subscribe() {
            warn!("ThreadListService: failed to subscribe event cache to sync: {e}");
        }

        let event_cache_task = room
            .client()
            .task_monitor()
            .spawn_infinite_task("thread_list_service::event_cache_listener", {
                let room = room.clone();
                let items = items.clone();
                let proofs = proofs.clone();
                async move {
                    // Obtain the room event cache and a subscriber.
                    let (_event_cache_drop, mut subscriber) = match async {
                        let (room_event_cache, drop_handles) = room.event_cache().await?;
                        let (_, subscriber) = room_event_cache.subscribe().await?;
                        matrix_sdk::event_cache::Result::Ok((drop_handles, subscriber))
                    }
                    .await
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            error!(
                                "ThreadListService: failed to subscribe to room event cache, \
                                 live updates will not work: {e}"
                            );
                            return;
                        }
                    };

                    trace!("ThreadListService: event cache listener started");

                    Self::event_cache_listener_loop(&room, &mut subscriber, items, proofs).await;
                }
            })
            .abort_on_drop();

        Self {
            room,
            proofs,
            token: AsyncMutex::new(PaginationToken::None),
            pagination_state: SharedObservable::new(ThreadListPaginationState::Idle {
                end_reached: false,
            }),
            items,
            _event_cache_task: event_cache_task,
        }
    }

    /// Returns the current pagination state.
    pub fn pagination_state(&self) -> ThreadListPaginationState {
        self.pagination_state.get()
    }

    /// Subscribes to pagination state updates.
    ///
    /// The returned [`Subscriber`] will emit a new value every time the
    /// pagination state changes.
    pub fn subscribe_to_pagination_state_updates(&self) -> Subscriber<ThreadListPaginationState> {
        self.pagination_state.subscribe()
    }

    /// Returns the current list of thread items as a snapshot.
    pub fn items(&self) -> Vec<ThreadListItem> {
        self.items.lock().iter().cloned().collect()
    }

    /// Subscribes to updates of the thread item list.
    ///
    /// Returns a snapshot of the current items alongside a batched stream of
    /// [`eyeball_im::VectorDiff`]s that describe subsequent changes.
    pub fn subscribe_to_items_updates(
        &self,
    ) -> (Vector<ThreadListItem>, VectorSubscriberBatchedStream<ThreadListItem>) {
        self.items.lock().subscribe().into_values_and_batched_stream()
    }

    /// Fetches the next page of threads, appending the results to the item
    /// list.
    ///
    /// - If the list is already loading or the end has been reached, this
    ///   method returns immediately with `Ok(())`.
    /// - On a network/SDK error the pagination state is reset to `Idle {
    ///   end_reached: false }` and the error is propagated.
    pub async fn paginate(&self) -> Result<(), ThreadListServiceError> {
        // Guard: do nothing if we are already loading or have reached the end.
        {
            let mut pagination_state = self.pagination_state.write();

            match *pagination_state {
                ThreadListPaginationState::Idle { end_reached: true }
                | ThreadListPaginationState::Loading => return Ok(()),
                _ => {}
            }

            ObservableWriteGuard::set(&mut pagination_state, ThreadListPaginationState::Loading);
        }

        let mut pagination_token = self.token.lock().await;

        // Build the options for this page, using the current token if we have one.
        let from = match &*pagination_token {
            PaginationToken::HasMore(token) => Some(token.clone()),
            _ => None,
        };

        let opts = ListThreadsOptions { from, ..Default::default() };

        match self.load_thread_list(opts).await {
            Ok(thread_list) => {
                // Update the pagination token based on whether there are more pages.
                *pagination_token = match &thread_list.prev_batch_token {
                    Some(token) => PaginationToken::HasMore(token.clone()),
                    None => PaginationToken::HitEnd,
                };

                let end_reached = thread_list.prev_batch_token.is_none();

                // Keep bundled summaries until local relation evidence proves their count.
                {
                    let mut proofs = self.proofs.lock();
                    for item in &thread_list.items {
                        let bundled =
                            (item.num_replies > 0 || item.latest_event.is_some()).then(|| {
                                BundledThreadProof {
                                    latest_event: item.latest_event.clone(),
                                    num_replies: item.num_replies,
                                }
                            });
                        proofs.insert(
                            item.root_event.event_id.clone(),
                            ThreadRelationProof { complete: bundled.is_none(), bundled },
                        );
                    }
                }

                let roots = thread_list
                    .items
                    .iter()
                    .map(|item| item.root_event.event_id.clone())
                    .collect::<Vec<_>>();

                // Append new items to the observable vector.
                self.items.lock().append(thread_list.items.into());

                // Resolve any already-persisted relation evidence as part of the
                // initial proof, not only after a later cache update.
                for root_event_id in roots {
                    if let Ok(aggregate) =
                        resolve_thread_relation_aggregate(&self.room, &root_event_id).await
                    {
                        Self::apply_aggregate(&self.items, &self.proofs, root_event_id, aggregate);
                    }
                }

                self.pagination_state.set(ThreadListPaginationState::Idle { end_reached });

                Ok(())
            }
            Err(err) => {
                self.pagination_state.set(ThreadListPaginationState::Idle { end_reached: false });
                Err(ThreadListServiceError::Sdk(err))
            }
        }
    }

    /// Resets the service back to its initial state.
    ///
    /// Clears all loaded items, discards the current pagination token, and
    /// sets the pagination state to `Idle { end_reached: false }`.  The next
    /// call to [`Self::paginate`] will therefore start from the beginning of
    /// the thread list.
    pub async fn reset(&self) {
        let mut pagination_token = self.token.lock().await;
        *pagination_token = PaginationToken::None;

        self.items.lock().clear();
        self.proofs.lock().clear();

        self.pagination_state.set(ThreadListPaginationState::Idle { end_reached: false });
    }

    async fn load_thread_list(&self, opts: ListThreadsOptions) -> Result<ThreadList> {
        let thread_roots = self.room.list_threads(opts).await?;

        let list_items = join_all(
            thread_roots
                .chunk
                .into_iter()
                .map(|timeline_event| Self::build_thread_list_item(&self.room, timeline_event))
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .flatten()
        .collect();

        Ok(ThreadList { items: list_items, prev_batch_token: thread_roots.prev_batch_token })
    }

    async fn build_thread_list_item(
        room: &Room,
        timeline_event: TimelineEvent,
    ) -> Option<ThreadListItem> {
        // Extract thread summary info before consuming the event.
        let thread_summary = timeline_event.thread_summary.summary().cloned();
        let bundled_latest_thread_event = timeline_event.bundled_latest_thread_event.clone();

        // Build the root event using the same logic as latest events.
        let root_event = Self::build_event(room, timeline_event).await?;

        // Build the latest event from the bundled thread summary, if available.
        let num_replies = thread_summary.as_ref().map(|s| s.num_replies).unwrap_or(0);

        let latest_event = if let Some(ev) = bundled_latest_thread_event.map(|b| *b) {
            Self::build_event(room, ev).await
        } else {
            None
        };

        Some(ThreadListItem { root_event, latest_event, num_replies })
    }

    /// Build a [`ThreadListItemEvent`] from a [`TimelineEvent`].
    async fn build_event(
        room: &Room,
        timeline_event: TimelineEvent,
    ) -> Option<ThreadListItemEvent> {
        let event_id = timeline_event.event_id()?;
        let timestamp = timeline_event.timestamp()?;
        let sender = timeline_event.sender()?;
        let is_own = room.own_user_id() == sender;
        let sender_profile =
            TimelineDetails::from_initial_value(Profile::load(room, &sender).await);
        let content = TimelineItemContent::from_event(room, timeline_event).await;
        Some(ThreadListItemEvent { event_id, timestamp, sender, is_own, sender_profile, content })
    }

    /// Resolve the local, relation-backed aggregate for one thread root.
    ///
    /// The event cache relation index is the source of truth. Bundled thread
    /// summaries are deliberately not consulted here because they are not
    /// persisted with cached events.
    async fn resolve_thread_relation_aggregate(
        room: &Room,
        root_event_id: &ruma::EventId,
    ) -> Result<ThreadRelationAggregate, ThreadListServiceError> {
        #[cfg(test)]
        if let Some(gate) = claim_resolver_test_gate(root_event_id) {
            let _ = gate.entered.send(true);
            let mut release = gate.release.clone();
            while !*release.borrow() {
                if release.changed().await.is_err() {
                    break;
                }
            }
        }

        let (room_event_cache, _drop_handles) = room.event_cache().await?;
        let now = MilliSecondsSinceUnixEpoch::now();
        let related_events = room_event_cache
            .find_event_relations(root_event_id, Some(vec![RelationType::Thread]))
            .await?;

        let mut originals = HashMap::new();
        for event in related_events {
            let Some(event_id) = event.event_id() else { continue };
            if Self::is_redacted_raw_event(event.raw())
                || extract_relation(event.raw())
                    != Some((RelationType::Thread, root_event_id.to_owned()))
            {
                continue;
            }
            originals.entry(event_id).or_insert(event);
        }

        let num_replies = u32::try_from(originals.len()).unwrap_or(u32::MAX);
        let mut latest_event = None;
        let mut latest_key = None;

        for original in originals.into_values() {
            let Some(mut projected) = ThreadListService::build_event(room, original.clone()).await
            else {
                continue;
            };

            if let Some(replacement) =
                Self::latest_valid_replacement(&room_event_cache, &original, now).await?
                && let Some(content) = TimelineItemContent::from_event(room, replacement).await
                && !content.is_unable_to_decrypt()
            {
                // The original event remains the identity/profile/timestamp anchor;
                // only its effective content comes from the validated replacement.
                projected.content = Some(content);
            }

            let key = (extract_timestamp(original.raw(), now), projected.event_id.clone());
            if latest_key.as_ref().is_none_or(|current| key > *current) {
                latest_key = Some(key);
                latest_event = Some(projected);
            }
        }

        Ok(ThreadRelationAggregate { latest_event, num_replies })
    }

    async fn latest_valid_replacement(
        room_event_cache: &RoomEventCache,
        original: &Event,
        max_timestamp: MilliSecondsSinceUnixEpoch,
    ) -> Result<Option<TimelineEvent>, ThreadListServiceError> {
        let Some(original_id) = original.event_id() else { return Ok(None) };
        let related_edits = room_event_cache
            .find_event_relations(&original_id, Some(vec![RelationType::Replacement]))
            .await?;
        let mut seen_ids = HashSet::new();
        let mut latest = None;

        for edit in related_edits {
            let Some(edit_id) = edit.event_id() else { continue };
            if !seen_ids.insert(edit_id.clone())
                || edit_id == original_id
                || Self::is_redacted_raw_event(edit.raw())
                || extract_relation(edit.raw())
                    != Some((RelationType::Replacement, original_id.clone()))
                || check_validity_of_replacement_events(
                    original.raw(),
                    original.encryption_info().map(|info| &**info),
                    edit.raw(),
                    edit.encryption_info().map(|info| &**info),
                )
                .is_err()
            {
                continue;
            }

            let key = (extract_timestamp(edit.raw(), max_timestamp), edit_id);
            if latest.as_ref().is_none_or(|(current, _)| key > *current) {
                latest = Some((key, edit));
            }
        }

        Ok(latest.map(|(_, event)| event))
    }

    fn is_redacted_raw_event(raw: &ruma::serde::Raw<ruma::events::AnySyncTimelineEvent>) -> bool {
        #[derive(serde::Deserialize)]
        struct Unsigned {
            redacted_because: Option<serde_json::Value>,
        }

        raw.get_field::<Unsigned>("unsigned")
            .ok()
            .flatten()
            .is_some_and(|unsigned| unsigned.redacted_because.is_some())
    }

    /// The main loop of the event-cache listener task.
    ///
    /// Each update is reconciled after the cache has applied the complete
    /// batch. Redactions and subscriber lag invalidate root discovery, so they
    /// reconcile every tracked root.
    async fn event_cache_listener_loop(
        room: &Room,
        subscriber: &mut RoomEventCacheSubscriber,
        items: Arc<Mutex<ObservableVector<ThreadListItem>>>,
        proofs: Arc<Mutex<HashMap<OwnedEventId, ThreadRelationProof>>>,
    ) {
        use tokio::sync::broadcast::error::RecvError;

        loop {
            let roots = match subscriber.recv().await {
                Ok(RoomEventCacheUpdate::UpdateTimelineEvents(timeline_diffs)) => {
                    let events = Self::collect_events_from_diffs(timeline_diffs.diffs);
                    if events.iter().any(Self::requires_full_reconciliation) {
                        Self::tracked_roots(&items)
                    } else {
                        Self::collect_affected_roots(room, &events).await
                    }
                }
                Ok(_) => continue,
                Err(RecvError::Closed) => {
                    error!("ThreadListService: event cache channel closed, stopping listener");
                    break;
                }
                Err(RecvError::Lagged(n)) => {
                    warn!("ThreadListService: lagged behind {n} event cache updates");
                    Self::tracked_roots(&items)
                }
            };

            for root_event_id in roots {
                let Ok(aggregate) = resolve_thread_relation_aggregate(room, &root_event_id).await
                else {
                    continue;
                };
                Self::apply_aggregate(&items, &proofs, root_event_id, aggregate);
            }
        }
    }

    async fn collect_affected_roots(room: &Room, events: &[Event]) -> Vec<OwnedEventId> {
        let Ok((room_event_cache, _drop_handles)) = room.event_cache().await else {
            return Vec::new();
        };
        let mut roots = HashSet::new();

        for event in events {
            let Some((relation_type, target)) = extract_relation(event.raw()) else {
                continue;
            };
            match relation_type {
                RelationType::Thread => {
                    roots.insert(target);
                }
                RelationType::Replacement => {
                    if let Ok(Some(original)) = room_event_cache.find_event(&target).await
                        && let Some(root) = extract_thread_root(original.raw())
                    {
                        roots.insert(root);
                    }
                }
                _ => {}
            }
        }

        roots.into_iter().collect()
    }

    fn tracked_roots(items: &Arc<Mutex<ObservableVector<ThreadListItem>>>) -> Vec<OwnedEventId> {
        items.lock().iter().map(|item| item.root_event.event_id.clone()).collect()
    }

    fn requires_full_reconciliation(event: &Event) -> bool {
        Self::is_redaction_event(event.raw()) || Self::is_redacted_raw_event(event.raw())
    }

    fn apply_aggregate(
        items: &Arc<Mutex<ObservableVector<ThreadListItem>>>,
        proofs: &Arc<Mutex<HashMap<OwnedEventId, ThreadRelationProof>>>,
        root_event_id: OwnedEventId,
        aggregate: ThreadRelationAggregate,
    ) {
        let (latest_event, num_replies) = {
            let mut proofs = proofs.lock();
            let proof = proofs
                .entry(root_event_id.clone())
                .or_insert(ThreadRelationProof { bundled: None, complete: true });
            let local_proven = proof
                .bundled
                .as_ref()
                .is_none_or(|bundled| aggregate.num_replies >= bundled.num_replies);
            if local_proven {
                proof.complete = true;
            }

            if proof.complete {
                (aggregate.latest_event, aggregate.num_replies)
            } else {
                let bundled = proof.bundled.as_ref().expect("incomplete proof has bundled data");
                (bundled.latest_event.clone(), bundled.num_replies)
            }
        };

        let mut guard = items.lock();
        if let Some(index) = guard.iter().position(|item| item.root_event.event_id == root_event_id)
        {
            let mut updated = guard[index].clone();
            updated.latest_event = latest_event;
            updated.num_replies = num_replies;
            guard.set(index, updated);
        }
    }

    fn is_redaction_event(raw: &ruma::serde::Raw<ruma::events::AnySyncTimelineEvent>) -> bool {
        matches!(
            raw.get_field::<MessageLikeEventType>("type").ok().flatten(),
            Some(MessageLikeEventType::RoomRedaction)
        )
    }

    /// Extracts all events from a list of [`VectorDiff`]s.
    fn collect_events_from_diffs(diffs: Vec<VectorDiff<TimelineEvent>>) -> Vec<TimelineEvent> {
        let mut events = Vec::new();

        for diff in diffs {
            match diff {
                VectorDiff::Append { values } => events.extend(values),
                VectorDiff::PushBack { value }
                | VectorDiff::PushFront { value }
                | VectorDiff::Insert { value, .. }
                | VectorDiff::Set { value, .. } => events.push(value),
                VectorDiff::Reset { values } => events.extend(values),
                // These diffs don't carry new events.
                VectorDiff::Clear
                | VectorDiff::PopBack
                | VectorDiff::PopFront
                | VectorDiff::Remove { .. }
                | VectorDiff::Truncate { .. } => {}
            }
        }

        events
    }
}

/// Resolve the local, relation-backed aggregate for one thread root.
///
/// This module-level entry point is the stable API used by SDK consumers.
pub async fn resolve_thread_relation_aggregate(
    room: &Room,
    root_event_id: &ruma::EventId,
) -> Result<ThreadRelationAggregate, ThreadListServiceError> {
    ThreadListService::resolve_thread_relation_aggregate(room, root_event_id).await
}

/// A structure wrapping a Thread List endpoint response i.e.
/// [`ThreadListItem`]s and the current pagination token.
#[derive(Clone, Debug)]
struct ThreadList {
    /// The thread-root events that belong to this page of results.
    pub items: Vec<ThreadListItem>,

    /// Opaque pagination token returned by the homeserver.
    pub prev_batch_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use futures_util::{StreamExt, pin_mut};
    use matrix_sdk::{
        ThreadingSupport,
        event_cache::{RoomEventCacheSubscriber, RoomEventCacheUpdate},
        store::StoreConfig,
        test_utils::mocks::MatrixMockServer,
    };
    use matrix_sdk_base::event_cache::store::EventCacheStore;
    use matrix_sdk_common::cross_process_lock::CrossProcessLockConfig;
    use matrix_sdk_test::{async_test, event_factory::EventFactory};
    use ruma::{
        MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedUserId, event_id,
        events::{
            AnyTimelineEvent,
            room::{ImageInfo, message::RoomMessageEventContentWithoutRelation},
            sticker::StickerEventContent,
        },
        owned_mxc_uri, room_id,
        serde::Raw,
        user_id,
    };
    use serde_json::json;
    use stream_assert::{assert_next_matches, assert_pending};
    use tokio::sync::watch;
    use wiremock::ResponseTemplate;

    use super::{
        ResolverTestGate, ThreadListPaginationState, ThreadListService, ThreadRelationAggregate,
        resolve_thread_relation_aggregate, resolver_test_gate_slot,
    };

    struct ResolverTestGateHandle {
        entered: watch::Receiver<bool>,
        release: watch::Sender<bool>,
    }

    impl ResolverTestGateHandle {
        async fn wait_until_entered(&mut self) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !*self.entered.borrow() {
                    self.entered.changed().await.expect("resolver gate should stay alive");
                }
            })
            .await
            .expect("resolver should reach the deterministic gate");
        }

        fn release(&self) {
            self.release.send(true).expect("resolver gate should stay alive");
        }
    }

    impl Drop for ResolverTestGateHandle {
        fn drop(&mut self) {
            if let Ok(mut slot) = resolver_test_gate_slot().lock() {
                *slot = None;
            }
        }
    }

    fn install_resolver_test_gate(root_event_id: OwnedEventId) -> ResolverTestGateHandle {
        let (entered, entered_rx) = watch::channel(false);
        let (release, release_rx) = watch::channel(false);
        let gate = Arc::new(ResolverTestGate {
            root_event_id,
            entered,
            release: release_rx,
            claimed: std::sync::atomic::AtomicBool::new(false),
        });
        let mut slot = resolver_test_gate_slot().lock().expect("resolver test gate lock poisoned");
        assert!(slot.replace(gate).is_none(), "another resolver gate is already installed");
        ResolverTestGateHandle { entered: entered_rx, release }
    }

    type AggregateProjection =
        (u32, Option<(OwnedEventId, MilliSecondsSinceUnixEpoch, OwnedUserId, Option<String>)>);

    fn aggregate_projection(aggregate: &ThreadRelationAggregate) -> AggregateProjection {
        (
            aggregate.num_replies,
            aggregate.latest_event.as_ref().map(|event| {
                (
                    event.event_id.clone(),
                    event.timestamp,
                    event.sender.clone(),
                    event.content.as_ref().and_then(|content| {
                        content.as_message().map(|message| message.body().to_owned())
                    }),
                )
            }),
        )
    }

    async fn wait_for_timeline_update(subscriber: &mut RoomEventCacheSubscriber) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match subscriber.recv().await {
                    Ok(RoomEventCacheUpdate::UpdateTimelineEvents(_)) => return,
                    Ok(_) => {}
                    Err(_) => panic!("room cache subscriber closed"),
                }
            }
        })
        .await
        .expect("room cache update should arrive");
    }

    #[async_test]
    async fn test_initial_state() {
        let server = MatrixMockServer::new().await;
        let service = make_service(&server).await;

        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: false }
        );
        assert!(service.items().is_empty());
    }

    #[async_test]
    async fn test_pagination() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");

        let f = EventFactory::new().room(room_id).sender(sender_id);

        let eid1 = event_id!("$1");
        let eid2 = event_id!("$2");

        server
            .mock_room_threads()
            .ok(
                vec![f.text_msg("Thread root 1").event_id(eid1).into_raw()],
                Some("next_page_token".to_owned()),
            )
            .mock_once()
            .mount()
            .await;

        server
            .mock_room_threads()
            .match_from("next_page_token")
            .ok(vec![f.text_msg("Thread root 2").event_id(eid2).into_raw()], None)
            .mock_once()
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        service.paginate().await.expect("first paginate failed");

        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: false }
        );
        assert_eq!(service.items().len(), 1);
        assert_eq!(service.items()[0].root_event.event_id, eid1);

        service.paginate().await.expect("second paginate failed");

        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: true }
        );
        assert_eq!(service.items().len(), 2);
        assert_eq!(service.items()[1].root_event.event_id, eid2);
    }

    #[async_test]
    async fn test_pagination_end_reached() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let eid1 = event_id!("$1");

        server
            .mock_room_threads()
            .ok(vec![f.text_msg("Thread root").event_id(eid1).into_raw()], None)
            .mock_once()
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        service.paginate().await.expect("paginate failed");
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: true }
        );
        assert_eq!(service.items().len(), 1);

        service.paginate().await.expect("second paginate should be a no-op");
        assert_eq!(service.items().len(), 1);
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: true }
        );
    }

    /// Two concurrent calls to [`ThreadListService::paginate`] must not result
    /// in two concurrent HTTP requests. The second call should detect that a
    /// pagination is already in progress (state is `Loading`) and return
    /// immediately without making another network request.
    #[async_test]
    async fn test_concurrent_pagination_is_not_possible() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let eid1 = event_id!("$1");

        // Set up a slow mock response so both `paginate()` calls overlap in
        // flight. Using `expect(1)` means the test will panic during server
        // teardown if the endpoint is hit more than once.
        let chunk: Vec<Raw<AnyTimelineEvent>> =
            vec![f.text_msg("Thread root").event_id(eid1).into_raw()];
        server
            .mock_room_threads()
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "chunk": chunk, "next_batch": null }))
                    .set_delay(Duration::from_millis(100)),
            )
            .expect(1)
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        // Run two paginations concurrently.
        let (first, second) = tokio::join!(service.paginate(), service.paginate());

        first.expect("first paginate should succeed");
        second.expect("second (concurrent) paginate should succeed as a no-op");

        // Only one HTTP request was made, so we have exactly one item.
        assert_eq!(service.items().len(), 1);
        assert_eq!(service.items()[0].root_event.event_id, eid1);
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: true }
        );
    }

    /// When the server returns an error, [`ThreadListService::paginate`] must
    /// propagate the error *and* reset the pagination state back to
    /// `Idle { end_reached: false }` so that the caller can retry.
    #[async_test]
    async fn test_pagination_error() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");

        server.mock_room_threads().error500().mock_once().mount().await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        // Pagination must surface the server error.
        service.paginate().await.expect_err("paginate should fail on a 500 response");

        // The state must be reset so the caller can retry; it must *not* be
        // stuck in `Loading`.
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: false }
        );

        // No items should have been added.
        assert!(service.items().is_empty());
    }

    #[async_test]
    async fn test_reset() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let eid1 = event_id!("$1");

        server
            .mock_room_threads()
            .ok(vec![f.text_msg("Thread root").event_id(eid1).into_raw()], None)
            .expect(2)
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        service.paginate().await.expect("first paginate failed");
        assert_eq!(service.items().len(), 1);
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: true }
        );

        service.reset().await;
        assert!(service.items().is_empty());
        assert_eq!(
            service.pagination_state(),
            ThreadListPaginationState::Idle { end_reached: false }
        );

        service.paginate().await.expect("paginate after reset failed");
        assert_eq!(service.items().len(), 1);
    }

    #[async_test]
    async fn test_pagination_state_subscriber() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let eid1 = event_id!("$1");

        server
            .mock_room_threads()
            .ok(
                vec![f.text_msg("Thread root").event_id(eid1).into_raw()],
                Some("next_token".to_owned()),
            )
            .mock_once()
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        let subscriber = service.subscribe_to_pagination_state_updates();
        pin_mut!(subscriber);

        assert_pending!(subscriber);

        service.paginate().await.expect("paginate failed");

        assert_next_matches!(subscriber, ThreadListPaginationState::Idle { end_reached: false });
    }

    #[async_test]
    async fn test_paginated_items_have_num_replies_zero_without_summary() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let eid1 = event_id!("$1");

        // A thread root without bundled thread summary.
        server
            .mock_room_threads()
            .ok(vec![f.text_msg("Thread root").event_id(eid1).into_raw()], None)
            .mock_once()
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        service.paginate().await.expect("paginate failed");

        let items = service.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].num_replies, 0);
        assert!(items[0].latest_event.is_none());
    }

    #[async_test]
    async fn test_paginated_items_have_num_replies_from_bundled_summary() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let sender_id = user_id!("@alice:b.c");
        let f = EventFactory::new().room(room_id).sender(sender_id);
        let root_id = event_id!("$root");
        let reply_id = event_id!("$reply");

        // Build a reply event to use as the bundled latest event.
        // `with_bundled_thread_summary` expects `Raw<AnySyncMessageLikeEvent>`,
        // so we cast from the more general `Raw<AnySyncTimelineEvent>`.
        let reply_event =
            f.text_msg("Reply in thread").event_id(reply_id).into_raw_sync().cast_unchecked();

        // Build a thread root with a bundled thread summary (3 replies).
        let thread_root = f
            .text_msg("Thread root")
            .event_id(root_id)
            .with_bundled_thread_summary(reply_event, 3, false)
            .into_raw();

        server.mock_room_threads().ok(vec![thread_root], None).mock_once().mount().await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);

        service.paginate().await.expect("paginate failed");

        let items = service.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].root_event.event_id, root_id);
        assert_eq!(items[0].num_replies, 3);

        // The latest event should be populated from the bundled summary.
        let latest = items[0].latest_event.as_ref().expect("should have latest_event");
        assert_eq!(latest.event_id, reply_id);
        assert_eq!(latest.sender.as_str(), sender_id.as_str());
    }

    #[async_test]
    async fn test_sticker_thread_reply_contributes_to_exact_aggregate() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-sticker:example.org");
        let root_id = event_id!("$aggregate-sticker-root");
        let sticker_reply_id = event_id!("$aggregate-sticker-reply");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        let room = server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.text_msg("root").event_id(root_id).into_raw_sync(),
                    f.event(StickerEventContent::new(
                        "sticker".to_owned(),
                        ImageInfo::new(),
                        owned_mxc_uri!("mxc://example.org/sticker"),
                    ))
                    .reply_thread(root_id, root_id)
                    .event_id(sticker_reply_id)
                    .into_raw_sync(),
                ]),
            )
            .await;

        let aggregate = resolve_thread_relation_aggregate(&room, root_id)
            .await
            .expect("sticker thread reply should resolve");

        assert_eq!(aggregate.num_replies, 1);
        assert_eq!(aggregate.latest_event.as_ref().unwrap().event_id, sticker_reply_id);
    }

    #[async_test]
    async fn test_relation_aggregate_preserves_original_identity_and_new_content() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-edit:example.org");
        let root_id = event_id!("$aggregate-edit-root");
        let reply_id = event_id!("$aggregate-edit-reply");
        let first_edit_id = event_id!("$aggregate-edit-1");
        let second_edit_id = event_id!("$aggregate-edit-2");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        let room = server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.text_msg("root").event_id(root_id).into_raw_sync(),
                    f.text_msg("original reply")
                        .in_thread(root_id, root_id)
                        .event_id(reply_id)
                        .into_raw_sync(),
                ]),
            )
            .await;

        let before_edit = resolve_thread_relation_aggregate(&room, root_id)
            .await
            .expect("relation aggregate should resolve");
        let original = before_edit.latest_event.expect("reply should be latest");
        assert_eq!(before_edit.num_replies, 1);
        assert_eq!(original.event_id, reply_id);
        assert_eq!(
            original
                .content
                .as_ref()
                .and_then(|content| content.as_message())
                .map(|message| message.body()),
            Some("original reply")
        );

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("* fallback one")
                        .event_id(first_edit_id)
                        .edit(
                            &reply_id,
                            RoomMessageEventContentWithoutRelation::text_plain("effective one"),
                        )
                        .into_raw_sync(),
                ),
            )
            .await;

        let after_first_edit = resolve_thread_relation_aggregate(&room, root_id)
            .await
            .expect("edited aggregate should resolve");
        let first_latest =
            after_first_edit.latest_event.expect("edited reply should remain latest");
        assert_eq!(after_first_edit.num_replies, 1);
        assert_eq!(first_latest.event_id, reply_id);
        assert_eq!(first_latest.timestamp, original.timestamp);
        assert_eq!(first_latest.sender, original.sender);
        assert_eq!(
            first_latest
                .content
                .as_ref()
                .and_then(|content| content.as_message())
                .map(|message| message.body()),
            Some("effective one")
        );

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("* fallback two")
                        .event_id(second_edit_id)
                        .edit(
                            &reply_id,
                            RoomMessageEventContentWithoutRelation::text_plain("effective two"),
                        )
                        .into_raw_sync(),
                ),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.redaction(&second_edit_id).event_id(event_id!("$aggregate-edit-redaction")),
                ),
            )
            .await;

        let after_redacted_latest = resolve_thread_relation_aggregate(&room, root_id)
            .await
            .expect("redacted edit aggregate should resolve");
        let latest = after_redacted_latest.latest_event.expect("prior edit should be promoted");
        assert_eq!(after_redacted_latest.num_replies, 1);
        assert_eq!(latest.event_id, reply_id);
        assert_eq!(latest.timestamp, original.timestamp);
        assert_eq!(
            latest
                .content
                .as_ref()
                .and_then(|content| content.as_message())
                .map(|message| message.body()),
            Some("effective one")
        );
    }

    #[async_test]
    async fn test_edit_before_original_replay_matches_in_order_aggregate() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let out_of_order_room = room_id!("!aggregate-edit-before-original:example.org");
        let in_order_room = room_id!("!aggregate-edit-in-order:example.org");
        let root_id = event_id!("$aggregate-edit-order-root");
        let reply_id = event_id!("$aggregate-edit-order-reply");
        let edit_id = event_id!("$aggregate-edit-order-edit");
        let f = EventFactory::new().sender(user_id!("@alice:example.org"));
        let root = f.text_msg("root").event_id(root_id).into_raw_sync();
        let original =
            f.text_msg("original").in_thread(root_id, root_id).event_id(reply_id).into_raw_sync();
        let edit = f
            .text_msg("* fallback")
            .event_id(edit_id)
            .edit(&reply_id, RoomMessageEventContentWithoutRelation::text_plain("effective"))
            .into_raw_sync();

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(out_of_order_room)
                    .add_timeline_event(root.clone()),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(out_of_order_room)
                    .add_timeline_event(edit.clone()),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(out_of_order_room)
                    .add_timeline_event(original.clone()),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(out_of_order_room)
                    .add_timeline_event(edit.clone()),
            )
            .await;

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(in_order_room)
                    .add_timeline_event(root)
                    .add_timeline_event(original),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(in_order_room).add_timeline_event(edit),
            )
            .await;

        let out_of_order = client.get_room(out_of_order_room).unwrap();
        let in_order = client.get_room(in_order_room).unwrap();
        let out_of_order_aggregate =
            resolve_thread_relation_aggregate(&out_of_order, root_id).await.unwrap();
        let in_order_aggregate =
            resolve_thread_relation_aggregate(&in_order, root_id).await.unwrap();

        assert_eq!(
            aggregate_projection(&out_of_order_aggregate),
            aggregate_projection(&in_order_aggregate)
        );
        assert_eq!(out_of_order_aggregate.num_replies, 1);
        let latest = out_of_order_aggregate.latest_event.expect("reply should be projected");
        assert_eq!(latest.event_id, reply_id);
        assert_eq!(
            latest
                .content
                .as_ref()
                .and_then(|content| content.as_message())
                .map(|message| message.body()),
            Some("effective")
        );
    }

    #[async_test]
    async fn test_relation_aggregate_matches_after_persistent_reopen() {
        let server = MatrixMockServer::new().await;
        let room_id = room_id!("!aggregate-reopen-ui:example.org");
        let root_id = event_id!("$aggregate-reopen-ui-root");
        let reply_a_id = event_id!("$aggregate-reopen-ui-a");
        let reply_b_id = event_id!("$aggregate-reopen-ui-b");
        let redaction_id = event_id!("$aggregate-reopen-ui-redaction");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));
        let event_cache_store = Arc::new(matrix_sdk_base::event_cache::store::MemoryStore::new());
        let state_store = matrix_sdk_base::store::MemoryStore::new();
        let store_config =
            StoreConfig::new(CrossProcessLockConfig::multi_process("thread-list-aggregate-reopen"))
                .state_store(state_store)
                .event_cache_store(event_cache_store.clone());

        let live_projection;
        {
            let client = server
                .client_builder()
                .on_builder(|builder| {
                    builder
                        .with_threading_support(ThreadingSupport::Enabled {
                            with_subscriptions: false,
                        })
                        .store_config(store_config.clone())
                })
                .build()
                .await;
            client.event_cache().subscribe().unwrap();
            let room = server
                .sync_room(
                    &client,
                    matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                        f.text_msg("root").event_id(root_id).into_raw_sync(),
                        f.text_msg("reply a")
                            .in_thread(root_id, root_id)
                            .event_id(reply_a_id)
                            .into_raw_sync(),
                    ]),
                )
                .await;
            server
                .sync_room(
                    &client,
                    matrix_sdk_test::JoinedRoomBuilder::new(room_id)
                        .add_timeline_event(f.redaction(&reply_b_id).event_id(redaction_id)),
                )
                .await;
            let live = resolve_thread_relation_aggregate(&room, root_id).await.unwrap();
            live_projection = aggregate_projection(&live);
            assert_eq!(live.num_replies, 1);
            assert_eq!(live.latest_event.as_ref().unwrap().event_id, reply_a_id);
        }

        event_cache_store.close().await.unwrap();
        event_cache_store.reopen().await.unwrap();

        let client = server
            .client_builder()
            .on_builder(|builder| {
                builder
                    .with_threading_support(ThreadingSupport::Enabled { with_subscriptions: false })
                    .store_config(store_config)
            })
            .build()
            .await;
        client.event_cache().subscribe().unwrap();
        let room = client.get_room(room_id).expect("room should reload from the state store");
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("reply b")
                        .in_thread(root_id, root_id)
                        .event_id(reply_b_id)
                        .into_raw_sync(),
                ),
            )
            .await;

        let reopened = resolve_thread_relation_aggregate(&room, root_id).await.unwrap();
        assert_eq!(aggregate_projection(&reopened), live_projection);
        assert_eq!(reopened.num_replies, 1);
        assert_eq!(reopened.latest_event.as_ref().unwrap().event_id, reply_a_id);
    }

    #[async_test]
    async fn test_bundled_proof_keeps_latest_and_count_until_local_count_is_proven() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-proof:example.org");
        let root_id = event_id!("$aggregate-proof-root");
        let bundled_latest_id = event_id!("$aggregate-proof-bundled");
        let local_one_id = event_id!("$aggregate-proof-one");
        let local_two_id = event_id!("$aggregate-proof-two");
        let local_three_id = event_id!("$aggregate-proof-three");
        let local_four_id = event_id!("$aggregate-proof-four");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));
        let bundled_latest = f
            .text_msg("bundled latest")
            .event_id(bundled_latest_id)
            .into_raw_sync()
            .cast_unchecked();
        let root = f
            .text_msg("root")
            .event_id(root_id)
            .with_bundled_thread_summary(bundled_latest, 4, false)
            .into_raw();

        server.mock_room_threads().ok(vec![root], None).mock_once().mount().await;
        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);
        service.paginate().await.expect("paginate failed");
        let bundled = service.items();
        assert_eq!(bundled[0].num_replies, 4);
        assert_eq!(bundled[0].latest_event.as_ref().unwrap().event_id, bundled_latest_id);

        let (_snapshot, updates) = service.subscribe_to_items_updates();
        pin_mut!(updates);

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("local one")
                        .in_thread(root_id, root_id)
                        .event_id(local_one_id)
                        .into_raw_sync(),
                ),
            )
            .await;
        assert!(updates.next().await.is_some());
        let partial = &service.items()[0];
        assert_eq!(partial.num_replies, 4);
        assert_eq!(partial.latest_event.as_ref().unwrap().event_id, bundled_latest_id);

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.text_msg("local two")
                        .in_thread(root_id, local_one_id)
                        .event_id(local_two_id)
                        .into_raw_sync(),
                    f.text_msg("local three")
                        .in_thread(root_id, local_two_id)
                        .event_id(local_three_id)
                        .into_raw_sync(),
                    f.text_msg("local four")
                        .in_thread(root_id, local_three_id)
                        .event_id(local_four_id)
                        .into_raw_sync(),
                ]),
            )
            .await;
        while {
            let item = &service.items()[0];
            item.num_replies != 4
                || item.latest_event.as_ref().is_none_or(|event| event.event_id != local_four_id)
        } {
            assert!(updates.next().await.is_some());
        }

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.redaction(&local_four_id).event_id(event_id!("$aggregate-proof-redact-four")),
                ),
            )
            .await;
        while {
            let item = &service.items()[0];
            item.num_replies != 3
                || item.latest_event.as_ref().is_none_or(|event| event.event_id != local_three_id)
        } {
            assert!(updates.next().await.is_some());
        }

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.redaction(&local_one_id)
                        .event_id(event_id!("$aggregate-proof-redact-one"))
                        .into_raw_sync(),
                    f.redaction(&local_two_id)
                        .event_id(event_id!("$aggregate-proof-redact-two"))
                        .into_raw_sync(),
                    f.redaction(&local_three_id)
                        .event_id(event_id!("$aggregate-proof-redact-three"))
                        .into_raw_sync(),
                ]),
            )
            .await;
        while {
            let item = &service.items()[0];
            item.num_replies != 0 || item.latest_event.is_some()
        } {
            assert!(updates.next().await.is_some());
        }
        assert_eq!(service.items()[0].num_replies, 0);
        assert!(service.items()[0].latest_event.is_none());
    }

    #[async_test]
    async fn test_redaction_of_latest_reply_reconciles_exact_aggregate() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-service:example.org");
        let root_id = event_id!("$aggregate-service-root");
        let reply_a_id = event_id!("$aggregate-service-a");
        let reply_b_id = event_id!("$aggregate-service-b");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        server
            .mock_room_threads()
            .ok(vec![f.text_msg("root").event_id(root_id).into_raw()], None)
            .mock_once()
            .mount()
            .await;

        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);
        service.paginate().await.expect("paginate failed");
        tokio::task::yield_now().await;

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.text_msg("reply a")
                        .in_thread(root_id, root_id)
                        .event_id(reply_a_id)
                        .into_raw_sync(),
                    f.text_msg("reply b")
                        .in_thread(root_id, reply_a_id)
                        .event_id(reply_b_id)
                        .into_raw_sync(),
                ]),
            )
            .await;
        tokio::task::yield_now().await;

        let populated = service.items();
        assert_eq!(populated[0].num_replies, 2);
        assert_eq!(populated[0].latest_event.as_ref().unwrap().event_id, reply_b_id);

        let redaction_id = event_id!("$aggregate-service-redaction");
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(f.redaction(&reply_b_id).event_id(redaction_id)),
            )
            .await;
        tokio::task::yield_now().await;

        let reconciled = service.items();
        assert_eq!(reconciled[0].num_replies, 1);
        assert_eq!(reconciled[0].latest_event.as_ref().unwrap().event_id, reply_a_id);
    }

    #[async_test]
    async fn test_redaction_reconciles_all_tracked_roots() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-all-roots:example.org");
        let root_a = event_id!("$aggregate-all-root-a");
        let root_b = event_id!("$aggregate-all-root-b");
        let reply_a = event_id!("$aggregate-all-reply-a");
        let reply_b = event_id!("$aggregate-all-reply-b");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        server
            .mock_room_threads()
            .ok(
                vec![
                    f.text_msg("root a").event_id(root_a).into_raw(),
                    f.text_msg("root b").event_id(root_b).into_raw(),
                ],
                None,
            )
            .mock_once()
            .mount()
            .await;
        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);
        service.paginate().await.expect("paginate failed");

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.text_msg("reply a")
                        .in_thread(root_a, root_a)
                        .event_id(reply_a)
                        .into_raw_sync(),
                    f.text_msg("reply b")
                        .in_thread(root_b, root_b)
                        .event_id(reply_b)
                        .into_raw_sync(),
                ]),
            )
            .await;
        tokio::task::yield_now().await;

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.redaction(&reply_b).event_id(event_id!("$aggregate-all-redaction")),
                ),
            )
            .await;
        tokio::task::yield_now().await;

        let items = service.items();
        let item_a = items.iter().find(|item| item.root_event.event_id == root_a).unwrap();
        let item_b = items.iter().find(|item| item.root_event.event_id == root_b).unwrap();
        assert_eq!(item_a.num_replies, 1);
        assert_eq!(item_a.latest_event.as_ref().unwrap().event_id, reply_a);
        assert_eq!(item_b.num_replies, 0);
        assert!(item_b.latest_event.is_none());
    }

    #[async_test]
    async fn test_serial_batches_leave_the_latest_final_aggregate() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-serial:example.org");
        let root_id = event_id!("$aggregate-serial-root");
        let first_reply = event_id!("$aggregate-serial-first");
        let final_reply = event_id!("$aggregate-serial-final");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        server
            .mock_room_threads()
            .ok(vec![f.text_msg("root").event_id(root_id).into_raw()], None)
            .mock_once()
            .mount()
            .await;
        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room);
        service.paginate().await.expect("paginate failed");

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("first")
                        .in_thread(root_id, root_id)
                        .event_id(first_reply)
                        .into_raw_sync(),
                ),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.redaction(&first_reply).event_id(event_id!("$aggregate-serial-redaction")),
                ),
            )
            .await;
        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("final")
                        .in_thread(root_id, root_id)
                        .event_id(final_reply)
                        .into_raw_sync(),
                ),
            )
            .await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let item = &service.items()[0];
        assert_eq!(item.num_replies, 1);
        assert_eq!(item.latest_event.as_ref().unwrap().event_id, final_reply);
    }

    #[async_test]
    async fn test_queued_newer_batch_wins_after_first_resolver_is_released() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!aggregate-queued-newer:example.org");
        let root_id = event_id!("$aggregate-queued-newer-root");
        let first_reply_id = event_id!("$aggregate-queued-newer-first");
        let final_reply_id = event_id!("$aggregate-queued-newer-final");
        let f = EventFactory::new().room(room_id).sender(user_id!("@alice:example.org"));

        server
            .mock_room_threads()
            .ok(vec![f.text_msg("root").event_id(root_id).into_raw()], None)
            .mock_once()
            .mount()
            .await;
        let room = server.sync_joined_room(&client, room_id).await;
        let service = ThreadListService::new(room.clone());
        service.paginate().await.expect("paginate failed");
        let (room_event_cache, _drop_handles) = room.event_cache().await.unwrap();
        let (_, mut cache_updates) = room_event_cache.subscribe().await.unwrap();
        assert!(cache_updates.is_empty());
        let (_snapshot, updates) = service.subscribe_to_items_updates();
        pin_mut!(updates);
        let mut gate = install_resolver_test_gate(root_id.to_owned());

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("first")
                        .in_thread(root_id, root_id)
                        .event_id(first_reply_id)
                        .into_raw_sync(),
                ),
            )
            .await;
        gate.wait_until_entered().await;
        wait_for_timeline_update(&mut cache_updates).await;

        server
            .sync_room(
                &client,
                matrix_sdk_test::JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("final")
                        .in_thread(root_id, first_reply_id)
                        .event_id(final_reply_id)
                        .into_raw_sync(),
                ),
            )
            .await;
        wait_for_timeline_update(&mut cache_updates).await;
        assert_pending!(updates);

        gate.release();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let item = &service.items()[0];
                if item.num_replies == 2
                    && item
                        .latest_event
                        .as_ref()
                        .is_some_and(|event| event.event_id == final_reply_id)
                {
                    break;
                }
                assert!(updates.next().await.is_some());
            }
        })
        .await
        .expect("newer aggregate should be applied after the first release");

        let item = &service.items()[0];
        assert_eq!(item.num_replies, 2);
        assert_eq!(item.latest_event.as_ref().unwrap().event_id, final_reply_id);
    }

    /// Builds a [`ThreadListService`] and makes the room known to the client
    /// by performing a sync.
    async fn make_service(server: &MatrixMockServer) -> ThreadListService {
        let client = server.client_builder().build().await;
        let room_id = room_id!("!a:b.c");
        let room = server.sync_joined_room(&client, room_id).await;
        ThreadListService::new(room)
    }
}
