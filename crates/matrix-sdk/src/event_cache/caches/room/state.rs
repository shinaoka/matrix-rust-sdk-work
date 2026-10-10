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
//
// Modified for the Koushi desktop fork (cache-only search verification); see
// docs/upstream/matrix-rust-sdk-feedback.md in the Koushi repository.

use std::{
    collections::HashMap,
    iter::empty,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use eyeball::SharedObservable;
use eyeball_im::VectorDiff;
use matrix_sdk_base::{
    RoomInfoNotableUpdateReasons, apply_redaction,
    deserialized_responses::{ThreadSummary, ThreadSummaryStatus},
    event_cache::{Event, Gap, store::EventCacheStoreLockGuard},
    linked_chunk::{
        ChunkIdentifierGenerator, LinkedChunkId, OwnedLinkedChunkId, Position, Update, lazy_loader,
    },
    serde_helpers::extract_redaction_target,
    sync::Timeline,
};
use matrix_sdk_common::{
    check_validity_of_replacement_events, executor::spawn, serde_helpers::extract_timestamp,
};
use ruma::{
    EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId,
    events::{
        AnySyncMessageLikeEvent, AnySyncTimelineEvent, receipt::ReceiptEventContent,
        relation::RelationType, room::redaction::SyncRoomRedactionEvent,
    },
    room_version_rules::RoomVersionRules,
};
use tokio::sync::broadcast::Sender;
use tracing::{debug, error, instrument, trace};

#[cfg(feature = "e2e-encryption")]
use super::super::super::redecryptor::MaybeResolvedEvent;
use super::{
    super::{
        super::{
            EventCacheError,
            back_pagination_queue::BackPaginationQueue,
            deduplicator::{DeduplicationOutcome, filter_duplicate_events},
            persistence::{
                find_event, find_event_relations, find_event_with_relations,
                load_linked_chunk_metadata, send_updates_to_store,
            },
            states::{ReloadPreprocessing, StateLockReadGuard, StateLockWriteGuard},
        },
        EventLocation,
        event_linked_chunk::EventLinkedChunk,
        pagination::SharedPaginationStatus,
        read_receipts::{
            MaybeReceiptEventContent, RoomReadReceiptEventFilter, compute_unread_counts,
        },
        subscriber::SubscribersHandle,
    },
    RoomEventCacheLinkedChunkUpdate, RoomEventCacheUpdateSender, sort_positions_descending,
};
use crate::room::WeakRoom;

/// Process-local identity counter for room-cache state instances.
static NEXT_GAP_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

pub struct RoomEventCacheState {
    /// Whether thread support has been enabled for the event cache.
    pub enabled_thread_support: bool,

    /// The room this state relates to.
    pub room_id: OwnedRoomId,

    /// A weak reference to the actual room.
    weak_room: WeakRoom,

    /// The user's own user id.
    pub own_user_id: OwnedUserId,

    /// The loaded events for the current room, that is, the in-memory
    /// linked chunk for this room.
    room_linked_chunk: EventLinkedChunk,

    pagination_status: SharedObservable<SharedPaginationStatus>,

    /// Latest persisted redaction for each target whose redacted event has not
    /// yet been seen in this room cache.
    pending_redactions: Arc<Mutex<HashMap<OwnedEventId, Event>>>,

    /// Monotonic generation for persisted gap-topology mutations.
    gap_topology_generation: u64,

    /// Process-local identity for this room-cache state instance.
    gap_snapshot_id: u64,

    /// A clone of [`super::RoomEventCacheInner::update_sender`].
    ///
    /// This is used only by the [`RoomEventCacheStateLock::read`] and
    /// [`RoomEventCacheStateLock::write`] when the state must be reset.
    pub update_sender: RoomEventCacheUpdateSender,

    /// A clone of
    /// [`super::super::EventCacheInner::linked_chunk_update_sender`].
    pub(super) linked_chunk_update_sender: Sender<RoomEventCacheLinkedChunkUpdate>,

    /// The rules for the version of this room.
    room_version_rules: RoomVersionRules,

    /// Have we ever waited for a previous-batch-token to come from sync, in
    /// the context of pagination? We do this at most once per room,
    /// the first time we try to run backward pagination. We reset
    /// that upon clearing the timeline events.
    waited_for_initial_prev_token: bool,

    /// A handle for subscribers.
    subscribers_handle: SubscribersHandle,

    /// A handle to the shared back-pagination queue.
    back_pagination_queue: Option<BackPaginationQueue>,
}

impl RoomEventCacheState {
    /// Create a new state, or reload it from storage if it's been enabled.
    ///
    /// Not all events are going to be loaded. Only a portion of them. The
    /// [`EventLinkedChunk`] relies on a [`LinkedChunk`] to store all
    /// events. Only the last chunk will be loaded. It means the
    /// events are loaded from the most recent to the oldest. To
    /// load more events, see [`RoomPagination`].
    ///
    /// [`LinkedChunk`]: matrix_sdk_common::linked_chunk::LinkedChunk
    /// [`RoomPagination`]: super::RoomPagination
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        own_user_id: OwnedUserId,
        room_id: OwnedRoomId,
        weak_room: WeakRoom,
        room_version_rules: RoomVersionRules,
        enabled_thread_support: bool,
        update_sender: RoomEventCacheUpdateSender,
        linked_chunk_update_sender: Sender<RoomEventCacheLinkedChunkUpdate>,
        store_guard: EventCacheStoreLockGuard,
        pagination_status: SharedObservable<SharedPaginationStatus>,
        back_pagination_queue: Option<BackPaginationQueue>,
        pending_redactions: Arc<Mutex<HashMap<OwnedEventId, Event>>>,
    ) -> Result<Self, EventCacheError> {
        let linked_chunk_id = LinkedChunkId::Room(&room_id);

        // Load the full linked chunk's metadata, so as to feed the order tracker.
        //
        // If loading the full linked chunk failed, we'll clear the event cache, as it
        // indicates that at some point, there's some malformed data.
        let full_linked_chunk_metadata =
            match load_linked_chunk_metadata(&store_guard, linked_chunk_id).await {
                Ok(metas) => metas,
                Err(err) => {
                    error!("error when loading a linked chunk's metadata from the store: {err}");

                    // Try to clear storage for this room.
                    store_guard
                        .handle_linked_chunk_updates(linked_chunk_id, vec![Update::Clear])
                        .await?;

                    // Restart with an empty linked chunk.
                    None
                }
            };

        let linked_chunk = match store_guard
            .load_last_chunk(linked_chunk_id)
            .await
            .map_err(EventCacheError::from)
            .and_then(|(last_chunk, chunk_identifier_generator)| {
                lazy_loader::from_last_chunk(last_chunk, chunk_identifier_generator)
                    .map_err(EventCacheError::from)
            }) {
            Ok(linked_chunk) => linked_chunk,
            Err(err) => {
                error!("error when loading a linked chunk's latest chunk from the store: {err}");

                // Try to clear storage for this room.
                store_guard
                    .handle_linked_chunk_updates(linked_chunk_id, vec![Update::Clear])
                    .await?;

                None
            }
        };

        let mut state = RoomEventCacheState {
            own_user_id,
            enabled_thread_support,
            room_id,
            weak_room,
            room_linked_chunk: EventLinkedChunk::with_initial_linked_chunk(
                linked_chunk,
                full_linked_chunk_metadata,
            ),
            pagination_status,
            update_sender,
            linked_chunk_update_sender,
            room_version_rules,
            waited_for_initial_prev_token: false,
            subscribers_handle: Default::default(),
            back_pagination_queue,
            pending_redactions,
            gap_topology_generation: 0,
            gap_snapshot_id: NEXT_GAP_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed),
        };

        state.rebuild_pending_redactions_with_store(&store_guard).await?;

        Ok(state)
    }

    /// Return a reference to subscribers handle.
    pub fn subscribers_handle(&self) -> &SubscribersHandle {
        &self.subscribers_handle
    }

    /// Return a read-only reference to the underlying room linked chunk.
    pub fn room_linked_chunk(&self) -> &EventLinkedChunk {
        &self.room_linked_chunk
    }

    pub(super) fn pending_redactions_for(&self, event_ids: &[OwnedEventId]) -> std::collections::HashSet<OwnedEventId> {
        let pending = self.pending_redactions.lock().unwrap();
        event_ids.iter().filter(|id| pending.contains_key(*id)).cloned().collect()
    }

    fn redaction_target(&self, event: &Event) -> Option<OwnedEventId> {
        let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomRedaction(
            redaction,
        ))) = event.raw().deserialize()
        else {
            return None;
        };

        redaction.redacts(&self.room_version_rules.redaction).map(ToOwned::to_owned)
    }

    fn compare_redactions(candidate: &Event, current: &Event) -> std::cmp::Ordering {
        let now = MilliSecondsSinceUnixEpoch::now();
        match (
            extract_timestamp(candidate.raw(), now),
            candidate.event_id(),
            extract_timestamp(current.raw(), now),
            current.event_id(),
        ) {
            (Some(candidate_ts), Some(candidate_id), Some(current_ts), Some(current_id)) => {
                (candidate_ts, candidate_id).cmp(&(current_ts, current_id))
            }
            _ => std::cmp::Ordering::Equal,
        }
    }

    /// Remember this redaction as pending for its target, keeping the newest
    /// known redaction when several target the same event.
    fn remember_redaction(&mut self, event: &Event) -> Option<OwnedEventId> {
        let target = self.redaction_target(event)?;
        let mut pending = self.pending_redactions.lock().unwrap();
        let replace = pending
            .get(&target)
            .is_none_or(|current| Self::compare_redactions(event, current).is_gt());
        if replace {
            pending.insert(target.clone(), event.clone());
        }
        Some(target)
    }

    /// Redact events whose target has a pending redaction, before they are
    /// inserted into a chunk: the chunk item, the queued store updates and the
    /// store copy then all carry the redacted form. See `CachesInternals`.
    pub(super) fn redact_pending_events(&mut self, events: &mut [Event]) {
        let Ok(pending) = self.pending_redactions.lock() else {
            return;
        };
        for event in events.iter_mut() {
            let Some(event_id) = event.event_id().map(ToOwned::to_owned) else {
                continue;
            };
            let Some(redaction) = pending.get(&event_id) else {
                continue;
            };
            let _ = Self::apply_redaction_to_event(event, redaction, &self.room_version_rules);
        }
    }

    fn event_is_redacted(event: &Event) -> bool {
        event.raw().deserialize().is_ok_and(|event| event.is_redacted())
    }

    pub(in super::super) fn apply_redaction_to_event(
        target: &mut Event,
        redaction: &Event,
        rules: &RoomVersionRules,
    ) -> bool {
        if Self::event_is_redacted(target) {
            return false;
        }

        let Some(redacted_event) = apply_redaction(
            target.raw(),
            redaction.raw().cast_ref_unchecked::<SyncRoomRedactionEvent>(),
            &rules.redaction,
        ) else {
            return false;
        };

        target.replace_raw(redacted_event.cast_unchecked());
        true
    }

    /// Rebuild the pending-redaction map from the store, re-applying any
    /// redaction whose target is already known.
    async fn rebuild_pending_redactions_with_store(
        &mut self,
        store: &EventCacheStoreLockGuard,
    ) -> Result<(), EventCacheError> {
        self.pending_redactions.lock().unwrap().clear();

        for redaction in
            store.get_room_events(&self.room_id, Some("m.room.redaction"), None).await?
        {
            self.remember_redaction(&redaction);
        }

        let mut replaced_in_memory = false;
        let targets = self
            .pending_redactions
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for target_id in targets {
            let redaction = self.pending_redactions.lock().unwrap().get(&target_id).cloned();
            let Some(redaction) = redaction else {
                continue;
            };
            let Some((location, mut target)) =
                find_event(&target_id, &self.room_id, &self.room_linked_chunk, store).await?
            else {
                continue;
            };

            if !Self::apply_redaction_to_event(&mut target, &redaction, &self.room_version_rules) {
                continue;
            }

            match location {
                EventLocation::Memory(position) => {
                    self.room_linked_chunk
                        .replace_event_at(position, target)
                        .expect("should have been a valid position of an item");
                    replaced_in_memory = true;
                }
                EventLocation::Store => {
                    store.save_event(&self.room_id, target).await?;
                }
            }
        }

        // Only touch the store when this rebuild changed an in-memory event: the
        // linked chunk can carry updates recorded while it was loaded, and draining
        // them here would make creating a cache perform an unrelated store write.
        if replaced_in_memory {
            let updates = self.room_linked_chunk.store_updates().take();
            if !updates.is_empty() {
                store
                    .handle_linked_chunk_updates(LinkedChunkId::Room(&self.room_id), updates)
                    .await?;
            }
        }

        Ok(())
    }
}

impl<'a> StateLockReadGuard<'a, RoomEventCacheState> {
    /// Return the process-local room-cache snapshot identity.
    pub fn gap_snapshot_id(&self) -> u64 {
        self.state.gap_snapshot_id
    }

    /// Return the monotonic persisted gap-topology generation.
    pub fn gap_topology_generation(&self) -> u64 {
        self.state.gap_topology_generation
    }

    /// Return the newest event identity in the loaded room timeline.
    pub(super) fn newest_event_id(&self) -> Option<OwnedEventId> {
        self.state.room_linked_chunk.revents().find_map(|(_, event)| event.event_id().map(|id| id.to_owned()))
    }

    /// See documentation of [`find_event`].
    pub async fn find_event(
        &self,
        event_id: &EventId,
    ) -> Result<Option<(EventLocation, Event)>, EventCacheError> {
        find_event(event_id, &self.room_id, &self.room_linked_chunk, &self.store).await
    }

    /// See documentation of [`find_event_with_relations`].
    pub async fn find_event_with_relations(
        &self,
        event_id: &EventId,
        filters: Option<Vec<RelationType>>,
    ) -> Result<Option<(Event, Vec<Event>)>, EventCacheError> {
        find_event_with_relations(
            event_id,
            &self.room_id,
            filters,
            &self.room_linked_chunk,
            &self.store,
        )
        .await
    }

    /// See documentation of [`find_event_relations`].
    pub async fn find_event_relations(
        &self,
        event_id: &EventId,
        filters: Option<Vec<RelationType>>,
    ) -> Result<Vec<Event>, EventCacheError> {
        find_event_relations(event_id, &self.room_id, filters, &self.room_linked_chunk, &self.store)
            .await
    }

    //// Find a single event in this room, starting from the most recent event.
    ///
    /// The `predicate` receives the current event as its single argument.
    ///
    /// **Warning**! It looks into the loaded events from the in-memory
    /// linked chunk **only**. It doesn't look inside the storage,
    /// contrary to [`Self::find_event`].
    pub fn rfind_map_event_in_memory_by<O, P>(&self, mut predicate: P) -> Option<O>
    where
        P: FnMut(&Event) -> Option<O>,
    {
        self.state.room_linked_chunk.revents().find_map(|(_, event)| predicate(event))
    }

    #[cfg(test)]
    pub fn is_dirty(&self) -> bool {
        EventCacheStoreLockGuard::is_dirty(&self.store)
    }
}

impl<'a> StateLockWriteGuard<'a, RoomEventCacheState> {
    /// Return the process-local room-cache snapshot identity.
    pub fn gap_snapshot_id(&self) -> u64 {
        self.state.gap_snapshot_id
    }

    /// Return the monotonic persisted gap-topology generation.
    pub fn gap_topology_generation(&self) -> u64 {
        self.state.gap_topology_generation
    }

    /// Return the newest event identity in the loaded room timeline.
    pub(super) fn newest_event_id(&self) -> Option<OwnedEventId> {
        self.state.room_linked_chunk.revents().find_map(|(_, event)| event.event_id().map(|id| id.to_owned()))
    }

    /// Return a mutable reference to the underlying room linked chunk.
    pub fn room_linked_chunk_mut(&mut self) -> &mut EventLinkedChunk {
        &mut self.state.room_linked_chunk
    }

    /// Get the `waited_for_initial_prev_token` value.
    pub fn waited_for_initial_prev_token(&self) -> bool {
        self.state.waited_for_initial_prev_token
    }

    /// Get a mutable reference to the `waited_for_initial_prev_token` value.
    pub fn waited_for_initial_prev_token_mut(&mut self) -> &mut bool {
        &mut self.state.waited_for_initial_prev_token
    }

    /// See documentation of [`find_event`].
    pub async fn find_event(
        &self,
        event_id: &EventId,
    ) -> Result<Option<(EventLocation, Event)>, EventCacheError> {
        find_event(event_id, &self.room_id, &self.room_linked_chunk, &self.store).await
    }

    /// Reload the room: only the last events will be reloaded, shrinking the
    /// in-memory size of the cache.
    ///
    /// If `preprocessing` is set to [`ReloadPreprocessing::ForgetAll`], all
    /// events will be erased before reloaded.
    #[must_use = "Propagate `VectorDiff` updates via `RoomEventCacheUpdate`"]
    pub async fn reload(
        &mut self,
        preprocessing: ReloadPreprocessing,
    ) -> Result<Vec<VectorDiff<Event>>, EventCacheError> {
        match preprocessing {
            ReloadPreprocessing::ForgetAll => {
                // Clear the `LinkedChunk` and broadcast the updates to the store.
                self.room_linked_chunk_mut().reset();
                self.propagate_changes().await?;

                // Reset the pagination state too: pretend we never waited for the initial
                // prev-batch token, and indicate that we're not at the start of the timeline,
                // since we don't know about that anymore.
                *self.waited_for_initial_prev_token_mut() = false;

                // Note: this may cancel an ongoing pagination.
                self.state
                    .pagination_status
                    .set(SharedPaginationStatus::Idle { hit_timeline_start: false });

                self.rebuild_pending_redactions().await?;
            }

            ReloadPreprocessing::None => {}
        }

        self.shrink_to_last_reloaded_chunk().await?;

        Ok(self.room_linked_chunk_mut().updates_as_vector_diffs())
    }

    /// If storage is enabled, unload all the chunks, then reloads only the
    /// last one.
    ///
    /// If storage's enabled, return a diff update that starts with a clear
    /// of all events; as a result, the caller may override any
    /// pending diff updates with the result of this function.
    ///
    /// Otherwise, returns `None`.
    #[instrument(skip(self))]
    async fn shrink_to_last_reloaded_chunk(&mut self) -> Result<(), EventCacheError> {
        // Attempt to load the last chunk.
        let linked_chunk_id = LinkedChunkId::Room(&self.state.room_id);

        let full_linked_chunk_metadata =
            match load_linked_chunk_metadata(&self.store, linked_chunk_id).await {
                Ok(metas) => metas,
                Err(err) => {
                    error!("error when reloading a linked chunk's metadata from the store: {err}");

                    // Try to clear storage for this room.
                    self.store
                        .handle_linked_chunk_updates(linked_chunk_id, vec![Update::Clear])
                        .await?;

                    // Restart with an empty linked chunk.
                    None
                }
            };

        let (last_chunk, chunk_identifier_generator) =
            match self.store.load_last_chunk(linked_chunk_id).await {
                Ok(pair) => pair,

                Err(err) => {
                    // If loading the last chunk failed, clear the entire linked chunk.
                    error!("error when reloading a linked chunk from memory: {err}");

                    // Clear storage for this room.
                    self.store
                        .handle_linked_chunk_updates(linked_chunk_id, vec![Update::Clear])
                        .await?;

                    // Restart with an empty linked chunk.
                    (None, ChunkIdentifierGenerator::new_from_scratch())
                }
            };

        debug!("unloading the linked chunk, and resetting it to its last chunk");

        // Remove all the chunks from the linked chunks, except for the last one, and
        // updates the chunk identifier generator.
        if let Err(err) = self.state.room_linked_chunk.shrink_to_last_reloaded_chunk(
            last_chunk,
            chunk_identifier_generator,
            full_linked_chunk_metadata,
        ) {
            error!("error when replacing the linked chunk: {err}");

            self.state.room_linked_chunk.reset();
            self.propagate_changes().await?;

            // Reset the pagination state too: pretend we never waited for the initial
            // prev-batch token, and indicate that we're not at the start of the
            // timeline, since we don't know about that anymore.
            self.state.waited_for_initial_prev_token = false;

            // Note: this may cancel an ongoing pagination.
            self.state
                .pagination_status
                .set(SharedPaginationStatus::Idle { hit_timeline_start: false });

            return Ok(());
        }

        // Let pagination observers know that we may have not reached the start of the
        // timeline. This may cancel an ongoing pagination.
        self.state
            .pagination_status
            .set(SharedPaginationStatus::Idle { hit_timeline_start: false });

        Ok(())
    }

    /// Automatically shrink the room if there are no more subscribers, as
    /// indicated by the atomic number of active subscribers.
    #[must_use = "Propagate `VectorDiff` updates via `RoomEventCacheUpdate`"]
    pub async fn auto_shrink_if_no_subscribers(
        &mut self,
    ) -> Result<Option<Vec<VectorDiff<Event>>>, EventCacheError> {
        let number_of_subscribers = self.state.subscribers_handle.count();

        trace!(number_of_subscribers, "received request to auto-shrink");

        if number_of_subscribers == 0 {
            // There is no more subscribers listening to this cache, we can shrink the state
            // to its last chunk to save memory.
            //
            // In theory, between the condition (`… == 0`) and this instruction, a new
            // subscriber could be created, creating a race, except that this method takes a
            // `&mut`, ensuring an exclusive access to the state, ensuring no other
            // subscribers can be created.
            self.shrink_to_last_reloaded_chunk().await?;

            Ok(Some(self.state.room_linked_chunk.updates_as_vector_diffs()))
        } else {
            Ok(None)
        }
    }

    /// Decide what a same-ID re-delivery may change, and drop what it may not.
    ///
    /// An event we cannot decrypt, a replacement we can no longer use, or an
    /// older or invalid replacement is *unknown or worse*, not proof that what
    /// we already decoded is wrong, so none of them may erase it. A
    /// re-delivered redacted envelope is the opposite: authoritative
    /// redaction evidence, and it is never discarded as a downgrade. A
    /// redacted copy is never revived by an unredacted re-delivery.
    ///
    /// The dropped event is also removed from the duplicate sets, otherwise the
    /// removal step would delete the cached copy without re-inserting anything.
    async fn merge_duplicate_evidence(
        &mut self,
        events: &mut Vec<Event>,
        in_memory_duplicates: &mut Vec<(OwnedEventId, Position)>,
        in_store_duplicates: &mut Vec<(OwnedEventId, Position)>,
    ) -> Result<(), EventCacheError> {
        let mut dropped = Vec::new();

        for event in events.iter() {
            let Some(event_id) = event.event_id() else {
                continue;
            };

            let Some((_, cached)) = self.find_event(event_id).await? else {
                continue;
            };

            let incoming_redacted = is_positively_redacted_event(event);
            let cached_redacted = self.is_positively_redacted(event_id, &cached);

            let drop = if incoming_redacted {
                // Authoritative redaction evidence is always admitted.
                false
            } else if cached_redacted {
                // A redacted copy must not be revived by an unredacted re-delivery.
                true
            } else {
                (!carries_usable_content(event) && carries_usable_content(&cached))
                    || loses_replacement_evidence(&cached, event)
            };

            if drop {
                dropped.push(event_id.to_owned());
            }
        }

        if dropped.is_empty() {
            return Ok(());
        }

        let is_dropped = |event_id: &EventId| dropped.iter().any(|id| id == event_id);
        events.retain(|event| event.event_id().is_none_or(|id| !is_dropped(id)));
        in_memory_duplicates.retain(|(id, _)| !is_dropped(id));
        in_store_duplicates.retain(|(id, _)| !is_dropped(id));

        Ok(())
    }

    /// Apply, in place, the duplicates that do carry new evidence: a
    /// re-delivered redacted envelope, or a strictly newer valid bundled
    /// replacement.
    ///
    /// Invariant: what search verification reads must equal what the timeline
    /// renders. Discarding the newer envelope would let the cached root and the
    /// rendered timeline disagree after a duplicate sync.
    ///
    /// Returns the linked-chunk diffs for the refreshed events.
    async fn refresh_bundled_replacements(
        &mut self,
        events: &[Event],
        in_store_duplicates: &[(OwnedEventId, Position)],
    ) -> Result<Vec<VectorDiff<Event>>, EventCacheError> {
        let mut refreshed = false;

        for event in events {
            let Some(event_id) = event.event_id() else {
                continue;
            };

            let Some((location, cached)) = self.find_event(event_id).await? else {
                continue;
            };

            let cached_redacted = self.is_positively_redacted(event_id, &cached);
            let apply = if is_positively_redacted_event(event) {
                !cached_redacted
            } else if cached_redacted {
                false
            } else if let Some(incoming_replacement) = usable_replacement(event) {
                // Only a strictly newer, valid replacement is new evidence; the
                // drop pass already rejected older or invalid ones.
                let cached_key = usable_replacement(&cached)
                    .and_then(|replacement| replacement_key(&replacement));
                replacement_key(&incoming_replacement) > cached_key
                    && replacement_valid(&cached, &incoming_replacement)
            } else {
                false
            };

            if !apply {
                continue;
            }

            // The refresh must go through the sanitizing, index-notifying update
            // path, so a store-only root cannot acquire new visible text without
            // the index subscriber seeing it and without the relation narrowing.
            match location {
                EventLocation::Memory(_) => {
                    self.replace_event_at(location, event.clone()).await?;
                }
                EventLocation::Store => {
                    let Some(position) = in_store_duplicates
                        .iter()
                        .find(|(id, _)| id == event_id)
                        .map(|(_, position)| *position)
                    else {
                        continue;
                    };

                    self.apply_store_only_updates(vec![Update::ReplaceItem {
                        at: position,
                        item: event.clone(),
                    }])
                    .await?;
                }
            }
            refreshed = true;
        }

        Ok(if refreshed { self.room_linked_chunk.updates_as_vector_diffs() } else { Vec::new() })
    }

    /// Whether we hold positive proof that the cached event was redacted:
    /// either the committed redaction marker, or a pending redaction for it.
    fn is_positively_redacted(&self, event_id: &EventId, cached: &Event) -> bool {
        if !self.pending_redactions_for(&[event_id.to_owned()]).is_empty() {
            return true;
        }

        cached.raw().deserialize().map(|event| event.is_redacted()).unwrap_or(false)
    }

    /// Remove events by their position, in `EventLinkedChunk` and in
    /// `EventCacheStore`.
    ///
    /// This method is purposely isolated because it must ensure that
    /// positions are sorted appropriately or it can be disastrous.
    #[instrument(skip_all)]
    pub async fn remove_events(
        &mut self,
        in_memory_events: Vec<(OwnedEventId, Position)>,
        in_store_events: Vec<(OwnedEventId, Position)>,
    ) -> Result<(), EventCacheError> {
        // In-store events.
        if !in_store_events.is_empty() {
            let mut positions = in_store_events
                .into_iter()
                .map(|(_event_id, position)| position)
                .collect::<Vec<_>>();

            sort_positions_descending(&mut positions);

            let updates =
                positions.into_iter().map(|pos| Update::RemoveItem { at: pos }).collect::<Vec<_>>();

            self.apply_store_only_updates(updates).await?;
        }

        // In-memory events.
        if in_memory_events.is_empty() {
            // Nothing else to do, return early.
            return Ok(());
        }

        // `remove_events_by_position` is responsible of sorting positions.
        self.state
            .room_linked_chunk
            .remove_events_by_position(
                in_memory_events.into_iter().map(|(_event_id, position)| position).collect(),
            )
            .expect("failed to remove an event");

        self.propagate_changes().await
    }

    /// Rebuild the pending-redaction map from the store, re-applying any
    /// redaction whose target is already known.
    async fn rebuild_pending_redactions(&mut self) -> Result<(), EventCacheError> {
        self.state.rebuild_pending_redactions_with_store(&self.store).await
    }

    /// Apply a redaction that was persisted before its target arrived.
    async fn apply_pending_redaction_to_event(
        &mut self,
        event: &mut Event,
    ) -> Result<(), EventCacheError> {
        let Some(event_id) = event.event_id().map(|id| id.to_owned()) else {
            return Ok(());
        };
        let Some(redaction) = self.state.pending_redactions.lock().unwrap().get(&event_id).cloned()
        else {
            return Ok(());
        };

        if !RoomEventCacheState::apply_redaction_to_event(
            event,
            &redaction,
            &self.state.room_version_rules,
        ) {
            return Ok(());
        }

        let Some((location, _)) = self.find_event(&event_id).await? else {
            return Ok(());
        };

        self.replace_event_at(location, event.clone()).await?;
        Ok(())
    }

    /// Post-process the events committed by a live-tail refresh: flush the
    /// linked-chunk updates to the store, then apply redactions and read-receipt
    /// bookkeeping.
    pub(super) async fn post_process_live_tail_events(
        &mut self,
        events: Vec<Event>,
    ) -> Result<(), EventCacheError> {
        self.propagate_changes().await?;
        if let Err(error) = self.post_process_upserted_events(events.iter(), None).await {
            error!(?error, "post-processing a committed live-tail refresh failed");
        }

        Ok(())
    }

    pub(super) async fn propagate_changes(&mut self) -> Result<(), EventCacheError> {
        let updates = self.state.room_linked_chunk.store_updates().take();

        self.send_updates_to_store(updates).await
    }

    /// Apply some updates that are effective only on the store itself.
    ///
    /// This method should be used only for updates that happen *outside*
    /// the in-memory linked chunk. Such updates must be applied
    /// onto the ordering tracker as well as to the persistent
    /// storage.
    async fn apply_store_only_updates(
        &mut self,
        updates: Vec<Update<Event, Gap>>,
    ) -> Result<(), EventCacheError> {
        self.state.room_linked_chunk.order_tracker.map_updates(&updates);
        self.send_updates_to_store(updates).await
    }

    async fn send_updates_to_store(
        &mut self,
        updates: Vec<Update<Event, Gap>>,
    ) -> Result<(), EventCacheError> {
        let linked_chunk_id = OwnedLinkedChunkId::Room(self.state.room_id.clone());
        let changes_gap_topology = updates.iter().any(|update| {
            matches!(update, Update::NewGapChunk { .. } | Update::RemoveChunk(_) | Update::Clear)
        });

        send_updates_to_store(
            &self.store,
            linked_chunk_id,
            &self.state.linked_chunk_update_sender,
            updates,
        )
        .await?;

        if changes_gap_topology {
            self.state.gap_topology_generation = self.state.gap_topology_generation.wrapping_add(1);
        }

        Ok(())
    }

    /// Handle the result of a sync.
    ///
    /// It may send room event cache updates to the given sender, if it
    /// generated any of those.
    ///
    /// Returns `true` for the first part of the tuple if a new gap
    /// (previous-batch token) has been inserted, `false` otherwise.
    #[must_use = "Propagate `VectorDiff` updates via `RoomEventCacheUpdate`"]
    pub async fn handle_sync(
        &mut self,
        mut timeline: Timeline,
        read_receipt_event: &MaybeReceiptEventContent,
    ) -> Result<
        (bool, Vec<VectorDiff<Event>>, Option<super::RoomTimelineSyncObservation>),
        EventCacheError,
    > {
        // Capture the committed-timeline provenance before consuming the timeline.
        let limited = timeline.limited;
        let event_count = timeline.events.len();
        let prev_batch_present = timeline.prev_batch.is_some();
        let newest_event_id =
            timeline.events.iter().rev().find_map(|event| event.event_id().map(|id| id.to_owned()));

        let mut prev_batch_token = timeline.prev_batch.take();

        let DeduplicationOutcome {
            all_events: mut events,
            mut in_memory_duplicated_event_ids,
            mut in_store_duplicated_event_ids,
            non_empty_all_duplicates: all_duplicates,
        } = filter_duplicate_events(
            &self.state.own_user_id,
            &self.store,
            LinkedChunkId::Room(&self.state.room_id),
            &self.state.room_linked_chunk,
            timeline.events,
        )
        .await?;

        // If the timeline isn't limited, and we already knew about some past events,
        // then this definitely knows what the timeline head is (either we know
        // about all the events persisted in storage, or we have a gap
        // somewhere). In this case, we can ditch the previous-batch
        // token, which is an optimization to avoid unnecessary future back-pagination
        // requests.
        //
        // We can also ditch it if we knew about all the events that came from sync,
        // namely, they were all deduplicated. In this case, using the
        // previous-batch token would only result in fetching other events we
        // knew about. This is slightly incorrect in the presence of
        // network splits, but this has shown to be Good Enough™.
        if !timeline.limited && self.state.room_linked_chunk.events().next().is_some()
            || all_duplicates
        {
            prev_batch_token = None;
        }

        // A re-delivery that cannot be decrypted must not replace cached decrypted
        // content: unknown is not proof that what we already decoded is wrong.
        self.merge_duplicate_evidence(
            &mut events,
            &mut in_memory_duplicated_event_ids,
            &mut in_store_duplicated_event_ids,
        )
        .await?;

        if all_duplicates {
            // No new events and no gap (per the previous check), thus no need to change the
            // room state. We're done!
            //
            // That said, a duplicate can still carry a newer bundled replacement, so
            // refresh it in place before returning instead of discarding the evidence.
            let refreshed =
                self.refresh_bundled_replacements(&events, &in_store_duplicated_event_ids).await?;

            // We might have a new read receipt, though! If that's the case, handle it for
            // unread counts tracking.
            //
            // Post-process the ephemeral events.
            self.post_process_upserted_events(empty(), read_receipt_event.as_ref()).await?;

            return Ok((false, refreshed, None));
        }

        let has_new_gap = prev_batch_token.is_some();

        // If we've never waited for an initial previous-batch token, and we've now
        // inserted a gap, no need to wait for a previous-batch token later.
        if !self.state.waited_for_initial_prev_token && has_new_gap {
            self.state.waited_for_initial_prev_token = true;
        }

        // Remove the old duplicated events.
        //
        // We don't have to worry the removals can change the position of the existing
        // events, because we are pushing all _new_ `events` at the back.
        self.remove_events(in_memory_duplicated_event_ids, in_store_duplicated_event_ids).await?;

        self.redact_pending_events(&mut events);

        self.state.room_linked_chunk.push_live_events(
            prev_batch_token.map(|prev_token| Gap { token: prev_token }),
            &events,
        );

        // Update the store.
        self.propagate_changes().await?;

        // Post-process newly inserted events.
        self.post_process_upserted_events(events.iter(), read_receipt_event.as_ref()).await?;

        if timeline.limited && has_new_gap {
            // If there was a previous batch token for a limited timeline, unload the chunks
            // so it only contains the last one; otherwise, there might be a
            // valid gap in between, and observers may not render it (yet).
            //
            // We must do this *after* persisting these events to storage.
            self.shrink_to_last_reloaded_chunk().await?;
        }

        let timeline_event_diffs = self.room_linked_chunk.updates_as_vector_diffs();

        let inserted_gap = if has_new_gap {
            let chunks =
                self.store.load_all_chunks(LinkedChunkId::Room(&self.state.room_id)).await?;
            super::pagination::inspect_ordered_chunks(
                &self.state.room_id,
                self.state.gap_snapshot_id,
                self.state.gap_topology_generation,
                &super::pagination::order_persisted_chunks(chunks)?,
            )
            .gaps
            .last()
            .cloned()
        } else {
            None
        };

        Ok((
            has_new_gap,
            timeline_event_diffs,
            Some(super::RoomTimelineSyncObservation {
                sequence: 0,
                limited,
                event_count,
                prev_batch_present,
                newest_event_id,
                inserted_gap,
            }),
        ))
    }

    // --------------------------------------------
    // utility methods
    // --------------------------------------------

    /// Post-process newly inserted or updated events.
    pub(super) async fn post_process_upserted_events<'i, I>(
        &mut self,
        events: I,
        receipt_event: Option<&ReceiptEventContent>,
    ) -> Result<(), EventCacheError>
    where
        I: Iterator<Item = &'i Event>,
    {
        let events = events.cloned().collect::<Vec<_>>();

        // Replay any redaction that arrived before its target, now that the
        // target is known to this cache.
        for event in &events {
            let pending = event.event_id().is_some_and(|event_id| {
                self.state.pending_redactions.lock().unwrap().contains_key(event_id)
            });
            if pending {
                let mut event = event.clone();
                self.apply_pending_redaction_to_event(&mut event).await?;
            }
        }

        for event in &events {
            self.maybe_apply_new_redaction(event).await?;

            // Save a bundled thread event, if there was one.
            if let Some(bundled_thread) = event.bundled_latest_thread_event() {
                self.save_events([bundled_thread]).await?;
            }
        }

        self.update_read_receipts(receipt_event).await?;

        Ok(())
    }

    /// Update read receipts for all events in the room, based on the current
    /// state of the in-memory linked chunk.
    pub async fn update_read_receipts(
        &mut self,
        receipt_event: Option<&ReceiptEventContent>,
    ) -> Result<(), EventCacheError> {
        let Some(room) = self.state.weak_room.get() else {
            debug!("can't update read receipts: client's closing");
            return Ok(());
        };

        let prev_read_receipts = room.read_receipts().clone();
        let mut read_receipts = prev_read_receipts.clone();

        let client = room.client();
        let event_filter =
            RoomReadReceiptEventFilter::new(&self.state, client.state_store(), &self.store).await?;

        compute_unread_counts(
            &self.state.own_user_id,
            receipt_event,
            &self.state.room_linked_chunk,
            &event_filter,
            &mut read_receipts,
            self.state.back_pagination_queue.as_ref(),
        )
        .await;

        if prev_read_receipts != read_receipts {
            // The read receipt has changed! Do a little dance to update the `RoomInfo` in
            // the state store, and then in the room itself, so that observers
            // can be notified of the change.
            let result = room
                .update_and_save_room_info(|mut room_info| {
                    room_info.set_read_receipts(read_receipts);
                    (room_info, RoomInfoNotableUpdateReasons::READ_RECEIPT)
                })
                .await;

            if let Err(error) = result {
                error!(room_id = ?room.room_id(), ?error, "Failed to save the changes");
            }
        }

        Ok(())
    }

    /// Update a thread summary on the given thread root, if needs be.
    #[must_use = "Propagate `VectorDiff` updates via `RoomEventCacheUpdate`"]
    pub async fn update_thread_summary(
        &mut self,
        thread_id: &EventId,
        new_thread_summary: Option<ThreadSummary>,
    ) -> Result<Vec<VectorDiff<Event>>, EventCacheError> {
        let Some((location, mut thread_root_event)) = self.find_event(thread_id).await? else {
            trace!(%thread_id, "thread root event is missing from the room linked chunk");
            return Ok(Vec::new());
        };

        // Trigger an update to observers.
        trace!(%thread_id, "updating thread summary: {new_thread_summary:?}");
        thread_root_event.thread_summary = ThreadSummaryStatus::from_opt(new_thread_summary);
        self.replace_event_at(location, thread_root_event).await?;

        Ok(self.room_linked_chunk.updates_as_vector_diffs())
    }

    /// Replaces a single event, be it saved in memory or in the store.
    ///
    /// If it was saved in memory, this will emit a notification to
    /// observers that a single item has been replaced. Otherwise,
    /// such a notification is not emitted, because observers are
    /// unlikely to observe the store updates directly.
    pub async fn replace_event_at(
        &mut self,
        location: EventLocation,
        event: Event,
    ) -> Result<(), EventCacheError> {
        match location {
            EventLocation::Memory(position) => {
                self.state
                    .room_linked_chunk
                    .replace_event_at(position, event)
                    .expect("should have been a valid position of an item");
                // We just changed the in-memory representation; synchronize this with
                // the store.
                self.propagate_changes().await?;
            }
            EventLocation::Store => {
                self.save_events([event]).await?;
            }
        }

        Ok(())
    }

    /// If the given event is a redaction, try to retrieve the
    /// to-be-redacted event in the chunk, and replace it by the
    /// redacted form.
    #[instrument(skip_all)]
    async fn maybe_apply_new_redaction(&mut self, event: &Event) -> Result<(), EventCacheError> {
        let Some(target_event_id) =
            extract_redaction_target(event.raw(), &self.room_version_rules.redaction)
        else {
            trace!("missing target event id from the redaction event");
            return Ok(());
        };

        // Keep the committed redaction even when its target is not loaded yet.
        // The same map is rebuilt from encrypted storage when the cache opens.
        self.remember_redaction(event);

        // Replace the redacted event by a redacted form, if we knew about it.
        let Some((location, mut target_event)) = self.find_event(&target_event_id).await? else {
            trace!("redacted event is missing from the linked chunk");
            return Ok(());
        };

        let target_event_raw = target_event.raw();

        // Don't redact already redacted events.
        if let Ok(deserialized) = target_event_raw.deserialize()
            && deserialized.is_redacted()
        {
            return Ok(());
        }

        if let Some(redacted_event) = apply_redaction(
            target_event_raw,
            event.raw().cast_ref_unchecked::<SyncRoomRedactionEvent>(),
            &self.room_version_rules.redaction,
        ) {
            // It's safe to cast `redacted_event` here:
            // - either the event was an `AnyTimelineEvent` cast to `AnySyncTimelineEvent`
            //   when calling .raw(), so it's still one under the hood.
            // - or it wasn't, and it's a plain `AnySyncTimelineEvent` in this case.
            target_event.replace_raw(redacted_event.cast_unchecked());

            self.replace_event_at(location, target_event.clone()).await?;
        }

        Ok(())
    }

    /// Try to locate the events in the linked chunk corresponding to the given
    /// list of resolved events, and replace them, while alerting observers
    /// about the update.
    #[cfg(feature = "e2e-encryption")]
    #[must_use = "Propagate `VectorDiff` updates via `TimelineVectorDiffs`"]
    pub(in super::super::super) async fn replace_in_memory_utds(
        &mut self,
        resolved_events: &[MaybeResolvedEvent],
    ) -> Result<Option<Vec<VectorDiff<Event>>>, EventCacheError> {
        Ok(if self.room_linked_chunk_mut().replace_utds(resolved_events) {
            // Drain the updates to the store, events have already been updated with
            // `save_events`!
            let _ = self.room_linked_chunk_mut().store_updates().take();

            self.post_process_upserted_events(
                resolved_events.iter().filter_map(|resolved_event| resolved_event.as_resolved()),
                // Read receipt events aren't encrypted, so we can't have decrypted a new
                // one here. As a result, we don't have any new receipt events to
                // post-process, so we can just pass `None` here.
                //
                // Note: read receipts may be updated anyhow in the post-processing step,
                // as the redecryption may have decrypted some events that don't count as
                // unreads.
                None,
            )
            .await?;

            Some(self.room_linked_chunk_mut().updates_as_vector_diffs())
        } else {
            None
        })
    }

    /// Save events into the database, without notifying observers.
    pub async fn save_events(
        &mut self,
        events: impl IntoIterator<Item = Event>,
    ) -> Result<(), EventCacheError> {
        let store = self.store.clone();
        let room_id = self.state.room_id.clone();
        let events = events.into_iter().collect::<Vec<_>>();

        // Spawn a task so the save is uninterrupted by task cancellation.
        spawn(async move {
            for event in events {
                store.save_event(&room_id, event).await?;
            }
            super::Result::Ok(())
        })
        .await
        .expect("joining failed")?;

        Ok(())
    }

    #[cfg(test)]
    pub fn is_dirty(&self) -> bool {
        EventCacheStoreLockGuard::is_dirty(&self.store)
    }
}

/// Whether the event, or its bundled replacement, holds content we can actually
/// decode. An undecryptable event alone is unknown, not evidence against a
/// copy we already decoded.
fn carries_usable_content(event: &Event) -> bool {
    !event.kind.is_utd() || usable_replacement(event).is_some()
}

/// Whether the event itself carries positive proof that it was redacted.
fn is_positively_redacted_event(event: &Event) -> bool {
    event.raw().deserialize().map(|event| event.is_redacted()).unwrap_or(false)
}

/// The event's bundled replacement, when it is present, decodable, and decodes
/// into the room-message replacement the resolver can actually apply.
fn usable_replacement(event: &Event) -> Option<Box<Event>> {
    let bundled = event.bundled_replacement()?;
    if bundled.kind.is_utd() {
        return None;
    }

    matches!(
        bundled.raw().deserialize(),
        Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(message)))
            if message.as_original().is_some()
    )
    .then_some(bundled)
}

/// Whether the incoming event would lose, or downgrade, replacement evidence
/// the cached copy still holds.
fn loses_replacement_evidence(cached: &Event, incoming: &Event) -> bool {
    let Some(cached_replacement) = usable_replacement(cached) else {
        return false;
    };

    let Some(incoming_replacement) = usable_replacement(incoming) else {
        return true;
    };

    replacement_key(&incoming_replacement) <= replacement_key(&cached_replacement)
        || !replacement_valid(cached, &incoming_replacement)
}

/// Whether a replacement is valid against the root we hold.
fn replacement_valid(cached: &Event, replacement: &Event) -> bool {
    check_validity_of_replacement_events(
        cached.raw(),
        cached.encryption_info().map(|info| &**info),
        replacement.raw(),
        replacement.encryption_info().map(|info| &**info),
    )
    .is_ok()
}

/// The raw `(timestamp, event id)` of a bundled replacement, when it has one.
/// `None` sorts before any replacement, so a first aggregate counts as newer.
fn replacement_key(replacement: &Event) -> Option<(u64, OwnedEventId)> {
    let timestamp = replacement.raw().get_field::<u64>("origin_server_ts").ok().flatten()?;
    Some((timestamp, replacement.event_id()?.to_owned()))
}

#[cfg(test)]
mod tests {
    use matrix_sdk_base::RoomState;
    use matrix_sdk_test::{async_test, event_factory::EventFactory};
    use ruma::{
        event_id,
        events::room::message::{
            RedactedRoomMessageEventContent, RoomMessageEventContentWithoutRelation,
        },
        room_id, user_id,
    };

    use super::{is_positively_redacted_event, replacement_key, usable_replacement};
    use crate::{event_cache::caches::room::RoomEventCache, test_utils::logged_in_client};

    #[async_test]
    async fn test_utd_redelivery_does_not_erase_decoded_content() {
        use matrix_sdk_base::{
            deserialized_responses::{TimelineEvent, UnableToDecryptInfo, UnableToDecryptReason},
            sync::Timeline,
        };

        use super::super::super::read_receipts::MaybeReceiptEventContent;

        let client = logged_in_client(None).await;
        let room_id = room_id!("!galette:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (room_event_cache, _drop_handles) = room.event_cache().await.unwrap();

        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let event_id = event_id!("$decoded");

        let mut state = room_event_cache.inner.state.write().await.unwrap();
        state.save_events([f.text_msg("knownneedle").event_id(event_id).into()]).await.unwrap();

        let utd = TimelineEvent::from_utd(
            ruma::serde::Raw::from_json_string(
                serde_json::json!({
                    "type": "m.room.encrypted", "event_id": event_id, "room_id": room_id,
                    "sender": "@ben:saucisse.bzh", "origin_server_ts": 100,
                    "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "synthetic",
                        "device_id": "TEST", "sender_key": "synthetic", "session_id": "s"},
                })
                .to_string(),
            )
            .unwrap(),
            UnableToDecryptInfo {
                session_id: Some("s".to_owned()),
                reason: UnableToDecryptReason::Unknown,
            },
        );

        state
            .handle_sync(
                Timeline { limited: false, prev_batch: None, events: vec![utd] },
                &MaybeReceiptEventContent::none(),
            )
            .await
            .unwrap();

        let (_, cached) = state.find_event(event_id).await.unwrap().unwrap();
        assert!(
            !cached.kind.is_utd(),
            "an undecryptable re-delivery must not erase decoded content"
        );
    }

    /// A root carrying a bundled replacement, as the server aggregates it.
    fn root_with_bundle(
        f: &EventFactory,
        root: &ruma::EventId,
        edit: &ruma::EventId,
        edit_ts: u64,
    ) -> matrix_sdk_base::event_cache::Event {
        f.text_msg("originalneedle")
            .event_id(root)
            .with_bundled_edit(
                f.text_msg("* currentneedle").server_ts(edit_ts).event_id(edit).edit(
                    root,
                    RoomMessageEventContentWithoutRelation::text_plain("currentneedle"),
                ),
            )
            .into_event()
    }

    /// Sync one batch into the room cache and return the resulting replacement
    /// key.
    async fn sync_and_read_bundle(
        cache: &RoomEventCache,
        events: Vec<matrix_sdk_base::event_cache::Event>,
        root: &ruma::EventId,
    ) -> Option<(u64, String)> {
        sync_batch(cache, events).await;
        let cached = cached_event(cache, root).await;
        let replacement = usable_replacement(&cached)?;
        let (timestamp, event_id) = replacement_key(&replacement)?;
        Some((timestamp, event_id.to_string()))
    }

    /// Sync one batch into the room cache through the production ingestion
    /// path.
    async fn sync_batch(cache: &RoomEventCache, events: Vec<matrix_sdk_base::event_cache::Event>) {
        use matrix_sdk_base::sync::Timeline;

        use super::super::super::read_receipts::MaybeReceiptEventContent;

        cache
            .inner
            .state
            .write()
            .await
            .unwrap()
            .handle_sync(
                Timeline { limited: false, prev_batch: None, events },
                &MaybeReceiptEventContent::none(),
            )
            .await
            .unwrap();
    }

    /// Read a cached event through the same lookup the resolver uses.
    async fn cached_event(
        cache: &RoomEventCache,
        event_id: &ruma::EventId,
    ) -> matrix_sdk_base::event_cache::Event {
        cache.inner.state.read().await.unwrap().find_event(event_id).await.unwrap().unwrap().1
    }

    /// A malformed bundled replacement: valid relation, undecodable content.
    fn malformed_bundle(
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        root: &ruma::EventId,
    ) -> ruma::serde::Raw<ruma::events::AnySyncTimelineEvent> {
        ruma::serde::Raw::from_json_string(
            serde_json::json!({
                "type": "m.room.message", "event_id": "$malformed-bundle-edit",
                "room_id": room_id, "sender": sender, "origin_server_ts": 200,
                "content": {"msgtype": "m.text", "body": 42,
                    "m.relates_to": {"rel_type": "m.replace", "event_id": root}},
            })
            .to_string(),
        )
        .unwrap()
    }

    #[async_test]
    async fn test_redacted_root_is_not_revived_by_a_bundled_redelivery() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!redacted-bundle:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let root = event_id!("$redacted-bundle-root");
        let edit = event_id!("$redacted-bundle-edit");

        let plain = f.text_msg("originalneedle").event_id(root).into_event();
        assert!(sync_and_read_bundle(&cache, vec![plain], root).await.is_none());

        // A redaction whose target we already know is pending until the target is
        // revisited; it is positive proof, so the re-delivery must not revive it.
        cache
            .inner
            .state
            .write()
            .await
            .unwrap()
            .pending_redactions
            .lock()
            .unwrap()
            .insert(root.to_owned(), f.text_msg("ignored").into_event());

        let revived = root_with_bundle(&f, root, edit, 100);
        assert!(
            sync_and_read_bundle(&cache, vec![revived], root).await.is_none(),
            "a redacted root must not be revived by an unredacted re-delivery"
        );
    }

    #[async_test]
    async fn test_mixed_batch_keeps_the_cached_bundled_replacement() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!mixed-bundle:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let root = event_id!("$mixed-bundle-root");
        let edit = event_id!("$mixed-bundle-edit");

        let with_bundle = root_with_bundle(&f, root, edit, 100);
        assert_eq!(
            sync_and_read_bundle(&cache, vec![with_bundle], root).await,
            Some((100, edit.to_string()))
        );

        // The duplicate root loses its aggregate while a genuinely new event is
        // appended in the same batch; the cached replacement must survive.
        let bundleless = f.text_msg("originalneedle").event_id(root).into_event();
        let fresh = f.text_msg("unrelated").event_id(event_id!("$mixed-bundle-new")).into_event();
        assert_eq!(
            sync_and_read_bundle(&cache, vec![bundleless, fresh], root).await,
            Some((100, edit.to_string())),
            "a bundleless duplicate must not erase the cached replacement"
        );
    }

    #[async_test]
    async fn test_invalid_newer_bundle_does_not_erase_the_cached_replacement() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!invalid-bundle:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let root = event_id!("$invalid-bundle-root");
        let edit = event_id!("$invalid-bundle-edit");

        let with_bundle = root_with_bundle(&f, root, edit, 100);
        assert_eq!(
            sync_and_read_bundle(&cache, vec![with_bundle], root).await,
            Some((100, edit.to_string()))
        );

        // A newer replacement from another sender is invalid, so it must not
        // displace the valid one we already hold.
        let other = EventFactory::new().room(room_id).sender(user_id!("@mallory:saucisse.bzh"));
        let invalid = f
            .text_msg("originalneedle")
            .event_id(root)
            .with_bundled_edit(
                other
                    .text_msg("* evil")
                    .server_ts(200)
                    .event_id(event_id!("$invalid-bundle-new"))
                    .edit(root, RoomMessageEventContentWithoutRelation::text_plain("evil")),
            )
            .into_event();
        assert_eq!(
            sync_and_read_bundle(&cache, vec![invalid], root).await,
            Some((100, edit.to_string())),
            "an invalid newer replacement must not displace a valid cached one"
        );
    }

    #[async_test]
    async fn test_redacted_redelivery_is_applied_instead_of_dropped() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!redacted-redelivery:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let sender = user_id!("@ben:saucisse.bzh");
        let f = EventFactory::new().room(room_id).sender(sender);
        let root = event_id!("$redacted-redelivery-root");
        let edit = event_id!("$redacted-redelivery-edit");

        let with_bundle = root_with_bundle(&f, root, edit, 100);
        assert_eq!(
            sync_and_read_bundle(&cache, vec![with_bundle], root).await,
            Some((100, edit.to_string()))
        );

        // The server re-sends the root already redacted. That envelope is the only
        // redaction evidence this cache has, so it must be applied, not dropped as
        // a downgrade of the bundled replacement.
        let redacted =
            f.redacted(sender, RedactedRoomMessageEventContent::new()).event_id(root).into_event();
        sync_batch(&cache, vec![redacted]).await;

        let cached = cached_event(&cache, root).await;
        assert!(
            is_positively_redacted_event(&cached),
            "a re-delivered redacted envelope must be applied"
        );
        // `resolve_cached_message` only exists with `experimental-search`, so the
        // end-to-end assertion is gated while the cache-level one always runs.
        #[cfg(feature = "experimental-search")]
        assert!(room.resolve_cached_message(root).await.unwrap().is_none());
    }

    #[async_test]
    async fn test_mixed_batch_keeps_the_newer_cached_bundle() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!mixed-older-bundle:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let root = event_id!("$mixed-older-root");
        let newer = event_id!("$mixed-older-newer");
        let older = event_id!("$mixed-older-older");

        assert_eq!(
            sync_and_read_bundle(&cache, vec![root_with_bundle(&f, root, newer, 200)], root).await,
            Some((200, newer.to_string()))
        );

        // A mixed batch carries the duplicate root with an older aggregate; the
        // batch is not all-duplicates, so it must still not downgrade the cache.
        let fresh = f.text_msg("unrelated").event_id(event_id!("$mixed-older-new")).into_event();
        assert_eq!(
            sync_and_read_bundle(&cache, vec![root_with_bundle(&f, root, older, 100), fresh], root)
                .await,
            Some((200, newer.to_string())),
            "a mixed batch must not replace a newer cached aggregate with an older one"
        );
    }

    #[async_test]
    async fn test_mixed_batch_keeps_the_cached_bundle_over_a_malformed_one() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!mixed-malformed:saucisse.bzh");
        client.event_cache().subscribe().unwrap();
        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();
        let (cache, _handles) = room.event_cache().await.unwrap();
        let sender = user_id!("@ben:saucisse.bzh");
        let f = EventFactory::new().room(room_id).sender(sender);
        let root = event_id!("$mixed-malformed-root");
        let edit = event_id!("$mixed-malformed-edit");

        assert_eq!(
            sync_and_read_bundle(&cache, vec![root_with_bundle(&f, root, edit, 100)], root).await,
            Some((100, edit.to_string()))
        );

        // The newer aggregate does not decode into replacement content, so it is not
        // evidence the cache can use.
        let malformed = f
            .text_msg("originalneedle")
            .event_id(root)
            .with_bundled_edit(malformed_bundle(room_id, sender, root))
            .into_event();
        let fresh =
            f.text_msg("unrelated").event_id(event_id!("$mixed-malformed-new")).into_event();
        assert_eq!(
            sync_and_read_bundle(&cache, vec![malformed, fresh], root).await,
            Some((100, edit.to_string())),
            "an undecodable newer aggregate must not displace a usable one"
        );
    }

    #[async_test]
    async fn test_save_event() {
        let client = logged_in_client(None).await;
        let room_id = room_id!("!galette:saucisse.bzh");

        let event_cache = client.event_cache();
        event_cache.subscribe().unwrap();

        let f = EventFactory::new().room(room_id).sender(user_id!("@ben:saucisse.bzh"));
        let event_id = event_id!("$1");

        client.base_client().get_or_create_room(room_id, RoomState::Joined);
        let room = client.get_room(room_id).unwrap();

        let (room_event_cache, _drop_handles) = room.event_cache().await.unwrap();
        room_event_cache
            .inner
            .state
            .write()
            .await
            .unwrap()
            .save_events([f.text_msg("hey there").event_id(event_id).into()])
            .await
            .unwrap();

        // Retrieving the event at the room-wide cache works.
        assert!(room_event_cache.find_event(event_id).await.unwrap().is_some());
    }
}
