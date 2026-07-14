// Copyright 2024 The Matrix.org Foundation C.I.C.
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

//! The [`RoomPagination`] type makes it possible to paginate a
//! [`RoomEventCache`].
//!
//! [`RoomEventCache`]: super::super::super::RoomEventCache

use std::{
    collections::HashMap,
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use eyeball::{SharedObservable, Subscriber};
use eyeball_im::VectorDiff;
use futures_core::{Stream, ready};
use matrix_sdk_base::{
    event_cache::{Event, Gap},
    linked_chunk::{ChunkContent, ChunkIdentifier, LinkedChunkId, RawChunk, Update},
};
use matrix_sdk_common::executor::spawn;
use pin_project_lite::pin_project;
use ruma::{EventId, OwnedEventId, OwnedRoomId, api::Direction};
use tracing::{error, trace};

pub use super::super::pagination::PaginationStatus;
use super::{
    super::{
        super::{
            EventCacheError, EventsOrigin, Result, RoomEventCacheGenericUpdate,
            deduplicator::{DeduplicationOutcome, filter_duplicate_events},
        },
        TimelineVectorDiffs,
        pagination::{
            BackPaginationOutcome, LoadMoreEventsBackwardsOutcome, PaginatedCache, Pagination,
        },
    },
    PostProcessingOrigin, RoomEventCacheInner, RoomEventCacheUpdate,
};
use crate::{event_cache::caches::pagination::SharedPaginationStatus, room::MessagesOptions};

/// Whether the persisted room timeline is known to be continuous.
// Matrix desktop fork patch surface: opaque persisted-gap inspection for
// koushi #260. Pagination tokens and linked-chunk identifiers stay SDK-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomTimelineContinuity {
    /// No persisted timeline evidence exists yet.
    Unknown,
    /// One or more repairable gaps exist.
    Gapped,
    /// The persisted timeline contains no gaps and has a definitive start.
    Complete,
}

/// An opaque handle for one persisted room timeline gap.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomTimelineGapHandle {
    room_id: OwnedRoomId,
    snapshot_id: u64,
    chunk_identifier: ChunkIdentifier,
    token: String,
}

impl fmt::Debug for RoomTimelineGapHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RoomTimelineGapHandle").finish_non_exhaustive()
    }
}

/// A token-free description of one persisted room timeline gap.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomTimelineGapDescriptor {
    /// Opaque, snapshot-scoped handle used to request repair.
    pub handle: RoomTimelineGapHandle,
    /// Revision of the persisted gap topology observed with this descriptor.
    pub revision: u64,
    /// Nearest known event on the older side of the gap.
    pub older_event_id: Option<OwnedEventId>,
    /// Nearest known event on the newer side of the gap.
    pub newer_event_id: Option<OwnedEventId>,
}

impl fmt::Debug for RoomTimelineGapDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoomTimelineGapDescriptor")
            .field("handle", &self.handle)
            .field("revision", &self.revision)
            .field("has_older_boundary", &self.older_event_id.is_some())
            .field("has_newer_boundary", &self.newer_event_id.is_some())
            .finish()
    }
}

/// Snapshot of the persisted gap topology for a room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomTimelineGapInspection {
    /// Overall continuity proven by the persisted linked chunk.
    pub continuity: RoomTimelineContinuity,
    /// Gaps ordered from oldest to newest.
    pub gaps: Vec<RoomTimelineGapDescriptor>,
}

/// Limits one targeted gap-repair operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomTimelineGapRepairBudget {
    /// Maximum number of events requested from the homeserver.
    pub event_limit: u16,
    /// Maximum number of persisted chunks revealed into the live cache before
    /// the selected gap is reached.
    pub cached_chunk_limit: u16,
}

/// Result of one bounded targeted gap-repair request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomTimelineGapRepairOutcome {
    /// The descriptor no longer matches the persisted gap topology.
    Stale,
    /// The selected gap was not reached within the cache-reveal budget. The
    /// caller may re-inspect and continue with another bounded operation.
    Deferred {
        /// Number of persisted chunks revealed by this operation.
        cached_chunks_loaded: usize,
    },
    /// The owning client shut down before the request could be sent.
    Failed,
    /// Events were added, but the server returned another pagination token.
    Progress {
        /// Number of events returned by this request after deduplication.
        events: usize,
    },
    /// The selected gap was removed while another gap remains elsewhere.
    BoundariesJoined {
        /// Number of events returned by this request after deduplication.
        events: usize,
    },
    /// The selected gap was removed and the timeline start is now proven.
    StartReached {
        /// Number of events returned by this request after deduplication.
        events: usize,
    },
}

fn invalid_gap_topology(details: impl Into<String>) -> EventCacheError {
    EventCacheError::InvalidLinkedChunkMetadata { details: details.into() }
}

fn order_persisted_chunks(chunks: Vec<RawChunk<Event, Gap>>) -> Result<Vec<RawChunk<Event, Gap>>> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

    let total = chunks.len();
    let heads = chunks.iter().filter(|chunk| chunk.previous.is_none()).count();
    if heads != 1 {
        return Err(invalid_gap_topology("persisted room timeline must have exactly one head"));
    }

    let mut by_identifier =
        chunks.into_iter().map(|chunk| (chunk.identifier, chunk)).collect::<HashMap<_, _>>();
    if by_identifier.len() != total {
        return Err(invalid_gap_topology("persisted room timeline contains duplicate chunks"));
    }

    let head = by_identifier
        .values()
        .find(|chunk| chunk.previous.is_none())
        .map(|chunk| chunk.identifier)
        .expect("the head count was checked above");
    let mut ordered = Vec::with_capacity(total);
    let mut current = Some(head);
    let mut previous = None;

    while let Some(identifier) = current {
        let Some(chunk) = by_identifier.remove(&identifier) else {
            return Err(invalid_gap_topology("persisted room timeline contains a broken link"));
        };
        if chunk.previous != previous {
            return Err(invalid_gap_topology("persisted room timeline links are inconsistent"));
        }
        current = chunk.next;
        previous = Some(chunk.identifier);
        ordered.push(chunk);
    }

    if !by_identifier.is_empty() {
        return Err(invalid_gap_topology("persisted room timeline contains detached chunks"));
    }
    Ok(ordered)
}

fn mix_revision(revision: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *revision ^= u64::from(*byte);
        *revision = revision.wrapping_mul(0x100000001b3);
    }
}

fn inspect_ordered_chunks(
    room_id: &OwnedRoomId,
    snapshot_id: u64,
    topology_generation: u64,
    chunks: &[RawChunk<Event, Gap>],
) -> RoomTimelineGapInspection {
    if chunks.is_empty() {
        return RoomTimelineGapInspection {
            continuity: RoomTimelineContinuity::Unknown,
            gaps: Vec::new(),
        };
    }

    let gap_data = chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| match &chunk.content {
            ChunkContent::Items(_) => None,
            ChunkContent::Gap(gap) => {
                let older_event_id =
                    chunks[..index].iter().rev().find_map(|chunk| match &chunk.content {
                        ChunkContent::Gap(_) => None,
                        ChunkContent::Items(events) => {
                            events.iter().rev().find_map(Event::event_id)
                        }
                    });
                let newer_event_id =
                    chunks[index + 1..].iter().find_map(|chunk| match &chunk.content {
                        ChunkContent::Gap(_) => None,
                        ChunkContent::Items(events) => events.iter().find_map(Event::event_id),
                    });
                Some((chunk.identifier, gap.token.clone(), older_event_id, newer_event_id))
            }
        })
        .collect::<Vec<_>>();

    let mut revision = 0xcbf29ce484222325;
    mix_revision(&mut revision, &snapshot_id.to_le_bytes());
    mix_revision(&mut revision, &topology_generation.to_le_bytes());

    let gaps = gap_data
        .into_iter()
        .map(|(chunk_identifier, token, older_event_id, newer_event_id)| {
            RoomTimelineGapDescriptor {
                handle: RoomTimelineGapHandle {
                    room_id: room_id.clone(),
                    snapshot_id,
                    chunk_identifier,
                    token,
                },
                revision,
                older_event_id,
                newer_event_id,
            }
        })
        .collect::<Vec<_>>();

    RoomTimelineGapInspection {
        continuity: if gaps.is_empty() {
            RoomTimelineContinuity::Complete
        } else {
            RoomTimelineContinuity::Gapped
        },
        gaps,
    }
}

#[cfg(test)]
mod gap_snapshot_tests {
    use matrix_sdk_base::{
        event_cache::{Event, Gap},
        linked_chunk::{ChunkContent, ChunkIdentifier, RawChunk},
    };
    use ruma::OwnedRoomId;

    use super::inspect_ordered_chunks;

    #[test]
    fn reconstructed_room_state_invalidates_old_gap_descriptors() {
        let chunks: Vec<RawChunk<Event, Gap>> = vec![
            RawChunk {
                content: ChunkContent::Items(Vec::new()),
                previous: None,
                identifier: ChunkIdentifier::new(0),
                next: Some(ChunkIdentifier::new(1)),
            },
            RawChunk {
                content: ChunkContent::Gap(Gap { token: "private".to_owned() }),
                previous: Some(ChunkIdentifier::new(0)),
                identifier: ChunkIdentifier::new(1),
                next: Some(ChunkIdentifier::new(2)),
            },
            RawChunk {
                content: ChunkContent::Items(Vec::new()),
                previous: Some(ChunkIdentifier::new(1)),
                identifier: ChunkIdentifier::new(2),
                next: None,
            },
        ];
        let room_id = OwnedRoomId::try_from("!snapshot:example.org").unwrap();

        let first = inspect_ordered_chunks(&room_id, 1, 0, &chunks);
        let reconstructed = inspect_ordered_chunks(&room_id, 2, 0, &chunks);

        assert_ne!(first.gaps, reconstructed.gaps);
    }

    #[test]
    fn public_revision_does_not_fingerprint_the_private_gap_token() {
        let room_id = OwnedRoomId::try_from("!token-opacity:example.org").unwrap();
        let chunks_with_token = |token: &str| -> Vec<RawChunk<Event, Gap>> {
            vec![RawChunk {
                content: ChunkContent::Gap(Gap { token: token.to_owned() }),
                previous: None,
                identifier: ChunkIdentifier::new(0),
                next: None,
            }]
        };

        let first = inspect_ordered_chunks(&room_id, 7, 11, &chunks_with_token("candidate-a"));
        let second = inspect_ordered_chunks(&room_id, 7, 11, &chunks_with_token("candidate-b"));

        assert_eq!(first.gaps[0].revision, second.gaps[0].revision);
        assert_ne!(first.gaps[0].handle, second.gaps[0].handle);
    }
}

pin_project! {
    /// A subscriber to a [`PaginationStatus`].
    ///
    /// This is a manual implementation of a map function on top of an internal type
    /// representing a [`PaginationStatus`].
    pub struct PaginationStatusSubscriber {
        #[pin]
        subscriber: Subscriber<SharedPaginationStatus>,
    }
}

#[cfg(not(tarpaulin_include))]
impl fmt::Debug for PaginationStatusSubscriber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaginationStatusSubscriber").finish_non_exhaustive()
    }
}

impl PaginationStatusSubscriber {
    fn map(from: SharedPaginationStatus) -> PaginationStatus {
        match from {
            SharedPaginationStatus::Idle { hit_timeline_start } => {
                PaginationStatus::Idle { hit_timeline_start }
            }
            SharedPaginationStatus::Paginating { .. } => PaginationStatus::Paginating,
        }
    }

    pub fn get(&self) -> PaginationStatus {
        Self::map(self.subscriber.get())
    }

    pub async fn next(&mut self) -> Option<PaginationStatus> {
        self.subscriber.next().await.map(Self::map)
    }

    pub fn next_now(&mut self) -> PaginationStatus {
        Self::map(self.subscriber.next_now())
    }
}

impl Stream for PaginationStatusSubscriber {
    type Item = PaginationStatus;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(self.project().subscriber.as_mut().poll_next(cx)).map(Self::map))
    }
}

/// An API object to run pagination queries on a [`RoomEventCache`].
///
/// Can be created with [`RoomEventCache::pagination()`].
///
/// [`RoomEventCache`]: super::super::super::RoomEventCache
/// [`RoomEventCache::pagination()`]: super::super::super::RoomEventCache::pagination
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct RoomPagination(Pagination<Arc<RoomEventCacheInner>>);

impl RoomPagination {
    /// Construct a new [`RoomPagination`].
    pub(super) fn new(cache: Arc<RoomEventCacheInner>) -> Self {
        Self(Pagination::new(cache))
    }

    /// Starts a back-pagination for the requested number of events.
    ///
    /// This automatically takes care of waiting for a pagination token from
    /// sync, if we haven't done that before.
    ///
    /// It will run multiple back-paginations until one of these two conditions
    /// is met:
    /// - either we've reached the start of the timeline,
    /// - or we've obtained enough events to fulfill the requested number of
    ///   events.
    pub async fn run_backwards_until(
        &self,
        num_requested_events: u16,
    ) -> Result<BackPaginationOutcome> {
        let mut events = Vec::new();

        loop {
            let outcome = self.run_backwards_once_serialized(num_requested_events).await?;
            let reached_start = outcome.reached_start;
            events.extend(outcome.events);
            if reached_start || events.len() >= usize::from(num_requested_events) {
                return Ok(BackPaginationOutcome { reached_start, events });
            }
        }
    }

    /// Run a single back-pagination for the requested number of events.
    ///
    /// This automatically takes care of waiting for a pagination token from
    /// sync, if we haven't done that before.
    pub async fn run_backwards_once(&self, batch_size: u16) -> Result<BackPaginationOutcome> {
        self.run_backwards_once_serialized(batch_size).await
    }

    async fn run_backwards_once_serialized(
        &self,
        batch_size: u16,
    ) -> Result<BackPaginationOutcome> {
        let status = self.0.cache.shared_pagination_status.subscribe();

        loop {
            if let SharedPaginationStatus::Paginating { shared_task } = status.get() {
                if let Some(outcome) = shared_task.outcome().await? {
                    return Ok(outcome);
                }
                continue;
            }

            return self.0.run_backwards_once(batch_size).await;
        }
    }

    /// Inspect all persisted room-timeline gaps without exposing SDK
    /// pagination tokens or linked-chunk identifiers.
    pub async fn inspect_timeline_gaps(&self) -> Result<RoomTimelineGapInspection> {
        let state = self.0.cache.state.read().await?;
        let chunks = state.store.load_all_chunks(LinkedChunkId::Room(&state.state.room_id)).await?;
        Ok(inspect_ordered_chunks(
            &state.state.room_id,
            state.gap_snapshot_id(),
            state.gap_topology_generation(),
            &order_persisted_chunks(chunks)?,
        ))
    }

    /// Repair one persisted room-timeline gap with a single bounded network
    /// request.
    ///
    /// The descriptor is revalidated before and after the request. If sync or
    /// another pagination changed the gap topology,
    /// [`RoomTimelineGapRepairOutcome::Stale`] is returned without applying
    /// the response.
    pub async fn repair_timeline_gap(
        &self,
        descriptor: &RoomTimelineGapDescriptor,
        budget: RoomTimelineGapRepairBudget,
    ) -> Result<RoomTimelineGapRepairOutcome> {
        let pagination = self.clone();
        let descriptor = descriptor.clone();
        let task =
            spawn(async move { pagination.repair_timeline_gap_inner(&descriptor, budget).await });

        task.await.expect("targeted room-timeline gap repair task panicked")
    }

    async fn repair_timeline_gap_inner(
        &self,
        descriptor: &RoomTimelineGapDescriptor,
        budget: RoomTimelineGapRepairBudget,
    ) -> Result<RoomTimelineGapRepairOutcome> {
        let _operation_guard = self.0.cache.pagination_operation_lock.write().await;

        let (prev_token, cached_chunks_loaded) = {
            let mut state = self.0.cache.state.write().await?;
            let persisted =
                state.store.load_all_chunks(LinkedChunkId::Room(&state.state.room_id)).await?;
            let current = inspect_ordered_chunks(
                &state.state.room_id,
                state.gap_snapshot_id(),
                state.gap_topology_generation(),
                &order_persisted_chunks(persisted)?,
            );
            if !current.gaps.iter().any(|gap| gap == descriptor) {
                return Ok(RoomTimelineGapRepairOutcome::Stale);
            }

            let mut cached_chunks_loaded = 0usize;

            loop {
                if let Some(chunk) = state
                    .room_linked_chunk()
                    .chunks()
                    .find(|chunk| chunk.identifier() == descriptor.handle.chunk_identifier)
                {
                    let ChunkContent::Gap(gap) = chunk.content() else {
                        return Ok(RoomTimelineGapRepairOutcome::Stale);
                    };
                    break (Some(gap.token.clone()), cached_chunks_loaded);
                }

                if cached_chunks_loaded >= usize::from(budget.cached_chunk_limit) {
                    break (None, cached_chunks_loaded);
                }

                let first = state
                    .room_linked_chunk()
                    .chunks()
                    .next()
                    .expect("a linked chunk is never empty")
                    .identifier();
                let Some(previous) = state
                    .store
                    .load_previous_chunk(LinkedChunkId::Room(&state.state.room_id), first)
                    .await?
                else {
                    return Ok(RoomTimelineGapRepairOutcome::Stale);
                };

                state.room_linked_chunk_mut().insert_new_chunk_as_first(previous)?;
                let _ = state.room_linked_chunk_mut().store_updates().take();
                let cache_diffs = state.room_linked_chunk_mut().updates_as_vector_diffs();
                if !cache_diffs.is_empty() {
                    // There is no cancellation point between mutating the in-memory
                    // linked chunk and publishing its diffs. A cancelled repair can
                    // therefore never leave subscribers behind the cache state.
                    self.0.cache.update_sender.send(
                        RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                            diffs: cache_diffs,
                            origin: EventsOrigin::Cache,
                        }),
                        Some(RoomEventCacheGenericUpdate { room_id: self.0.cache.room_id.clone() }),
                    );
                }
                cached_chunks_loaded += 1;
            }
        };

        let Some(prev_token) = prev_token else {
            return Ok(RoomTimelineGapRepairOutcome::Deferred { cached_chunks_loaded });
        };

        let request_result = self
            .0
            .cache
            .paginate_backwards_with_network(budget.event_limit, &Some(prev_token.clone()))
            .await;

        let mut state = self.0.cache.state.write().await?;
        let persisted =
            state.store.load_all_chunks(LinkedChunkId::Room(&state.state.room_id)).await?;
        let current = inspect_ordered_chunks(
            &state.state.room_id,
            state.gap_snapshot_id(),
            state.gap_topology_generation(),
            &order_persisted_chunks(persisted)?,
        );
        if !current.gaps.iter().any(|gap| gap == descriptor) {
            return Ok(RoomTimelineGapRepairOutcome::Stale);
        }
        let target_still_matches = state.room_linked_chunk().chunks().any(|chunk| {
            chunk.identifier() == descriptor.handle.chunk_identifier
                && matches!(chunk.content(), ChunkContent::Gap(gap) if gap.token == prev_token)
        });
        if !target_still_matches {
            return Ok(RoomTimelineGapRepairOutcome::Stale);
        }

        let Some((events, new_token)) = request_result? else {
            return Ok(RoomTimelineGapRepairOutcome::Failed);
        };

        let gap_count_before = current.gaps.len();
        let DeduplicationOutcome {
            all_events: mut events,
            in_memory_duplicated_event_ids,
            in_store_duplicated_event_ids,
            non_empty_all_duplicates: all_duplicates,
        } = {
            let room_linked_chunk = state.room_linked_chunk();
            filter_duplicate_events(
                &state.state.own_user_id,
                &state.store,
                LinkedChunkId::Room(&state.state.room_id),
                room_linked_chunk,
                events,
            )
            .await?
        };

        let mut new_token = new_token;
        if !all_duplicates {
            state
                .remove_events(in_memory_duplicated_event_ids, in_store_duplicated_event_ids)
                .await?;
        } else {
            events.clear();
            new_token = None;
        }

        let events_count = events.len();
        let topo_ordered_events = events.iter().rev().cloned().collect::<Vec<_>>();
        let new_gap = new_token.map(|token| Gap { token });
        let _reached_start = state.room_linked_chunk_mut().push_backwards_pagination_events(
            Some(descriptor.handle.chunk_identifier),
            new_gap,
            &topo_ordered_events,
        );
        // `post_process_new_events` begins by flushing the linked-chunk updates
        // to the EventCacheStore. The persisted inspection below therefore
        // proves the repair survives cache reconstruction.
        state
            .post_process_new_events(
                topo_ordered_events,
                PostProcessingOrigin::Backpagination,
                None,
            )
            .await?;
        let timeline_event_diffs = state.room_linked_chunk_mut().updates_as_vector_diffs();
        let persisted_after =
            state.store.load_all_chunks(LinkedChunkId::Room(&state.state.room_id)).await?;
        let after = inspect_ordered_chunks(
            &state.state.room_id,
            state.gap_snapshot_id(),
            state.gap_topology_generation(),
            &order_persisted_chunks(persisted_after)?,
        );
        drop(state);

        if !timeline_event_diffs.is_empty() {
            self.0.cache.update_sender.send(
                RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                    diffs: timeline_event_diffs,
                    origin: EventsOrigin::Pagination,
                }),
                Some(RoomEventCacheGenericUpdate { room_id: self.0.cache.room_id.clone() }),
            );
        }

        Ok(if after.continuity == RoomTimelineContinuity::Complete {
            RoomTimelineGapRepairOutcome::StartReached { events: events_count }
        } else if after.gaps.len() >= gap_count_before {
            RoomTimelineGapRepairOutcome::Progress { events: events_count }
        } else {
            RoomTimelineGapRepairOutcome::BoundariesJoined { events: events_count }
        })
    }

    /// Returns a subscriber to the pagination status.
    pub fn status(&self) -> PaginationStatusSubscriber {
        PaginationStatusSubscriber { subscriber: self.0.cache.status().subscribe() }
    }

    /// Load the next disk chunk backward from the cache, without going to the
    /// network.
    ///
    /// Returns [`LoadMoreEventsBackwardsOutcome`] which is either a gap, the
    /// start of the timeline, or a set of events loaded from disk.
    #[cfg(test)]
    pub(super) async fn load_more_events_backwards(
        &self,
    ) -> Result<LoadMoreEventsBackwardsOutcome> {
        self.0.cache.load_more_events_backwards().await
    }

    /// Load up to `n` events backward from the on-disk cache only, without
    /// touching the network.
    ///
    /// Loops over [`load_more_events_backwards`] (one SQLite chunk per call)
    /// and fires the same [`RoomEventCacheUpdate::UpdateTimelineEvents`]
    /// broadcast that [`conclude_backwards_pagination_from_disk`] produces, so
    /// a subscribed live [`Timeline`] ingests the events exactly as if
    /// [`paginate_backwards`] had been called — but without the pagination-
    /// status changes or network round-trips.
    // Matrix desktop fork patch surface: cache-only backward load used by
    // live_restore_from_cache (matrix-sdk-ui) for deep-history anchor restore
    // in koushi-core. Returns CacheOnlyBackOutcome including anchor_present so
    // the caller can decide the restore terminal without timing heuristics.
    // Not part of upstream matrix-sdk.
    ///
    /// If `anchor_event_id` is `Some`, the loop stops as soon as a loaded chunk
    /// contains that event — `anchor_present` in the returned outcome will be
    /// `true`. This is the authoritative "anchor found in cache" signal: the
    /// anchor's broadcast has been fired and will arrive at the Timeline
    /// subscriber, so the caller can wait for it deterministically.
    ///
    /// Stops when any of the following is true:
    /// - The anchor event is found in a loaded chunk (`anchor_present`).
    /// - The cumulative loaded-event count reaches `n`.
    /// - A [`LoadMoreEventsBackwardsOutcome::Gap`] is encountered (`hit_gap`).
    /// - A [`LoadMoreEventsBackwardsOutcome::StartOfTimeline`] is encountered
    ///   (`reached_start`).
    ///
    /// [`load_more_events_backwards`]: PaginatedCache::load_more_events_backwards
    /// [`conclude_backwards_pagination_from_disk`]: PaginatedCache::conclude_backwards_pagination_from_disk
    /// [`Timeline`]: matrix_sdk_ui::timeline::Timeline
    /// [`paginate_backwards`]: Self::run_backwards_once
    pub async fn run_backwards_cache_only(
        &self,
        n: u16,
        anchor_event_id: Option<&EventId>,
        max_chunks: u16,
    ) -> Result<CacheOnlyBackOutcome> {
        let _operation_guard = self.0.cache.pagination_operation_lock.read().await;
        let mut events_loaded: usize = 0;
        let mut chunks_loaded: usize = 0;
        let target = n as usize;
        let chunk_cap = max_chunks as usize;

        loop {
            // Stop when either the event count or the chunk cap is reached.
            // The chunk cap enforces RESTORE_ANCHOR_MAX_CHUNKS so a fragmented
            // cache (many small chunks) cannot walk beyond the safety bound.
            if events_loaded >= target || chunks_loaded >= chunk_cap {
                break;
            }

            match self.0.cache.load_more_events_backwards().await? {
                LoadMoreEventsBackwardsOutcome::Gap { .. } => {
                    return Ok(CacheOnlyBackOutcome {
                        events_loaded,
                        chunks_loaded,
                        anchor_present: false,
                        reached_start: false,
                        hit_gap: true,
                    });
                }

                LoadMoreEventsBackwardsOutcome::StartOfTimeline => {
                    return Ok(CacheOnlyBackOutcome {
                        events_loaded,
                        chunks_loaded,
                        anchor_present: false,
                        reached_start: true,
                        hit_gap: false,
                    });
                }

                LoadMoreEventsBackwardsOutcome::Events {
                    events,
                    timeline_event_diffs,
                    reached_start,
                } => {
                    let count = events.len();
                    // Check for the anchor in this chunk BEFORE broadcasting.
                    // The events are in memory at this point; we can scan them
                    // synchronously before the async broadcast fires. This gives
                    // an authoritative "anchor is in the loaded cache" signal
                    // without waiting for the Timeline subscriber's relay.
                    // Compare by string representation to avoid OwnedEventId vs
                    // &EventId PartialEq edge cases.
                    let anchor_present = anchor_event_id
                        .map(|id| {
                            let id_str = id.as_str();
                            let found = events
                                .iter()
                                .any(|e| e.event_id().is_some_and(|eid| eid.as_str() == id_str));
                            trace!(
                                "run_backwards_cache_only: chunk={} events={} \
                                 anchor_search={} found={}",
                                chunks_loaded + 1,
                                events.len(),
                                // log only event count, not the anchor id itself
                                1,
                                found as u8
                            );
                            found
                        })
                        .unwrap_or(false);

                    self.0
                        .cache
                        .conclude_backwards_pagination_from_disk(
                            events,
                            timeline_event_diffs,
                            reached_start,
                        )
                        .await;
                    events_loaded += count;
                    chunks_loaded += 1;

                    if anchor_present {
                        return Ok(CacheOnlyBackOutcome {
                            events_loaded,
                            chunks_loaded,
                            anchor_present: true,
                            reached_start,
                            hit_gap: false,
                        });
                    }

                    if reached_start {
                        return Ok(CacheOnlyBackOutcome {
                            events_loaded,
                            chunks_loaded,
                            anchor_present: false,
                            reached_start: true,
                            hit_gap: false,
                        });
                    }
                }
            }
        }

        Ok(CacheOnlyBackOutcome {
            events_loaded,
            chunks_loaded,
            anchor_present: false,
            reached_start: false,
            hit_gap: false,
        })
    }
}

/// Outcome of a cache-only backward load via
/// [`RoomPagination::run_backwards_cache_only`].
// Matrix desktop fork patch surface: returned by run_backwards_cache_only to
// expose anchor_present (authoritative anchor-in-cache signal) and chunks_loaded
// for the koushi-core TimelineActor anchor-restore path. Not part of upstream
// matrix-sdk.
#[derive(Debug)]
pub struct CacheOnlyBackOutcome {
    /// Total number of events loaded from disk in this call.
    pub events_loaded: usize,
    /// Number of disk chunks read (one
    /// `conclude_backwards_pagination_from_disk` broadcast per chunk).
    pub chunks_loaded: usize,
    /// `true` if the requested anchor event was found in one of the loaded
    /// chunks. When `true`, a `RoomEventCacheUpdate::UpdateTimelineEvents`
    /// broadcast carrying the anchor has already been fired; the Timeline
    /// subscriber will deliver a `DiffBatch` for it. The caller should wait
    /// for `timeline_contains(anchor)` to become true rather than concluding
    /// EndReached/BudgetExhausted immediately.
    pub anchor_present: bool,
    /// `true` if the start of the stored timeline was reached (no more disk
    /// chunks behind the current oldest).
    pub reached_start: bool,
    /// `true` if a gap chunk was encountered before `n` events were loaded.
    /// The caller must decide whether to resolve the gap via the network or
    /// to treat the cache as non-contiguous.
    pub hit_gap: bool,
}

impl PaginatedCache for Arc<RoomEventCacheInner> {
    fn status(&self) -> &SharedObservable<SharedPaginationStatus> {
        &self.shared_pagination_status
    }

    fn pagination_operation_lock(&self) -> Option<Arc<tokio::sync::RwLock<()>>> {
        Some(self.pagination_operation_lock.clone())
    }

    async fn load_more_events_backwards(&self) -> Result<LoadMoreEventsBackwardsOutcome> {
        let mut state = self.state.write().await?;

        // If any in-memory chunk is a gap, don't load more events, and let the caller
        // resolve the gap.
        if let Some(prev_token) = state.room_linked_chunk().rgap().map(|gap| gap.token) {
            return Ok(LoadMoreEventsBackwardsOutcome::Gap {
                prev_token: Some(prev_token),
                waited_for_initial_prev_token: state.waited_for_initial_prev_token(),
            });
        }

        let prev_first_chunk =
            state.room_linked_chunk().chunks().next().expect("a linked chunk is never empty");

        // The first chunk is not a gap, we can load its previous chunk.
        let linked_chunk_id = LinkedChunkId::Room(&state.state.room_id);
        let new_first_chunk = match state
            .store
            .load_previous_chunk(linked_chunk_id, prev_first_chunk.identifier())
            .await
        {
            Ok(Some(new_first_chunk)) => {
                // All good, let's continue with this chunk.
                new_first_chunk
            }

            Ok(None) => {
                // If we never received events for this room, this means we've never received a
                // sync for that room, because every room must have *at least* a room creation
                // event. Otherwise, we have reached the start of the timeline.

                if state.room_linked_chunk().events().next().is_some() {
                    // If there's at least one event, this means we've reached the start of the
                    // timeline, since the chunk is fully loaded.
                    trace!("chunk is fully loaded and non-empty: reached_start=true");
                    return Ok(LoadMoreEventsBackwardsOutcome::StartOfTimeline);
                }

                // Otherwise, start back-pagination from the end of the room.
                return Ok(LoadMoreEventsBackwardsOutcome::Gap {
                    prev_token: None,
                    waited_for_initial_prev_token: state.waited_for_initial_prev_token(),
                });
            }

            Err(err) => {
                error!("error when loading the previous chunk of a linked chunk: {err}");

                // Clear storage for this room.
                state
                    .store
                    .handle_linked_chunk_updates(linked_chunk_id, vec![Update::Clear])
                    .await?;

                // Return the error.
                return Err(err.into());
            }
        };

        let chunk_content = new_first_chunk.content.clone();

        // We've reached the start on disk, if and only if, there was no chunk prior to
        // the one we just loaded.
        //
        // This value is correct, if and only if, it is used for a chunk content of kind
        // `Items`.
        let reached_start = new_first_chunk.previous.is_none();

        if let Err(err) = state.room_linked_chunk_mut().insert_new_chunk_as_first(new_first_chunk) {
            error!("error when inserting the previous chunk into its linked chunk: {err}");

            // Clear storage for this room.
            state
                .store
                .handle_linked_chunk_updates(
                    LinkedChunkId::Room(&state.state.room_id),
                    vec![Update::Clear],
                )
                .await?;

            // Return the error.
            return Err(err.into());
        }

        // ⚠️ Let's not propagate the updates to the store! We already have these data
        // in the store! Let's drain them.
        let _ = state.room_linked_chunk_mut().store_updates().take();

        // However, we want to get updates as `VectorDiff`s.
        let timeline_event_diffs = state.room_linked_chunk_mut().updates_as_vector_diffs();

        Ok(match chunk_content {
            ChunkContent::Gap(gap) => {
                trace!("reloaded chunk from disk (gap)");

                LoadMoreEventsBackwardsOutcome::Gap {
                    prev_token: Some(gap.token),
                    waited_for_initial_prev_token: state.waited_for_initial_prev_token(),
                }
            }

            ChunkContent::Items(events) => {
                trace!(?reached_start, "reloaded chunk from disk ({} items)", events.len());

                LoadMoreEventsBackwardsOutcome::Events {
                    events,
                    timeline_event_diffs,
                    reached_start,
                }
            }
        })
    }

    async fn mark_has_waited_for_initial_prev_token(&self) -> Result<()> {
        *self.state.write().await?.waited_for_initial_prev_token_mut() = true;

        Ok(())
    }

    async fn wait_for_prev_token(&self) {
        self.pagination_batch_token_notifier.notified().await
    }

    async fn paginate_backwards_with_network(
        &self,
        batch_size: u16,
        prev_token: &Option<String>,
    ) -> Result<Option<(Vec<Event>, Option<String>)>> {
        let Some(room) = self.weak_room.get() else {
            // The client is shutting down.
            return Ok(None);
        };

        let mut options = MessagesOptions::new(Direction::Backward).from(prev_token.as_deref());
        options.limit = batch_size.into();

        let response = room
            .messages(options)
            .await
            .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;

        Ok(Some((response.chunk, response.end)))
    }

    async fn conclude_backwards_pagination_from_disk(
        &self,
        events: Vec<Event>,
        timeline_event_diffs: Vec<VectorDiff<Event>>,
        reached_start: bool,
    ) -> BackPaginationOutcome {
        if !timeline_event_diffs.is_empty() {
            self.update_sender.send(
                RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                    diffs: timeline_event_diffs,
                    origin: EventsOrigin::Cache,
                }),
                Some(RoomEventCacheGenericUpdate { room_id: self.room_id.clone() }),
            );
        }

        BackPaginationOutcome {
            reached_start,
            // This is a backwards pagination. `BackPaginationOutcome` expects events to
            // be in “reverse order”.
            events: events.into_iter().rev().collect(),
        }
    }

    async fn conclude_backwards_pagination_from_network(
        &self,
        events: Vec<Event>,
        prev_token: Option<String>,
        mut new_token: Option<String>,
    ) -> Result<Option<BackPaginationOutcome>> {
        let mut state = self.state.write().await?;

        // Check that the previous token still exists; otherwise it's a sign that the
        // room's timeline has been cleared.
        let prev_gap_id = if let Some(token) = prev_token {
            // Find the corresponding gap in the in-memory linked chunk.
            let gap_chunk_id = state.room_linked_chunk().chunk_identifier(|chunk| {
                    matches!(chunk.content(), ChunkContent::Gap(Gap { token: prev_token }) if *prev_token == token)
                });

            if gap_chunk_id.is_none() {
                // We got a previous-batch token from the linked chunk *before* running the
                // request, but it is missing *after* completing the request.
                //
                // It may be a sign the linked chunk has been reset, but it's fine!
                return Ok(None);
            }

            gap_chunk_id
        } else {
            None
        };

        let DeduplicationOutcome {
            all_events: mut events,
            in_memory_duplicated_event_ids,
            in_store_duplicated_event_ids,
            non_empty_all_duplicates: all_duplicates,
        } = {
            let room_linked_chunk = state.room_linked_chunk();

            filter_duplicate_events(
                &state.state.own_user_id,
                &state.store,
                LinkedChunkId::Room(&state.state.room_id),
                room_linked_chunk,
                events,
            )
            .await?
        };

        // If not all the events have been back-paginated, we need to remove the
        // previous ones, otherwise we can end up with misordered events.
        //
        // Consider the following scenario:
        // - sync returns [D, E, F]
        // - then sync returns [] with a previous batch token PB1, so the internal
        //   linked chunk state is [D, E, F, PB1].
        // - back-paginating with PB1 may return [A, B, C, D, E, F].
        //
        // Only inserting the new events when replacing PB1 would result in a timeline
        // ordering of [D, E, F, A, B, C], which is incorrect. So we do have to remove
        // all the events, in case this happens (see also #4746).

        if !all_duplicates {
            // Let's forget all the previous events.
            state
                .remove_events(in_memory_duplicated_event_ids, in_store_duplicated_event_ids)
                .await?;
        } else {
            // All new events are duplicated, they can all be ignored.
            events.clear();
            // The gap can be ditched too, as it won't be useful to backpaginate any
            // further.
            new_token = None;
        }

        // `/messages` has been called with `dir=b` (backwards), so the events are in
        // the inverted order; reorder them.
        let topo_ordered_events = events.iter().rev().cloned().collect::<Vec<_>>();

        let new_gap = new_token.map(|prev_token| Gap { token: prev_token });
        let reached_start = state.room_linked_chunk_mut().push_backwards_pagination_events(
            prev_gap_id,
            new_gap,
            &topo_ordered_events,
        );

        // A back-pagination can't include new read receipt events, as those are
        // ephemeral events not included in /messages responses, so we can
        // safely set the receipt event to None here.
        //
        // Note: read receipts may be updated anyhow in the post-processing step, as the
        // back-pagination may have revealed the event pointed to by the latest read
        // receipt.
        let receipt_event = None;

        // Note: this flushes updates to the store.
        state
            .post_process_new_events(
                topo_ordered_events,
                PostProcessingOrigin::Backpagination,
                receipt_event,
            )
            .await?;

        let timeline_event_diffs = state.room_linked_chunk_mut().updates_as_vector_diffs();

        if !timeline_event_diffs.is_empty() {
            self.update_sender.send(
                RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                    diffs: timeline_event_diffs,
                    origin: EventsOrigin::Pagination,
                }),
                Some(RoomEventCacheGenericUpdate { room_id: self.room_id.clone() }),
            );
        }

        Ok(Some(BackPaginationOutcome { events, reached_start }))
    }
}
