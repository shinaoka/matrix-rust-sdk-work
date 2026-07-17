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

use std::sync::Arc;

use matrix_sdk_base::{event_cache::Gap, linked_chunk::LinkedChunkId};
use ruma::OwnedEventId;

use super::{
    RoomEventCacheGenericUpdate, RoomEventCacheStateLockReadGuard,
    RoomEventCacheStateLockWriteGuard, RoomEventCacheUpdate,
    pagination::{
        RoomLiveTailRefreshCancellation, RoomLiveTailRefreshOutcome, RoomLiveTailRefreshResult,
        RoomPagination, RoomTimelineGapProjectionId,
    },
};
use crate::{
    event_cache::{
        EventCacheError, EventsOrigin, Result, TimelineVectorDiffs,
        deduplicator::{DeduplicationOutcome, filter_duplicate_events},
    },
    room::{Messages, MessagesOptions},
};

/// Captured identity of the room cache before a tokenless live-tail request.
struct LiveTailSnapshotFence {
    gap_snapshot_id: u64,
    gap_topology_generation: u64,
    newest_event_id: Option<OwnedEventId>,
}

impl LiveTailSnapshotFence {
    fn capture(state: &RoomEventCacheStateLockReadGuard<'_>) -> Self {
        Self {
            gap_snapshot_id: state.gap_snapshot_id(),
            gap_topology_generation: state.gap_topology_generation(),
            newest_event_id: state.newest_event_id(),
        }
    }

    fn matches(&self, state: &RoomEventCacheStateLockWriteGuard<'_>) -> bool {
        self.gap_snapshot_id == state.gap_snapshot_id()
            && self.gap_topology_generation == state.gap_topology_generation()
            && self.newest_event_id == state.newest_event_id()
    }
}

impl RoomPagination {
    /// Install a one-shot pause immediately after the live-tail write lock is acquired.
    ///
    /// This is exposed only by the `testing` feature to verify the cancellation
    /// boundary around an already-started commit.
    #[cfg(feature = "testing")]
    #[doc(hidden)]
    pub fn set_live_tail_commit_test_hook(
        &self,
        commit_entered: Arc<tokio::sync::Notify>,
        release_commit: Arc<tokio::sync::Notify>,
    ) {
        *self.cache().live_tail_commit_test_hook.lock().expect("live-tail test hook poisoned") =
            Some((commit_entered, release_commit));
    }

    /// Refresh the authoritative live tail without selecting a persisted gap.
    pub async fn refresh_live_tail_with_projection(
        &self,
        event_limit: u16,
        projection: RoomTimelineGapProjectionId,
        cancellation: RoomLiveTailRefreshCancellation,
    ) -> Result<RoomLiveTailRefreshResult> {
        if event_limit == 0 {
            return Err(EventCacheError::InvalidLinkedChunkMetadata {
                details: "live-tail refresh event limit must be greater than zero".to_owned(),
            });
        }

        let fence = {
            let state = self.cache().state.read().await?;
            LiveTailSnapshotFence::capture(&state)
        };
        let Some(room) = self.cache().weak_room.get() else {
            return Ok(RoomLiveTailRefreshResult {
                outcome: RoomLiveTailRefreshOutcome::Failed,
                returned_events: 0,
                last_projection_batch: None,
            });
        };
        let mut options = MessagesOptions::backward();
        options.limit = event_limit.into();
        let response = tokio::select! {
            _ = cancellation.cancelled() => {
                return Ok(RoomLiveTailRefreshResult {
                    outcome: RoomLiveTailRefreshOutcome::Cancelled,
                    returned_events: 0,
                    last_projection_batch: None,
                });
            }
            response = room.messages(options) => {
                response.map_err(|error| EventCacheError::PaginationError(Arc::new(error)))?
            }
        };

        // Deliberately no cancellation branch below this line: after a response
        // wins the network phase, cache mutation and publication are one commit.
        self.commit_live_tail_response(fence, response, projection).await
    }

    async fn commit_live_tail_response(
        &self,
        fence: LiveTailSnapshotFence,
        response: Messages,
        projection: RoomTimelineGapProjectionId,
    ) -> Result<RoomLiveTailRefreshResult> {
        let returned_events = response.chunk.len();
        let previous_edge = fence.newest_event_id.clone();
        let response_contains_previous_edge = previous_edge.as_ref().is_some_and(|previous_edge| {
            response
                .chunk
                .iter()
                .any(|event| event.event_id().as_deref() == Some(previous_edge.as_ref()))
        });
        let historical_gap_remaining = response.end.is_some();
        let mut response_events = response.chunk;

        // When the page overlaps the cached edge, only the edge and events newer
        // than it belong to the live-tail commit. Older page members already have
        // their place in the retained history.
        if let Some(previous_edge) = previous_edge.as_ref()
            && let Some(edge_index) = response_events
                .iter()
                .position(|event| event.event_id().as_deref() == Some(previous_edge.as_ref()))
        {
            response_events.truncate(edge_index + 1);
        }

        let mut state = self.cache().state.write().await?;
        #[cfg(feature = "testing")]
        let commit_test_hook = self
            .cache()
            .live_tail_commit_test_hook
            .lock()
            .expect("live-tail test hook poisoned")
            .take();
        #[cfg(feature = "testing")]
        if let Some((commit_entered, release_commit)) = commit_test_hook {
            commit_entered.notify_one();
            release_commit.notified().await;
        }
        if !fence.matches(&state) {
            return Ok(RoomLiveTailRefreshResult {
                outcome: RoomLiveTailRefreshOutcome::Stale,
                returned_events,
                last_projection_batch: None,
            });
        }

        let DeduplicationOutcome {
            all_events: events,
            in_memory_duplicated_event_ids,
            in_store_duplicated_event_ids,
            ..
        } = {
            let room_linked_chunk = state.room_linked_chunk();
            filter_duplicate_events(
                &state.state.own_user_id,
                &state.store,
                LinkedChunkId::Room(&state.state.room_id),
                room_linked_chunk,
                response_events,
            )
            .await?
        };
        let duplicate_count =
            in_memory_duplicated_event_ids.len() + in_store_duplicated_event_ids.len();
        let new_event_count = events.len().saturating_sub(duplicate_count);
        let outcome =
            match (previous_edge.as_ref(), response_contains_previous_edge, new_event_count) {
                (_, _, 0) => RoomLiveTailRefreshOutcome::Unchanged,
                (Some(_), true, count) => RoomLiveTailRefreshOutcome::Advanced { events: count },
                (Some(_), false, count) => {
                    RoomLiveTailRefreshOutcome::Detached { events: count, historical_gap_remaining }
                }
                (None, _, count) => RoomLiveTailRefreshOutcome::Advanced { events: count },
            };
        if matches!(outcome, RoomLiveTailRefreshOutcome::Unchanged) {
            return Ok(RoomLiveTailRefreshResult {
                outcome,
                returned_events,
                last_projection_batch: None,
            });
        }

        state.remove_events(in_memory_duplicated_event_ids, in_store_duplicated_event_ids).await?;
        let chronological_events = events.into_iter().rev().collect::<Vec<_>>();
        let insert_historical_gap = matches!(outcome, RoomLiveTailRefreshOutcome::Detached { .. })
            || previous_edge.is_none();
        let new_gap =
            insert_historical_gap.then_some(response.end).flatten().map(|token| Gap { token });
        state.room_linked_chunk_mut().push_live_events(new_gap, &chronological_events);
        state.post_process_live_tail_events(chronological_events).await?;
        let timeline_event_diffs = state.room_linked_chunk_mut().updates_as_vector_diffs();

        let last_projection_batch = if timeline_event_diffs.is_empty() {
            None
        } else {
            self.cache().update_sender.send(
                RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                    diffs: timeline_event_diffs,
                    origin: EventsOrigin::GapRepair {
                        actor_generation: projection.actor_generation,
                        repair_generation: projection.repair_generation,
                        projection_batch: 1,
                    },
                }),
                Some(RoomEventCacheGenericUpdate { room_id: self.cache().room_id.clone() }),
            );
            Some(1)
        };
        drop(state);

        Ok(RoomLiveTailRefreshResult { outcome, returned_events, last_projection_batch })
    }
}
