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

use matrix_sdk_base::{
    event_cache::Gap,
    linked_chunk::{ChunkContent, LinkedChunkId},
};
use ruma::OwnedEventId;

use super::{
    RoomEventCacheGenericUpdate, RoomEventCacheStateLockReadGuard,
    RoomEventCacheStateLockWriteGuard, RoomEventCacheUpdate,
    pagination::{
        RoomLiveTailRefreshCancellation, RoomLiveTailRefreshDiagnostics,
        RoomLiveTailRefreshOutcome, RoomLiveTailRefreshResult, RoomPagination,
        RoomTimelineGapProjectionId,
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
    contiguous_suffix_event_ids: Vec<OwnedEventId>,
}

impl LiveTailSnapshotFence {
    fn capture(state: &RoomEventCacheStateLockReadGuard<'_>) -> Self {
        let mut contiguous_suffix_event_ids = Vec::new();
        for chunk in state.room_linked_chunk().rchunks() {
            match chunk.content() {
                ChunkContent::Items(events) => contiguous_suffix_event_ids
                    .extend(events.iter().rev().filter_map(|event| event.event_id())),
                ChunkContent::Gap(_) => break,
            }
        }
        Self {
            gap_snapshot_id: state.gap_snapshot_id(),
            gap_topology_generation: state.gap_topology_generation(),
            newest_event_id: state.newest_event_id(),
            contiguous_suffix_event_ids,
        }
    }

    fn matches(&self, state: &RoomEventCacheStateLockWriteGuard<'_>) -> bool {
        self.gap_snapshot_id == state.gap_snapshot_id()
            && self.gap_topology_generation == state.gap_topology_generation()
            && self.newest_event_id == state.newest_event_id()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveTailReconciliation {
    /// Replace the cached suffix newer than this proven older anchor. The
    /// response is ordered newest-to-oldest, and the anchor itself stays in
    /// place, so only the preceding prefix is committed.
    Anchored { response_prefix_len: usize },
    /// One page did not reach an older event in the contiguous cached suffix.
    /// Install the authoritative page as a detached tail and retain its token
    /// as an explicit historical gap.
    Detached,
}

fn plan_live_tail_reconciliation(
    cached_suffix_event_ids: &[OwnedEventId],
    response_event_ids: &[OwnedEventId],
) -> LiveTailReconciliation {
    let (newest_cached_response_index, older_anchor) =
        live_tail_anchor_indices(cached_suffix_event_ids, response_event_ids);
    let Some(_) = newest_cached_response_index else {
        return LiveTailReconciliation::Detached;
    };
    older_anchor.map_or(LiveTailReconciliation::Detached, |response_prefix_len| {
        LiveTailReconciliation::Anchored { response_prefix_len }
    })
}

fn live_tail_anchor_indices(
    cached_suffix_event_ids: &[OwnedEventId],
    response_event_ids: &[OwnedEventId],
) -> (Option<usize>, Option<usize>) {
    let newest_cached_response_index = cached_suffix_event_ids
        .first()
        .and_then(|newest| response_event_ids.iter().position(|response| response == newest));
    let older_anchor = newest_cached_response_index.and_then(|newest_index| {
        response_event_ids
            .iter()
            .enumerate()
            .skip(newest_index + 1)
            .filter(|(_, response_event_id)| {
                cached_suffix_event_ids
                    .iter()
                    .skip(1)
                    .any(|cached_event_id| cached_event_id == *response_event_id)
            })
            .map(|(index, _)| index)
            .last()
    });
    (newest_cached_response_index, older_anchor)
}

fn anchored_materialized_event_count(
    response_event_count: usize,
    in_memory_duplicate_count: usize,
) -> usize {
    // Store-only duplicates are absent from the loaded linked chunk. They are
    // not globally new, but the reconciliation must remove their old stored
    // positions and materialize them into the authoritative live suffix.
    response_event_count.saturating_sub(in_memory_duplicate_count)
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
                diagnostics: RoomLiveTailRefreshDiagnostics::default(),
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
                    diagnostics: RoomLiveTailRefreshDiagnostics::default(),
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
        let historical_gap_remaining = response.end.is_some();
        let mut response_events = response.chunk;
        let response_event_ids =
            response_events.iter().filter_map(|event| event.event_id()).collect::<Vec<_>>();
        let (newest_cached_response_index, older_anchor_response_index) =
            live_tail_anchor_indices(&fence.contiguous_suffix_event_ids, &response_event_ids);
        let mut diagnostics = RoomLiveTailRefreshDiagnostics {
            cached_suffix_events: fence.contiguous_suffix_event_ids.len(),
            response_events_with_ids: response_event_ids.len(),
            newest_cached_response_index,
            older_anchor_response_index,
            ..Default::default()
        };
        let reconciliation =
            plan_live_tail_reconciliation(&fence.contiguous_suffix_event_ids, &response_event_ids);
        if let LiveTailReconciliation::Anchored { response_prefix_len } = reconciliation {
            // Keep the proven older anchor in place. Rebuild everything newer
            // than it, including the formerly cached newest event, so events
            // hidden immediately before that newest event are not discarded.
            response_events.truncate(response_prefix_len);
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
                diagnostics,
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
        let in_memory_duplicate_count = in_memory_duplicated_event_ids.len();
        diagnostics.in_memory_duplicates = in_memory_duplicate_count;
        diagnostics.in_store_duplicates = in_store_duplicated_event_ids.len();
        let duplicate_count = in_memory_duplicate_count + in_store_duplicated_event_ids.len();
        let new_event_count = events.len().saturating_sub(duplicate_count);
        diagnostics.new_events = new_event_count;
        let materialized_event_count =
            anchored_materialized_event_count(events.len(), in_memory_duplicate_count);
        let outcome = match reconciliation {
            LiveTailReconciliation::Anchored { .. } if materialized_event_count == 0 => {
                RoomLiveTailRefreshOutcome::Unchanged
            }
            LiveTailReconciliation::Anchored { .. } => {
                RoomLiveTailRefreshOutcome::Advanced { events: materialized_event_count }
            }
            LiveTailReconciliation::Detached => RoomLiveTailRefreshOutcome::Detached {
                events: new_event_count,
                historical_gap_remaining,
            },
        };
        if matches!(outcome, RoomLiveTailRefreshOutcome::Unchanged) {
            return Ok(RoomLiveTailRefreshResult {
                outcome,
                returned_events,
                diagnostics,
                last_projection_batch: None,
            });
        }

        state.remove_events(in_memory_duplicated_event_ids, in_store_duplicated_event_ids).await?;
        let chronological_events = events.into_iter().rev().collect::<Vec<_>>();
        let new_gap = matches!(reconciliation, LiveTailReconciliation::Detached)
            .then_some(response.end)
            .flatten()
            .map(|token| Gap { token });
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

        Ok(RoomLiveTailRefreshResult {
            outcome,
            returned_events,
            diagnostics,
            last_projection_batch,
        })
    }
}

#[cfg(test)]
mod tests {
    use ruma::owned_event_id;

    use super::{
        LiveTailReconciliation, anchored_materialized_event_count, plan_live_tail_reconciliation,
    };

    #[test]
    fn cached_newest_event_does_not_hide_a_gap_immediately_before_it() {
        let cached = [owned_event_id!("$latest"), owned_event_id!("$older")];
        let response =
            [owned_event_id!("$latest"), owned_event_id!("$missing"), owned_event_id!("$older")];

        assert_eq!(
            plan_live_tail_reconciliation(&cached, &response),
            LiveTailReconciliation::Anchored { response_prefix_len: 2 }
        );
    }

    #[test]
    fn matching_contiguous_suffix_has_no_events_to_insert() {
        let cached = [owned_event_id!("$latest"), owned_event_id!("$older")];
        let response = [owned_event_id!("$latest"), owned_event_id!("$older")];

        assert_eq!(
            plan_live_tail_reconciliation(&cached, &response),
            LiveTailReconciliation::Anchored { response_prefix_len: 1 }
        );
    }

    #[test]
    fn page_without_an_older_cached_anchor_becomes_a_detached_tail() {
        let cached = [owned_event_id!("$latest"), owned_event_id!("$far-older")];
        let response = [owned_event_id!("$latest"), owned_event_id!("$missing")];

        assert_eq!(
            plan_live_tail_reconciliation(&cached, &response),
            LiveTailReconciliation::Detached
        );
    }

    #[test]
    fn store_only_duplicates_are_materialized_into_the_live_timeline() {
        // A store-only duplicate is not present in the in-memory linked chunk.
        // It must therefore count as materialized work even though it is not a
        // globally new event.
        assert_eq!(anchored_materialized_event_count(3, 2), 1);
    }
}
