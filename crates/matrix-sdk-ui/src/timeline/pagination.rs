// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use async_rx::StreamExt as _;
use async_stream::stream;
use futures_core::Stream;
use futures_util::{StreamExt as _, pin_mut};
use matrix_sdk::event_cache::{CacheOnlyBackOutcome, PaginationStatus};
use tracing::instrument;

use super::Error;
use crate::timeline::{
    PaginationError::{self, NotSupported},
    controller::TimelineFocusKind,
};

/// Outcome of a cache-only backward restore via
/// [`Timeline::live_restore_from_cache`].
// Matrix desktop fork patch surface: outcome type for the cache-only
// deep-history restore path. Exposes `chunks_loaded` and `lazy_reveal_batches`
// so the koushi-core TimelineActor can compute an exact settle fence (total =
// lazy_reveal_batches + chunks_loaded) without guessing chunk capacity.
// Not part of upstream matrix-sdk-ui.
#[derive(Debug)]
pub struct RestoreFromCacheOutcome {
    /// Total number of events loaded from disk and revealed in the timeline.
    pub events_loaded: usize,
    /// Number of disk chunks read. Each chunk produces exactly one
    /// [`RoomEventCacheUpdate::UpdateTimelineEvents`] broadcast that flows
    /// through the 3-hop async pipeline to the Timeline subscriber as one
    /// `DiffBatch` actor message.
    pub chunks_loaded: usize,
    /// Whether the lazy in-memory reveal (via `live_lazy_paginate_backwards`)
    /// emitted a `VectorDiff` batch to the timeline subscriber by changing the
    /// `Skip` adaptor's count. `1` if the count changed, `0` if it was already
    /// zero (no items hidden). Combined with `chunks_loaded`, gives the total
    /// expected `DiffBatch` count: `lazy_reveal_batches + chunks_loaded`.
    pub lazy_reveal_batches: usize,
    /// `true` if the start of the stored timeline was reached.
    pub reached_start: bool,
    /// `true` if a gap was encountered before `n` events were loaded. The
    /// caller should fall back to network-backed pagination.
    pub hit_gap: bool,
}

impl super::Timeline {
    /// Add more events to the start of the timeline.
    ///
    /// Returns whether we hit the start of the timeline.
    #[instrument(skip_all, fields(room_id = ?self.room().room_id()))]
    pub async fn paginate_backwards(&self, mut num_events: u16) -> Result<bool, Error> {
        match self.controller.focus() {
            TimelineFocusKind::Live { .. } => {
                match self.controller.live_lazy_paginate_backwards(num_events).await {
                    Some(needed_num_events) => {
                        num_events = needed_num_events.try_into().expect(
                            "failed to cast `needed_num_events` (`usize`) into `num_events` (`usize`)",
                        );
                    }
                    None => {
                        // We could adjust the skip count to a lower value, while passing the
                        // requested number of events. We *may* have reached the start of the
                        // timeline, but since we're fulfilling the caller's request, assume it's
                        // not the case and return false here. A subsequent call will go to the
                        // `Some()` arm of this match, and cause a call to the event cache's
                        // pagination.
                        return Ok(false);
                    }
                }

                Ok(self.live_paginate_backwards(num_events).await?)
            }

            TimelineFocusKind::Event { focused_event_id, thread_mode, .. } => Ok(self
                .event_cache
                .get_event_focused_cache(focused_event_id.clone(), (*thread_mode).into())
                .await?
                .ok_or(PaginationError::MissingCache)?
                .paginate_backwards(num_events)
                .await?
                .hit_end_of_timeline),

            TimelineFocusKind::Thread { root_event_id } => Ok(self
                .event_cache
                .thread_pagination(root_event_id.to_owned())
                .await
                .map_err(PaginationError::EventCache)?
                .run_backwards_once(num_events)
                .await
                .map(|outcome| outcome.reached_start)?),

            TimelineFocusKind::PinnedEvents => Err(Error::PaginationError(NotSupported)),
        }
    }

    /// Add more events to the end of the timeline.
    ///
    /// Returns whether we hit the end of the timeline.
    #[instrument(skip_all, fields(room_id = ?self.room().room_id()))]
    pub async fn paginate_forwards(&self, num_events: u16) -> Result<bool, Error> {
        match self.controller.focus() {
            TimelineFocusKind::Live { .. } => Ok(true),

            TimelineFocusKind::Event { focused_event_id, thread_mode, .. } => Ok(self
                .event_cache
                .get_event_focused_cache(focused_event_id.clone(), (*thread_mode).into())
                .await?
                .ok_or(PaginationError::MissingCache)?
                .paginate_forwards(num_events)
                .await?
                .hit_end_of_timeline),

            TimelineFocusKind::Thread { .. } | TimelineFocusKind::PinnedEvents => {
                Err(Error::PaginationError(NotSupported))
            }
        }
    }

    /// Paginate backwards in live mode.
    ///
    /// This can only be called when the timeline is in live mode, not focused
    /// on a specific event.
    ///
    /// Returns whether we hit the start of the timeline.
    async fn live_paginate_backwards(&self, batch_size: u16) -> Result<bool, Error> {
        loop {
            match self.event_cache.pagination().run_backwards_once(batch_size).await {
                Ok(outcome) => {
                    if outcome.reached_start {
                        self.controller.insert_timeline_start_if_missing().await;
                        return Ok(true);
                    }

                    if !outcome.events.is_empty() {
                        return Ok(false);
                    }

                    // Fallthrough: as a special contract, restart pagination,
                    // if it returned 0 events.
                }

                // Propagate errors as such.
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Load up to `n` events backward from the on-disk cache only, without
    /// touching the network, and reveal them in the live timeline stream.
    ///
    /// This is the ~O(1) alternative to calling [`paginate_backwards`] in a
    /// loop for deep-history restore. It mirrors [`paginate_backwards`] in live
    /// mode: first call [`live_lazy_paginate_backwards`] to reveal any
    /// already-in-memory hidden rows (decrementing the `Skip` adaptor count);
    /// if that is not enough, call [`run_backwards_cache_only`] for the
    /// remainder from disk, with no network round-trips.
    ///
    /// Only meaningful when the timeline is in live mode. If the timeline is
    /// in focused/pinned-events mode this returns an error.
    ///
    /// Returns [`RestoreFromCacheOutcome`] which carries the number of events
    /// loaded plus flags for `reached_start` and `hit_gap`. When `hit_gap` is
    /// `true`, the caller should fall back to network-backed pagination to
    /// reach events that are not yet on disk.
    ///
    /// [`paginate_backwards`]: Self::paginate_backwards
    /// [`live_lazy_paginate_backwards`]: crate::timeline::controller::TimelineController::live_lazy_paginate_backwards
    /// [`run_backwards_cache_only`]: matrix_sdk::event_cache::RoomPagination::run_backwards_cache_only
    // Matrix desktop fork patch surface: cache-only deep-history restore path
    // used by the anchor-restore actor (koushi-core TimelineActor). Mirrors
    // the live_lazy_paginate_backwards + run_backwards_once pattern of
    // paginate_backwards, but substitutes run_backwards_cache_only for the
    // disk-load step so no network round-trips occur.
    pub async fn live_restore_from_cache(
        &self,
        n: u16,
    ) -> Result<RestoreFromCacheOutcome, Error> {
        match self.controller.focus() {
            TimelineFocusKind::Live { .. } => {}
            _ => return Err(Error::PaginationError(NotSupported)),
        }

        // Step 1: reveal already-in-memory hidden rows by decrementing the Skip
        // count, exactly like live_lazy_paginate_backwards does. Returns:
        //   (did_reveal, Some(needs)) — in-memory partial, disk needed for rest
        //   (did_reveal, None) — in-memory fully satisfied the request
        // `did_reveal` is true when the Skip adaptor's count changed and thus
        // one synthetic VectorDiff batch was emitted to the timeline subscriber.
        let (did_reveal, needs) =
            self.controller.live_lazy_paginate_backwards_with_reveal(n).await;
        let lazy_reveal_batches = did_reveal as usize;

        let Some(needs) = needs else {
            // All `n` events were already in memory (skip count covered them).
            return Ok(RestoreFromCacheOutcome {
                events_loaded: 0,
                chunks_loaded: 0,
                lazy_reveal_batches,
                reached_start: false,
                hit_gap: false,
            });
        };

        // Step 2: load the remainder from disk only (no network).
        let needs_u16 = needs.try_into().unwrap_or(u16::MAX);
        let CacheOnlyBackOutcome { events_loaded, chunks_loaded, reached_start, hit_gap } =
            self.event_cache.pagination().run_backwards_cache_only(needs_u16).await?;

        Ok(RestoreFromCacheOutcome {
            events_loaded,
            chunks_loaded,
            lazy_reveal_batches,
            reached_start,
            hit_gap,
        })
    }

    /// Subscribe to the back-pagination status of a live timeline.
    ///
    /// This will return `None` if the timeline is in the focused mode.
    ///
    /// Note: this may send multiple Paginating/Idle sequences during a single
    /// call to [`Self::paginate_backwards()`].
    pub async fn live_back_pagination_status(
        &self,
    ) -> Option<(PaginationStatus, impl Stream<Item = PaginationStatus> + use<>)> {
        if !self.controller.is_live() {
            return None;
        }

        let pagination = self.event_cache.pagination();

        let mut status = pagination.status();

        let current_value = self.controller.map_pagination_status(status.next_now()).await;

        let controller = self.controller.clone();
        let stream = Box::pin(stream! {
            let status_stream = status.dedup();

            pin_mut!(status_stream);

            while let Some(state) = status_stream.next().await {
                let state = controller.map_pagination_status(state).await;

                match state {
                    PaginationStatus::Idle { hit_timeline_start } => {
                        if hit_timeline_start {
                            controller.insert_timeline_start_if_missing().await;
                        }
                    }
                    PaginationStatus::Paginating => {}
                }

                yield state;
            }
        });

        Some((current_value, stream))
    }
}
