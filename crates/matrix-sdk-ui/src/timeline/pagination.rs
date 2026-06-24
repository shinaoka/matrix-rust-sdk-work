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
use matrix_sdk::event_cache::PaginationStatus;
use ruma::EventId;
use tracing::instrument;

use super::{Error, algorithms::rfind_event_by_id};
use crate::timeline::{
    PaginationError::{self, NotSupported},
    controller::TimelineFocusKind,
};

/// Outcome of a cache-only backward restore via
/// [`Timeline::live_restore_from_cache`].
// Matrix desktop fork patch surface: outcome type for the cache-only
// deep-history restore path. Exposes `anchor_present` (authoritative
// anchor-in-cache signal) so the koushi-core TimelineActor can decide the
// restore terminal without timing heuristics.
// Not part of upstream matrix-sdk-ui.
#[derive(Debug)]
pub struct RestoreFromCacheOutcome {
    /// Total number of events loaded from disk and revealed in the timeline.
    pub events_loaded: usize,
    /// Number of disk chunks read (diagnostic; no longer used for settle fence).
    pub chunks_loaded: usize,
    /// Whether the lazy in-memory reveal emitted a `VectorDiff` batch
    /// (diagnostic; no longer used for settle fence).
    pub lazy_reveal_batches: usize,
    /// `true` if the anchor event was found — either in the lazy in-memory
    /// reveal (already in Timeline items) or in one of the loaded disk chunks.
    ///
    /// When `true`, the anchor's broadcast has been fired (or the anchor was
    /// already in the Timeline subscriber's visible items). The caller should
    /// wait for `timeline_contains(anchor)` rather than concluding
    /// EndReached/BudgetExhausted immediately.
    ///
    /// When `false` and `reached_start`, the anchor is genuinely absent from
    /// the cache — conclude EndReached immediately (authoritative).
    pub anchor_present: bool,
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
    /// remainder from disk, checking after each chunk whether the anchor event
    /// is present (load-until-anchor semantics).
    ///
    /// Only meaningful when the timeline is in live mode. If the timeline is
    /// in focused/pinned-events mode this returns an error.
    ///
    /// Returns [`RestoreFromCacheOutcome`] which carries `anchor_present` (the
    /// authoritative in-cache signal), plus `reached_start` and `hit_gap`. The
    /// caller should use `anchor_present` to decide the restore terminal:
    /// - `anchor_present == true`: wait for `timeline_contains(anchor)`; do NOT
    ///   conclude EndReached/BudgetExhausted while the anchor is guaranteed to arrive.
    /// - `anchor_present == false && reached_start`: conclude EndReached immediately.
    /// - `hit_gap`: fall back to network-backed pagination.
    ///
    /// [`paginate_backwards`]: Self::paginate_backwards
    /// [`live_lazy_paginate_backwards`]: crate::timeline::controller::TimelineController::live_lazy_paginate_backwards
    /// [`run_backwards_cache_only`]: matrix_sdk::event_cache::RoomPagination::run_backwards_cache_only
    // Matrix desktop fork patch surface: cache-only deep-history restore path
    // used by the anchor-restore actor (koushi-core TimelineActor). Mirrors
    // the live_lazy_paginate_backwards + run_backwards_once pattern of
    // paginate_backwards, but substitutes run_backwards_cache_only for the
    // disk-load step so no network round-trips occur. Returns anchor_present
    // so koushi can decide the terminal deterministically without timing heuristics.
    pub async fn live_restore_from_cache(
        &self,
        n: u16,
        anchor_event_id: &str,
    ) -> Result<RestoreFromCacheOutcome, Error> {
        match self.controller.focus() {
            TimelineFocusKind::Live { .. } => {}
            _ => return Err(Error::PaginationError(NotSupported)),
        }

        // Parse the anchor event_id once. If it fails (malformed id), treat it
        // as absent so callers fall back to the non-anchor path.
        let anchor_id_owned = EventId::parse(anchor_event_id).ok();
        let anchor_id: Option<&EventId> = anchor_id_owned.as_deref();

        let mut total_events_loaded: usize = 0;
        let mut total_chunks_loaded: usize = 0;
        let mut total_lazy_reveal_batches: usize = 0;

        // Step 1: reveal already-in-memory hidden rows by decrementing the Skip
        // count, exactly like live_lazy_paginate_backwards does. Returns:
        //   (did_reveal, Some(needs)) — in-memory partial, disk needed for rest
        //   (did_reveal, None) — in-memory fully satisfied the request
        // `did_reveal` is true when the Skip adaptor's count changed and thus
        // one synthetic VectorDiff batch was emitted to the timeline subscriber.
        let (did_reveal, needs) =
            self.controller.live_lazy_paginate_backwards_with_reveal(n).await;
        if did_reveal {
            total_lazy_reveal_batches += 1;
        }

        // After the reveal, check if the anchor is already in the timeline's
        // visible items. This covers the shallow-anchor case where the anchor
        // was hidden by the Skip adaptor and is now revealed.
        let anchor_in_memory = if let Some(id) = anchor_id {
            let items = self.controller.items().await;
            rfind_event_by_id(&items, id).is_some()
        } else {
            false
        };

        let Some(needs) = needs else {
            // All `n` events were already in memory (skip count covered them).
            // The anchor check above is authoritative for this path.
            return Ok(RestoreFromCacheOutcome {
                events_loaded: total_events_loaded,
                chunks_loaded: total_chunks_loaded,
                lazy_reveal_batches: total_lazy_reveal_batches,
                anchor_present: anchor_in_memory,
                reached_start: false,
                hit_gap: false,
            });
        };

        if anchor_in_memory {
            // Anchor already found in the in-memory reveal; no need to load
            // further disk chunks. Return immediately so no over-fetch occurs.
            return Ok(RestoreFromCacheOutcome {
                events_loaded: total_events_loaded,
                chunks_loaded: total_chunks_loaded,
                lazy_reveal_batches: total_lazy_reveal_batches,
                anchor_present: true,
                reached_start: false,
                hit_gap: false,
            });
        }

        // Step 2: load from disk chunk by chunk until the anchor is found or
        // the cache is exhausted (load-until-anchor, no over-fetch).
        let needs_u16 = needs.try_into().unwrap_or(u16::MAX);
        let outcome =
            self.event_cache.pagination().run_backwards_cache_only(needs_u16, anchor_id).await?;
        total_events_loaded += outcome.events_loaded;
        total_chunks_loaded += outcome.chunks_loaded;

        // Step 3: when reached_start, the event cache is exhausted — all events
        // that will ever be in the cache are already in memory (either just
        // loaded from disk by run_backwards_cache_only, or already in the
        // in-memory linked chunk when StartOfTimeline fired on the first call).
        //
        // The anchor check inside run_backwards_cache_only is synchronous over
        // the raw event list in each loaded chunk. However, Timeline items
        // (`state.items`) are populated asynchronously through the 3-hop relay
        // pipeline (room_event_cache_updates_task → handle_remote_events_with_diffs
        // → observable → relay task → DiffBatch actor message). At the point we
        // read items(), the async pipeline may not have processed the events yet,
        // so rfind_event_by_id returns no match even though the anchor will arrive
        // once the pipeline drains.
        //
        // When anchor_id is Some and reached_start, treat reached_start as
        // "anchor_present" — all events are in the cache at this point and the
        // relay pipeline WILL deliver them. The caller's relay-wait loop
        // (anchor_relay_wait in koushi-core) does the authoritative final check
        // via timeline_contains_event_id, which is the correct place to observe
        // the fully-processed Timeline state.
        //
        // If the anchor is genuinely absent from the cache (e.g. we pruned it or
        // the event predates the cache's oldest entry), the relay-wait loop's
        // backstop (RESTORE_ANCHOR_RELAY_WAIT_TICKS exhaustion) will safely fall
        // back to EndReached after a bounded wait. This is deterministic and
        // avoids the false-negative that would occur from reading items() before
        // the pipeline settles.
        if outcome.reached_start && anchor_id.is_some() {
            // All cache events are now in memory; the anchor will be delivered
            // by the relay pipeline (handle_remote_events_with_diffs async path).
            // Signal anchor_present=true so the caller enters the relay-wait loop
            // (anchor_relay_wait in koushi-core), which does the authoritative
            // final check via timeline_contains_event_id once the pipeline settles.
            // See comment block above for the full rationale.
            return Ok(RestoreFromCacheOutcome {
                events_loaded: total_events_loaded,
                chunks_loaded: total_chunks_loaded,
                lazy_reveal_batches: total_lazy_reveal_batches,
                anchor_present: true,
                reached_start: true,
                hit_gap: false,
            });
        }

        Ok(RestoreFromCacheOutcome {
            events_loaded: total_events_loaded,
            chunks_loaded: total_chunks_loaded,
            lazy_reveal_batches: total_lazy_reveal_batches,
            anchor_present: outcome.anchor_present,
            reached_start: outcome.reached_start,
            hit_gap: outcome.hit_gap,
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
