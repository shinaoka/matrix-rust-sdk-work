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

//! Event-focused timeline cache.
//!
//! This module provides [`EventFocusedCache`], a cache for an event-focused
//! timeline (e.g., for permalinks). It handles:
//! - Initialization from a focused event via `/context`.
//! - Thread detection (if the focused event is in a thread).
//! - Forward and backward pagination.
//! - In-memory storage, as these linked chunks are meant to be short-lived.
//!
//! Pagination tokens are stored as Gap items in the linked chunk:
//! - Backward token: Gap at the front of the linked chunk.
//! - Forward token: Gap at the back of the linked chunk.
//!
//! This allows pagination to resume at any point, and supports a future use
//! case where we'd want to persist these caches on disk (e.g., for permalinks
//! to work across sessions).

use std::sync::Arc;

use eyeball_im::VectorDiff;
use matrix_sdk_base::{
    deserialized_responses::TimelineEvent,
    event_cache::{Event, Gap},
    linked_chunk::OwnedLinkedChunkId,
};
use matrix_sdk_common::{linked_chunk::ChunkIdentifier, serde_helpers::extract_thread_root};
use ruma::{OwnedEventId, OwnedRoomId, RoomId, UInt, api::Direction};
use tokio::sync::broadcast::{Receiver, Sender};
use tracing::{instrument, trace};

#[cfg(feature = "e2e-encryption")]
use super::super::redecryptor::{MaybeResolvedEvent, TryResolveEvents};
use super::{
    super::{
        EventCacheError, EventsOrigin, Result, RoomEventCacheLinkedChunkUpdate,
        states::{
            CacheStateLock, ReloadPreprocessing, StateLock, selectors::EventFocusedStateSelector,
        },
    },
    TimelineVectorDiffs,
    event_linked_chunk::EventLinkedChunk,
    room::EventLocalWindow,
};
use crate::{
    Room,
    paginators::{PaginationResult, Paginator, StartFromResult, thread::PaginableThread},
    room::{IncludeRelations, MessagesOptions, RelationsOptions, WeakRoom},
};

/// Options for controlling the behaviour of an `EventFocusedCache` when the
/// focused event may be part of a thread, or a thread's root.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum EventFocusThreadMode {
    /// Force the timeline represented by the linked chunk to only include
    /// threaded events.
    ///
    /// When the focused event is part of a thread, the linked chunk will be
    /// focused on that thread's root. Otherwise, the linked chunk will treat
    /// the target event itself as the thread root. Threaded events will never
    /// be hidden.
    ForceThread,

    /// Automatically determine if the target event is part of a thread or not.
    ///
    /// If the event is part of a thread, the linked chunk will be filtered to
    /// on-thread events.
    Automatic {
        /// When the target event is not part of a thread, whether to hide
        /// in-thread replies from the room context.
        hide_threaded_events: bool,
    },
}

/// The mode of pagination for an event-focused linked chunk.
#[derive(Debug, Clone)]
pub(crate) enum EventFocusedPaginationMode {
    /// Standard room pagination (for all events as for an unthreaded/main room
    /// linked chunk).
    Room { hide_thread_events: bool },

    /// Threaded pagination (the focused event is part of a thread).
    Thread {
        /// The root event ID of the thread.
        thread_root: OwnedEventId,
    },
}

pub struct EventFocusedCacheState {
    /// The room owning this event-focused cache.
    room: WeakRoom,

    /// The focused event ID.
    focused_event_id: OwnedEventId,

    /// The pagination mode (room or thread).
    pagination_mode: EventFocusedPaginationMode,

    /// The linked chunk for this event-focused cache.
    chunk: EventLinkedChunk,

    /// The `num_context_events` given to [`Self::start_from`].
    ///
    /// This is useful for [`Self::reload`] to load the same amount of events.
    initial_num_context_events: u16,

    /// The thread mode.
    thread_mode: EventFocusThreadMode,

    /// A sender of timeline updates.
    pub update_sender: EventFocusedCacheUpdateSender,

    /// A sender for globally observable linked chunk updates.
    linked_chunk_update_sender: Sender<RoomEventCacheLinkedChunkUpdate>,
}

impl EventFocusedCacheState {
    /// Initialize the cache from a focused event.
    ///
    /// When `local_window` is given and it covers the focused event usefully,
    /// the cache is built from the events the room already holds, without any
    /// request. Otherwise this uses `/context` to fetch the event with
    /// surrounding context.
    ///
    /// This detects if the event is part of a thread and sets up the
    /// appropriate pagination mode.
    ///
    /// Pagination tokens are stored as gaps in the linked chunk:
    ///
    /// - Backward token (start): Gap at the front of the linked chunk.
    /// - Forward token (end): Gap at the back of the linked chunk.
    #[instrument(skip(self, local_window), fields(room_id = %self.room.room_id(), event_id = %self.focused_event_id))]
    async fn start_from(
        &mut self,
        num_context_events: u16,
        thread_mode: EventFocusThreadMode,
        local_window: Option<EventLocalWindow>,
    ) -> Result<StartFromResult> {
        self.initial_num_context_events = num_context_events;
        self.thread_mode = thread_mode;

        let result = match local_window.and_then(|window| self.seed_from_local_window(window)) {
            Some(result) => result,
            None => self.reload_impl().await?,
        };

        // Empty the updates_as_vector_diffs(), since it's impossible for an
        // observer to have subscribed to this cache yet, since this code is
        // part of the constructor flow.
        //
        // If we didn't empty those, such initial updates would be duplicated,
        // since the subscriber would get the full initial list of events as
        // diffs and as a set of initial events.
        let _ = self.chunk.updates_as_vector_diffs();

        Ok(result)
    }

    /// Build the linked chunk from a contiguous window of the room cache,
    /// instead of asking the server for the same context.
    ///
    /// Returns `None` when the server's view is still needed, leaving the
    /// caller to fall back to `/context`: a forced-thread timeline, and a
    /// focused event that is itself part of a thread, both need `/context` to
    /// locate the thread root and to know which events belong to the thread.
    ///
    /// The two tokens of the window become the front and back gaps, so both
    /// pagination directions keep working exactly as after a `/context` start.
    fn seed_from_local_window(&mut self, window: EventLocalWindow) -> Option<StartFromResult> {
        let hide_thread_events = match self.thread_mode {
            EventFocusThreadMode::ForceThread => {
                trace!("forced thread mode needs /context to locate the thread root");
                return None;
            }

            EventFocusThreadMode::Automatic { hide_threaded_events } => hide_threaded_events,
        };

        let focused_event = window.events.get(window.target_index)?;

        // The room cache's window is the room's timeline, not the thread's: a
        // threaded focused event must still go through `/context` to find its
        // root and to keep only the thread's events.
        if extract_thread_root(focused_event.raw()).is_some() {
            trace!("the focused event belongs to a thread, /context is required");
            return None;
        }

        let stage = crate::event_cache::focused_diagnostics::Stage::new("local_seed");

        let mut events = window.events;

        if hide_thread_events {
            events.retain(|event| extract_thread_root(event.raw()).is_none());
        }

        let local_events = events.len();
        let has_prev = window.prev_token.is_some();
        let has_next = window.next_token.is_some();

        self.pagination_mode = EventFocusedPaginationMode::Room { hide_thread_events };
        self.add_initial_events_with_gaps(events.clone(), window.prev_token, window.next_token);
        self.propagate_changes();

        stage.finish(true);

        trace!(
            local_events,
            has_prev, has_next, "seeded the event-focused linked chunk from the room cache"
        );

        Some(StartFromResult { events, has_prev, has_next })
    }

    /// Reload the event-focused cache: only the last events will be reloaded,
    /// shrinking the in-memory size of the cache.
    ///
    /// Since there is no persistent storage for this cache, `preprocessing` is
    /// ignored.
    #[must_use = "Propagate `VectorDiff` updates via `TimelineVectorDiffs`"]
    pub async fn reload(
        &mut self,
        _preprocessing: ReloadPreprocessing,
    ) -> Result<Vec<VectorDiff<Event>>> {
        let _ = self.reload_impl().await?;

        Ok(self.chunk.updates_as_vector_diffs())
    }

    /// Replace existing events, then load and store fresh events from
    /// `/context`.
    async fn reload_impl(&mut self) -> Result<StartFromResult> {
        let room = self.room.get().ok_or(EventCacheError::ClientDropped)?;
        let num_context_events = self.initial_num_context_events;
        let thread_mode = self.thread_mode;

        trace!(num_context_events, "fetching event with context via /context");

        let paginator = Paginator::new(room);

        let stage = crate::event_cache::focused_diagnostics::Stage::new("context");
        let result =
            paginator.start_from(&self.focused_event_id, UInt::from(num_context_events)).await;
        stage.finish(result.is_ok());
        let result = result?;

        // Detect if the focused event is part of a thread.
        let thread_root = match thread_mode {
            EventFocusThreadMode::ForceThread => {
                // Try to extract a thread root from the focused event, first.
                let focused_event = result
                    .events
                    .iter()
                    .find(|event| event.event_id() == Some(&self.focused_event_id));

                // If the focused event has a thread root, use it.
                let mut thread_root =
                    focused_event.and_then(|event| extract_thread_root(event.raw()));

                // If there's no thread root, consider that the focused event
                // itself is the thread root.
                if thread_root.is_none() {
                    thread_root = Some(self.focused_event_id.clone());
                }

                trace!("force thread mode enabled, treating focused event as thread root");
                thread_root
            }

            EventFocusThreadMode::Automatic { .. } => {
                trace!(
                    "automatic thread mode enabled, checking if focused event is part of a thread"
                );
                result
                    .events
                    .iter()
                    .find(|event| event.event_id() == Some(&self.focused_event_id))
                    .and_then(|event| extract_thread_root(event.raw()))
            }
        };

        // Get pagination tokens from the paginator.
        let tokens = paginator.tokens();

        if let Some(root_id) = thread_root {
            trace!(thread_root = %root_id, "focused event is part of a thread, setting up thread pagination");

            // Check if the thread root is included in the response. Start from
            // the beginning, since it's more likely to be around there, in that
            // case.
            let includes_root =
                result.events.iter().any(|event| event.event_id() == Some(&root_id));

            self.pagination_mode =
                EventFocusedPaginationMode::Thread { thread_root: root_id.clone() };

            // Filter events to only include those in the thread.
            let thread_events = result
                .events
                .iter()
                .filter(|event| {
                    extract_thread_root(event.raw()).as_ref() == Some(&root_id)
                        || event.event_id() == Some(&root_id)
                })
                .cloned()
                .collect();

            // Determine backward token (only if we don't have the thread root).
            let backward_token = if includes_root {
                // We have the root, no need for backward pagination.
                None
            } else {
                tokens.previous.into_token()
            };

            // Forward token.
            let forward_token = tokens.next.into_token();

            self.add_initial_events_with_gaps(thread_events, backward_token, forward_token);
        } else {
            trace!("focused event is not part of a thread, setting up room pagination");

            let backward_token = tokens.previous.into_token();
            let forward_token = tokens.next.into_token();

            let hide_thread_events = match thread_mode {
                EventFocusThreadMode::Automatic { hide_threaded_events } => hide_threaded_events,
                EventFocusThreadMode::ForceThread => false,
            };

            self.pagination_mode = EventFocusedPaginationMode::Room { hide_thread_events };

            let events = if hide_thread_events {
                result
                    .events
                    .iter()
                    .filter(|event| extract_thread_root(event.raw()).is_none())
                    .cloned()
                    .collect()
            } else {
                result.events.clone()
            };

            self.add_initial_events_with_gaps(events, backward_token, forward_token);
        }

        self.propagate_changes();

        Ok(result)
    }

    /// Add initial events to the chunk, with gaps for pagination tokens.
    fn add_initial_events_with_gaps(
        &mut self,
        events: Vec<TimelineEvent>,
        prev_gap_token: Option<String>,
        next_gap_token: Option<String>,
    ) {
        // Clear all existing events as we are about to insert initial events.
        self.chunk.reset();

        // Insert backward gap at the back if we have a token, and the events
        // themselves.
        self.chunk
            .push_live_events(prev_gap_token.map(|prev_token| Gap { token: prev_token }), &events);

        // Insert forward gap at back if we have a token.
        if let Some(next_token) = next_gap_token {
            trace!("inserting forward pagination gap at back");
            self.chunk.push_gap(Gap { token: next_token });
        }
    }

    /// Propagate changes to the linked chunk update sender.
    fn propagate_changes(&mut self) {
        let updates = self.chunk.store_updates().take();
        if !updates.is_empty() {
            let _ = self.linked_chunk_update_sender.send(RoomEventCacheLinkedChunkUpdate {
                updates,
                linked_chunk_id: OwnedLinkedChunkId::EventFocused(
                    self.room.room_id().to_owned(),
                    self.focused_event_id.clone(),
                ),
            });
        }
    }

    /// Notify subscribers of timeline updates.
    fn notify_subscribers(&mut self, origin: EventsOrigin) {
        let diffs = self.chunk.updates_as_vector_diffs();
        if !diffs.is_empty() {
            let _ = self.update_sender.send(TimelineVectorDiffs { diffs, origin });
        }
    }

    /// Return the first chunk as a gap, if it's one.
    fn first_chunk_as_gap(&self) -> Option<(ChunkIdentifier, Gap)> {
        self.chunk.first_chunk_as_gap()
    }

    /// Return the last chunk as a gap, if it's one.
    fn last_chunk_as_gap(&self) -> Option<(ChunkIdentifier, Gap)> {
        self.chunk.last_chunk_as_gap()
    }

    /// Paginate backwards in this event-focused linked chunk.
    ///
    /// This finds the gap at the front of the linked chunk, fetches older
    /// events, replaces the gap with the events, and inserts a new gap if there
    /// are more events to fetch.
    #[instrument(skip(self), fields(room_id = %self.room.room_id()))]
    async fn paginate_backwards(&mut self, num_events: u16) -> Result<PaginationResult> {
        let room = self.room.get().ok_or(EventCacheError::ClientDropped)?;

        // Find the gap at the front (backward pagination token).
        let Some((gap_id, gap)) = self.first_chunk_as_gap() else {
            // No gap at front means we've already hit the start of the
            // timeline.
            trace!("no front gap found, already at timeline start");
            return Ok(PaginationResult { events: Vec::new(), hit_end_of_timeline: true });
        };

        let token = gap.token;
        trace!(?token, "paginating backwards with token from front gap");

        // Fetch events based on pagination mode.
        let (mut events, new_token) = match &self.pagination_mode {
            EventFocusedPaginationMode::Room { .. } => {
                Self::fetch_room_backwards(&room, num_events, &token).await?
            }
            EventFocusedPaginationMode::Thread { thread_root } => {
                Self::fetch_thread_backwards(&room, num_events, &token, thread_root.clone()).await?
            }
        };

        // Events are in the reverse order, per the API contracts defined in the
        // two fetch methods.
        events.reverse();

        let hit_end = new_token.is_none();
        let new_gap = new_token.map(|t| Gap { token: t });

        let hide_thread_events = match &self.pagination_mode {
            EventFocusedPaginationMode::Room { hide_thread_events } => *hide_thread_events,
            EventFocusedPaginationMode::Thread { .. } => false,
        };

        let events = if hide_thread_events {
            events.into_iter().filter(|event| extract_thread_root(event.raw()).is_none()).collect()
        } else {
            events
        };

        // Replace the gap and insert the new events.
        self.chunk.push_backwards_pagination_events(Some(gap_id), new_gap, &events);

        self.propagate_changes();
        self.notify_subscribers(EventsOrigin::Pagination);

        Ok(PaginationResult { events, hit_end_of_timeline: hit_end })
    }

    /// Fetch events for backward room pagination (returns events and optional
    /// next token).
    ///
    /// Returns the events in the same ordering as the one received by the
    /// server, i.e., newest to oldest.
    async fn fetch_room_backwards(
        room: &Room,
        num_events: u16,
        token: &str,
    ) -> Result<(Vec<Event>, Option<String>)> {
        let mut options = MessagesOptions::backward().from(token);
        options.limit = UInt::from(num_events);

        let messages = room
            .messages(options)
            .await
            .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;

        Ok((messages.chunk, messages.end))
    }

    /// Fetch events for backward thread pagination.
    ///
    /// Returns the events in the same ordering as the one received by the
    /// server, i.e., newest to oldest.
    async fn fetch_thread_backwards(
        room: &Room,
        num_events: u16,
        token: &str,
        thread_root: OwnedEventId,
    ) -> Result<(Vec<Event>, Option<String>)> {
        let options = RelationsOptions {
            from: Some(token.to_owned()),
            dir: Direction::Backward,
            limit: Some(UInt::from(num_events)),
            include_relations: IncludeRelations::AllRelations,
            recurse: true,
        };

        let mut result = room
            .relations(thread_root.clone(), options)
            .await
            .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;

        // If we hit the end (no more token), load the thread root event.
        if result.next_batch_token.is_none() {
            let root_event = room
                .load_event(&thread_root)
                .await
                .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;
            result.chunk.push(root_event);
        }

        Ok((result.chunk, result.next_batch_token))
    }

    /// Paginate forwards in this event-focused timeline.
    ///
    /// This finds the gap at the back of the linked chunk, fetches newer
    /// events, replaces the gap with the events, and inserts a new gap if there
    /// are more events to fetch.
    #[instrument(skip(self), fields(room_id = %self.room.room_id()))]
    async fn paginate_forwards(&mut self, num_events: u16) -> Result<PaginationResult> {
        let room = self.room.get().ok_or(EventCacheError::ClientDropped)?;

        // Find the gap at the back (forward pagination token).
        let Some((gap_id, gap)) = self.last_chunk_as_gap() else {
            // No gap at back means we've already hit the end of the timeline.
            trace!("no back gap found, already at timeline end");
            return Ok(PaginationResult { events: Vec::new(), hit_end_of_timeline: true });
        };

        let token = gap.token;
        trace!(?token, "paginating forwards with token from back gap");

        // Fetch events based on pagination mode.
        let (events, new_token) = match &self.pagination_mode {
            EventFocusedPaginationMode::Room { .. } => {
                Self::fetch_room_forwards(&room, num_events, &token).await?
            }
            EventFocusedPaginationMode::Thread { thread_root } => {
                Self::fetch_thread_forwards(&room, num_events, &token, thread_root.clone()).await?
            }
        };

        let hit_end = new_token.is_none();
        let new_gap = new_token.map(|t| Gap { token: t });

        let hide_thread_events = match &self.pagination_mode {
            EventFocusedPaginationMode::Room { hide_thread_events } => *hide_thread_events,
            EventFocusedPaginationMode::Thread { .. } => false,
        };

        let events = if hide_thread_events {
            events.into_iter().filter(|event| extract_thread_root(event.raw()).is_none()).collect()
        } else {
            events
        };

        // Replace the gap and insert new events.
        self.chunk.push_forwards_pagination_events(Some(gap_id), new_gap, &events);

        self.propagate_changes();
        self.notify_subscribers(EventsOrigin::Pagination);

        Ok(PaginationResult { events, hit_end_of_timeline: hit_end })
    }

    /// Fetch events for forward room pagination.
    async fn fetch_room_forwards(
        room: &Room,
        num_events: u16,
        token: &str,
    ) -> Result<(Vec<Event>, Option<String>)> {
        let mut options = MessagesOptions::new(Direction::Forward);
        options = options.from(Some(token));
        options.limit = UInt::from(num_events);

        let messages = room
            .messages(options)
            .await
            .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;

        Ok((messages.chunk, messages.end))
    }

    /// Fetch events for forward thread pagination.
    async fn fetch_thread_forwards(
        room: &Room,
        num_events: u16,
        token: &str,
        thread_root: OwnedEventId,
    ) -> Result<(Vec<Event>, Option<String>)> {
        let options = RelationsOptions {
            from: Some(token.to_owned()),
            dir: Direction::Forward,
            limit: Some(UInt::from(num_events)),
            include_relations: IncludeRelations::AllRelations,
            recurse: true,
        };

        let result = room
            .relations(thread_root, options)
            .await
            .map_err(|err| EventCacheError::PaginationError(Arc::new(err)))?;

        Ok((result.chunk, result.next_batch_token))
    }
}

/// A cache for an event-focused timeline.
///
/// This represents a timeline centred around a specific event (e.g., from a
/// permalink), supporting both forward and backward pagination. The focused
/// event may be part of a thread, in which case pagination will use the
/// `/relations` API instead of `/messages`.
///
/// Pagination tokens are stored as Gap items in the linked chunk itself:
///
/// - A gap at the **front** (first position) contains the backward pagination
///   token.
/// - A gap at the **back** (last position) contains the forward pagination
///   token.
///
/// This is a shallow data structure, and can be cloned cheaply.
#[derive(Clone)]
pub struct EventFocusedCache {
    room_id: OwnedRoomId,
    inner: Arc<CacheStateLock<EventFocusedStateSelector>>,
}

impl EventFocusedCache {
    /// Create an initialized event-focused cache before publishing its state.
    pub(super) async fn new(
        room: WeakRoom,
        key: EventFocusedCacheKey,
        state: &StateLock,
        linked_chunk_update_sender: Sender<RoomEventCacheLinkedChunkUpdate>,
        number_of_initial_events: u16,
        local_window: Option<EventLocalWindow>,
    ) -> Result<Self> {
        let room_id = room.room_id().to_owned();
        let thread_mode = key.thread_mode;
        let cache_state = state
            .try_insert_once_with(
                EventFocusedStateSelector::new(room_id.clone(), key.clone()),
                |store_guard| async {
                    // Keep the existing cross-process store lock through
                    // initialization.
                    let _store_guard = store_guard;
                    let mut cache = EventFocusedCacheState {
                        room,
                        focused_event_id: key.focused_event_id,
                        pagination_mode: EventFocusedPaginationMode::Room {
                            hide_thread_events: false,
                        },
                        chunk: EventLinkedChunk::new(),
                        initial_num_context_events: 0, // dummy value
                        thread_mode: EventFocusThreadMode::Automatic {
                            hide_threaded_events: false,
                        }, // dummy value
                        update_sender: Sender::new(32),
                        linked_chunk_update_sender,
                    };
                    // Register only after initialization succeeds. Dropping or
                    // failing the context request must not
                    // strand a state without a cache handle.
                    cache.start_from(number_of_initial_events, thread_mode, local_window).await?;
                    Ok(cache)
                },
            )
            .await?;

        Ok(Self { room_id, inner: Arc::new(cache_state) })
    }

    /// Get the room ID of this cache.
    pub fn room_id(&self) -> &RoomId {
        &self.room_id
    }

    /// Read all current events.
    ///
    /// Use [`EventFocusedCache::subscribe`] to get all current events, plus a
    /// subscriber.
    pub async fn events(&self) -> Result<Vec<Event>> {
        let state = self.inner.read().await?;

        Ok(state.chunk.events().map(|(_position, item)| item.clone()).collect())
    }

    /// Subscribe to updates from this event-focused timeline.
    pub async fn subscribe(&self) -> Result<(Vec<Event>, Receiver<TimelineVectorDiffs>)> {
        let state = self.inner.read().await?;
        let events = state.chunk.events().map(|(_position, item)| item.clone()).collect();
        let recv = state.update_sender.subscribe();
        Ok((events, recv))
    }

    /// Check if we've hit the start of the timeline (no more backward
    /// pagination possible).
    pub async fn hit_timeline_start(&self) -> Result<bool> {
        Ok(self.inner.read().await?.first_chunk_as_gap().is_none())
    }

    /// Check if we've hit the end of the timeline (no more forward pagination
    /// possible).
    pub async fn hit_timeline_end(&self) -> Result<bool> {
        Ok(self.inner.read().await?.last_chunk_as_gap().is_none())
    }

    /// Paginate backwards in this event-focused timeline, be it room or thread
    /// pagination depending on the mode.
    pub async fn paginate_backwards(&self, num_events: u16) -> Result<PaginationResult> {
        self.inner.write().await?.paginate_backwards(num_events).await
    }

    /// Paginate forwards in this event-focused timeline, be it room or thread
    /// pagination depending on the mode.
    pub async fn paginate_forwards(&self, num_events: u16) -> Result<PaginationResult> {
        self.inner.write().await?.paginate_forwards(num_events).await
    }

    /// Get the thread root event ID if this linked chunk is in thread mode.
    pub async fn thread_root(&self) -> Result<Option<OwnedEventId>> {
        Ok(match &self.inner.read().await?.pagination_mode {
            EventFocusedPaginationMode::Thread { thread_root } => Some(thread_root.clone()),
            _ => None,
        })
    }

    /// Try to locate the events in the linked chunk corresponding to the given
    /// list of resolved events, and replace them, while alerting observers
    /// about the update.
    #[cfg(feature = "e2e-encryption")]
    pub(in super::super) async fn replace_in_memory_utds(
        &self,
        resolved_events: &[MaybeResolvedEvent],
    ) -> Result<()> {
        let mut state = self.inner.write().await?;

        // `Redecryptor` tried to resolve the events partly based on in-store
        // events. Because this cache doesn't persist anything in the store,
        // `Redecryptor` is unable to resolve some events present here. To
        // address that, let's try to resolve events here with the current
        // `EventLinkedChunk`.
        let new_resolved_events = resolved_events.try_resolve_events(&state.chunk);

        if state.chunk.replace_utds(&new_resolved_events) {
            state.propagate_changes();
            state.notify_subscribers(EventsOrigin::Cache);
        }

        Ok(())
    }
}

#[cfg(not(tarpaulin_include))]
impl std::fmt::Debug for EventFocusedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventFocusedCache").finish_non_exhaustive()
    }
}

/// Key for the event-focused caches.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EventFocusedCacheKey {
    /// The event ID that the cache is focused on.
    pub focused_event_id: OwnedEventId,
    /// The thread mode for this cache.
    pub thread_mode: EventFocusThreadMode,
}

/// A small type to send updates in all channels.
pub type EventFocusedCacheUpdateSender = Sender<TimelineVectorDiffs>;

#[cfg(test)]
mod tests {
    use matrix_sdk_base::RoomState;
    use matrix_sdk_test::{async_test, event_factory::EventFactory};
    use ruma::{EventId, event_id, room_id, user_id};

    use super::{
        EventFocusThreadMode, EventFocusedCacheState, EventFocusedPaginationMode, EventLocalWindow,
    };
    use crate::{
        event_cache::caches::event_linked_chunk::EventLinkedChunk, room::WeakRoom,
        test_utils::client::MockClientBuilder,
    };

    async fn state(
        thread_mode: EventFocusThreadMode,
        focused_event_id: &EventId,
    ) -> EventFocusedCacheState {
        let room_id = room_id!("!focused-local-seed:example.org");
        let client = MockClientBuilder::new(None).build().await;
        client.base_client().get_or_create_room(room_id, RoomState::Joined);

        EventFocusedCacheState {
            room: WeakRoom::new(client.downgrade(), room_id.to_owned()),
            focused_event_id: focused_event_id.to_owned(),
            pagination_mode: EventFocusedPaginationMode::Room { hide_thread_events: false },
            chunk: EventLinkedChunk::new(),
            initial_num_context_events: 0,
            thread_mode,
            update_sender: tokio::sync::broadcast::Sender::new(4),
            linked_chunk_update_sender: tokio::sync::broadcast::Sender::new(4),
        }
    }

    fn window(
        events: &[(String, bool)],
        target_index: usize,
        prev_token: Option<&str>,
        next_token: Option<&str>,
    ) -> EventLocalWindow {
        let factory = EventFactory::new()
            .room(room_id!("!focused-local-seed:example.org"))
            .sender(user_id!("@alice:example.org"));

        EventLocalWindow {
            events: events
                .iter()
                .map(|(event_id, threaded)| {
                    let event_id = EventId::parse(event_id).unwrap();
                    let builder = factory.text_msg("hello").event_id(&event_id);

                    if *threaded {
                        builder.in_thread(event_id!("$thread_root"), &event_id).into_event()
                    } else {
                        builder.into_event()
                    }
                })
                .collect(),
            target_index,
            prev_token: prev_token.map(ToOwned::to_owned),
            next_token: next_token.map(ToOwned::to_owned),
        }
    }

    fn event_ids<I: IntoIterator<Item = matrix_sdk_base::event_cache::Event>>(
        events: I,
    ) -> Vec<String> {
        events.into_iter().map(|event| event.event_id().unwrap().to_string()).collect()
    }

    /// A window becomes the linked chunk, with its two tokens as the two gaps,
    /// so both pagination directions are still available.
    #[async_test]
    async fn test_a_local_window_becomes_the_two_gaps() {
        let mut state =
            state(EventFocusThreadMode::Automatic { hide_threaded_events: false }, event_id!("$2"))
                .await;

        let loaded = window(
            &[("$1".to_owned(), false), ("$2".to_owned(), false), ("$3".to_owned(), false)],
            1,
            Some("older"),
            Some("newer"),
        );

        let result = state.seed_from_local_window(loaded).expect("the window is usable");

        assert_eq!(event_ids(result.events), ["$1", "$2", "$3"]);
        assert!(result.has_prev);
        assert!(result.has_next);

        assert_eq!(
            state.first_chunk_as_gap().map(|(_, gap)| gap.token),
            Some("older".to_owned()),
            "the window's older token is the front gap"
        );
        assert_eq!(
            state.last_chunk_as_gap().map(|(_, gap)| gap.token),
            Some("newer".to_owned()),
            "the window's newer token is the back gap"
        );

        assert!(matches!(
            state.pagination_mode,
            EventFocusedPaginationMode::Room { hide_thread_events: false }
        ));
    }

    /// A window that is the whole known timeline has no gaps at all, and says
    /// so.
    #[async_test]
    async fn test_a_window_without_tokens_has_no_gaps() {
        let mut state =
            state(EventFocusThreadMode::Automatic { hide_threaded_events: false }, event_id!("$1"))
                .await;

        let loaded = window(&[("$1".to_owned(), false)], 0, None, None);

        let result = state.seed_from_local_window(loaded).expect("the window is usable");

        assert!(!result.has_prev);
        assert!(!result.has_next);
        assert!(state.first_chunk_as_gap().is_none());
        assert!(state.last_chunk_as_gap().is_none());
    }

    /// Threads keep their server-side initialization: the room's window is the
    /// room's timeline, not the thread's.
    #[async_test]
    async fn test_a_threaded_target_keeps_context() {
        let mut automatic =
            state(EventFocusThreadMode::Automatic { hide_threaded_events: false }, event_id!("$2"))
                .await;

        assert!(
            automatic
                .seed_from_local_window(window(
                    &[("$1".to_owned(), false), ("$2".to_owned(), true)],
                    1,
                    Some("older"),
                    Some("newer"),
                ))
                .is_none(),
            "a threaded focused event needs /context to find its root"
        );

        let mut forced = state(EventFocusThreadMode::ForceThread, event_id!("$2")).await;

        assert!(
            forced
                .seed_from_local_window(window(
                    &[("$1".to_owned(), false), ("$2".to_owned(), false)],
                    1,
                    Some("older"),
                    Some("newer"),
                ))
                .is_none(),
            "a forced thread needs /context even for an unthreaded event"
        );
    }
}
