// Copyright 2025 The Matrix.org Foundation C.I.C.
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

//! The Redecryptor (affectionately known as R2D2) is a layer and long-running
//! background task which handles redecryption of events in case we couldn't
//! decrypt them immediately.
//!
//! There are various reasons why a room key might not be available immediately
//! when the event becomes available:
//!     - The to-device message containing the room key just arrives late, i.e.
//!       after the room event.
//!     - The event is a historic event and we need to first download the room
//!       key from the backup.
//!     - The event is a historic event in a previously unjoined room, we need
//!       to receive historic room keys as defined in [MSC3061].
//!
//! R2D2 listens to the [`OlmMachine`] for received room keys and new
//! m.room_key.withheld events.
//!
//! If a new room key has been received, it attempts to find any UTDs in the
//! [`EventCache`]. If R2D2 decrypts any UTDs from the event cache, it will
//! replace the events in the cache and send out new [`RoomEventCacheUpdate`]s
//! to any of its listeners.
//!
//! If a new withheld info has been received, it attempts to find any relevant
//! events and updates the [`EncryptionInfo`] of an event.
//!
//! There's an additional gotcha: the [`OlmMachine`] might get recreated by
//! calls to [`BaseClient::regenerate_olm()`]. When this happens, we will
//! receive a `None` on the room keys stream and we need to re-listen to it.
//!
//! Another gotcha is that room keys might be received on another process if the
//! [`Client`] is operating on a Apple iOS device. A separate process is used
//! in this case to receive push notifications. In this case, the room key will
//! be received and R2D2 won't get notified about it. To work around this,
//! decryption requests can be explicitly sent to R2D2.
//!
//! The final gotcha is that a room key might be received just in between the
//! time the event was initially tried to be decrypted and the time it took to
//! persist it in the event cache. To handle this race condition, R2D2 listens
//! to the event cache and attempts to decrypt any UTDs the event cache
//! persists.
//!
//! In the graph below, the Timeline block is meant to be the `Timeline` from
//! the `matrix-sdk-ui` crate, but it could be any other listener that
//! subscribes to [`RedecryptorReport`] stream.
//!
//! ```markdown
//!      .----------------------.
//!     |                        |
//!     |      Beeb, boop!       |
//!     |                        .
//!      ----------------------._ \
//!                               -;  _____
//!                                 .`/L|__`.
//!                                / =[_]O|` \
//!                                |"+_____":|
//!                              __:='|____`-:__
//!                             ||[] ||====|| []||
//!                             ||[] ||====|| []||
//!                             |:== ||====|| ==:|
//!                             ||[] ||====|| []||
//!                             ||[] ||====|| []||
//!                            _||_  ||====||  _||_
//!                           (====) |:====:| (====)
//!                            }--{  | |  | |  }--{
//!                           (____) |_|  |_| (____)
//!
//!                              ┌─────────────┐
//!                              │             │
//!                  ┌───────────┤   Timeline  │◄────────────┐
//!                  │           │             │             │
//!                  │           └──────▲──────┘             │
//!                  │                  │                    │
//!                  │                  │                    │
//!                  │                  │                    │
//!              Decryption             │                Redecryptor
//!                request              │                  report
//!                  │        RoomEventCacheUpdates          │
//!                  │                  │                    │
//!                  │                  │                    │
//!                  │      ┌───────────┴───────────┐        │
//!                  │      │                       │        │
//!                  └──────►         R2D2          │────────┘
//!                         │                       │
//!                         └──▲─────────────────▲──┘
//!                            │                 │
//!                            │                 │
//!                            │                 │
//!                         Received        Received room
//!                          events          keys stream
//!                            │                 │
//!                            │                 │
//!                            │                 │
//!                    ┌───────┴──────┐  ┌───────┴──────┐
//!                    │              │  │              │
//!                    │  Event Cache │  │  OlmMachine  │
//!                    │              │  │              │
//!                    └──────────────┘  └──────────────┘
//! ```
//!
//! [MSC3061]: https://github.com/matrix-org/matrix-spec/pull/1655#issuecomment-2213152255

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    pin::{Pin, pin},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use as_variant::as_variant;
use futures_core::Stream;
use futures_util::{StreamExt, future::try_join_all};
#[cfg(feature = "e2e-encryption")]
use matrix_sdk_base::deserialized_responses::UnableToDecryptReason;
#[cfg(doc)]
use matrix_sdk_base::{BaseClient, crypto::OlmMachine};
use matrix_sdk_base::{
    crypto::{
        store::types::{RoomKeyInfo, RoomKeyWithheldInfo},
        types::events::room::encrypted::EncryptedEvent,
    },
    deserialized_responses::{DecryptedRoomEvent, TimelineEvent, TimelineEventKind},
    locks::Mutex,
    task_monitor::BackgroundTaskHandle,
    timer,
};
#[cfg(doc)]
use matrix_sdk_common::deserialized_responses::EncryptionInfo;
use ruma::{
    OwnedEventId, OwnedRoomId, RoomId,
    events::{
        AnyMessageLikeEvent, AnySyncTimelineEvent, AnyTimelineEvent, MessageLikeEvent,
        room::{encrypted::OriginalSyncRoomEncryptedEvent, message::MessageType},
    },
    push::Action,
    serde::Raw,
};
use tokio::sync::{
    broadcast::{self, Sender},
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_stream::wrappers::{
    BroadcastStream, UnboundedReceiverStream, errors::BroadcastStreamRecvError,
};
use tracing::{info, instrument, trace, warn};

#[cfg(doc)]
use super::RoomEventCache;
use super::{
    EventCache, EventCacheError, EventCacheInner, EventsOrigin, RoomEventCacheGenericUpdate,
    RoomEventCacheUpdate, TimelineVectorDiffs,
    caches::{
        EventLocation, event_linked_chunk::EventLinkedChunk, room::RoomEventCacheLinkedChunkUpdate,
    },
};
use crate::{Client, Result, Room, encryption::backups::BackupState, room::PushContext};

type SessionId<'a> = &'a str;
type OwnedSessionId = String;

type EventIdAndUtd = (OwnedEventId, Raw<AnySyncTimelineEvent>);
type EventIdAndEvent = (OwnedEventId, DecryptedRoomEvent);

/// Whether a decrypted room event is relevant to the verification machine.
///
/// Mirrors the event selection used when sync feeds freshly decrypted events
/// to the verification machine: an original `m.room.message` with the
/// `m.key.verification.request` msgtype, or one of the in-room
/// `m.key.verification.*` events.
fn is_verification_event(event: &AnyMessageLikeEvent) -> bool {
    match event {
        AnyMessageLikeEvent::RoomMessage(MessageLikeEvent::Original(original)) => {
            matches!(original.content.msgtype, MessageType::VerificationRequest(_))
        }
        AnyMessageLikeEvent::KeyVerificationReady(_)
        | AnyMessageLikeEvent::KeyVerificationStart(_)
        | AnyMessageLikeEvent::KeyVerificationCancel(_)
        | AnyMessageLikeEvent::KeyVerificationAccept(_)
        | AnyMessageLikeEvent::KeyVerificationKey(_)
        | AnyMessageLikeEvent::KeyVerificationMac(_)
        | AnyMessageLikeEvent::KeyVerificationDone(_) => true,
        _ => false,
    }
}

/// Feed late-decrypted in-room verification events to the verification
/// machine.
///
/// Sync only hands an in-room verification event to the verification machine
/// when it decrypts on the first attempt. When the room key arrives after the
/// event (for example because the room key and the room event travel on
/// different sync connections), the event is first stored as a UTD and only
/// resolved here, so without this step an in-room verification request would
/// be displayed but never become an actionable request.
async fn receive_resolved_verification_events(client: &Client, resolved: &[ResolvedUtd]) {
    if !client.base_client().handle_verification_events {
        return;
    }

    let machine = client.olm_machine().await;
    let Some(machine) = machine.as_ref() else {
        return;
    };

    for resolved_utd in resolved {
        let Ok(AnyTimelineEvent::MessageLike(event)) =
            resolved_utd.decrypted_event.event.deserialize()
        else {
            continue;
        };

        if !is_verification_event(&event) {
            continue;
        }

        if let Err(error) = machine.receive_verification_event(&event).await {
            warn!(
                event_id = %resolved_utd.event_id,
                "Failed to handle a late-decrypted verification event: {error}"
            );
        }
    }
}

#[derive(Clone)]
pub(super) struct ResolvedUtd {
    pub event_id: OwnedEventId,
    decrypted_event: DecryptedRoomEvent,
    actions: Option<Vec<Action>>,
}

#[derive(Clone)]
pub(super) enum MaybeResolvedEvent {
    NotYet(ResolvedUtd),
    Resolved(TimelineEvent),
}

impl MaybeResolvedEvent {
    pub fn try_resolve_event(self, mut unresolved_event: TimelineEvent) -> Self {
        match self {
            Self::NotYet(resolved_utd) => {
                // There is a race between the multiple sources of updates. It's
                // possible that two sources trigger a decryption for the same
                // event (for example, the room key stream and the event cache
                // updates). It is then likely that the event has been already
                // resolved. This race is fine, but we should avoid to replace
                // an event that has already been resolved as it is a
                // non-negligible operation.
                //
                // Note that a simple check like “event's kind is
                // `UnableToDecrypt`” is not enough. The event can already be
                // decrypted but its encryption info can change. So we must
                // ensure they are also different.
                if matches!(unresolved_event.kind, TimelineEventKind::UnableToDecrypt { .. })
                    || unresolved_event.encryption_info()
                        != Some(&resolved_utd.decrypted_event.encryption_info)
                {
                    unresolved_event.kind =
                        TimelineEventKind::Decrypted(resolved_utd.decrypted_event);

                    if let Some(actions) = resolved_utd.actions {
                        unresolved_event.set_push_actions(actions);
                    }

                    // The unresolved event becomes resolved :-].
                    Self::Resolved(unresolved_event)
                } else {
                    Self::NotYet(resolved_utd)
                }
            }

            Self::Resolved(event) => Self::Resolved(event),
        }
    }

    pub fn as_resolved(&self) -> Option<&TimelineEvent> {
        if let Self::Resolved(event) = self { Some(event) } else { None }
    }
}

/// Internal trait to resolve events on a `&[MaybeResolvedEvent]` with the help
/// of `Cow` to avoid copying if no event is newly resolved.
pub(super) trait TryResolveEvents {
    fn try_resolve_events(
        &self,
        event_linked_chunk: &EventLinkedChunk,
    ) -> Cow<'_, [MaybeResolvedEvent]>;
}

impl TryResolveEvents for [MaybeResolvedEvent] {
    fn try_resolve_events(
        &self,
        event_linked_chunk: &EventLinkedChunk,
    ) -> Cow<'_, [MaybeResolvedEvent]> {
        let mut new_resolved_events = Cow::Borrowed(self);

        for (nth, resolved_event) in self.iter().enumerate() {
            match resolved_event {
                MaybeResolvedEvent::NotYet(resolved_utd) => {
                    // Event has not been resolved. Let's try to locate the
                    // corresponding event with the provided `EventLinkedChunk`
                    // and try to resolve it.

                    if let Some((_location, event)) =
                        event_linked_chunk.find_event(&resolved_utd.event_id)
                    {
                        let new_resolved_event = MaybeResolvedEvent::NotYet(resolved_utd.clone())
                            .try_resolve_event(event);

                        if matches!(new_resolved_event, MaybeResolvedEvent::Resolved(_)) {
                            // Use `slice::get_unchecked_mut` to avoid a bounds
                            // check.
                            //
                            // SAFETY: `self` and `new_resolved_events` have the
                            // same size and represent the same data. Thus, the
                            // index `nth` exists in `new_resolved_events`.
                            unsafe {
                                *new_resolved_events.to_mut().get_unchecked_mut(nth) =
                                    new_resolved_event;
                            }
                        }
                    }
                }

                MaybeResolvedEvent::Resolved(_event) => {
                    // Event has already been resolved. Nothing to do.
                }
            }
        }

        new_resolved_events
    }
}

/// The information sent across the channel to the long-running task requesting
/// that the supplied set of sessions be retried.
#[derive(Clone)]
pub struct DecryptionRetryRequest {
    /// The room ID of the room the events belong to.
    pub room_id: OwnedRoomId,
    /// Events that are not decrypted.
    pub utd_session_ids: BTreeSet<OwnedSessionId>,
    /// Events that are decrypted but might need to have their
    /// [`EncryptionInfo`] refreshed.
    pub refresh_info_session_ids: BTreeSet<OwnedSessionId>,
}

impl fmt::Debug for DecryptionRetryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Privacy: never print room or Megolm session identifiers from a
        // retry request; only the closed counts.
        f.debug_struct("DecryptionRetryRequest")
            .field("room_id", &"RoomId(..)")
            .field("utd_session_ids", &self.utd_session_ids.len())
            .field("refresh_info_session_ids", &self.refresh_info_session_ids.len())
            .finish()
    }
}

/// A report coming from the redecryptor.
#[derive(Debug, Clone)]
pub enum RedecryptorReport {
    /// Events which we were able to decrypt.
    ResolvedUtds {
        /// The room ID of the room the events belong to.
        room_id: OwnedRoomId,
        /// The list of event IDs of the decrypted events.
        events: BTreeSet<OwnedEventId>,
    },
    /// The redecryptor might have missed some room keys so it might not have
    /// re-decrypted events that are now decryptable.
    Lagging,
    /// A room key backup has become available.
    ///
    /// This means that components might want to tell R2D2 about events they
    /// care about to attempt a decryption.
    BackupAvailable,
}

/// Aggregate privacy-safe counters for late decryption by the event cache.
///
/// Only counts and closed buckets; no identifiers or key material ever enter
/// these counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoomKeyLateDecryptionCounters {
    /// Room-key updates broadcast by the crypto store and observed here.
    pub room_key_updates_broadcast: u64,
    /// Per-session redecryption attempts driven by the room-key stream.
    pub redecryption_requests: u64,
    /// Explicit [`DecryptionRetryRequest`] messages handled.
    pub explicit_retry_requests: u64,
    /// Attempts that matched zero encrypted events.
    pub matching_events_bucket_0: u64,
    /// Attempts that matched one encrypted event.
    pub matching_events_bucket_1: u64,
    /// Attempts that matched 2-5 encrypted events.
    pub matching_events_bucket_2_to_5: u64,
    /// Attempts that matched 6-20 encrypted events.
    pub matching_events_bucket_6_to_20: u64,
    /// Attempts that matched 21-100 encrypted events.
    pub matching_events_bucket_21_to_100: u64,
    /// Attempts that matched more than 100 encrypted events.
    pub matching_events_bucket_101_plus: u64,
    /// Encrypted events successfully redecrypted.
    pub redecryption_succeeded: u64,
    /// Encrypted events that remained undecryptable after a retry.
    pub redecryption_remained_utd: u64,
    /// Encrypted events whose redecryption failed with an SDK error.
    pub redecryption_failed: u64,
    /// Cache/store update failures after a successful redecryption.
    pub redecryption_store_failed: u64,
    /// The room-key (or linked-chunk) stream lagged.
    pub room_key_stream_lagged: u64,
    /// The room-key subscription was recreated after the stream closed.
    pub room_key_stream_recreated: u64,
}

impl RoomKeyLateDecryptionCounters {
    fn record_matching_bucket(&mut self, matched: usize) {
        match matched {
            0 => self.matching_events_bucket_0 += 1,
            1 => self.matching_events_bucket_1 += 1,
            2..=5 => self.matching_events_bucket_2_to_5 += 1,
            6..=20 => self.matching_events_bucket_6_to_20 += 1,
            21..=100 => self.matching_events_bucket_21_to_100 += 1,
            _ => self.matching_events_bucket_101_plus += 1,
        }
    }
}

/// Snapshot of the event-cache late-decryption state for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomKeyLateDecryptionDiagnostics {
    /// Aggregate counters accumulated by the redecryptor task.
    pub counters: RoomKeyLateDecryptionCounters,
    /// Whether the event cache has been subscribed (has an active task set).
    pub subscribed: bool,
    /// Whether the redecryptor background task is still running.
    pub redecryptor_alive: bool,
}

/// Outcome of a single-event redecryption attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedecryptionAttemptOutcome {
    /// The event was decrypted.
    Decrypted,
    /// The event is still undecryptable (key still missing, benign).
    StillUtd,
    /// Decryption failed with an SDK error.
    Failed,
}

pub(super) struct RedecryptorChannels {
    utd_reporter: Sender<RedecryptorReport>,
    pub(super) decryption_request_sender: UnboundedSender<DecryptionRetryRequest>,
    pub(super) decryption_request_receiver:
        Mutex<Option<UnboundedReceiver<DecryptionRetryRequest>>>,
    pub(super) late_decryption_counters: Arc<StdMutex<RoomKeyLateDecryptionCounters>>,
}

impl RedecryptorChannels {
    pub(super) fn new() -> Self {
        let (utd_reporter, _) = broadcast::channel(100);
        let (decryption_request_sender, decryption_request_receiver) = unbounded_channel();

        Self {
            utd_reporter,
            decryption_request_sender,
            decryption_request_receiver: Mutex::new(Some(decryption_request_receiver)),
            late_decryption_counters: Arc::new(StdMutex::new(
                RoomKeyLateDecryptionCounters::default(),
            )),
        }
    }
}

/// Apply an update to the privacy-safe late-decryption counters.
fn counters_bump(
    counters: &Arc<StdMutex<RoomKeyLateDecryptionCounters>>,
    update: impl FnOnce(&mut RoomKeyLateDecryptionCounters),
) {
    if let Ok(mut guard) = counters.lock() {
        update(&mut guard);
    }
}

/// A function which can be used to filter and map [`TimelineEvent`]s into a
/// tuple of event ID and raw [`AnySyncTimelineEvent`].
///
/// The tuple can be used to attempt to redecrypt events.
fn filter_timeline_event_to_utd(
    event: TimelineEvent,
) -> Option<(OwnedEventId, Raw<AnySyncTimelineEvent>)> {
    let event_id = event.event_id().map(ToOwned::to_owned);

    // Only pick out events that are UTDs, get just the Raw event as this is
    // what the OlmMachine needs.
    let event = as_variant!(event.kind, TimelineEventKind::UnableToDecrypt { event, .. } => event);
    // Zip the event ID and event together so we don't have to pick out the
    // event ID again. We need the event ID to replace the event in the cache.
    event_id.zip(event)
}

/// A function which can be used to filter an map [`TimelineEvent`]s into a
/// tuple of event ID and [`DecryptedRoomEvent`].
///
/// The tuple can be used to attempt to update the encryption info of the
/// decrypted event.
fn filter_timeline_event_to_decrypted(
    event: TimelineEvent,
) -> Option<(OwnedEventId, DecryptedRoomEvent)> {
    let event_id = event.event_id().map(ToOwned::to_owned);

    let event = as_variant!(event.kind, TimelineEventKind::Decrypted(event) => event);
    // Zip the event ID and event together so we don't have to pick out the
    // event ID again. We need the event ID to replace the event in the cache.
    event_id.zip(event)
}

impl EventCacheInner {
    /// Retrieve a set of events that we weren't able to decrypt.
    ///
    /// # Arguments
    ///
    /// - `room_id` - The ID of the room where the events were sent to.
    /// - `session_id` - The unique ID of the room key that was used to encrypt
    ///   the event.
    async fn all_encrypted_events(
        &self,
        room_id: &RoomId,
        session_id: SessionId<'_>,
    ) -> Result<Vec<EventIdAndUtd>, EventCacheError> {
        let caches = self.all_caches_for_room(room_id).await?;

        Ok(caches
            .all_events_of_type(Some("m.room.encrypted"), Some(session_id))
            .await?
            .filter_map(filter_timeline_event_to_utd)
            .collect())
    }

    /// Retrieve a set of events that we weren't able to decrypt from the memory
    /// of the event cache.
    async fn all_in_memory_encrypted_events(&self) -> BTreeMap<OwnedRoomId, Vec<EventIdAndUtd>> {
        let mut utds = BTreeMap::new();

        for (room_id, caches) in self.by_room.read().await.iter() {
            let room_utds: Vec<_> = caches
                .all_in_memory_events()
                .await
                .into_iter()
                .flatten()
                .filter_map(filter_timeline_event_to_utd)
                .collect();

            utds.insert(room_id.to_owned(), room_utds);
        }

        utds
    }

    async fn all_decrypted_events(
        &self,
        room_id: &RoomId,
        session_id: SessionId<'_>,
    ) -> Result<Vec<EventIdAndEvent>, EventCacheError> {
        let caches = self.all_caches_for_room(room_id).await?;

        Ok(caches
            .all_events_of_type(None, Some(session_id))
            .await?
            .filter_map(filter_timeline_event_to_decrypted)
            .collect())
    }

    async fn all_in_memory_decrypted_events(&self) -> BTreeMap<OwnedRoomId, Vec<EventIdAndEvent>> {
        let mut decrypted_events = BTreeMap::new();

        for (room_id, caches) in self.by_room.read().await.iter() {
            let room_utds: Vec<_> = caches
                .all_in_memory_events()
                .await
                .into_iter()
                .flatten()
                .filter_map(filter_timeline_event_to_decrypted)
                .collect();

            decrypted_events.insert(room_id.to_owned(), room_utds);
        }

        decrypted_events
    }

    /// Handle a chunk of events that we were previously unable to decrypt but
    /// have now successfully decrypted.
    ///
    /// This function will replace the existing UTD events in memory and the
    /// store and send out a [`RoomEventCacheUpdate`] for the newly decrypted
    /// events.
    ///
    /// # Arguments
    ///
    /// - `room_id` - The ID of the room where the events were sent to.
    /// - `events` - A chunk of events that were successfully decrypted.
    #[instrument(skip_all, fields(room_id))]
    async fn on_resolved_utds(
        &self,
        room_id: &RoomId,
        resolved_utds: Vec<ResolvedUtd>,
    ) -> Result<(), EventCacheError> {
        if resolved_utds.is_empty() {
            trace!("No events were redecrypted or updated, nothing to replace");
            return Ok(());
        }

        timer!("Resolving UTDs");

        let event_ids: BTreeSet<_> =
            resolved_utds.iter().map(|resolved_utd| resolved_utd.event_id.clone()).collect();

        let all_caches = self.all_caches_for_room(room_id).await?;
        let mut maybe_resolved_events = Vec::with_capacity(resolved_utds.len());

        // # Room cache, thread caches, and pinned-event cache
        //
        // For each resolved UTD, find the corresponding event (either in-store
        // or in-memory of the room cache), build the resolved event, and
        // replace it in the store. We use the room cache for that because it
        // contains all events (there is an exception with the event-focused
        // cache, see below).
        //
        // # Event-focused cache
        //
        // Events received by the sync or pagination are not forwarded to the
        // event-focused cache: it handles its own set of events. All of them
        // live in-memory, there are not put in the store by any cache. So this
        // cache will miss all UTD resolutions. To address that, the
        // event-focused cache resolves UTD on its own, without the general
        // logic described above.
        {
            let room_cache = &all_caches.room;
            let mut state = room_cache.state().write().await?;

            let mut maybe_resolved_in_memory_events = Vec::new();

            for resolved_utd in resolved_utds {
                // Try to locate the event (either in-store or in-memory).
                if let Some((location, event)) = state.find_event(&resolved_utd.event_id).await? {
                    let maybe_resolved_event =
                        MaybeResolvedEvent::NotYet(resolved_utd).try_resolve_event(event);

                    // It is an in-memory event, let's keep it apart to replace
                    // in-memory UTDs.
                    if matches!(location, EventLocation::Memory(_)) {
                        maybe_resolved_in_memory_events.push(maybe_resolved_event.clone());
                    }

                    // Even is known, let's keep it for later, even if
                    // unresolved.
                    maybe_resolved_events.push(maybe_resolved_event);
                } else {
                    // Event is unknown by the room cache, the thread caches,
                    // nor the pinned-events cache. However, it might be known
                    // by an event-focused cache! So let's keep it for later.
                    maybe_resolved_events.push(MaybeResolvedEvent::NotYet(resolved_utd));
                }
            }

            // Replace all resolved events in the store.
            state
                .save_events(
                    maybe_resolved_events
                        .iter()
                        .filter_map(|resolved_event| resolved_event.as_resolved())
                        .cloned(),
                )
                .await?;

            // Now, replace the in-memory events.
            let timeline_event_diffs = state
                .replace_in_memory_utds(&maybe_resolved_in_memory_events)
                .await?
                .unwrap_or_default();

            if !timeline_event_diffs.is_empty() {
                state.update_sender.send(
                    RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs {
                        diffs: timeline_event_diffs,
                        origin: EventsOrigin::Cache,
                    }),
                    Some(RoomEventCacheGenericUpdate { room_id: room_id.to_owned() }),
                );
            }
        }

        // Resolve in-memory UTDs on the thread caches.
        {
            // TODO: This ain't great for performance; there shouldn't be that
            // many thread caches alive at the same time, but they could
            // accumulate over time. Consider keeping track of which linked
            // chunk contains which event ID, to avoid doing the linear searches
            // here.

            // Replaces UTDs in each thread, and maybe update the thread
            // summary.
            for (thread_id, thread_cache) in try_join_all(
                all_caches.threads.read().await.iter().map(|(thread_id, thread_cache)| async {
                    Result::<_, EventCacheError>::Ok(
                        // If at least one event has been replaced, return the
                        // `thread_id` and the `thread_cache` to update the
                        // thread summary later.
                        thread_cache
                            .replace_in_memory_utds(&maybe_resolved_events)
                            .await?
                            .then(|| (thread_id.clone(), thread_cache.clone())),
                    )
                }),
            )
            .await?
            .into_iter()
            // Filter out results that are `None`, i.e. a thread where no UTD has been replaced.
            .flatten()
            {
                let new_thread_summary = thread_cache.update_thread_summary().await?;

                all_caches.room.update_thread_summary(&thread_id, new_thread_summary)?;
            }
        }

        // Resolve in-memory UTDs on the pinned-events cache.
        if let Some(pinned_events_cache) = all_caches.pinned_events.get() {
            pinned_events_cache.replace_in_memory_utds(&maybe_resolved_events).await?;
        }

        // Resolve in-memory UTDs on the event-focused caches.
        {
            // TODO: This ain't great for performance; there shouldn't be that
            // many event-focused caches alive at the same time, but they could
            // accumulate over time. Consider keeping track of which linked
            // chunk contains which event ID, to avoid doing the linear searches
            // here.
            try_join_all(all_caches.event_focused.read().await.values().map(
                |event_focused_cache| {
                    event_focused_cache.replace_in_memory_utds(&maybe_resolved_events)
                },
            ))
            .await?;
        }

        let report =
            RedecryptorReport::ResolvedUtds { room_id: room_id.to_owned(), events: event_ids };
        let _ = self.redecryption_channels.utd_reporter.send(report);

        Ok(())
    }

    /// Attempt to decrypt a single event.
    ///
    /// Returns the closed outcome plus the resolved event, if any.
    async fn decrypt_event(
        &self,
        room_id: &RoomId,
        room: Option<&Room>,
        push_context: Option<&PushContext>,
        event: &Raw<EncryptedEvent>,
    ) -> (RedecryptionAttemptOutcome, Option<(DecryptedRoomEvent, Option<Vec<Action>>)>) {
        if let Some(room) = room {
            match room
                .decrypt_event(
                    event.cast_ref_unchecked::<OriginalSyncRoomEncryptedEvent>(),
                    push_context,
                )
                .await
            {
                Ok(maybe_decrypted) => {
                    let actions = maybe_decrypted.push_actions().map(|a| a.to_vec());

                    if let TimelineEventKind::Decrypted(decrypted) = maybe_decrypted.kind {
                        (RedecryptionAttemptOutcome::Decrypted, Some((decrypted, actions)))
                    } else {
                        warn!(
                            "Failed to redecrypt an event despite receiving a room key or request to redecrypt"
                        );
                        (RedecryptionAttemptOutcome::StillUtd, None)
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to redecrypt an event despite receiving a room key or request to redecrypt {e:?}"
                    );
                    (RedecryptionAttemptOutcome::Failed, None)
                }
            }
        } else {
            let Ok(client) = self.client() else {
                return (RedecryptionAttemptOutcome::Failed, None);
            };
            let machine = client.olm_machine().await;
            let Some(machine) = machine.as_ref() else {
                return (RedecryptionAttemptOutcome::Failed, None);
            };

            match machine.decrypt_room_event(event, room_id, client.decryption_settings()).await {
                Ok(decrypted) => (RedecryptionAttemptOutcome::Decrypted, Some((decrypted, None))),
                Err(matrix_sdk_base::crypto::MegolmError::MissingRoomKey(_)) => {
                    (RedecryptionAttemptOutcome::StillUtd, None)
                }
                Err(e) => {
                    warn!(
                        "Failed to redecrypt an event despite receiving a room key or a request to redecrypt {e:?}"
                    );
                    (RedecryptionAttemptOutcome::Failed, None)
                }
            }
        }
    }

    /// Attempt to redecrypt events after a room key with the given session ID
    /// has been received.
    #[instrument(skip_all, fields(room_id, session_id))]
    async fn retry_decryption(
        &self,
        room_id: &RoomId,
        session_id: SessionId<'_>,
    ) -> Result<(), EventCacheError> {
        // Get all the relevant UTDs.
        let events = self.all_encrypted_events(room_id, session_id).await?;
        self.retry_decryption_for_events(room_id, events).await
    }

    /// Attempt to redecrypt events that were persisted in the event cache.
    #[instrument(skip_all, fields(updates.linked_chunk_id))]
    async fn retry_decryption_for_event_cache_updates(
        &self,
        updates: RoomEventCacheLinkedChunkUpdate,
    ) -> Result<(), EventCacheError> {
        let room_id = updates.linked_chunk_id.room_id();
        let events: Vec<_> = updates
            .updates
            .into_iter()
            .flat_map(|updates| updates.into_items())
            .filter_map(filter_timeline_event_to_utd)
            .collect();

        self.retry_decryption_for_events(room_id, events).await
    }

    async fn retry_decryption_for_in_memory_events(&self) {
        let utds = self.all_in_memory_encrypted_events().await;

        for (room_id, utds) in utds.into_iter() {
            if let Err(e) = self.retry_decryption_for_events(&room_id, utds).await {
                warn!(%room_id, "Failed to redecrypt in-memory events {e:?}");
            }
        }
    }

    /// Attempt to redecrypt a chunk of UTDs.
    #[instrument(skip_all, fields(room_id, session_id))]
    async fn retry_decryption_for_events(
        &self,
        room_id: &RoomId,
        events: Vec<EventIdAndUtd>,
    ) -> Result<(), EventCacheError> {
        trace!("Retrying to decrypt");

        // Record the matched-event bucket before the empty early return so an
        // attempt that matches nothing is still observable.
        counters_bump(&self.redecryption_channels.late_decryption_counters, |c| {
            c.record_matching_bucket(events.len())
        });

        if events.is_empty() {
            trace!("No relevant events found.");
            return Ok(());
        }

        let room = self.client().ok().and_then(|client| client.get_room(room_id));
        let push_context =
            if let Some(room) = &room { room.push_context().await.ok().flatten() } else { None };

        // Let's attempt to decrypt them them.
        let mut decrypted_events = Vec::with_capacity(events.len());

        for (event_id, event) in events {
            // If decryption succeeded after receiving the key, replace the
            // event.
            let (outcome, resolved) = self
                .decrypt_event(
                    room_id,
                    room.as_ref(),
                    push_context.as_ref(),
                    event.cast_ref_unchecked(),
                )
                .await;
            match outcome {
                RedecryptionAttemptOutcome::Decrypted => {
                    counters_bump(&self.redecryption_channels.late_decryption_counters, |c| {
                        c.redecryption_succeeded += 1
                    });
                }
                RedecryptionAttemptOutcome::StillUtd => {
                    counters_bump(&self.redecryption_channels.late_decryption_counters, |c| {
                        c.redecryption_remained_utd += 1
                    });
                }
                RedecryptionAttemptOutcome::Failed => {
                    counters_bump(&self.redecryption_channels.late_decryption_counters, |c| {
                        c.redecryption_failed += 1
                    });
                }
            }
            if let Some((decrypted_event, actions)) = resolved {
                decrypted_events.push(ResolvedUtd { event_id, decrypted_event, actions });
            }
        }

        // A verification event that was a UTD at sync time never reached the
        // verification machine, because sync only feeds successfully decrypted
        // events to it. Feed the resolved ones now, before listeners learn
        // that the UTDs have been resolved, so the request is already known
        // when they look it up.
        if !decrypted_events.is_empty()
            && let Ok(client) = self.client()
        {
            receive_resolved_verification_events(&client, &decrypted_events).await;
        }

        if !decrypted_events.is_empty() && tracing::level_enabled!(tracing::Level::TRACE) {
            let event_ids: BTreeSet<_> =
                decrypted_events.iter().map(|resolved_utd| &resolved_utd.event_id).collect();

            trace!(?event_ids, "Successfully redecrypted events");
        }

        // Replace the events and notify listeners that UTDs have been replaced
        // with decrypted events.
        if let Err(e) = self.on_resolved_utds(room_id, decrypted_events).await {
            counters_bump(&self.redecryption_channels.late_decryption_counters, |c| {
                c.redecryption_store_failed += 1
            });
            return Err(e);
        }

        Ok(())
    }

    /// Attempt to update the encryption info for the given list of events.
    async fn update_encryption_info_for_events(
        &self,
        room: &Room,
        events: Vec<EventIdAndEvent>,
    ) -> Result<(), EventCacheError> {
        // Let's attempt to update their encryption info.
        let mut updated_events = Vec::with_capacity(events.len());

        for (event_id, mut event) in events {
            if let Some(session_id) = event.encryption_info.session_id() {
                let new_encryption_info =
                    room.get_encryption_info(session_id, &event.encryption_info.sender).await;

                // Only create a replacement if the encryption info actually
                // changed.
                if let Some(new_encryption_info) = new_encryption_info
                    && event.encryption_info != new_encryption_info
                {
                    event.encryption_info = new_encryption_info;
                    updated_events.push(ResolvedUtd {
                        event_id,
                        decrypted_event: event,
                        actions: None,
                    });
                }
            }
        }

        if !updated_events.is_empty() && tracing::level_enabled!(tracing::Level::TRACE) {
            let event_ids: BTreeSet<_> =
                updated_events.iter().map(|resolved_utd| &resolved_utd.event_id).collect();

            trace!(?event_ids, "Replacing the encryption info of some events");
        }

        self.on_resolved_utds(room.room_id(), updated_events).await
    }

    #[instrument(skip_all, fields(room_id, session_id))]
    async fn update_encryption_info(
        &self,
        room_id: &RoomId,
        session_id: SessionId<'_>,
    ) -> Result<(), EventCacheError> {
        trace!("Updating encryption info");

        let Ok(client) = self.client() else {
            return Ok(());
        };

        let Some(room) = client.get_room(room_id) else {
            return Ok(());
        };

        // Get all the relevant events.
        let events = self.all_decrypted_events(room_id, session_id).await?;

        if events.is_empty() {
            trace!("No relevant events found.");
            return Ok(());
        }

        // Let's attempt to update their encryption info.
        self.update_encryption_info_for_events(&room, events).await
    }

    async fn retry_update_encryption_info_for_in_memory_events(&self) {
        let decrypted_events = self.all_in_memory_decrypted_events().await;

        for (room_id, events) in decrypted_events.into_iter() {
            let Some(room) = self.client().ok().and_then(|c| c.get_room(&room_id)) else {
                continue;
            };

            if let Err(e) = self.update_encryption_info_for_events(&room, events).await {
                warn!(
                    %room_id,
                    "Failed to replace the encryption info for in-memory events {e:?}"
                );
            }
        }
    }

    /// Retry to decrypt and update the encryption info of all the events
    /// contained in the memory part of the event cache.
    ///
    /// This list of events will map one-to-one to the events components
    /// subscribed to the event cache are have received and are keeping cached.
    ///
    /// If components subscribed to the event cache are doing additional
    /// caching, they'll need to listen to [`RedecryptorReport`]s and explicitly
    /// request redecryption attempts using [`EventCache::request_decryption`].
    async fn retry_in_memory_events(&self) {
        self.retry_decryption_for_in_memory_events().await;
        self.retry_update_encryption_info_for_in_memory_events().await;
    }
}

impl EventCache {
    /// Explicitly request the redecryption of a set of events.
    ///
    /// The redecryption logic in the event cache might sometimes miss that a
    /// room key has become available and that a certain set of events has
    /// become decryptable.
    ///
    /// This might happen because some room keys might arrive in a separate
    /// process handling push notifications or if a room key arrives but the
    /// process shuts down before we could have decrypted the events.
    ///
    /// For this reason it is useful to tell the event cache explicitly that
    /// some events should be retried to be redecrypted.
    ///
    /// This method allows you to do so. The events that get decrypted, if any,
    /// will be advertised over the usual event cache subscription mechanism
    /// which can be accessed using the [`RoomEventCache::subscribe()`] method.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{Client, event_cache::DecryptionRetryRequest};
    /// # use url::Url;
    /// # use ruma::owned_room_id;
    /// # use std::collections::BTreeSet;
    /// # async {
    /// # let homeserver = Url::parse("http://localhost:8080")?;
    /// # let client = Client::new(homeserver).await?;
    /// let event_cache = client.event_cache().unwrap();
    /// let room_id = owned_room_id!("!my_room:localhost");
    ///
    /// let request = DecryptionRetryRequest {
    ///     room_id,
    ///     utd_session_ids: BTreeSet::from(["session_id".into()]),
    ///     refresh_info_session_ids: BTreeSet::new(),
    /// };
    ///
    /// event_cache.request_decryption(request);
    /// # anyhow::Ok(()) };
    /// ```
    pub fn request_decryption(&self, request: DecryptionRetryRequest) {
        let _ =
            self.inner.redecryption_channels.decryption_request_sender.send(request).inspect_err(
                |_| warn!("Requesting a decryption while the redecryption task has been shut down"),
            );
    }

    /// Subscribe to reports that the redecryptor generates.
    ///
    /// The redecryption logic in the event cache might sometimes miss that a
    /// room key has become available and that a certain set of events has
    /// become decryptable.
    ///
    /// This might happen because some room keys might arrive in a separate
    /// process handling push notifications or if room keys arrive faster than
    /// we can handle them.
    ///
    /// This stream can be used to get notified about such situations as well as
    /// a general channel where the event cache reports which events got
    /// successfully redecrypted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{Client, event_cache::RedecryptorReport};
    /// # use url::Url;
    /// # use tokio_stream::StreamExt;
    /// # async {
    /// # let homeserver = Url::parse("http://localhost:8080")?;
    /// # let client = Client::new(homeserver).await?;
    /// let event_cache = client.event_cache().unwrap();
    ///
    /// let mut stream = event_cache.subscribe_to_decryption_reports();
    ///
    /// while let Some(Ok(report)) = stream.next().await {
    ///     match report {
    ///         RedecryptorReport::Lagging => {
    ///             // The event cache might have missed to redecrypt some events. We should tell
    ///             // it which events we care about, i.e. which events we're displaying to the
    ///             // user, and let it redecrypt things with an explicit request.
    ///         }
    ///         RedecryptorReport::BackupAvailable => {
    ///             // A backup has become available. We can, just like in the Lagging case, tell
    ///             // the event cache to attempt to redecrypt some events.
    ///             //
    ///             // This is only necessary with the BackupDownloadStrategy::OnDecryptionFailure
    ///             // as the decryption attempt in this case will trigger the download of the
    ///             // room key from the backup.
    ///         }
    ///         RedecryptorReport::ResolvedUtds { .. } => {
    ///             // This may be interesting for statistical reasons or in case we'd like to
    ///             // fetch and inspect these events in some manner.
    ///         }
    ///     }
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    pub fn subscribe_to_decryption_reports(
        &self,
    ) -> impl Stream<Item = Result<RedecryptorReport, BroadcastStreamRecvError>> + use<> {
        BroadcastStream::new(self.inner.redecryption_channels.utd_reporter.subscribe())
    }
}

async fn send_report_and_retry_memory_events(
    cache: &Weak<EventCacheInner>,
    report: RedecryptorReport,
) -> Result<(), ()> {
    let Some(cache) = cache.upgrade() else {
        return Err(());
    };

    cache.retry_in_memory_events().await;
    let _ = cache.redecryption_channels.utd_reporter.send(report);

    Ok(())
}

/// Struct holding on to the redecryption task.
///
/// This struct implements the bulk of the redecryption task. It listens to the
/// various streams that should trigger redecryption attempts.
///
/// For more info see the [module level docs](self).
pub(crate) struct Redecryptor {
    _task: BackgroundTaskHandle,
}

impl Redecryptor {
    /// Whether the redecryption background task has finished.
    pub(super) fn is_finished(&self) -> bool {
        self._task.is_finished()
    }

    /// Create a new [`Redecryptor`].
    ///
    /// This creates a task that listens to various streams and attempts to
    /// redecrypt UTDs that can be found inside the [`EventCache`].
    pub(super) fn new(
        client: &Client,
        cache: Weak<EventCacheInner>,
        receiver: UnboundedReceiver<DecryptionRetryRequest>,
        linked_chunk_update_sender: &Sender<RoomEventCacheLinkedChunkUpdate>,
        late_decryption_counters: Arc<StdMutex<RoomKeyLateDecryptionCounters>>,
    ) -> Self {
        let linked_chunk_stream = BroadcastStream::new(linked_chunk_update_sender.subscribe());
        let backup_state_stream = client.encryption().backups().state_stream();

        let task = client
            .task_monitor()
            .spawn_infinite_task("event_cache::redecryptor", async {
                let request_redecryption_stream = UnboundedReceiverStream::new(receiver);

                Self::listen_for_room_keys_task(
                    cache,
                    request_redecryption_stream,
                    linked_chunk_stream,
                    backup_state_stream,
                    late_decryption_counters,
                )
                .await;
            })
            .abort_on_drop();

        Self { _task: task }
    }

    /// (Re)-subscribe to the room key stream from the [`OlmMachine`].
    ///
    /// This needs to happen any time this stream returns a `None` meaning that
    /// the sending part of the stream has been dropped.
    async fn subscribe_to_room_key_stream(
        cache: &Weak<EventCacheInner>,
    ) -> Option<(
        impl Stream<Item = Result<Vec<RoomKeyInfo>, BroadcastStreamRecvError>>,
        impl Stream<Item = Vec<RoomKeyWithheldInfo>>,
    )> {
        let event_cache = cache.upgrade()?;
        let client = event_cache.client().ok()?;
        let machine = client.olm_machine().await;

        machine.as_ref().map(|m| {
            (m.store().room_keys_received_stream(), m.store().room_keys_withheld_received_stream())
        })
    }

    async fn redecryption_loop(
        cache: &Weak<EventCacheInner>,
        decryption_request_stream: &mut Pin<&mut impl Stream<Item = DecryptionRetryRequest>>,
        events_stream: &mut Pin<
            &mut impl Stream<Item = Result<RoomEventCacheLinkedChunkUpdate, BroadcastStreamRecvError>>,
        >,
        backup_state_stream: &mut Pin<
            &mut impl Stream<Item = Result<BackupState, BroadcastStreamRecvError>>,
        >,
        late_decryption_counters: &Arc<StdMutex<RoomKeyLateDecryptionCounters>>,
    ) -> bool {
        let Some((room_key_stream, withheld_stream)) =
            Self::subscribe_to_room_key_stream(cache).await
        else {
            return false;
        };

        let mut room_key_stream = pin!(room_key_stream);
        let mut withheld_stream = pin!(withheld_stream);

        loop {
            tokio::select! {
                // An explicit request, presumably from the timeline, has been
                // received to decrypt events that were encrypted with a certain
                // room key.
                Some(request) = decryption_request_stream.next() => {
                        let Some(cache) = cache.upgrade() else {
                            break false;
                        };

                        trace!(?request, "Received a redecryption request");
                        counters_bump(
                            late_decryption_counters,
                            |c| c.explicit_retry_requests += 1,
                        );

                        for session_id in request.utd_session_ids {
                            let _ = cache
                                .retry_decryption(&request.room_id, &session_id)
                                .await
                                .inspect_err(|e| warn!("Error redecrypting after an explicit request was received {e:?}"));
                        }

                        for session_id in request.refresh_info_session_ids {
                            let _ = cache.update_encryption_info(&request.room_id, &session_id).await.inspect_err(|e|
                                warn!(
                                    room_id = %request.room_id,
                                    session_id = session_id,
                                    "Unable to update the encryption info {e:?}",
                            ));
                        }
                }
                // The room key stream from the OlmMachine. Needs to be
                // recreated every time we receive a `None` from the stream.
                room_keys = room_key_stream.next() => {
                    match room_keys {
                        Some(Ok(room_keys)) => {
                            // Alright, some room keys were received and
                            // persisted in our store, let's attempt to
                            // redecrypt events that were encrypted using these
                            // room keys.
                            let Some(cache) = cache.upgrade() else {
                                break false;
                            };

                            trace!(?room_keys, "Received new room keys");
                            counters_bump(
                                late_decryption_counters,
                                |c| {
                                    c.room_key_updates_broadcast += 1;
                                    c.redecryption_requests += room_keys.len() as u64;
                                },
                            );

                            for key in &room_keys {
                                let _ = cache
                                    .retry_decryption(&key.room_id, &key.session_id)
                                    .await
                                    .inspect_err(|e| warn!("Error redecrypting {e:?}"));
                            }

                            for key in room_keys {
                                let _ = cache.update_encryption_info(&key.room_id, &key.session_id).await.inspect_err(|e|
                                    warn!(
                                        room_id = %key.room_id,
                                        session_id = key.session_id,
                                        "Unable to update the encryption info {e:?}",
                                ));
                            }
                        },
                        Some(Err(_)) => {
                            // We missed some room keys, we need to report this
                            // in case a listener has and idea which UTDs we
                            // should attempt to redecrypt.
                            //
                            // This would most likely be the timeline from the
                            // UI crate. The timeline might attempt to redecrypt
                            // all UTDs it is showing to the user.
                            warn!("The room key stream lagged, reporting the lag to our listeners");
                            counters_bump(
                                late_decryption_counters,
                                |c| c.room_key_stream_lagged += 1,
                            );

                            if send_report_and_retry_memory_events(cache, RedecryptorReport::Lagging).await.is_err() {
                                break false;
                            }
                        },
                        // The stream got closed, this could mean that our
                        // OlmMachine got regenerated, let's return true and try
                        // to recreate the stream.
                        None => {
                            break true;
                        }
                    }
                }
                withheld_info = withheld_stream.next() => {
                    match withheld_info {
                        Some(infos) => {
                            let Some(cache) = cache.upgrade() else {
                                break false;
                            };

                            trace!(?infos, "Received new withheld infos");

                            for RoomKeyWithheldInfo { room_id, session_id, .. } in &infos {
                                let _ = cache.update_encryption_info(room_id, session_id).await.inspect_err(|e|
                                    warn!(
                                        room_id = %room_id,
                                        session_id = session_id,
                                        "Unable to update the encryption info {e:?}",
                                ));
                            }
                        }
                        // The stream got closed, same as for the room key
                        // stream, we'll try to recreate the streams.
                        None => break true,
                    }
                }
                // Events that the event cache handled. If the event cache
                // received any UTDs, let's attempt to redecrypt them in case
                // the room key was received before the event cache was able to
                // return them using `get_utds()`.
                Some(event_updates) = events_stream.next() => {
                    match event_updates {
                        Ok(updates) => {
                            let Some(cache) = cache.upgrade() else {
                                break false;
                            };

                            let linked_chunk_id = updates.linked_chunk_id.to_owned();

                            let _ = cache.retry_decryption_for_event_cache_updates(updates).await.inspect_err(|e|
                                warn!(
                                    %linked_chunk_id,
                                    "Unable to handle UTDs from event cache updates {e:?}",
                                )
                            );
                        }
                        Err(_) => {
                            counters_bump(
                                late_decryption_counters,
                                |c| c.room_key_stream_lagged += 1,
                            );
                            if send_report_and_retry_memory_events(cache, RedecryptorReport::Lagging).await.is_err() {
                                break false;
                            }
                        }
                    }
                }
                Some(backup_state_update) = backup_state_stream.next() => {
                    match backup_state_update {
                        Ok(state) => {
                            match state {
                                BackupState::Unknown |
                                BackupState::Creating |
                                BackupState::Enabling |
                                BackupState::Resuming |
                                BackupState::Downloading |
                                BackupState::Disabling => {
                                    // Those states aren't particularly
                                    // interesting to components listening to
                                    // R2D2 reports.
                                }
                                BackupState::Enabled => {
                                    // Alright, the backup got enabled, we might
                                    // or might not have downloaded the room
                                    // keys from the backup. In case they get
                                    // downloaded on-demand, let's try to
                                    // decrypt all the events we have cached
                                    // in-memory.
                                    if send_report_and_retry_memory_events(cache, RedecryptorReport::BackupAvailable).await.is_err() {
                                        break false;
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            if send_report_and_retry_memory_events(cache, RedecryptorReport::Lagging).await.is_err() {
                                break false;
                            }
                        }
                    }
                }
                else => break false,
            }
        }
    }

    async fn listen_for_room_keys_task(
        cache: Weak<EventCacheInner>,
        decryption_request_stream: UnboundedReceiverStream<DecryptionRetryRequest>,
        events_stream: BroadcastStream<RoomEventCacheLinkedChunkUpdate>,
        backup_state_stream: impl Stream<Item = Result<BackupState, BroadcastStreamRecvError>>,
        late_decryption_counters: Arc<StdMutex<RoomKeyLateDecryptionCounters>>,
    ) {
        // We pin the decryption request stream here since that one doesn't need
        // to be recreated and we don't want to miss messages coming from the
        // stream while recreating it unnecessarily.
        let mut decryption_request_stream = pin!(decryption_request_stream);
        let mut events_stream = pin!(events_stream);
        let mut backup_state_stream = pin!(backup_state_stream);

        while Self::redecryption_loop(
            &cache,
            &mut decryption_request_stream,
            &mut events_stream,
            &mut backup_state_stream,
            &late_decryption_counters,
        )
        .await
        {
            info!("Regenerating the re-decryption streams");
            counters_bump(&late_decryption_counters, |c| c.room_key_stream_recreated += 1);

            // Report that the stream got recreated so listeners know about it,
            // at the same time retry to decrypt anything we have cached in
            // memory.
            if send_report_and_retry_memory_events(&cache, RedecryptorReport::Lagging)
                .await
                .is_err()
            {
                break;
            }
        }

        info!("Shutting down the event cache redecryptor");
    }
}

/// Helper method used by `RoomEventCacheState` and `ThreadEventCacheState` to
/// attempt to decrypt a bundled thread event we haven't tried to decrypt yet.
pub(super) async fn try_decrypt_in_place(event: &mut TimelineEvent, room: Option<&Room>) {
    if let TimelineEventKind::UnableToDecrypt { utd_info, .. } = &event.kind
        && let Some(room) = room
        && utd_info.reason == UnableToDecryptReason::Unknown
    {
        match room
            // Cast safety: a `TimelineEventKind::UnableToDecrypt` always holds the
            // `m.room.encrypted` event, and the `Unknown` reason above narrows this
            // further to the branch that has positively checked the `type` field in
            // `TimelineEvent::from_bundled_latest_event`.
            .decrypt_event(event.raw().cast_ref_unchecked::<OriginalSyncRoomEncryptedEvent>(), None)
            .await
        {
            Ok(decrypted) => *event = decrypted,
            Err(e) => warn!(
                "Failed to decrypt a bundled thread event we haven't tried to decrypt yet {e:?}"
            ),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[cfg(test)]
mod tests {
    use std::{assert_matches, collections::BTreeSet, time::Duration};

    use eyeball_im::VectorDiff;
    use futures_util::future::join_all;
    use matrix_sdk_base::{
        crypto::types::events::room::encrypted::EncryptedToDeviceEvent,
        deserialized_responses::{TimelineEventKind, UnableToDecryptReason, VerificationState},
        event_cache::store::ControlledMemoryStore,
        locks::Mutex,
        sleep::sleep,
        store::StoreConfig,
    };
    use matrix_sdk_common::{cross_process_lock::CrossProcessLockConfig, executor::spawn};
    use matrix_sdk_test::{
        JoinedRoomBuilder, SyncResponseBuilder, async_test, event_factory::EventFactory,
    };
    use ruma::{
        EventId, OwnedEventId, RoomId, RoomVersionId, UserId, device_id, event_id,
        events::{
            AnySyncTimelineEvent, MessageLikeEventContent,
            relation::Thread,
            room::message::{
                AddMentions, ReplyMetadata, ReplyWithinThread, RoomMessageEventContent,
            },
        },
        room_id,
        serde::Raw,
        user_id,
    };
    use serde_json::json;
    use strass::assert_let;
    use tracing::{Instrument, info};
    use wiremock::{Request, Respond, ResponseTemplate};

    use crate::{
        Client, assert_let_timeout,
        encryption::EncryptionSettings,
        event_cache::{
            DecryptionRetryRequest, RoomEventCacheGenericUpdate, RoomEventCacheUpdate,
            TimelineVectorDiffs,
        },
        test_utils::mocks::MatrixMockServer,
    };

    async fn set_up_clients(
        room_id: &RoomId,
        alice_enables_cross_signing: bool,
        use_delayed_store: bool,
    ) -> (Client, Client, MatrixMockServer, Option<ControlledMemoryStore>) {
        let alice_span = tracing::info_span!("alice");
        let bob_span = tracing::info_span!("bob");

        let alice_user_id = user_id!("@alice:localhost");
        let alice_device_id = device_id!("ALICEDEVICE");
        let bob_user_id = user_id!("@bob:localhost");
        let bob_device_id = device_id!("BOBDEVICE");

        let matrix_mock_server = MatrixMockServer::new().await;
        matrix_mock_server.mock_crypto_endpoints_preset().await;

        let encryption_settings = EncryptionSettings {
            auto_enable_cross_signing: alice_enables_cross_signing,
            ..Default::default()
        };

        // Create some clients for Alice and Bob.

        let alice = matrix_mock_server
            .client_builder_for_crypto_end_to_end(alice_user_id, alice_device_id)
            .on_builder(|builder| {
                builder
                    .with_enable_share_history_on_invite(true)
                    .with_encryption_settings(encryption_settings)
            })
            .build()
            .instrument(alice_span.clone())
            .await;

        let encryption_settings =
            EncryptionSettings { auto_enable_cross_signing: true, ..Default::default() };

        let (store_config, store) = if use_delayed_store {
            let store = ControlledMemoryStore::new();
            store.block_writes();

            (
                StoreConfig::new(CrossProcessLockConfig::multi_process(
                    "delayed_store_event_cache_test",
                ))
                .event_cache_store(store.clone()),
                Some(store),
            )
        } else {
            (
                StoreConfig::new(CrossProcessLockConfig::multi_process(
                    "normal_store_event_cache_test",
                )),
                None,
            )
        };

        let bob = matrix_mock_server
            .client_builder_for_crypto_end_to_end(bob_user_id, bob_device_id)
            .on_builder(|builder| {
                builder
                    .with_enable_share_history_on_invite(true)
                    .with_encryption_settings(encryption_settings)
                    .store_config(store_config)
            })
            .build()
            .instrument(bob_span.clone())
            .await;

        // Ensure that Alice and Bob are aware of their devices and identities.
        matrix_mock_server.exchange_e2ee_identities(&alice, &bob).await;

        let event_factory = EventFactory::new().room(room_id).sender(alice_user_id);

        // Let us now create a room for them.
        let room_builder = JoinedRoomBuilder::new(room_id)
            .add_state_event(event_factory.create(alice_user_id, RoomVersionId::V1))
            .add_state_event(event_factory.room_encryption());

        matrix_mock_server
            .mock_sync()
            .ok_and_run(&alice, |builder| {
                builder.add_joined_room(room_builder.clone());
            })
            .instrument(alice_span)
            .await;

        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_joined_room(room_builder);
            })
            .instrument(bob_span)
            .await;

        // Mock the members endpoint, so that Alice can share room keys with
        // Bob.
        let member_factory = EventFactory::new().room(room_id);
        matrix_mock_server
            .mock_get_members()
            .ok(vec![
                member_factory.member(alice_user_id).into_raw(),
                member_factory.member(bob_user_id).into_raw(),
            ])
            .mount()
            .await;

        (alice, bob, matrix_mock_server, store)
    }

    async fn prepare_room(
        matrix_mock_server: &MatrixMockServer,
        alice: &Client,
        room_id: &RoomId,
    ) -> (Raw<AnySyncTimelineEvent>, Raw<EncryptedToDeviceEvent>) {
        let content = json!({"body": "It's a secret to everybody", "msgtype": "m.text"});
        prepare_room_with_content(matrix_mock_server, alice, room_id, content).await
    }

    async fn prepare_room_with_content(
        matrix_mock_server: &MatrixMockServer,
        alice: &Client,
        room_id: &RoomId,
        content: serde_json::Value,
    ) -> (Raw<AnySyncTimelineEvent>, Raw<EncryptedToDeviceEvent>) {
        let alice_user_id = alice.user_id().unwrap();
        let room = alice
            .get_room(room_id)
            .expect("Alice should have access to the room now that we synced");

        // Alice will send a single event to the room, but this will trigger a
        // to-device message containing the room key to be sent as well.
        // We capture both the event and the to-device message.

        let event_type = "m.room.message";

        let event_id = event_id!("$some_id");
        let (event_receiver, mock) =
            matrix_mock_server.mock_room_send().ok_with_capture(event_id, alice_user_id);
        let (_guard, room_key) = matrix_mock_server.mock_capture_put_to_device(alice_user_id).await;

        {
            let _guard = mock.mock_once().mount_as_scoped().await;

            room.send_raw(event_type, content)
                .await
                .expect("We should be able to send an initial message");
        };

        // Let us retrieve the captured event and to-device message.
        let event = event_receiver.await.expect("Alice should have sent the event by now");
        let room_key = room_key.await;

        (event, room_key)
    }

    #[async_test]
    async fn test_redecryptor() {
        let room_id = room_id!("!test:localhost");

        let (alice, bob, matrix_mock_server, _) = set_up_clients(room_id, true, false).await;

        let (event, room_key) = send_encrypted(
            &matrix_mock_server,
            &alice,
            room_id,
            event_id!("$some_id"),
            RoomMessageEventContent::text_plain("It's a secret to everybody"),
        )
        .await;

        // Let's now see what Bob's event cache does.

        let event_cache = bob.event_cache().unwrap();
        let (room_cache, _) = event_cache
            .room(room_id)
            .await
            .expect("We should be able to get to the event cache for a specific room");

        let (_, mut subscriber) = room_cache.subscribe().await.unwrap();
        let mut generic_stream = event_cache.subscribe_to_room_generic_updates();

        // We regenerate the Olm machine to check if the room key stream is
        // recreated to correctly.
        bob.inner
            .base_client
            .regenerate_olm(None)
            .await
            .expect("We should be able to regenerate the Olm machine");

        // Let us forward the event to Bob.
        sync_room(
            &matrix_mock_server,
            &bob,
            JoinedRoomBuilder::new(room_id).add_timeline_event(event),
        )
        .await;

        // Alright, Bob has received an update from the cache.

        assert_let_timeout!(
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // There should be a single new event, and it should be a UTD as we did
        // not receive the room key yet.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Append { values } = &diffs[0]);
        assert_eq!(values.len(), 1);
        assert_matches!(&values[0].kind, TimelineEventKind::UnableToDecrypt { .. });

        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());

        // Now we send the room key to Bob.
        sync_room_keys(&matrix_mock_server, &bob, &[room_key]).await;

        // Bob should receive a new update from the cache.
        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // It should replace the UTD with a decrypted event.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Set { index, value } = &diffs[0]);
        assert_eq!(*index, 0);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });

        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());
    }

    /// An in-room verification request that is a UTD when it is first synced
    /// must still reach the verification machine once R2D2 resolves it;
    /// otherwise the request is only ever displayed and the recipient can
    /// never act on it.
    #[async_test]
    async fn test_redecryptor_feeds_late_decrypted_verification_request() {
        let room_id = room_id!("!test:localhost");

        let (alice, bob, matrix_mock_server, _) = set_up_clients(room_id, true, false).await;

        let alice_user_id = alice.user_id().unwrap().to_owned();
        let content = json!({
            "body": "Alice is requesting to verify your device",
            "msgtype": "m.key.verification.request",
            "to": bob.user_id().unwrap(),
            "from_device": alice.device_id().unwrap(),
            "methods": ["m.sas.v1"],
        });
        let (event, room_key) =
            prepare_room_with_content(&matrix_mock_server, &alice, room_id, content).await;
        let event_id = event
            .get_field::<OwnedEventId>("event_id")
            .expect("the captured event should be valid")
            .expect("the captured event should have an event id");

        let event_cache = bob.event_cache().unwrap();
        let (room_cache, _) = event_cache.room(room_id).await.expect("room event cache");
        let (_, mut subscriber) = room_cache.subscribe().await.unwrap();

        // Deliver the encrypted request before its room key: it is a UTD.
        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_joined_room(JoinedRoomBuilder::new(room_id).add_timeline_event(event));
            })
            .await;

        assert_let_timeout!(
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );
        assert_let!(VectorDiff::Append { values } = &diffs[0]);
        assert_matches!(&values[0].kind, TimelineEventKind::UnableToDecrypt { .. });
        assert!(
            bob.encryption().get_verification_request(&alice_user_id, &event_id).await.is_none(),
            "a UTD request cannot be known to the verification machine yet"
        );

        // The room key arrives afterwards; R2D2 resolves the UTD.
        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_to_device_event(
                    room_key
                        .deserialize_as()
                        .expect("We should be able to deserialize the room key"),
                );
            })
            .await;

        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );
        assert_let!(VectorDiff::Set { value, .. } = &diffs[0]);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });

        let request = bob.encryption().get_verification_request(&alice_user_id, &event_id).await;
        assert!(
            request.is_some(),
            "the late-decrypted request must reach the verification machine"
        );
    }

    #[async_test]
    async fn test_redecryptor_counts_late_decryption() {
        let room_id = room_id!("!test:localhost");

        let (alice, bob, matrix_mock_server, _) = set_up_clients(room_id, true, false).await;

        let (event, room_key) = prepare_room(&matrix_mock_server, &alice, room_id).await;

        let event_cache = bob.event_cache().unwrap();
        let (room_cache, _) = event_cache.room(room_id).await.expect("room event cache");
        let (_, mut subscriber) = room_cache.subscribe().await.unwrap();

        // Deliver the encrypted event as a UTD (room key not yet received).
        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_joined_room(JoinedRoomBuilder::new(room_id).add_timeline_event(event));
            })
            .await;

        assert_let_timeout!(Ok(RoomEventCacheUpdate::UpdateTimelineEvents(_)) = subscriber.recv());

        let before = event_cache.room_key_receive_diagnostics();
        assert!(before.subscribed);
        assert!(before.redecryptor_alive);
        assert_eq!(before.counters.redecryption_succeeded, 0);

        // Now send the room key; the redecryptor should redecrypt the UTD.
        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_to_device_event(
                    room_key
                        .deserialize_as()
                        .expect("We should be able to deserialize the room key"),
                );
            })
            .await;

        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );
        let VectorDiff::Set { index, value } = &diffs[0] else {
            panic!("expected Set diff");
        };
        assert_eq!(*index, 0);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });

        let diagnostics = event_cache.room_key_receive_diagnostics();
        assert!(diagnostics.subscribed);
        assert!(diagnostics.redecryptor_alive);
        assert!(diagnostics.counters.room_key_updates_broadcast >= 1);
        assert!(diagnostics.counters.redecryption_requests >= 1);
        assert!(diagnostics.counters.matching_events_bucket_1 >= 1);
        assert!(diagnostics.counters.redecryption_succeeded >= 1);
        // A second broadcast can re-attempt the same stored event after the
        // linked chunk already resolved it; that attempt legitimately reports
        // "still UTD" for the raw stored copy, so this is an upper-bound check
        // rather than an exact one.
        assert!(diagnostics.counters.redecryption_remained_utd <= 1);

        // An explicit retry for a session with no matching events must be
        // observable in the zero-match bucket.
        event_cache.request_decryption(DecryptionRetryRequest {
            room_id: room_id.to_owned(),
            utd_session_ids: BTreeSet::from(["no-such-session".to_owned()]),
            refresh_info_session_ids: BTreeSet::new(),
        });
        let zero_match_seen = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if event_cache.room_key_receive_diagnostics().counters.matching_events_bucket_0 > 0
                {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(zero_match_seen, "zero-match retry attempt was not counted");
        assert_eq!(diagnostics.counters.redecryption_failed, 0);
        assert_eq!(diagnostics.counters.redecryption_store_failed, 0);
    }

    #[async_test]
    async fn test_redecryptor_updating_encryption_info() {
        let bob_span = tracing::info_span!("bob");

        let room_id = room_id!("!test:localhost");

        let (alice, bob, matrix_mock_server, _) = set_up_clients(room_id, false, false).await;

        let (event, room_key) = send_encrypted(
            &matrix_mock_server,
            &alice,
            room_id,
            event_id!("$some_id"),
            RoomMessageEventContent::text_plain("It's a secret to everybody"),
        )
        .await;

        // Let's now see what Bob's event cache does.

        let event_cache = bob.event_cache().unwrap();
        let (room_cache, _) = event_cache
            .room(room_id)
            .instrument(bob_span.clone())
            .await
            .expect("We should be able to get to the event cache for a specific room");

        let (_, mut subscriber) = room_cache.subscribe().await.unwrap();
        let mut generic_stream = event_cache.subscribe_to_room_generic_updates();

        // Let us forward the event to Bob.
        sync_room(
            &matrix_mock_server,
            &bob,
            JoinedRoomBuilder::new(room_id).add_timeline_event(event),
        )
        .instrument(bob_span.clone())
        .await;

        // Alright, Bob has received an update from the cache.

        assert_let_timeout!(
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // There should be a single new event, and it should be a UTD as we did
        // not receive the room key yet.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Append { values } = &diffs[0]);
        assert_eq!(values.len(), 1);
        assert_matches!(&values[0].kind, TimelineEventKind::UnableToDecrypt { .. });

        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());

        // Now we send the room key to Bob.
        sync_room_keys(&matrix_mock_server, &bob, &[room_key]).instrument(bob_span.clone()).await;

        // Bob should receive a new update from the cache.
        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // It should replace the UTD with a decrypted event.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Set { index: 0, value } = &diffs[0]);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });

        let encryption_info = value.encryption_info().unwrap();
        assert_matches!(&encryption_info.verification_state, VerificationState::Unverified(_));

        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());

        let session_id = encryption_info.session_id().unwrap().to_owned();
        let alice_user_id = alice.user_id().unwrap();

        // Alice now creates the identity.
        alice
            .encryption()
            .bootstrap_cross_signing(None)
            .await
            .expect("Alice should be able to create the cross-signing keys");

        bob.update_tracked_users_for_testing([alice_user_id]).instrument(bob_span.clone()).await;
        matrix_mock_server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_change_device(alice_user_id);
            })
            .instrument(bob_span.clone())
            .await;

        bob.event_cache().unwrap().request_decryption(DecryptionRetryRequest {
            room_id: room_id.into(),
            utd_session_ids: BTreeSet::new(),
            refresh_info_session_ids: BTreeSet::from([session_id]),
        });

        // Bob should again receive a new update from the cache, this time
        // updating the encryption info.
        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Set { index: 0, value } = &diffs[0]);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });
        let encryption_info = value.encryption_info().unwrap();

        assert_matches!(
            &encryption_info.verification_state,
            VerificationState::Unverified(_),
            "The event should now know about the identity but still be unverified"
        );

        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());
    }

    #[async_test]
    async fn test_event_is_redecrypted_even_if_key_arrives_while_event_processing() {
        let room_id = room_id!("!test:localhost");

        let (alice, bob, matrix_mock_server, delayed_store) =
            set_up_clients(room_id, true, true).await;

        let delayed_store = delayed_store.unwrap();

        let (event, room_key) = send_encrypted(
            &matrix_mock_server,
            &alice,
            room_id,
            event_id!("$some_id"),
            RoomMessageEventContent::text_plain("It's a secret to everybody"),
        )
        .await;

        let event_cache = bob.event_cache().unwrap();

        // Let's now see what Bob's event cache does.
        let (room_cache, _) = event_cache
            .room(room_id)
            .await
            .expect("We should be able to get to the event cache for a specific room");

        let (_, mut subscriber) = room_cache.subscribe().await.unwrap();
        let mut generic_stream = event_cache.subscribe_to_room_generic_updates();

        // Custom type to mock the `/sync` endpoints.
        struct Responder<'a> {
            sync_response_builder: Mutex<(usize, SyncResponseBuilder)>,
            room_id: &'a RoomId,
            event: Raw<AnySyncTimelineEvent>,
            room_key: Raw<EncryptedToDeviceEvent>,
        }

        impl<'a> Responder<'a> {
            fn new(
                room_id: &'a RoomId,
                event: Raw<AnySyncTimelineEvent>,
                room_key: Raw<EncryptedToDeviceEvent>,
            ) -> Self {
                Self {
                    sync_response_builder: Mutex::new((0, SyncResponseBuilder::new())),
                    room_id,
                    event,
                    room_key,
                }
            }
        }

        impl<'a> Respond for Responder<'a> {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                let (nth_sync, sync_response_builder) = &mut *self.sync_response_builder.lock();

                match nth_sync {
                    // First request for `sync_room`.
                    0 => {
                        *nth_sync = 1;
                        ResponseTemplate::new(200).set_body_json(
                            sync_response_builder
                                .add_joined_room(
                                    JoinedRoomBuilder::new(self.room_id)
                                        .add_timeline_event(self.event.clone()),
                                )
                                .build_json_sync_response(),
                        )
                    }

                    // Second request for `sync_room_keys`.
                    1 => {
                        *nth_sync = 2;
                        ResponseTemplate::new(200).set_body_json(
                            sync_response_builder
                                .add_to_device_event(self.room_key.deserialize_as().unwrap())
                                .build_json_sync_response(),
                        )
                    }

                    _ => panic!("`/sync` is called once too much"),
                }
            }
        }

        let mock = matrix_mock_server
            .mock_sync()
            .respond_with(Responder::new(room_id, event, room_key))
            .mount_as_scoped()
            .await;

        let sync_room = spawn({
            let bob = bob.clone();

            // Let us forward the event to Bob, immediately. It will stop
            // before persisting everything in the store.
            async move {
                let _ = bob.sync_once(Default::default()).await.unwrap();
            }
        });

        let sync_room_keys = spawn({
            let bob = bob.clone();

            // Now we send the room key to Bob, let's say after a delay of
            // 1sec, so that the Event Cache had time to start handling the
            // event and being blocked when persisting it.
            async move {
                // Wait on `sync_room` to hang.
                sleep(Duration::from_secs(1)).await;

                let _ = bob.sync_once(Default::default()).await.unwrap();

                // Allow the redecryptor some time to retry any UTDs.
                sleep(Duration::from_millis(100)).await;
            }
        });

        let delay = spawn({
            // Unblock `sync_room` after 2 secs, so that `sync_room_keys` has
            // finished before `sync_room` finishes.
            async move {
                sleep(Duration::from_secs(2)).await;
                info!("Stopping the delay");
                delayed_store.unblock_writes();
                delayed_store.wait_for_write_to_finish().await;
            }
        });

        assert!(
            join_all([sync_room, sync_room_keys, delay]).await.into_iter().all(|res| res.is_ok()),
            "all tasks should succeed"
        );

        drop(mock);

        // The first decryption attempt has failed because the first sync (the
        // one with the event) did not contain the room key. The decryptor has
        // later received the room key.

        // Alright, Bob has received an update from the cache.
        assert_let_timeout!(
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // There should be a single new event, and it should be a UTD as we did
        // not receive the room key yet.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Append { values } = &diffs[0]);
        assert_eq!(values.len(), 1);
        assert_matches!(&values[0].kind, TimelineEventKind::UnableToDecrypt { .. });

        // And the companion generic update.
        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);

        // Bob should receive a new update from the cache.
        assert_let_timeout!(
            Duration::from_secs(1),
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );

        // It should replace the UTD with a decrypted event.
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Set { index, value } = &diffs[0]);
        assert_eq!(*index, 0);
        assert_matches!(&value.kind, TimelineEventKind::Decrypted { .. });

        // And the companion generic update.
        assert_let_timeout!(
            Ok(RoomEventCacheGenericUpdate { room_id: expected_room_id }) = generic_stream.recv()
        );
        assert_eq!(expected_room_id, room_id);
        assert!(generic_stream.is_empty());
    }

    /// Regression test: the redecryptor must NOT hold the room state write
    /// lock while calling replace_utds() on event-focused caches, otherwise
    /// an ABBA deadlock occurs with concurrent event-focused cache pagination.
    #[test]
    fn test_decryption_retry_request_debug_is_privacy_safe() {
        let request = DecryptionRetryRequest {
            room_id: ruma::owned_room_id!("!private-room:example.invalid"),
            utd_session_ids: BTreeSet::from(["PRIVATE-MEGOLM-SESSION".to_owned()]),
            refresh_info_session_ids: BTreeSet::from(["PRIVATE-REFRESH-SESSION".to_owned()]),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("private-room"));
        assert!(!debug.contains("PRIVATE-MEGOLM-SESSION"));
        assert!(!debug.contains("PRIVATE-REFRESH-SESSION"));
        assert!(debug.contains("utd_session_ids: 1"));
        assert!(debug.contains("refresh_info_session_ids: 1"));
    }

    #[async_test]
    async fn test_redecryptor_no_deadlock_with_event_focused_cache_pagination() {
        use crate::{
            event_cache::EventFocusThreadMode,
            test_utils::mocks::{RoomContextResponseTemplate, RoomMessagesResponseTemplate},
        };

        let room_id = room_id!("!test:localhost");
        let f = EventFactory::new().room(room_id);
        let (alice, bob, server, _) = set_up_clients(room_id, true, false).await;

        let (encrypted_event, room_key) = prepare_room(&server, &alice, room_id).await;

        let event_cache = bob.event_cache().unwrap();
        let (room_cache, _drop_handles) =
            event_cache.room(room_id).await.expect("Bob should have an event cache for the room");

        let (_initial_events, mut subscriber) = room_cache.subscribe().await.unwrap();

        // Sync the encrypted event to Bob. Without the room key, it's a UTD.
        server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_joined_room(
                    JoinedRoomBuilder::new(room_id).add_timeline_event(encrypted_event),
                );
            })
            .await;

        // Consume the UTD update from the subscriber.
        assert_let_timeout!(
            Ok(RoomEventCacheUpdate::UpdateTimelineEvents(TimelineVectorDiffs { diffs, .. })) =
                subscriber.recv()
        );
        assert_eq!(diffs.len(), 1);
        assert_let!(VectorDiff::Append { values } = &diffs[0]);
        assert_matches!(&values[0].kind, TimelineEventKind::UnableToDecrypt { .. });

        // Create an event-focused cache with a backward pagination gap.
        let focused_event_id = event_id!("$focused");
        let bob_user_id = bob.user_id().unwrap();

        server
            .mock_room_event_context()
            .expect_any_access_token()
            .ok(RoomContextResponseTemplate::new(
                f.text_msg("focused msg")
                    .sender(bob_user_id)
                    .event_id(focused_event_id)
                    .into_event(),
            )
            .start("back-token"))
            .mock_once()
            .mount()
            .await;

        let event_focused_cache = event_cache
            .event_focused(
                room_id,
                focused_event_id,
                EventFocusThreadMode::Automatic { hide_threaded_events: true },
                20,
            )
            .await
            .unwrap()
            .0;

        // Mock /messages with a long delay, simulating a slow network.
        server
            .mock_room_messages()
            .expect_any_access_token()
            .with_delay(Duration::from_secs(5))
            .ok(RoomMessagesResponseTemplate::default())
            .mock_once()
            .mount()
            .await;

        // Start backward pagination on the event-focused cache. This holds the
        // cache write lock across the slow /messages network request.
        let event_focused_cache_clone = event_focused_cache.clone();
        let pagination_task = spawn(async move {
            let _ = event_focused_cache_clone.paginate_backwards(20).await;
        });

        // Let the pagination task acquire the event-focused cache write lock.
        sleep(Duration::from_millis(200)).await;

        // Send the room key to Bob.
        //
        // The redecryptor background task will pick it up and decrypt the UTD.
        // Previously, on_resolved_utds would hold the room state write lock
        // while calling replace_utds on event-focused caches, creating an ABBA
        // deadlock with pagination (which holds event-focused lock and needs
        // room state lock via save_events).
        server
            .mock_sync()
            .ok_and_run(&bob, |builder| {
                builder.add_to_device_event(
                    room_key
                        .deserialize_as()
                        .expect("We should be able to deserialize the room key"),
                );
            })
            .await;

        // Wait for the redecryptor to process the room key.
        sleep(Duration::from_secs(1)).await;

        // Subscribing requires the event cache state lock. Upstream serializes
        // every cache kind (room, thread, pinned, event-focused) on one
        // state lock, so a read is expected to wait for the in-flight
        // event-focused pagination below, but it must never be awaited
        // forever: the previous ABBA deadlock between UTD replacement
        // and event-focused pagination would hang here.
        let (_events, _subscriber) =
            tokio::time::timeout(Duration::from_secs(8), room_cache.subscribe())
                .await
                .expect("subscribing must not deadlock")
                .expect("subscribing should succeed");

        pagination_task.abort();
    }

    /// Helper method to send an encrypted message to a room, and capture both
    /// the sent event and the to-device message sharing its room key.
    ///
    /// The message must share a new room key: it has to be the first message in
    /// the room, or the first one after the room key was discarded.
    async fn send_encrypted(
        matrix_mock_server: &MatrixMockServer,
        client: &Client,
        room_id: &RoomId,
        event_id: &EventId,
        content: impl MessageLikeEventContent,
    ) -> (Raw<AnySyncTimelineEvent>, Raw<EncryptedToDeviceEvent>) {
        let user_id = client.user_id().unwrap();
        let room = client.get_room(room_id).unwrap();

        let (event_receiver, mock) =
            matrix_mock_server.mock_room_send().ok_with_capture(event_id, user_id);
        // Keep the guards bound until the end of the method, or the mocks are
        // dropped immediately.
        let _send_guard = mock.mock_once().mount_as_scoped().await;
        let (_to_device_guard, room_key) =
            matrix_mock_server.mock_capture_put_to_device(user_id).await;

        room.send(content).await.unwrap();

        (event_receiver.await.unwrap(), room_key.await)
    }

    /// Bundle `child` as the latest thread event of `root`.
    fn with_bundled_thread(
        root: &Raw<AnySyncTimelineEvent>,
        child: &Raw<AnySyncTimelineEvent>,
    ) -> Raw<AnySyncTimelineEvent> {
        let mut root: serde_json::Value = root.deserialize_as().unwrap();
        root["unsigned"] = json!({
            "m.relations": {
                "m.thread": {
                    "latest_event": child,
                    "count": 1,
                    "current_user_participated": false,
                },
            },
        });
        Raw::new(&root).unwrap().cast_unchecked()
    }

    /// Helper method to sync room keys to a client, in a single sync response.
    async fn sync_room_keys(
        matrix_mock_server: &MatrixMockServer,
        client: &Client,
        room_keys: &[Raw<EncryptedToDeviceEvent>],
    ) {
        matrix_mock_server
            .mock_sync()
            .ok_and_run(client, |builder| {
                for room_key in room_keys {
                    builder.add_to_device_event(room_key.deserialize_as().unwrap());
                }
            })
            .await;
        // Allow the redecryptor some time to retry any UTDs.
        sleep(Duration::from_millis(100)).await;
    }

    /// Helper method to sync a joined room update to a client.
    async fn sync_room(
        matrix_mock_server: &MatrixMockServer,
        client: &Client,
        room: JoinedRoomBuilder,
    ) {
        matrix_mock_server
            .mock_sync()
            .ok_and_run(client, |builder| {
                builder.add_joined_room(room);
            })
            .await;
        // Allow the redecryptor some time to retry any UTDs.
        sleep(Duration::from_millis(200)).await;
    }

    /// Get the cached timeline event kind for a given event ID in a room, if it
    /// exists. Returns `None` if the event is not in the cache.
    async fn get_cached_timeline_event_kind(
        client: &Client,
        room_id: &RoomId,
        event_id: &EventId,
    ) -> Option<TimelineEventKind> {
        client
            .get_room(room_id)
            .unwrap()
            .load_or_fetch_event(event_id, None)
            .await
            .map(|event| event.kind)
            // An error here means the event is not in the cache, so we return `None`.
            .ok()
    }

    /// Helper method to create a thread reply event contents.
    fn make_thread_reply_event_content(
        root_id: &EventId,
        sender: &UserId,
    ) -> RoomMessageEventContent {
        RoomMessageEventContent::text_plain("In the thread").make_for_thread(
            ReplyMetadata::new(
                root_id,
                sender,
                Some(&Thread::plain(root_id.to_owned(), root_id.to_owned())),
            ),
            ReplyWithinThread::No,
            AddMentions::No,
        )
    }

    /// Case 1 (normal): the key arrives first, then the root and the reply as
    /// separate events.
    #[async_test]
    async fn test_thread_reply_in_timeline_after_key() {
        let room_id = room_id!("!test:localhost");
        let root_id = event_id!("$root");
        let reply_id = event_id!("$reply");

        // Alice and Bob are in an encrypted room ...
        let (alice, bob, server, _) = set_up_clients(room_id, true, false).await;
        let alice_id = alice.user_id().unwrap();

        // ... in which Alice sends a message.
        let (root, root_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            root_id,
            RoomMessageEventContent::text_plain("Root"),
        )
        .await;

        // Alice discards the room key ...
        alice.get_room(room_id).unwrap().discard_room_key().await.unwrap();

        // ... then sends a reply in a new thread using a newly generated room
        // key.
        let (reply, reply_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            reply_id,
            make_thread_reply_event_content(root_id, alice_id),
        )
        .await;

        // Bob receives both room keys first, then the root and reply events.
        sync_room_keys(&server, &bob, &[root_key, reply_key]).await;
        sync_room(&server, &bob, JoinedRoomBuilder::new(room_id).add_timeline_bulk([root, reply]))
            .await;

        // Bob should now have both events in his cache, and they should be
        // decrypted.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, root_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, reply_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
    }

    /// Case 2: The key arrives first, then the root and bundled reply arrive in
    /// a single sync.
    #[async_test]
    async fn test_bundled_thread_reply_after_key_decryptable_root() {
        let room_id = room_id!("!test:localhost");
        let root_id = event_id!("$root");
        let reply_id = event_id!("$reply");

        // Alice and Bob are in an encrypted room ...
        let (alice, bob, server, _) = set_up_clients(room_id, true, false).await;
        let alice_id = alice.user_id().unwrap();

        // ... in which Alice sends a message.
        let (root, root_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            root_id,
            RoomMessageEventContent::text_plain("Root"),
        )
        .await;

        // Alice discards the room key ...
        alice.get_room(room_id).unwrap().discard_room_key().await.unwrap();

        // ... then sends a reply in a new thread using a newly generated room
        // key.
        let (reply, reply_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            reply_id,
            make_thread_reply_event_content(root_id, alice_id),
        )
        .await;

        // Bob receives both room keys first, then the reply bundled as the
        // latest thread event of the root.
        sync_room_keys(&server, &bob, &[root_key, reply_key]).await;
        sync_room(
            &server,
            &bob,
            // Servers only bundle aggregations into limited timelines, per https://spec.matrix.org/latest/client-server-api/#aggregations-of-child-events
            JoinedRoomBuilder::new(room_id)
                .add_timeline_event(with_bundled_thread(&root, &reply))
                .set_timeline_limited()
                .set_timeline_prev_batch("prev_batch"),
        )
        .await;

        // Bob should have both events in his cache, and they should be
        // decrypted.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, root_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, reply_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
    }

    /// Case 3: The root key arrives first, then the root and bundled reply
    /// arrive in a single sync, then the reply key arrives.
    #[async_test]
    async fn test_bundled_thread_reply_key_arrives_later() {
        let room_id = room_id!("!test:localhost");
        let root_id = event_id!("$root");
        let reply_id = event_id!("$reply");

        // Alice and Bob are in an encrypted room ...
        let (alice, bob, server, _) = set_up_clients(room_id, true, false).await;
        let alice_id = alice.user_id().unwrap();

        // ... in which Alice sends a message.
        let (root, root_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            root_id,
            RoomMessageEventContent::text_plain("Root"),
        )
        .await;

        // Alice discards the room key ...
        alice.get_room(room_id).unwrap().discard_room_key().await.unwrap();

        // ... then sends a reply in a new thread using a newly generated room
        // key.
        let (reply, reply_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            reply_id,
            make_thread_reply_event_content(root_id, alice_id),
        )
        .await;

        // Bob receives the root key first, then the root and reply events
        // bundled together, but not the reply key.
        sync_room_keys(&server, &bob, &[root_key]).await;
        sync_room(
            &server,
            &bob,
            // Servers only bundle aggregations into limited timelines, per https://spec.matrix.org/latest/client-server-api/#aggregations-of-child-events
            JoinedRoomBuilder::new(room_id)
                .add_timeline_event(with_bundled_thread(&root, &reply))
                .set_timeline_limited()
                .set_timeline_prev_batch("prev_batch"),
        )
        .await;

        // Bob should have both events in his cache, but should only be able to
        // decrypt the root.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, root_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
        // Bob should also know why the decryption failed, rather than a generic
        // `UnableToDecryptReason::Unknown`.
        assert_let!(
            Some(TimelineEventKind::UnableToDecrypt { utd_info, .. }) =
                get_cached_timeline_event_kind(&bob, room_id, reply_id).await
        );
        assert_matches!(
            utd_info.reason,
            UnableToDecryptReason::MissingMegolmSession { withheld_code: None }
        );

        // Now Bob receives the reply key ...
        sync_room_keys(&server, &bob, &[reply_key]).await;

        // ... and should therefore be able to decrypt the reply as well.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, reply_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
    }

    /// Case 4: The reply key arrives first, then the root and bundled reply
    /// arrive in a single sync, then the root key arrives.
    #[async_test]
    async fn test_bundled_thread_reply_root_key_arrives_later() {
        let room_id = room_id!("!test:localhost");
        let root_id = event_id!("$root");
        let reply_id = event_id!("$reply");

        // Alice and Bob are in an encrypted room ...
        let (alice, bob, server, _) = set_up_clients(room_id, true, false).await;
        let alice_id = alice.user_id().unwrap();

        // ... in which Alice sends a message.
        let (root, root_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            root_id,
            RoomMessageEventContent::text_plain("Root"),
        )
        .await;

        // Alice discards the room key ...
        alice.get_room(room_id).unwrap().discard_room_key().await.unwrap();

        // ... then sends a reply in a new thread using a newly generated room
        // key.
        let (reply, reply_key) = send_encrypted(
            &server,
            &alice,
            room_id,
            reply_id,
            make_thread_reply_event_content(root_id, alice_id),
        )
        .await;

        // Bob receives the reply key first, then the root and reply events
        // bundled together, but not the root key.
        sync_room_keys(&server, &bob, &[reply_key]).await;
        sync_room(
            &server,
            &bob,
            // Servers only bundle aggregations into limited timelines, per https://spec.matrix.org/latest/client-server-api/#aggregations-of-child-events
            JoinedRoomBuilder::new(room_id)
                .add_timeline_event(with_bundled_thread(&root, &reply))
                .set_timeline_limited()
                .set_timeline_prev_batch("prev_batch"),
        )
        .await;

        // Bob should have both events in his cache. The root stays a UTD, since
        // its room key is still missing, but the reply must be
        // decrypted: it was bundled inside a UTD, so nothing decrypted
        // it on the way in, but Bob does have its room key, and the
        // redecryptor is asked to retry bundled UTDs as soon as they're
        // saved.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, root_id).await,
            Some(TimelineEventKind::UnableToDecrypt { .. })
        );
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, reply_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );

        // Now Bob receives the root key ...
        sync_room_keys(&server, &bob, &[root_key]).await;

        // ... and should therefore be able to decrypt both the root and the
        // reply.
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, root_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
        assert_matches!(
            get_cached_timeline_event_kind(&bob, room_id, reply_id).await,
            Some(TimelineEventKind::Decrypted { .. })
        );
    }
}
