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
// See the License for that specific language governing permissions and
// limitations under the License.

//! `RoomListService` API.
//!
//! The `RoomListService` is a UI API dedicated to present a list of Matrix
//! rooms to the user. The syncing is handled by [`SlidingSync`]. The idea is to
//! expose a simple API to handle most of the client app use cases, like:
//! Showing and updating a list of rooms, filtering a list of rooms, handling
//! particular updates of a range of rooms (the ones the client app is showing
//! to the view, i.e. the rooms present in the viewport) etc.
//!
//! As such, the `RoomListService` works as an opinionated state machine. The
//! states are defined by [`State`]. Actions are attached to the each state
//! transition.
//!
//! The API is purposely small. Sliding Sync is versatile. `RoomListService` is
//! _one_ specific usage of Sliding Sync.
//!
//! # Basic principle
//!
//! `RoomListService` works with 1 Sliding Sync List:
//!
//! * `all_rooms` (referred by the constant [`ALL_ROOMS_LIST_NAME`]) is the only
//!   list. Its goal is to load all the user' rooms. It starts with a
//!   [`SlidingSyncMode::Selective`] sync-mode with a small range (i.e. a small
//!   set of rooms) to load the first rooms quickly, and then updates to a
//!   [`SlidingSyncMode::Growing`] sync-mode to load the remaining rooms “in the
//!   background”: it will sync the existing rooms and will fetch new rooms, by
//!   a certain batch size.
//!
//! This behavior has proven to be empirically satisfying to provide a fast and
//! fluid user experience for a Matrix client.
//!
//! [`RoomListService::all_rooms`] provides a way to get a [`RoomList`] for all
//! the rooms. From that, calling [`RoomList::entries_with_dynamic_adapters`]
//! provides a way to get a stream of rooms. This stream is sorted, can be
//! filtered, and the filter can be changed over time.
//!
//! [`RoomListService::state`] provides a way to get a stream of the state
//! machine's state, which can be pretty helpful for the client app.

mod all_rooms;
pub mod filters;
mod room_list;
pub mod sorters;
mod state;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_stream::stream;
use eyeball::{SharedObservable, Subscriber};
use futures_util::{Stream, StreamExt, pin_mut};
use matrix_sdk::{
    Client, Error as SlidingSyncError, Room, SlidingSync, SlidingSyncList, SlidingSyncMode,
    event_cache::EventCacheError, sliding_sync::PollTimeout, timeout::timeout,
};
pub use room_list::*;
use ruma::{
    OwnedRoomId, RoomId, UInt, UserId, api::client::sync::sync_events::v5 as http, assign,
    events::StateEventType,
};
pub use state::*;
use thiserror::Error;
use tracing::{debug, error, warn};

pub use self::all_rooms::CommittedAllRoomsResponse;
use self::all_rooms::{AllRoomsObservedIdsObservable, CommittedAllRoomsResponseObservable};

/// The default `required_state` constant value for sliding sync lists and
/// sliding sync room subscriptions.
const DEFAULT_REQUIRED_STATE: &[(StateEventType, &str)] = &[
    (StateEventType::RoomName, ""),
    (StateEventType::RoomEncryption, ""),
    (StateEventType::RoomMember, "$LAZY"),
    (StateEventType::RoomMember, "$ME"),
    (StateEventType::RoomTopic, ""),
    // Temporary workaround for https://github.com/matrix-org/matrix-rust-sdk/issues/5285
    (StateEventType::RoomAvatar, ""),
    (StateEventType::RoomCanonicalAlias, ""),
    (StateEventType::RoomPowerLevels, ""),
    (StateEventType::CallMember, "*"),
    (StateEventType::RoomJoinRules, ""),
    (StateEventType::RoomTombstone, ""),
    // Those two events are required to properly compute room previews.
    // `StateEventType::RoomCreate` is also necessary to compute the room
    // version, and thus handling the tombstoned room correctly.
    (StateEventType::RoomCreate, ""),
    (StateEventType::RoomHistoryVisibility, ""),
    // Required to correctly calculate the room display name.
    (StateEventType::MemberHints, ""),
    (StateEventType::SpaceParent, "*"),
    (StateEventType::SpaceChild, "*"),
    // Required for live location sharing to work - beacon events reference this state.
    (StateEventType::BeaconInfo, "*"),
];

/// The default `required_state` constant value for sliding sync room
/// subscriptions that must be added to `DEFAULT_REQUIRED_STATE`.
const DEFAULT_ROOM_SUBSCRIPTION_EXTRA_REQUIRED_STATE: &[(StateEventType, &str)] =
    &[(StateEventType::RoomPinnedEvents, "")];

// An authenticated user's exact state key is equivalent to `$ME` and remains
// compatible with servers that advertise MSC4186 without expanding the
// placeholder. Without an authenticated user, preserve `$ME` as the fallback.
fn required_state_for_user(
    required_state: &[(StateEventType, &str)],
    own_user_id: Option<&UserId>,
) -> Vec<(StateEventType, String)> {
    required_state
        .iter()
        .map(|(state_event, value)| {
            let value = if *state_event == StateEventType::RoomMember && *value == "$ME" {
                own_user_id.map_or(*value, UserId::as_str)
            } else {
                value
            };

            (state_event.clone(), value.to_owned())
        })
        .collect()
}

/// The default Sliding Sync connection ID for the room list service.
pub(crate) const DEFAULT_CONNECTION_ID: &str = "room-list";

/// The default timeline limit for the room list service.
pub(crate) const DEFAULT_LIST_TIMELINE_LIMIT: u32 = 1;

/// The default `timeline_limit` value when used with room subscriptions.
const DEFAULT_ROOM_SUBSCRIPTION_TIMELINE_LIMIT: u32 = 20;

/// Process-local generation of one complete room-subscription set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RoomSubscriptionGeneration(u64);

impl RoomSubscriptionGeneration {
    /// Return the coarse generation number.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Provenance checkpoint for a room present in a subscription response.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomSubscriptionCheckpoint {
    subscription_generation: RoomSubscriptionGeneration,
    response_sequence: u64,
    room_id: OwnedRoomId,
    timeline: Option<matrix_sdk::event_cache::RoomTimelineSyncObservation>,
}

impl RoomSubscriptionCheckpoint {
    /// Generation of the subscription request that produced this response.
    pub fn subscription_generation(&self) -> RoomSubscriptionGeneration {
        self.subscription_generation
    }

    /// Exact committed `all_rooms` response that produced this checkpoint.
    pub fn response_sequence(&self) -> u64 {
        self.response_sequence
    }

    /// Room associated with this checkpoint.
    pub fn room_id(&self) -> &RoomId {
        &self.room_id
    }

    /// New timeline observation committed after the subscription baseline.
    pub fn timeline(&self) -> Option<&matrix_sdk::event_cache::RoomTimelineSyncObservation> {
        self.timeline.as_ref()
    }
}

impl fmt::Debug for RoomSubscriptionCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoomSubscriptionCheckpoint")
            .field("subscription_generation", &self.subscription_generation)
            .field("response_sequence", &self.response_sequence)
            .field("has_timeline", &self.timeline.is_some())
            .finish()
    }
}

#[derive(Clone, Default)]
struct RoomSubscriptionState {
    generation: u64,
    active_rooms: BTreeSet<OwnedRoomId>,
}

impl fmt::Debug for RoomSubscriptionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoomSubscriptionState")
            .field("generation", &self.generation)
            .field("active_room_count", &self.active_rooms.len())
            .finish()
    }
}

#[derive(Clone)]
struct RoomSubscriptionIteration {
    generation: RoomSubscriptionGeneration,
    active_rooms: BTreeSet<OwnedRoomId>,
    observation_baselines: BTreeMap<OwnedRoomId, u64>,
}

/// The [`RoomListService`] type. See the module's documentation to learn more.
#[derive(Debug)]
pub struct RoomListService {
    /// Client that has created this [`RoomListService`].
    client: Client,

    /// The Sliding Sync instance.
    sliding_sync: Arc<SlidingSync>,

    /// The current state of the `RoomListService`.
    ///
    /// `RoomListService` is a simple state-machine.
    state_machine: StateMachine,

    room_subscription_state: Arc<Mutex<RoomSubscriptionState>>,
    room_subscription_checkpoints:
        SharedObservable<Arc<BTreeMap<OwnedRoomId, RoomSubscriptionCheckpoint>>>,

    committed_all_rooms_response: CommittedAllRoomsResponseObservable,
    all_rooms_observed_ids: AllRoomsObservedIdsObservable,
}

impl RoomListService {
    /// Create a new `RoomList`.
    ///
    /// A [`matrix_sdk::SlidingSync`] client will be created, with a cached list
    /// already pre-configured.
    ///
    /// This won't start an encryption sync, and it's the user's responsibility
    /// to create one in this case using
    /// [`EncryptionSyncService`][crate::encryption_sync_service::EncryptionSyncService].
    pub async fn new(client: Client) -> Result<Self, Error> {
        Self::new_with(client, true, DEFAULT_CONNECTION_ID, DEFAULT_LIST_TIMELINE_LIMIT).await
    }

    /// Like [`RoomListService::new`] but with additional configuration options.
    ///
    /// - `share_pos`: toggles [`SlidingSyncBuilder::share_pos`] for
    ///   cross-process position sharing.
    /// - `connection_id`: the Sliding Sync connection ID
    /// - `timeline_limit`: the timeline limit
    ///
    /// [`SlidingSyncBuilder::share_pos`]: matrix_sdk::sliding_sync::SlidingSyncBuilder::share_pos
    pub async fn new_with(
        client: Client,
        share_pos: bool,
        connection_id: &str,
        timeline_limit: u32,
    ) -> Result<Self, Error> {
        let mut builder = client
            .sliding_sync(connection_id)
            .map_err(Error::SlidingSync)?
            .with_account_data_extension(
                assign!(http::request::AccountData::default(), { enabled: Some(true) }),
            )
            .with_receipt_extension(assign!(http::request::Receipts::default(), {
                enabled: Some(true),
                rooms: Some(vec![http::request::ExtensionRoomConfig::AllSubscribed])
            }))
            .with_typing_extension(assign!(http::request::Typing::default(), {
                enabled: Some(true),
            }));

        match client.enabled_thread_subscriptions().await {
            Ok(true) => {
                debug!("Client requested thread subscriptions extension");

                builder = builder.with_thread_subscriptions_extension(
                    assign!(http::request::ThreadSubscriptions::default(), {
                        enabled: Some(true),
                        limit: Some(ruma::uint!(10))
                    }),
                );
            }

            Ok(false) => {
                debug!(
                    "Thread subscriptions extension either not requested on the client, or the server doesn't advertise support for it: not enabling."
                );
            }

            Err(error) => {
                warn!(
                    ?error,
                    "Failed to check whether the client requested thread subscriptions extension: not enabling."
                );
            }
        }

        if share_pos {
            // The e2ee extensions aren't enabled in this sliding sync instance, and this is
            // the only one that could be used from a different process. So it's
            // fine to enable position sharing (i.e. reloading it from disk),
            // since it's always exclusively owned by the current process.
            debug!("Enabling `share_pos` for the room list sliding sync");
            builder = builder.share_pos();
        }

        let state_machine = StateMachine::new();
        let observable_state = state_machine.cloned_state();

        let sliding_sync = builder
            .add_cached_list(
                SlidingSyncList::builder(ALL_ROOMS_LIST_NAME)
                    .sync_mode(
                        SlidingSyncMode::new_selective()
                            .add_range(ALL_ROOMS_DEFAULT_SELECTIVE_RANGE),
                    )
                    .timeline_limit(timeline_limit)
                    .required_state(required_state_for_user(
                        DEFAULT_REQUIRED_STATE,
                        client.user_id(),
                    ))
                    .filters(Some(assign!(http::request::ListFilters::default(), {
                        // As defined in the [SlidingSync MSC](https://github.com/matrix-org/matrix-spec-proposals/blob/9450ced7fb9cf5ea9077d029b3adf36aebfa8709/proposals/3575-sync.md?plain=1#L444)
                        // If unset, both invited and joined rooms are returned. If false, no invited rooms are
                        // returned. If true, only invited rooms are returned.
                        is_invite: None,
                    })))
                    .requires_timeout(move |request_generator| {
                        // We want Sliding Sync to apply the poll + network timeout —i.e. to do the
                        // long-polling— in some particular cases. Let's define them.
                        match observable_state.get() {
                            // These are the states where we want an immediate response from the
                            // server, with no long-polling.
                            State::Init
                            | State::SettingUp
                            | State::Recovering
                            | State::Error { .. }
                            | State::Terminated { .. } => PollTimeout::Some(0),

                            // Otherwise we want long-polling if the list is fully-loaded.
                            State::Running => {
                                if request_generator.is_fully_loaded() {
                                    // Long-polling.
                                    PollTimeout::Default
                                } else {
                                    // No long-polling yet.
                                    PollTimeout::Some(0)
                                }
                            }
                        }
                    }),
            )
            .await
            .map_err(Error::SlidingSync)?
            .build()
            .await
            .map(Arc::new)
            .map_err(Error::SlidingSync)?;

        // Eagerly subscribe the event cache to sync responses.
        client.event_cache().subscribe()?;

        Ok(Self {
            client,
            sliding_sync,
            state_machine,
            room_subscription_state: Default::default(),
            room_subscription_checkpoints: SharedObservable::new(Arc::new(BTreeMap::new())),
            committed_all_rooms_response: CommittedAllRoomsResponseObservable::new(),
            all_rooms_observed_ids: AllRoomsObservedIdsObservable::new(),
        })
    }

    /// Start to sync the room list.
    ///
    /// It's the main method of this entire API. Calling `sync` allows to
    /// receive updates on the room list: new rooms, rooms updates etc. Those
    /// updates can be read with `RoomList::entries` for example. This method
    /// returns a [`Stream`] where produced items only hold an empty value
    /// in case of a sync success, otherwise an error.
    ///
    /// The `RoomListService`' state machine is run by this method.
    ///
    /// Stopping the [`Stream`] (i.e. by calling [`Self::stop_sync`]), and
    /// calling [`Self::sync`] again will resume from the previous state of
    /// the state machine.
    ///
    /// This should be used only for testing. In practice, most users should be
    /// using the [`SyncService`](crate::sync_service::SyncService) instead.
    #[doc(hidden)]
    pub fn sync(&self) -> impl Stream<Item = Result<(), Error>> + '_ {
        stream! {
            let sync = self.sliding_sync.sync();
            pin_mut!(sync);

            // This is a state machine implementation.
            // Things happen in this order:
            //
            // 1. The next state is calculated,
            // 2. The actions associated to the next state are run,
            // 3. A sync is done,
            // 4. The next state is stored.
            loop {
                debug!("Run a sync iteration");

                // Calculate the next state, and run the associated actions.
                let next_state = self.state_machine.next(&self.sliding_sync).await?;
                if matches!(next_state, State::SettingUp | State::Recovering) {
                    self.all_rooms_observed_ids.begin_cycle();
                }

                // Bind the event-cache baseline to this exact sync iteration,
                // rather than to the earlier subscription API call. An older
                // in-flight response therefore keeps its older generation,
                // while a response polled after reconfiguration gets a fresh
                // baseline that cannot reuse a pre-iteration observation.
                let subscription_iteration = self.capture_room_subscription_iteration().await;

                // Do the sync.
                match sync.next().await {
                    // Got a successful result while syncing.
                    Some(Ok(update_summary)) => {
                        let room_subscription_checkpoints = self
                            .collect_room_subscription_checkpoints(
                            &subscription_iteration,
                            &update_summary.rooms,
                        )
                        .await;

                        // `SlidingSync::sync` returns only after client response handling,
                        // including the event-cache commit, and a successful v5 response has
                        // committed its required `pos`. Publish only coarse process-local
                        // evidence after that work has completed.
                        let (range_fully_loaded, maximum_number_of_rooms) = self
                            .sliding_sync
                            .on_list(ALL_ROOMS_LIST_NAME, |list| {
                                std::future::ready((
                                    RoomListRangeLoadingState::from_states(
                                        &list.state(),
                                        &next_state,
                                    ) == RoomListRangeLoadingState::FullyLoaded,
                                    list.maximum_number_of_rooms(),
                                ))
                            })
                            .await
                            .ok_or_else(|| Error::UnknownList(ALL_ROOMS_LIST_NAME.to_owned()))?;
                        self.committed_all_rooms_response.advance_after(
                            range_fully_loaded,
                            move |response_sequence| {
                                self.publish_room_subscription_checkpoints(
                                    subscription_iteration,
                                    room_subscription_checkpoints,
                                    response_sequence,
                                );
                                self.all_rooms_observed_ids.accumulate(
                                    response_sequence,
                                    range_fully_loaded,
                                    maximum_number_of_rooms,
                                    &update_summary.rooms_from_response,
                                );
                            },
                        );
                        debug!(state = ?next_state, "New state");

                        // Update the state.
                        self.state_machine.set(next_state);

                        yield Ok(());
                    }

                    // Got an error while syncing.
                    Some(Err(error)) => {
                        debug!(expected_state = ?next_state, "New state is an error");

                        let next_state = State::Error { from: Box::new(next_state) };
                        self.state_machine.set(next_state);

                        yield Err(Error::SlidingSync(error));

                        break;
                    }

                    // Sync loop has terminated.
                    None => {
                        debug!(expected_state = ?next_state, "New state is a termination");

                        let next_state = State::Terminated { from: Box::new(next_state) };
                        self.state_machine.set(next_state);

                        break;
                    }
                }
            }
        }
    }

    /// Force to stop the sync of the `RoomListService` started by
    /// [`Self::sync`].
    ///
    /// It's of utter importance to call this method rather than stop polling
    /// the `Stream` returned by [`Self::sync`] because it will force the
    /// cancellation and exit the sync loop, i.e. it will cancel any
    /// in-flight HTTP requests, cancel any pending futures etc. and put the
    /// service into a termination state.
    ///
    /// Ideally, one wants to consume the `Stream` returned by [`Self::sync`]
    /// until it returns `None`, because of [`Self::stop_sync`], so that it
    /// ensures the states are correctly placed.
    ///
    /// Stopping the sync of the room list via this method will put the
    /// state-machine into the [`State::Terminated`] state.
    ///
    /// This should be used only for testing. In practice, most users should be
    /// using the [`SyncService`](crate::sync_service::SyncService) instead.
    #[doc(hidden)]
    pub fn stop_sync(&self) -> Result<(), Error> {
        self.sliding_sync.stop_sync().map_err(Error::SlidingSync)
    }

    /// Force the sliding sync session to expire.
    ///
    /// This is used by [`SyncService`](crate::sync_service::SyncService).
    ///
    /// **Warning**: This method **must not** be called while the sync loop is
    /// running!
    pub(crate) async fn expire_sync_session(&self) {
        self.sliding_sync.expire_session().await;

        // Usually, when the session expires, it leads the state to be `Error`,
        // thus some actions (like refreshing the lists) are executed. However,
        // if the sync loop has been stopped manually, the state is `Terminated`, and
        // when the session is forced to expire, the state remains `Terminated`, thus
        // the actions aren't executed as expected. Consequently, let's update the
        // state.
        if let State::Terminated { from } = self.state_machine.get() {
            self.state_machine.set(State::Error { from });
        }
    }

    /// Get a [`Stream`] of [`SyncIndicator`].
    ///
    /// Read the documentation of [`SyncIndicator`] to learn more about it.
    pub fn sync_indicator(
        &self,
        delay_before_showing: Duration,
        delay_before_hiding: Duration,
    ) -> impl Stream<Item = SyncIndicator> + use<> {
        let mut state = self.state();

        stream! {
            // Ensure the `SyncIndicator` is always hidden to start with.
            yield SyncIndicator::Hide;

            // Let's not wait for an update to happen. The `SyncIndicator` must be
            // computed as fast as possible.
            let mut current_state = state.next_now();

            loop {
                let (sync_indicator, yield_delay) = match current_state {
                    State::SettingUp | State::Error { .. } => {
                        (SyncIndicator::Show, delay_before_showing)
                    }

                    State::Init | State::Recovering | State::Running | State::Terminated { .. } => {
                        (SyncIndicator::Hide, delay_before_hiding)
                    }
                };

                // `state.next().await` has a maximum of `yield_delay` time to execute…
                let next_state = match timeout(state.next(), yield_delay).await {
                    // A new state has been received before `yield_delay` time. The new
                    // `sync_indicator` value won't be yielded.
                    Ok(next_state) => next_state,

                    // No new state has been received before `yield_delay` time. The
                    // `sync_indicator` value can be yielded.
                    Err(_) => {
                        yield sync_indicator;

                        // Now that `sync_indicator` has been yielded, let's wait on
                        // the next state again.
                        state.next().await
                    }
                };

                if let Some(next_state) = next_state {
                    // Update the `current_state`.
                    current_state = next_state;
                } else {
                    // Something is broken with the state. Let's stop this stream too.
                    break;
                }
            }
        }
    }

    /// Get the [`Client`] that has been used to create [`Self`].
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get a subscriber to the state.
    pub fn state(&self) -> Subscriber<State> {
        self.state_machine.subscribe()
    }

    async fn list_for(&self, sliding_sync_list_name: &str) -> Result<RoomList, Error> {
        RoomList::new(
            &self.client,
            &self.sliding_sync,
            sliding_sync_list_name,
            self.state(),
            self.all_rooms_observed_ids.clone(),
        )
        .await
    }

    /// Get a [`RoomList`] for all rooms.
    pub async fn all_rooms(&self) -> Result<RoomList, Error> {
        self.list_for(ALL_ROOMS_LIST_NAME).await
    }

    /// Subscribe to coarse evidence of successfully committed `all_rooms` responses.
    pub fn committed_all_rooms_response(&self) -> Subscriber<CommittedAllRoomsResponse> {
        self.committed_all_rooms_response.subscribe()
    }

    /// Get a [`Room`] if it exists.
    pub fn room(&self, room_id: &RoomId) -> Result<Room, Error> {
        self.client.get_room(room_id).ok_or_else(|| Error::RoomNotFound(room_id.to_owned()))
    }

    /// Subscribe to rooms.
    ///
    /// It means that all events from these rooms will be received every time,
    /// no matter how the `RoomList` is configured.
    ///
    /// [`LatestEvents::listen_to_room`][listen_to_room] will be called for each
    /// room in `room_ids`, so that the [`LatestEventValue`] will automatically
    /// be calculated and updated for these rooms, for free.
    ///
    /// All previous room subscriptions will be forgotten.
    ///
    /// [listen_to_room]: matrix_sdk::latest_events::LatestEvents::listen_to_room
    /// [`LatestEventValue`]: matrix_sdk::latest_events::LatestEventValue
    pub async fn subscribe_to_rooms(&self, room_ids: &[&RoomId]) {
        self.subscribe_to_rooms_with_generation(room_ids).await;
    }

    /// Replace room subscriptions and return their process-local generation.
    pub async fn subscribe_to_rooms_with_generation(
        &self,
        room_ids: &[&RoomId],
    ) -> RoomSubscriptionGeneration {
        // Calculate the settings for the room subscriptions.
        let settings = assign!(http::request::RoomSubscription::default(), {
            required_state: required_state_for_user(DEFAULT_REQUIRED_STATE, self.client.user_id())
            .into_iter()
            .chain(
                DEFAULT_ROOM_SUBSCRIPTION_EXTRA_REQUIRED_STATE.iter().map(|(state_event, value)| {
                    (state_event.clone(), (*value).to_owned())
                })
            )
            .collect(),
            timeline_limit: UInt::from(DEFAULT_ROOM_SUBSCRIPTION_TIMELINE_LIMIT),
        });

        // Decide whether the in-flight request (if any) should be cancelled if needed.
        let cancel_in_flight_request = match self.state_machine.get() {
            State::Init | State::Recovering | State::Error { .. } | State::Terminated { .. } => {
                false
            }
            State::SettingUp | State::Running => true,
        };

        // Before subscribing, let's listen these rooms to calculate their latest
        // events.
        if self.client.event_cache().has_subscribed() {
            let latest_events = self.client.latest_events().await;

            for room_id in room_ids {
                if let Err(error) = latest_events.listen_to_room(room_id).await {
                    // Let's not fail the room subscription. Instead, emit a log because it's very
                    // unlikely to happen.
                    error!(?error, ?room_id, "Failed to listen to the latest event for this room");
                }
            }
        }

        // Reconfigure, publish the generation, and clear retained checkpoints
        // under the same lock used by iteration capture and publication
        // commit. No observer can pair the new request configuration with the
        // old generation or restore an inactive generation after the clear.
        let generation = {
            let mut state = self.room_subscription_state.lock().unwrap();
            self.sliding_sync.clear_and_subscribe_to_rooms(
                room_ids,
                Some(settings),
                cancel_in_flight_request,
            );
            state.generation = state.generation.wrapping_add(1).max(1);
            state.active_rooms = room_ids.iter().map(|room_id| (*room_id).to_owned()).collect();
            self.room_subscription_checkpoints.set(Arc::new(BTreeMap::new()));
            RoomSubscriptionGeneration(state.generation)
        };

        generation
    }

    /// Subscribe to the retained latest checkpoint per room.
    pub fn room_subscription_checkpoints(
        &self,
    ) -> Subscriber<Arc<BTreeMap<OwnedRoomId, RoomSubscriptionCheckpoint>>> {
        self.room_subscription_checkpoints.subscribe()
    }

    async fn capture_room_subscription_iteration(&self) -> RoomSubscriptionIteration {
        loop {
            let state = self.room_subscription_state.lock().unwrap().clone();
            let mut observation_baselines = BTreeMap::new();

            for room_id in &state.active_rooms {
                let sequence = if let Some(room) = self.client.get_room(room_id) {
                    match room.event_cache().await {
                        Ok((cache, _drop_handles)) => cache
                            .latest_sync_observation()
                            .await
                            .map_or(0, |observation| observation.sequence()),
                        Err(_) => 0,
                    }
                } else {
                    0
                };
                observation_baselines.insert(room_id.clone(), sequence);
            }

            let current = self.room_subscription_state.lock().unwrap();
            if current.generation == state.generation && current.active_rooms == state.active_rooms
            {
                return RoomSubscriptionIteration {
                    generation: RoomSubscriptionGeneration(state.generation),
                    active_rooms: state.active_rooms,
                    observation_baselines,
                };
            }
        }
    }

    async fn collect_room_subscription_checkpoints(
        &self,
        iteration: &RoomSubscriptionIteration,
        updated_rooms: &[OwnedRoomId],
    ) -> Vec<(OwnedRoomId, Option<matrix_sdk::event_cache::RoomTimelineSyncObservation>)> {
        let mut additions = Vec::new();
        for room_id in updated_rooms {
            if !iteration.active_rooms.contains(room_id) {
                continue;
            }
            let baseline = iteration.observation_baselines.get(room_id).copied().unwrap_or(0);
            let timeline = if let Some(room) = self.client.get_room(room_id) {
                match room.event_cache().await {
                    Ok((cache, _drop_handles)) => cache
                        .latest_sync_observation()
                        .await
                        .filter(|observation| observation.sequence() > baseline),
                    Err(_) => None,
                }
            } else {
                None
            };
            additions.push((room_id.clone(), timeline));
        }

        additions
    }

    fn publish_room_subscription_checkpoints(
        &self,
        iteration: RoomSubscriptionIteration,
        additions: Vec<(OwnedRoomId, Option<matrix_sdk::event_cache::RoomTimelineSyncObservation>)>,
        response_sequence: u64,
    ) {
        if additions.is_empty() {
            return;
        }

        // Validate and commit while holding the same lock used to replace the
        // subscription generation and clear retained checkpoints.
        let state = self.room_subscription_state.lock().unwrap();
        if state.generation != iteration.generation.0
            || state.active_rooms != iteration.active_rooms
        {
            return;
        }
        let mut retained = (*self.room_subscription_checkpoints.get()).clone();
        retained.extend(additions.into_iter().map(|(room_id, timeline)| {
            (
                room_id.clone(),
                RoomSubscriptionCheckpoint {
                    subscription_generation: iteration.generation,
                    response_sequence,
                    room_id,
                    timeline,
                },
            )
        }));
        self.room_subscription_checkpoints.set(Arc::new(retained));
    }

    #[cfg(test)]
    pub fn sliding_sync(&self) -> &SlidingSync {
        &self.sliding_sync
    }
}

/// [`RoomList`]'s errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Error from [`matrix_sdk::SlidingSync`].
    #[error(transparent)]
    SlidingSync(SlidingSyncError),

    /// An operation has been requested on an unknown list.
    #[error("Unknown list `{0}`")]
    UnknownList(String),

    /// The requested room doesn't exist.
    #[error("Room `{0}` not found")]
    RoomNotFound(OwnedRoomId),

    #[error(transparent)]
    EventCache(#[from] EventCacheError),
}

/// An hint whether a _sync spinner/loader/toaster_ should be prompted to the
/// user, indicating that the [`RoomListService`] is syncing.
///
/// This is entirely arbitrary and optinionated. Of course, once
/// [`RoomListService::sync`] has been called, it's going to be constantly
/// syncing, until [`RoomListService::stop_sync`] is called, or until an error
/// happened. But in some cases, it's better for the user experience to prompt
/// to the user that a sync is happening. It's usually the first sync, or the
/// recovering sync. However, the sync indicator must be prompted if the
/// aforementioned sync is “slow”, otherwise the indicator is likely to “blink”
/// pretty fast, which can be very confusing. It's also common to indicate to
/// the user that a syncing is happening in case of a network error, that
/// something is catching up etc.
#[derive(Debug, Eq, PartialEq)]
pub enum SyncIndicator {
    /// Show the sync indicator.
    Show,

    /// Hide the sync indicator.
    Hide,
}

#[cfg(test)]
mod tests {
    use std::{future::ready, time::Duration};

    use eyeball_im::{Vector, VectorDiff};
    use futures_util::{FutureExt, StreamExt, pin_mut};
    use matrix_sdk::{SlidingSyncMode, ThreadingSupport, test_utils::mocks::MatrixMockServer};
    use matrix_sdk_test::{TestError, async_test};
    use ruma::{
        api::client::sync::sync_events::v5, assign, events::StateEventType, room_id, uint, user_id,
    };
    use serde_json::Value;
    use wiremock::ResponseTemplate;

    use super::{
        ALL_ROOMS_LIST_NAME, Error, RoomListRangeLoadingState, RoomListService,
        RoomSubscriptionCheckpoint, RoomSubscriptionGeneration, RoomSubscriptionState, State,
        filters::new_filter_non_left, required_state_for_user,
    };
    use crate::sync_service::{State as SyncServiceState, SyncService};

    #[tokio::test]
    async fn committed_all_rooms_response_observable_waits_for_committed_response()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let sync_service = SyncService::builder(client.clone()).build().await?;
        let room_list_service = sync_service.room_list_service();
        let mut committed = room_list_service.committed_all_rooms_response();
        let mut event_cache_commits =
            client.event_cache().subscribe_to_committed_room_updates_responses();

        assert_eq!(committed.get().sequence(), 0);
        assert!(!committed.get().pos_present());

        let _mock_guard = server
            .mock_sliding_sync()
            .respond_with(
                ResponseTemplate::new(200).set_delay(Duration::from_millis(100)).set_body_json(
                    serde_json::json!({
                        "pos": "private-pos-value",
                        "lists": { "all_rooms": { "count": 0, "ops": [] } }
                    }),
                ),
            )
            .mount_as_scoped()
            .await;

        let mut sync_state = sync_service.state();
        sync_service.start().await;
        assert!(matches!(sync_state.next().await, Some(SyncServiceState::Running)));
        assert_eq!(committed.get().sequence(), 0);
        assert!(!committed.get().pos_present());

        tokio::time::timeout(Duration::from_secs(2), committed.next())
            .await
            .expect("committed all-rooms response observable timed out")
            .expect("committed all-rooms response observable ended");

        let latest = committed.get();
        assert_eq!(latest.sequence(), 1);
        assert!(latest.pos_present());
        assert!(
            event_cache_commits.borrow_and_update().is_some(),
            "the all-rooms observable must advance after the event-cache response commit"
        );
        let debug = format!("{latest:?}");
        assert!(!debug.contains("private-pos-value"));
        assert!(!debug.contains("room_id"));

        sync_service.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn committed_all_rooms_response_observable_ignores_failure_then_advances()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let committed = room_list_service.committed_all_rooms_response();

        {
            let _failure_guard =
                server.mock_sliding_sync().error_unrecognized().mount_as_scoped().await;
            let sync = room_list_service.sync();
            pin_mut!(sync);
            assert!(matches!(sync.next().await, Some(Err(_))));
        }

        assert_eq!(committed.get().sequence(), 0);
        assert!(!committed.get().pos_present());

        let _success_guard = server
            .mock_sliding_sync()
            .ok({
                let mut response = v5::Response::new("private-reconnect-pos".to_owned());
                response.lists.insert(
                    ALL_ROOMS_LIST_NAME.to_owned(),
                    assign!(v5::response::List::default(), { count: uint!(0) }),
                );
                response
            })
            .mount_as_scoped()
            .await;
        let sync = room_list_service.sync();
        pin_mut!(sync);
        sync.next().await.expect("reconnect room-list sync result")?;

        let latest = committed.get();
        assert_eq!(latest.sequence(), 1);
        assert!(latest.pos_present());
        assert!(!format!("{latest:?}").contains("private-reconnect-pos"));

        Ok(())
    }

    #[tokio::test]
    async fn room_checkpoint_and_global_commit_share_the_exact_response_sequence()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let room_id = room_id!("!response-correlation:example.org");
        let committed = room_list_service.committed_all_rooms_response();
        let sync = room_list_service.sync();
        pin_mut!(sync);

        {
            let _initial_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": "initial",
                    "lists": { "all_rooms": { "count": 1 } },
                    "rooms": { room_id: { "initial": true } }
                })))
                .mount_as_scoped()
                .await;
            sync.next().await.expect("initial room-list sync result")?;
        }

        let generation = room_list_service.subscribe_to_rooms_with_generation(&[room_id]).await;

        {
            let _update_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": "with-gap",
                    "lists": { "all_rooms": { "count": 1 } },
                    "rooms": {
                        room_id: {
                            "timeline": [{
                                "event_id": "$correlated-event:example.org",
                                "sender": "@alice:example.org",
                                "type": "m.room.message",
                                "content": { "body": "private body", "msgtype": "m.text" },
                                "origin_server_ts": 1
                            }],
                            "prev_batch": "private-gap-token"
                        }
                    }
                })))
                .mount_as_scoped()
                .await;
            sync.next().await.expect("timeline room-list sync result")?;
        }

        let update_commit = committed.get();
        let update_checkpoint = room_list_service
            .room_subscription_checkpoints()
            .get()
            .get(room_id)
            .cloned()
            .expect("timeline checkpoint");
        assert_eq!(update_checkpoint.subscription_generation(), generation);
        assert_eq!(update_checkpoint.response_sequence(), update_commit.sequence());
        assert!(
            update_checkpoint.timeline().is_some_and(|timeline| timeline.inserted_gap().is_some())
        );

        {
            let _no_update_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": "without-timeline-update",
                    "lists": { "all_rooms": { "count": 1 } },
                    "rooms": { room_id: {} }
                })))
                .mount_as_scoped()
                .await;
            sync.next().await.expect("no-update room-list sync result")?;
        }

        let no_update_commit = committed.get();
        let no_update_checkpoint = room_list_service
            .room_subscription_checkpoints()
            .get()
            .get(room_id)
            .cloned()
            .expect("no-update checkpoint");
        assert_eq!(no_update_checkpoint.subscription_generation(), generation);
        assert_eq!(no_update_checkpoint.response_sequence(), no_update_commit.sequence());
        assert!(no_update_checkpoint.response_sequence() > update_checkpoint.response_sequence());
        assert!(no_update_checkpoint.timeline().is_none());

        Ok(())
    }

    #[test]
    fn room_subscription_checkpoint_debug_is_private_safe() {
        let room_id = room_id!("!private-checkpoint:example.org");
        let checkpoint = RoomSubscriptionCheckpoint {
            subscription_generation: RoomSubscriptionGeneration(7),
            response_sequence: 11,
            room_id: room_id.to_owned(),
            timeline: None,
        };

        let debug = format!("{checkpoint:?}");
        assert!(debug.contains("subscription_generation"));
        assert!(debug.contains("response_sequence: 11"));
        assert!(debug.contains("has_timeline: false"));
        assert!(!debug.contains(room_id.as_str()));
        assert!(!debug.contains("private-checkpoint"));
    }

    #[tokio::test]
    async fn all_rooms_range_loading_state_becomes_full_only_after_final_growing_range()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut range_state = all_rooms.range_loading_state();
        let committed = room_list_service.committed_all_rooms_response();

        assert_eq!(range_state.next().await, Some(RoomListRangeLoadingState::PartiallyLoaded));
        assert!(!committed.get().range_fully_loaded());

        let sync = room_list_service.sync();
        pin_mut!(sync);

        for pos in ["selective", "growing-partial"] {
            let _mock_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": pos,
                    "lists": { "all_rooms": { "count": 150, "ops": [] } },
                    "rooms": {}
                })))
                .mount_as_scoped()
                .await;

            sync.next().await.expect("room-list sync result")?;
            tokio::task::yield_now().await;

            while let Some(Some(state)) = range_state.next().now_or_never() {
                assert_eq!(state, RoomListRangeLoadingState::PartiallyLoaded);
            }
            assert!(!committed.get().range_fully_loaded());
        }

        let mut current_range_state = all_rooms.range_loading_state();
        assert_eq!(
            current_range_state.next().await,
            Some(RoomListRangeLoadingState::PartiallyLoaded)
        );

        let _mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "growing-full",
                "lists": { "all_rooms": { "count": 150, "ops": [] } },
                "rooms": {}
            })))
            .mount_as_scoped()
            .await;

        sync.next().await.expect("final room-list sync result")?;
        assert!(committed.get().range_fully_loaded());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), range_state.next()).await?,
            Some(RoomListRangeLoadingState::FullyLoaded)
        );

        let requests = server.received_requests().await.expect("captured requests");
        let ranges = requests
            .iter()
            .filter(|request| request.url.path().ends_with("/sync"))
            .map(|request| {
                let body: Value = serde_json::from_slice(&request.body).expect("sync request JSON");
                body["lists"]["all_rooms"]["ranges"].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ranges,
            [
                serde_json::json!([[0, 19]]),
                serde_json::json!([[0, 99]]),
                serde_json::json!([[0, 149]]),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn dynamic_entries_add_one_page_expands_two_four_five() -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(2);
        pin_mut!(entries);

        let _mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "five-rooms",
                "lists": { "all_rooms": { "count": 5, "ops": [] } },
                "rooms": {
                    "!room-0:example.org": { "initial": true, "bump_stamp": 1 },
                    "!room-1:example.org": { "initial": true, "bump_stamp": 2 },
                    "!room-2:example.org": { "initial": true, "bump_stamp": 3 },
                    "!room-3:example.org": { "initial": true, "bump_stamp": 4 },
                    "!room-4:example.org": { "initial": true, "bump_stamp": 5 }
                }
            })))
            .mount_as_scoped()
            .await;
        let sync = room_list_service.sync();
        pin_mut!(sync);
        sync.next().await.expect("room-list sync result")?;
        tokio::task::yield_now().await;

        assert!(controller.set_filter(Box::new(new_filter_non_left())));
        let mut visible = Vector::new();
        for expected_len in [2, 4, 5] {
            let diffs = tokio::time::timeout(Duration::from_secs(2), entries.next())
                .await?
                .expect("dynamic entries stream ended");
            for diff in diffs {
                diff.apply(&mut visible);
            }
            assert_eq!(visible.len(), expected_len);
            controller.add_one_page();
        }

        Ok(())
    }

    #[tokio::test]
    async fn fully_loaded_all_rooms_entries_exclude_cache_only_omitted_room()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let cache_only_room_id = room_id!("!cache-only:example.org");
        let live_room_id = room_id!("!live:example.org");
        server.sync_joined_room(&client, cache_only_room_id).await;

        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut committed = room_list_service.committed_all_rooms_response();
        let mut range_state = all_rooms.range_loading_state();
        assert_eq!(range_state.next().await, Some(RoomListRangeLoadingState::PartiallyLoaded));

        let sync = room_list_service.sync();
        pin_mut!(sync);
        for pos in ["selective", "growing-full"] {
            let _mock_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": pos,
                    "lists": {
                        "all_rooms": {
                            "count": 1
                        }
                    },
                    "rooms": {
                        "!live:example.org": { "initial": true, "bump_stamp": 1 }
                    }
                })))
                .mount_as_scoped()
                .await;

            sync.next().await.expect("room-list sync result")?;
            tokio::time::timeout(Duration::from_secs(2), committed.next())
                .await?
                .expect("committed all-rooms response stream ended");
        }

        let requests = server.received_requests().await.expect("captured requests");
        let final_request = requests
            .iter()
            .filter(|request| {
                request.url.path() == "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"
            })
            .last()
            .expect("final all-rooms request");
        let final_body: Value = serde_json::from_slice(&final_request.body)?;
        assert_eq!(final_body["lists"]["all_rooms"]["ranges"], serde_json::json!([[0, 0]]));

        assert!(committed.get().range_fully_loaded());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match range_state.next().await {
                    Some(RoomListRangeLoadingState::FullyLoaded) => break,
                    Some(RoomListRangeLoadingState::PartiallyLoaded) => continue,
                    None => panic!("room range loading-state stream ended"),
                }
            }
        })
        .await?;

        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(usize::MAX);
        pin_mut!(entries);
        assert!(controller.set_filter(Box::new(new_filter_non_left())));
        let diffs = tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended");
        let mut visible = Vector::new();
        for diff in diffs {
            diff.apply(&mut visible);
        }

        assert!(visible.iter().any(|room| room.room_id() == live_room_id));
        assert!(visible.iter().all(|room| room.room_id() != cache_only_room_id));

        Ok(())
    }

    #[tokio::test]
    async fn all_rooms_entries_reset_when_first_response_acquires_authority()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let cache_only_room_id = room_id!("!cache-only:example.org");
        let live_room_id = room_id!("!live:example.org");
        server.sync_joined_room(&client, cache_only_room_id).await;

        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(usize::MAX);
        pin_mut!(entries);
        assert!(controller.set_filter(Box::new(new_filter_non_left())));

        let mut visible = Vector::new();
        let initial = tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended before initial cache projection");
        for diff in initial {
            diff.apply(&mut visible);
        }
        assert!(visible.iter().any(|room| room.room_id() == cache_only_room_id));

        let _mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "first-authority",
                "lists": { "all_rooms": { "count": 1 } },
                "rooms": {
                    "!live:example.org": { "initial": true, "bump_stamp": 1 }
                }
            })))
            .mount_as_scoped()
            .await;
        let sync = room_list_service.sync();
        pin_mut!(sync);
        sync.next().await.expect("room-list sync result")?;

        let authority_update = tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended before authority reset");
        assert!(authority_update.iter().any(|diff| matches!(diff, VectorDiff::Reset { .. })));
        for diff in authority_update {
            diff.apply(&mut visible);
        }
        assert!(visible.iter().any(|room| room.room_id() == live_room_id));
        assert!(visible.iter().all(|room| room.room_id() != cache_only_room_id));

        Ok(())
    }

    #[tokio::test]
    async fn committed_response_correlates_fresh_snapshot_before_entries_reset_is_polled()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let cache_only_room_id = room_id!("!cache-only:example.org");
        let live_room_id = room_id!("!live:example.org");
        server.sync_joined_room(&client, cache_only_room_id).await;

        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut committed = room_list_service.committed_all_rooms_response();
        let provisional = all_rooms.current_entries_snapshot();
        assert!(!provisional.is_authoritative());
        assert_eq!(provisional.entries().len(), 1);
        assert_eq!(provisional.entries()[0].room_id(), cache_only_room_id);

        // Keep the dynamic stream alive with its cache-only Reset applied, but do not
        // poll it after the response. This reproduces a committed consumer winning
        // the scheduling race against authority Reset delivery.
        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(usize::MAX);
        pin_mut!(entries);
        assert!(controller.set_filter(Box::new(new_filter_non_left())));
        let mut stale_visible = Vector::new();
        for diff in tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended before provisional reset")
        {
            diff.apply(&mut stale_visible);
        }
        assert_eq!(stale_visible.len(), 1);
        assert_eq!(stale_visible[0].room_id(), cache_only_room_id);

        let _mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "same-count-replacement",
                "lists": { "all_rooms": { "count": 1 } },
                "rooms": {
                    "!live:example.org": { "initial": true, "bump_stamp": 1 }
                }
            })))
            .mount_as_scoped()
            .await;
        let sync = room_list_service.sync();
        pin_mut!(sync);
        sync.next().await.expect("room-list sync result")?;

        let committed = tokio::time::timeout(Duration::from_secs(2), committed.next())
            .await?
            .expect("committed all-rooms response stream ended");
        let authoritative = all_rooms.current_entries_snapshot();
        assert!(authoritative.is_authoritative());
        assert_eq!(authoritative.response_sequence(), Some(committed.sequence()));
        assert_eq!(authoritative.entries().len(), 1);
        assert_eq!(authoritative.entries()[0].room_id(), live_room_id);
        assert!(authoritative.entries().iter().all(|room| room.room_id() != cache_only_room_id));
        let debug = format!("{authoritative:?}");
        assert!(!debug.contains(cache_only_room_id.as_str()));
        assert!(!debug.contains(live_room_id.as_str()));

        Ok(())
    }

    #[tokio::test]
    async fn recovery_keeps_authority_until_next_response_replaces_observed_rooms()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let cache_only_room_id = room_id!("!cache-only:example.org");
        let previous_live_room_id = room_id!("!previous-live:example.org");
        let recovered_live_room_id = room_id!("!recovered-live:example.org");
        server.sync_joined_room(&client, cache_only_room_id).await;

        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut committed = room_list_service.committed_all_rooms_response();

        let _initial_mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "initial-authority",
                "lists": { "all_rooms": { "count": 1 } },
                "rooms": {
                    "!previous-live:example.org": { "initial": true, "bump_stamp": 1 }
                }
            })))
            .mount_as_scoped()
            .await;
        let initial_sync = room_list_service.sync();
        pin_mut!(initial_sync);
        initial_sync.next().await.expect("initial room-list sync result")?;
        let initial_committed = tokio::time::timeout(Duration::from_secs(2), committed.next())
            .await?
            .expect("initial committed response stream ended");

        let initial = all_rooms.current_entries_snapshot();
        assert_eq!(initial.response_sequence(), Some(initial_committed.sequence()));
        assert_eq!(initial.entries().len(), 1);
        assert_eq!(initial.entries()[0].room_id(), previous_live_room_id);

        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(usize::MAX);
        pin_mut!(entries);
        assert!(controller.set_filter(Box::new(new_filter_non_left())));
        let mut visible = Vector::new();
        for diff in tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended before authoritative reset")
        {
            diff.apply(&mut visible);
        }
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].room_id(), previous_live_room_id);

        room_list_service.state_machine.set(State::Error { from: Box::new(State::Running) });
        drop(_initial_mock_guard);

        let _recovery_mock_guard = server
            .mock_sliding_sync()
            .respond_with(
                ResponseTemplate::new(200).set_delay(Duration::from_millis(100)).set_body_json(
                    serde_json::json!({
                        "pos": "recovered-authority",
                        "lists": { "all_rooms": { "count": 1 } },
                        "rooms": {
                            "!recovered-live:example.org": {
                                "initial": true,
                                "bump_stamp": 2
                            }
                        }
                    }),
                ),
            )
            .mount_as_scoped()
            .await;
        let recovery_sync = room_list_service.sync();
        pin_mut!(recovery_sync);

        assert!(recovery_sync.next().now_or_never().is_none());
        let during_recovery = all_rooms.current_entries_snapshot();
        assert_eq!(during_recovery.response_sequence(), Some(initial_committed.sequence()));
        assert_eq!(during_recovery.entries().len(), 1);
        assert_eq!(during_recovery.entries()[0].room_id(), previous_live_room_id);
        assert!(during_recovery.entries().iter().all(|room| room.room_id() != cache_only_room_id));
        assert!(entries.next().now_or_never().is_none());

        tokio::time::timeout(Duration::from_secs(2), recovery_sync.next())
            .await?
            .expect("recovery room-list sync result")?;
        let recovered_committed = tokio::time::timeout(Duration::from_secs(2), committed.next())
            .await?
            .expect("recovery committed response stream ended");
        let recovered = all_rooms.current_entries_snapshot();
        assert_eq!(recovered.response_sequence(), Some(recovered_committed.sequence()));
        assert_eq!(recovered.entries().len(), 1);
        assert_eq!(recovered.entries()[0].room_id(), recovered_live_room_id);
        assert!(recovered.entries().iter().all(|room| room.room_id() != previous_live_room_id));
        assert!(recovered.entries().iter().all(|room| room.room_id() != cache_only_room_id));

        for diff in tokio::time::timeout(Duration::from_secs(2), entries.next())
            .await?
            .expect("dynamic entries stream ended before recovered reset")
        {
            diff.apply(&mut visible);
        }
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].room_id(), recovered_live_room_id);

        Ok(())
    }

    #[tokio::test]
    async fn entries_snapshot_correlates_newer_partial_range_and_room_count()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut committed = room_list_service.committed_all_rooms_response();
        let sync = room_list_service.sync();
        pin_mut!(sync);

        for pos in ["initial-selective", "initial-full"] {
            let _mock_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": pos,
                    "lists": { "all_rooms": { "count": 1 } },
                    "rooms": {
                        "!previous-live:example.org": { "initial": true, "bump_stamp": 1 }
                    }
                })))
                .mount_as_scoped()
                .await;
            sync.next().await.expect("initial room-list sync result")?;
            tokio::time::timeout(Duration::from_secs(2), committed.next())
                .await?
                .expect("initial committed response stream ended");
        }

        let full_committed = committed.get();
        assert!(full_committed.range_fully_loaded());

        // Delay the consumer's snapshot read until after a newer response has
        // replaced the full-range evidence.
        room_list_service.state_machine.set(State::Error { from: Box::new(State::Running) });
        let _partial_mock_guard = server
            .mock_sliding_sync()
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pos": "newer-partial",
                "lists": { "all_rooms": { "count": 2 } },
                "rooms": {
                    "!new-live:example.org": { "initial": true, "bump_stamp": 2 }
                }
            })))
            .mount_as_scoped()
            .await;
        sync.next().await.expect("partial recovery room-list sync result")?;
        let partial_committed = tokio::time::timeout(Duration::from_secs(2), committed.next())
            .await?
            .expect("partial committed response stream ended");
        assert!(!partial_committed.range_fully_loaded());

        let partial = all_rooms.current_entries_snapshot();
        assert!(partial_committed.sequence() > full_committed.sequence());
        assert_eq!(partial.response_sequence(), Some(partial_committed.sequence()));
        assert_eq!(partial.range_fully_loaded(), Some(false));
        assert_eq!(partial.maximum_number_of_rooms(), Some(2));

        Ok(())
    }

    #[tokio::test]
    async fn unchanged_room_ids_advance_sequence_without_resetting_dynamic_entries()
    -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list_service = RoomListService::new(client).await?;
        let all_rooms = room_list_service.all_rooms().await?;
        let mut committed = room_list_service.committed_all_rooms_response();
        let (entries, controller) = all_rooms.entries_with_dynamic_adapters(usize::MAX);
        pin_mut!(entries);
        assert!(controller.set_filter(Box::new(new_filter_non_left())));
        let sync = room_list_service.sync();
        pin_mut!(sync);

        let mut previous_sequence = 0;
        for pos in ["same-rooms-1", "same-rooms-2"] {
            let _mock_guard = server
                .mock_sliding_sync()
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pos": pos,
                    "lists": { "all_rooms": { "count": 1 } },
                    "rooms": {
                        "!stable:example.org": { "initial": true, "bump_stamp": 1 }
                    }
                })))
                .mount_as_scoped()
                .await;
            sync.next().await.expect("room-list sync result")?;
            let response = tokio::time::timeout(Duration::from_secs(2), committed.next())
                .await?
                .expect("committed response stream ended");
            assert!(response.sequence() > previous_sequence);
            previous_sequence = response.sequence();

            if pos == "same-rooms-1" {
                tokio::time::timeout(Duration::from_secs(2), entries.next())
                    .await?
                    .expect("initial dynamic entries reset");
            } else if let Ok(Some(diffs)) =
                tokio::time::timeout(Duration::from_millis(100), entries.next()).await
            {
                assert!(
                    diffs.iter().all(|diff| !matches!(diff, VectorDiff::Reset { .. })),
                    "an unchanged authority room-ID set must not reset the full dynamic list"
                );
            }
        }

        assert_eq!(
            all_rooms.current_entries_snapshot().response_sequence(),
            Some(previous_sequence)
        );
        Ok(())
    }

    #[test]
    fn required_state_expands_only_own_membership_placeholder() {
        let own_user_id = user_id!("@compat:example.org");
        let required_state = [
            (StateEventType::RoomMember, "$ME"),
            (StateEventType::RoomMember, "$LAZY"),
            (StateEventType::RoomMember, "*"),
            (StateEventType::RoomName, "$ME"),
            (StateEventType::SpaceChild, "*"),
        ];

        assert_eq!(
            required_state_for_user(&required_state, Some(own_user_id)),
            vec![
                (StateEventType::RoomMember, own_user_id.to_string()),
                (StateEventType::RoomMember, "$LAZY".to_owned()),
                (StateEventType::RoomMember, "*".to_owned()),
                (StateEventType::RoomName, "$ME".to_owned()),
                (StateEventType::SpaceChild, "*".to_owned()),
            ]
        );
    }

    #[test]
    fn required_state_preserves_own_membership_placeholder_without_user() {
        let required_state =
            [(StateEventType::RoomMember, "$ME"), (StateEventType::RoomMember, "$LAZY")];

        assert_eq!(
            required_state_for_user(&required_state, None),
            vec![
                (StateEventType::RoomMember, "$ME".to_owned()),
                (StateEventType::RoomMember, "$LAZY".to_owned()),
            ]
        );
    }

    #[test]
    fn room_subscription_state_debug_redacts_active_room_ids() {
        let room_id = room_id!("!private-subscription:example.org");
        let state = RoomSubscriptionState {
            generation: 7,
            active_rooms: [room_id.to_owned()].into_iter().collect(),
        };

        let debug = format!("{state:?}");
        assert!(!debug.contains(room_id.as_str()));
        assert!(debug.contains("active_room_count: 1"));
    }

    #[async_test]
    async fn test_all_rooms_are_declared() -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_list = RoomListService::new(client).await?;

        let sliding_sync = room_list.sliding_sync();

        // List is present, in Selective mode.
        assert_eq!(
            sliding_sync
                .on_list(ALL_ROOMS_LIST_NAME, |list| ready(matches!(
                    list.sync_mode(),
                    SlidingSyncMode::Selective { ranges } if ranges == vec![0..=19]
                )))
                .await,
            Some(true)
        );

        Ok(())
    }

    #[tokio::test]
    async fn all_rooms_request_matches_element_x_26_07_28() -> Result<(), TestError> {
        let server = MatrixMockServer::new().await;
        server.mock_versions().with_thread_subscriptions().ok().up_to_n_times(3).mount().await;
        let client = server
            .client_builder()
            .no_server_versions()
            .on_builder(|builder| {
                builder
                    .with_threading_support(ThreadingSupport::Enabled { with_subscriptions: true })
            })
            .build()
            .await;
        let room_list = RoomListService::new(client).await?;

        let _mock_guard = server
            .mock_sliding_sync()
            .ok({
                let mut response = v5::Response::new("0".to_owned());
                response.lists.insert(
                    ALL_ROOMS_LIST_NAME.to_owned(),
                    assign!(v5::response::List::default(), { count: uint!(0) }),
                );
                response
            })
            .mount_as_scoped()
            .await;
        let sync = room_list.sync();
        pin_mut!(sync);
        sync.next().await.expect("first room-list sync result")?;

        let requests = server.received_requests().await.expect("captured requests");
        let request = requests
            .iter()
            .find(|request| {
                request.url.path().ends_with("/sync") && request.method.as_str() == "POST"
            })
            .expect("first room-list sliding-sync request");
        let body: Value = serde_json::from_slice(&request.body)?;

        assert_eq!(
            request.url.path(),
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"
        );
        assert_eq!(request.url.query(), Some("timeout=0"));
        assert_eq!(body["conn_id"], "room-list");

        let lists = body["lists"].as_object().expect("request lists object");
        assert_eq!(lists.keys().map(String::as_str).collect::<Vec<_>>(), ["all_rooms"]);
        let all_rooms = &body["lists"]["all_rooms"];
        let invite_filter = all_rooms["filters"].get("is_invite");
        assert!(invite_filter.is_none() || invite_filter.is_some_and(Value::is_null));
        assert_eq!(all_rooms["timeline_limit"], 1);
        assert_eq!(
            all_rooms["required_state"],
            serde_json::json!([
                ["m.room.name", ""],
                ["m.room.encryption", ""],
                ["m.room.member", "$LAZY"],
                ["m.room.member", "@example:localhost"],
                ["m.room.topic", ""],
                ["m.room.avatar", ""],
                ["m.room.canonical_alias", ""],
                ["m.room.power_levels", ""],
                ["org.matrix.msc3401.call.member", "*"],
                ["m.room.join_rules", ""],
                ["m.room.tombstone", ""],
                ["m.room.create", ""],
                ["m.room.history_visibility", ""],
                ["io.element.functional_members", ""],
                ["m.space.parent", "*"],
                ["m.space.child", "*"],
                ["org.matrix.msc3672.beacon_info", "*"],
            ])
        );

        let extensions = &body["extensions"];
        assert_eq!(extensions["account_data"]["enabled"], true);
        assert_eq!(extensions["receipts"]["enabled"], true);
        assert_eq!(extensions["receipts"]["rooms"], serde_json::json!(["*"]));
        assert_eq!(extensions["typing"]["enabled"], true);
        assert_eq!(extensions["io.element.msc4308.thread_subscriptions"]["enabled"], true);
        assert_eq!(extensions["io.element.msc4308.thread_subscriptions"]["limit"], 10);

        Ok(())
    }

    #[async_test]
    async fn test_expire_sliding_sync_session_manually() -> Result<(), Error> {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let room_list = RoomListService::new(client).await?;

        let sync = room_list.sync();
        pin_mut!(sync);

        // Run a first sync.
        {
            let _mock_guard = server
                .mock_sliding_sync()
                .ok({
                    let mut response = v5::Response::new("0".to_owned());
                    response.lists.insert(
                        ALL_ROOMS_LIST_NAME.to_owned(),
                        assign!(v5::response::List::default(), { count: uint!(0) }),
                    );
                    response
                })
                .mount_as_scoped()
                .await;

            let _ = sync.next().await;
        }

        assert_eq!(room_list.state().get(), State::SettingUp);

        // Stop the sync.
        room_list.stop_sync()?;

        // Do another sync.
        let _ = sync.next().await;

        // State is `Terminated`, as expected!
        assert_eq!(
            room_list.state_machine.get(),
            State::Terminated { from: Box::new(State::Running) }
        );

        // Now, let's make the sliding sync session to expire.
        room_list.expire_sync_session().await;

        // State is `Error`, as a regular session expiration would generate!
        assert_eq!(room_list.state_machine.get(), State::Error { from: Box::new(State::Running) });

        Ok(())
    }
}
