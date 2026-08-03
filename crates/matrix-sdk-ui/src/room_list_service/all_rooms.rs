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
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex},
};

use eyeball::{SharedObservable, Subscriber};
use ruma::{OwnedRoomId, RoomId};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct AllRoomsObservedIds {
    response_sequence: u64,
    range_fully_loaded: bool,
    maximum_number_of_rooms: Option<u32>,
    room_ids: Arc<BTreeSet<OwnedRoomId>>,
}

impl AllRoomsObservedIds {
    pub(super) fn response_sequence(&self) -> u64 {
        self.response_sequence
    }

    pub(super) fn contains(&self, room_id: &RoomId) -> bool {
        self.room_ids.contains(room_id)
    }

    pub(super) fn range_fully_loaded(&self) -> bool {
        self.range_fully_loaded
    }

    pub(super) fn maximum_number_of_rooms(&self) -> Option<u32> {
        self.maximum_number_of_rooms
    }
}

impl fmt::Debug for AllRoomsObservedIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllRoomsObservedIds")
            .field("response_sequence", &self.response_sequence)
            .field("range_fully_loaded", &self.range_fully_loaded)
            .field("maximum_number_of_rooms", &self.maximum_number_of_rooms)
            .field("room_count", &self.room_ids.len())
            .finish()
    }
}

#[derive(Clone)]
pub(super) struct AllRoomsObservedIdsObservable {
    latest: SharedObservable<Option<AllRoomsObservedIds>>,
    visible_room_ids: SharedObservable<Option<Arc<BTreeSet<OwnedRoomId>>>>,
    replace_on_next_response: Arc<Mutex<bool>>,
}

impl AllRoomsObservedIdsObservable {
    pub(super) fn new() -> Self {
        Self {
            latest: SharedObservable::new(None),
            visible_room_ids: SharedObservable::new(None),
            replace_on_next_response: Arc::new(Mutex::new(false)),
        }
    }

    pub(super) fn current(&self) -> Option<AllRoomsObservedIds> {
        self.latest.get()
    }

    pub(super) fn subscribe_visible_room_ids(
        &self,
    ) -> Subscriber<Option<Arc<BTreeSet<OwnedRoomId>>>> {
        self.visible_room_ids.subscribe_reset()
    }

    pub(super) fn begin_cycle(&self) {
        *self.replace_on_next_response.lock().unwrap() = true;
    }

    pub(super) fn accumulate(
        &self,
        response_sequence: u64,
        range_fully_loaded: bool,
        maximum_number_of_rooms: Option<u32>,
        room_ids: &[OwnedRoomId],
    ) {
        let replace = std::mem::take(&mut *self.replace_on_next_response.lock().unwrap());
        let mut observed = if replace {
            BTreeSet::new()
        } else {
            self.latest.get().map(|observed| observed.room_ids.as_ref().clone()).unwrap_or_default()
        };
        observed.extend(room_ids.iter().cloned());
        let room_ids = Arc::new(observed);
        self.latest.set_if_not_eq(Some(AllRoomsObservedIds {
            response_sequence,
            range_fully_loaded,
            maximum_number_of_rooms,
            room_ids: room_ids.clone(),
        }));
        self.visible_room_ids.set_if_not_eq(Some(room_ids));
    }
}

impl fmt::Debug for AllRoomsObservedIdsObservable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let latest = self.latest.get();
        formatter
            .debug_struct("AllRoomsObservedIdsObservable")
            .field("authority_acquired", &latest.is_some())
            .field(
                "response_sequence",
                &latest.as_ref().map(AllRoomsObservedIds::response_sequence),
            )
            .field(
                "range_fully_loaded",
                &latest.as_ref().map(AllRoomsObservedIds::range_fully_loaded),
            )
            .field(
                "maximum_number_of_rooms",
                &latest.as_ref().and_then(AllRoomsObservedIds::maximum_number_of_rooms),
            )
            .field("room_count", &latest.as_ref().map_or(0, |observed| observed.room_ids.len()))
            .finish()
    }
}

/// Process-local evidence that an `all_rooms` response was committed.
///
/// This deliberately omits the Sliding Sync position and all room identifiers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommittedAllRoomsResponse {
    sequence: u64,
    pos_present: bool,
    range_fully_loaded: bool,
}

impl CommittedAllRoomsResponse {
    /// Return the process-local monotonic response sequence.
    pub fn sequence(self) -> u64 {
        self.sequence
    }

    /// Whether the committed response carried the required Sliding Sync position.
    pub fn pos_present(self) -> bool {
        self.pos_present
    }

    /// Whether the complete growing room range was loaded by this committed response.
    pub fn range_fully_loaded(self) -> bool {
        self.range_fully_loaded
    }
}

pub(super) struct CommittedAllRoomsResponseObservable {
    sequence: Mutex<u64>,
    latest: SharedObservable<CommittedAllRoomsResponse>,
}

impl CommittedAllRoomsResponseObservable {
    pub(super) fn new() -> Self {
        Self {
            sequence: Mutex::new(0),
            latest: SharedObservable::new(CommittedAllRoomsResponse::default()),
        }
    }

    pub(super) fn subscribe(&self) -> Subscriber<CommittedAllRoomsResponse> {
        self.latest.subscribe()
    }

    pub(super) fn advance_after<F>(&self, range_fully_loaded: bool, before_publish: F)
    where
        F: FnOnce(u64),
    {
        let mut sequence = self.sequence.lock().unwrap();
        *sequence = sequence.checked_add(1).expect("all-rooms response sequence exhausted");
        before_publish(*sequence);
        self.latest.set(CommittedAllRoomsResponse {
            sequence: *sequence,
            pos_present: true,
            range_fully_loaded,
        });
    }
}

impl fmt::Debug for CommittedAllRoomsResponseObservable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAllRoomsResponseObservable")
            .field("latest", &self.latest.get())
            .finish()
    }
}
