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

use std::{fmt, sync::Mutex};

use eyeball::{SharedObservable, Subscriber};

/// Process-local evidence that an `all_rooms` response was committed.
///
/// This deliberately omits the Sliding Sync position and all room identifiers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommittedAllRoomsResponse {
    sequence: u64,
    pos_present: bool,
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

    pub(super) fn advance(&self) {
        let mut sequence = self.sequence.lock().unwrap();
        *sequence = sequence.checked_add(1).expect("all-rooms response sequence exhausted");
        self.latest.set(CommittedAllRoomsResponse { sequence: *sequence, pos_present: true });
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
