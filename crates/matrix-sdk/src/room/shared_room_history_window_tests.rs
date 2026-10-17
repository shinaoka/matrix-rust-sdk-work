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

use std::time::{Duration, SystemTime};

use matrix_sdk_base::crypto::store::types::RoomPendingKeyBundleDetails;
use ruma::{MilliSecondsSinceUnixEpoch, room_id, user_id};

use super::should_process_room_pending_key_bundle_details_at;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}

fn should_process(accepted_at: SystemTime) -> bool {
    should_process_room_pending_key_bundle_details_at(&details(accepted_at), now())
}

fn details(accepted_at: SystemTime) -> RoomPendingKeyBundleDetails {
    RoomPendingKeyBundleDetails {
        room_id: room_id!("!history:example.invalid").to_owned(),
        invite_accepted_at: MilliSecondsSinceUnixEpoch::from_system_time(accepted_at).unwrap(),
        inviter: user_id!("@inviter:example.invalid").to_owned(),
    }
}

#[test]
fn accepts_a_just_accepted_invite() {
    assert!(should_process(now()));
}

#[test]
fn accepts_after_the_former_one_day_limit() {
    assert!(should_process(now() - DAY));
}

#[test]
fn accepts_twenty_nine_days_after_acceptance() {
    assert!(should_process(now() - 29 * DAY));
}

#[test]
fn accepts_just_before_the_thirty_day_limit() {
    assert!(should_process(now() - 30 * DAY + Duration::from_millis(1)));
}

#[test]
fn rejects_at_the_thirty_day_limit() {
    assert!(!should_process(now() - 30 * DAY));
}

#[test]
fn rejects_after_the_thirty_day_limit() {
    assert!(!should_process(now() - 30 * DAY - Duration::from_millis(1)));
}

#[test]
fn rejects_future_acceptance_timestamps() {
    assert!(!should_process(now() + Duration::from_millis(1)));
}
