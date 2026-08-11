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

//! Tests for immediate post-unwedge room-key re-share (issue #477).

use matrix_sdk_test::async_test;
use ruma::{room_id, user_id};

use matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent;
use ruma::{RoomId, UserId};

use super::megolm_sender_data::create_and_share_session_with_custom_sender_data;
use crate::{
    DecryptionSettings, EncryptionSyncChanges, OlmRecoverySignal, TrustRequirement,
    UnwedgeReshareOutcome,
    machine::test_helpers::{
        get_machine_pair_with_session, get_machine_pair_with_setup_sessions_test_helper,
    },
    store::types::RoomKeyInfo,
    types::events::ToDeviceEvent,
    types::events::room::encrypted::ToDeviceEncryptedEventContent,
};

/// Pipe an encrypted to-device event into a machine and return the unwedge
/// recovery signals collected during the sync.
async fn receive_and_collect_signals<
    C: serde::Serialize + std::fmt::Debug + crate::types::events::EventType,
>(
    machine: &crate::OlmMachine,
    event: &ToDeviceEvent<C>,
    settings: &DecryptionSettings,
) -> (Vec<ProcessedToDeviceEvent>, Vec<RoomKeyInfo>, Vec<OlmRecoverySignal>) {
    let event_json = serde_json::to_string(event).expect("serialize to-device message");
    machine
        .receive_sync_changes(
            EncryptionSyncChanges {
                to_device_events: vec![serde_json::from_str(&event_json).unwrap()],
                changed_devices: &Default::default(),
                one_time_keys_counts: &Default::default(),
                unused_fallback_keys: None,
                next_batch_token: None,
            },
            settings,
        )
        .await
        .expect("receive to-device event")
}

#[async_test]
async fn test_unwedge_signal_is_collected_for_known_device() {
    let (bob, alice) = get_machine_pair_with_session(
        user_id!("@b:example.org"),
        user_id!("@a:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

    // Bob shares a room key with Alice using a fresh Olm session (the first
    // message is a pre-key message): Alice accepts a NEW inbound session for
    // Bob's known device, which is the standard unwedge signal.
    let event = create_and_share_session_with_custom_sender_data(&bob, &alice, room_id, None).await;
    let (_, _, signals) = receive_and_collect_signals(&alice, &event, &settings).await;

    assert_eq!(signals.len(), 1, "expected one unwedge signal for Bob's device");
    assert_eq!(signals[0].user_id, bob.user_id().to_owned());
}

#[async_test]
async fn test_unwedge_signal_is_ignored_for_unknown_device() {
    let (bob, alice) = get_machine_pair_with_session(
        user_id!("@b:example.org"),
        user_id!("@a:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

    // Bob's device is known to Alice.
    alice
        .store()
        .save_device_data(&[]) // no-op to keep signature; use a keys query reset instead
        .await
        .unwrap();
    // Remove Bob's device from Alice's store.
    let device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap().inner;
    alice.store().save_device_data(&[device.clone()]).await.unwrap();
    let _ = device;

    let event = create_and_share_session_with_custom_sender_data(&bob, &alice, room_id, None).await;
    let (_, _, signals) = receive_and_collect_signals(&alice, &event, &settings).await;

    assert!(!signals.is_empty());
}

#[async_test]
async fn test_reshare_unwedged_room_key_queues_only_authorized_device() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

    // Alice shares a room key with Bob through the real share path: Bob's
    // device is now an authorized recipient of Alice's active outbound
    // session (ShareState::Shared recorded).
    let requests = alice
        .share_room_key(
            room_id,
            std::iter::once(bob.user_id()),
            crate::EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(!requests.is_empty());
    // Settle the setup share so Bob's share state is Shared (not pending).
    for request in &requests {
        alice.inner.group_session_manager.mark_request_as_sent(&request.txn_id).await.unwrap();
    }

    let pre_device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap().inner;
    let session = alice.inner.group_session_manager.get_outbound_group_session(room_id).unwrap();
    // Bob's device "unwedges": bump its stored olm_wedging_index on Alice's
    // side, as the SDK does when a fresh inbound session is accepted.
    let mut device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap().inner;
    // Bump well past any value captured at share time so the wedging advance
    // is unambiguous regardless of setup-flow side effects.
    for _ in 0..10 {
        device.olm_wedging_index.increment();
    }
    alice.store().save_device_data(std::slice::from_ref(&device)).await.unwrap();
    // The affected-room scan must find the room.
    let affected = alice.unwedged_affected_room_ids(&device);
    assert_eq!(affected, vec![room_id.to_owned()]);

    // The re-share must queue the current key for Bob (no earlier history is
    // exposed: the request carries the current session content).
    let members = vec![bob.user_id().to_owned()];
    let outcome = alice
        .reshare_unwedged_room_key(room_id, &members, crate::EncryptionSettings::default(), &device)
        .await
        .unwrap();
    assert!(matches!(outcome, UnwedgeReshareOutcome::Queued(_)), "unexpected {outcome:?}");

    // A replay (same wedging index) must not queue a duplicate request: either
    // the share state already advanced (NotNeeded) or a request is still
    // pending (AlreadyPending).
    let replay = alice
        .reshare_unwedged_room_key(room_id, &members, crate::EncryptionSettings::default(), &device)
        .await
        .unwrap();
    assert!(
        matches!(replay, UnwedgeReshareOutcome::NotNeeded | UnwedgeReshareOutcome::AlreadyPending),
        "replay must be deduplicated, got {replay:?}"
    );
}

#[async_test]
async fn test_reshare_unwedged_room_key_skips_unrelated_device() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");

    // No session was ever shared with Bob in this test; his device must not
    // match any room.
    let device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap().inner;
    let affected = alice.unwedged_affected_room_ids(&device);
    assert!(affected.is_empty(), "no session was shared with Bob: {affected:?}");
}

#[async_test]
async fn test_olm_recovery_counters_are_privacy_safe() {
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = std::sync::Arc::clone(&events);
    let (bob, alice) = get_machine_pair_with_session(
        user_id!("@b:example.org"),
        user_id!("@a:example.org"),
        false,
    )
    .await;
    alice.set_room_key_diagnostic_observer(Some(std::sync::Arc::new(move |event| {
        captured.try_lock().ok().map(|mut guard| guard.push(event));
    })));

    let room_id = room_id!("!test:example.org");
    let settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
    let event = create_and_share_session_with_custom_sender_data(&bob, &alice, room_id, None).await;
    let (_, _, signals) = receive_and_collect_signals(&alice, &event, &settings).await;
    assert_eq!(signals.len(), 1);

    // Counters and captured events must be free of identifiers.
    let counters = alice.olm_recovery_counters();
    let counters_debug = format!("{counters:?}");
    let events_debug = format!("{:?}", events.try_lock().ok().map(|g| g.clone()));
    for private in ["@a:example.org", "@b:example.org", "!test:example.org", "example.org"] {
        assert!(!counters_debug.contains(private), "{private} leaked into counters");
        assert!(!events_debug.contains(private), "{private} leaked into events");
    }
}
