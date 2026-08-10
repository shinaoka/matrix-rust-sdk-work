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

//! Integration tests for receive-side room-key diagnostics (issue #476).

use std::sync::Arc;

use matrix_sdk_test::async_test;
use ruma::{room_id, user_id};
use serde_json::json;

use super::megolm_sender_data::{
    create_and_share_session_with_custom_sender_data, receive_to_device_event,
};
use crate::{
    DecryptionSettings, EncryptionSettings, TrustRequirement,
    machine::test_helpers::get_machine_pair_with_setup_sessions_test_helper,
    room_key_diagnostics::{
        RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver, RoomKeyIngressKind,
        RoomKeyMergeDecision, RoomKeyReceiveDiagnosticKind,
    },
    olm::SenderData,
};

fn capture_observer(events: &Arc<std::sync::Mutex<Vec<RoomKeyDiagnosticEvent>>>) -> RoomKeyDiagnosticObserver {
    let captured = Arc::clone(events);
    Arc::new(move |event| captured.lock().unwrap().push(event))
}

#[async_test]
async fn test_receive_direct_room_key_ingress_and_accepted_new_are_counted() {
    let (alice, bob) =
        get_machine_pair_with_setup_sessions_test_helper(user_id!("@a:example.org"), user_id!("@b:example.org"), false).await;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    bob.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let room_id = room_id!("!test:example.org");
    let event =
        create_and_share_session_with_custom_sender_data(&alice, &bob, room_id, None).await;
    let decryption_settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
    receive_to_device_event(&bob, &event, &decryption_settings).await;

    let counters = bob.room_key_receive_counters();
    assert_eq!(counters.ingress_direct, 1);
    assert_eq!(counters.ingress_forwarded, 0);
    assert_eq!(counters.merge_accepted_new, 1);
    assert_eq!(counters.merge_accepted_improved, 0);
    assert_eq!(counters.to_device_olm_failed, 0);

    let events = events.lock().unwrap();
    match &events[0] {
        RoomKeyDiagnosticEvent::Receive(receive) => assert_eq!(
            receive.kind,
            RoomKeyReceiveDiagnosticKind::RoomKeyIngress { kind: RoomKeyIngressKind::Direct }
        ),
        other => panic!("unexpected first event: {other:?}"),
    }
    match &events[1] {
        RoomKeyDiagnosticEvent::Receive(receive) => assert_eq!(
            receive.kind,
            RoomKeyReceiveDiagnosticKind::Merge { decision: RoomKeyMergeDecision::AcceptedNew }
        ),
        other => panic!("unexpected second event: {other:?}"),
    }
}

#[async_test]
async fn test_receive_duplicate_room_key_is_benignly_ignored() {
    let (alice, bob) =
        get_machine_pair_with_setup_sessions_test_helper(user_id!("@a:example.org"), user_id!("@b:example.org"), false).await;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    bob.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let room_id = room_id!("!test:example.org");
    let decryption_settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
    let event =
        create_and_share_session_with_custom_sender_data(&alice, &bob, room_id, None).await;
    receive_to_device_event(&bob, &event, &decryption_settings).await;
    let event =
        create_and_share_session_with_custom_sender_data(&alice, &bob, room_id, None).await;
    receive_to_device_event(&bob, &event, &decryption_settings).await;

    let counters = bob.room_key_receive_counters();
    assert_eq!(counters.ingress_direct, 2);
    assert_eq!(counters.merge_accepted_new, 1);
    assert_eq!(counters.merge_duplicate_ignored, 1);
    assert_eq!(counters.merge_store_failed, 0);

    let events = events.lock().unwrap();
    match events.last() {
        Some(RoomKeyDiagnosticEvent::Receive(receive)) => assert_eq!(
            receive.kind,
            RoomKeyReceiveDiagnosticKind::Merge { decision: RoomKeyMergeDecision::DuplicateIgnored }
        ),
        other => panic!("unexpected last event: {other:?}"),
    }
}

#[async_test]
async fn test_receive_wedged_olm_counts_wedged_and_never_merges() {
    // Establish the session with one delivered message, then drop so many
    // messages that Bob's Olm ratchet falls beyond the out-of-order skip
    // window; the next delivered message cannot be decrypted and the SDK
    // classifies the session as wedged.
    let (alice, bob) = crate::machine::test_helpers::get_machine_pair_with_session(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    bob.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let room_id = room_id!("!test:example.org");
    let decryption_settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

    let bob_device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outbound, _) = alice
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            room_id,
            EncryptionSettings::default(),
            SenderData::unknown(),
        )
        .await
        .unwrap();
    let room_key_content = serde_json::to_value(outbound.as_content().await).unwrap();
    // First share is delivered: Bob establishes his Olm session copy.
    let first = bob_device
        .encrypt_event_raw("m.room_key", &room_key_content, crate::session_manager::CollectStrategy::AllDevices)
        .await
        .unwrap();
    let event = crate::types::events::ToDeviceEvent::new(alice.user_id().to_owned(), first);
    receive_to_device_event(&bob, &event, &decryption_settings).await;

    // Drop messages beyond the Olm out-of-order skip window (2000), advancing
    // Alice's stored session far ahead of Bob's copy.
    for _ in 0..2001 {
        let _ = bob_device
            .encrypt_event_raw("m.room_key", &room_key_content, crate::session_manager::CollectStrategy::AllDevices)
            .await
            .unwrap();
    }

    // The next delivered message is beyond the skip window: wedged.
    let late = bob_device
        .encrypt_event_raw("m.room_key", &room_key_content, crate::session_manager::CollectStrategy::AllDevices)
        .await
        .unwrap();
    let event = crate::types::events::ToDeviceEvent::new(alice.user_id().to_owned(), late);
    let (decrypted, _) = receive_to_device_event(&bob, &event, &decryption_settings).await;

    match &decrypted[0] {
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::UnableToDecrypt { .. } => {}
        other => panic!("expected unable-to-decrypt, got {other:?}"),
    }

    let counters = bob.room_key_receive_counters();
    assert_eq!(counters.to_device_olm_failed, 1);
    assert_eq!(counters.to_device_olm_wedged, 1);
    assert_eq!(counters.ingress_direct, 1);
    assert_eq!(counters.merge_accepted_new, 1);
    assert_eq!(counters.merge_accepted_improved, 0);

    let events = events.lock().unwrap();
    match events.last() {
        Some(RoomKeyDiagnosticEvent::Receive(receive)) => assert!(matches!(
            receive.kind,
            RoomKeyReceiveDiagnosticKind::ToDeviceOlmFailed
                | RoomKeyReceiveDiagnosticKind::ToDeviceOlmWedged
        )),
        other => panic!("unexpected last event: {other:?}"),
    }
}

#[async_test]
async fn test_receive_invalid_session_key_is_counted_and_never_merged() {
    let (alice, bob) =
        get_machine_pair_with_setup_sessions_test_helper(user_id!("@a:example.org"), user_id!("@b:example.org"), false).await;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    bob.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let room_id = room_id!("!test:example.org");
    let decryption_settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

    // An `m.room_key` whose megolm session key is not valid base64. The Olm
    // layer validates the decrypted payload, so this surfaces as a to-device
    // decrypt failure and never reaches the merge stage.
    let content = json!({
        "algorithm": "m.megolm.v1.aes-sha2",
        "room_id": room_id.to_string(),
        "session_id": "INVALID-SESSION-ID",
        "session_key": "INVALID-SESSION-KEY",
    });
    let plaintext = serde_json::to_string(&json!({
        "sender": alice.user_id(),
        "sender_device": alice.device_id(),
        "keys": { "ed25519": alice.identity_keys().ed25519.to_base64() },
        "recipient": bob.user_id(),
        "recipient_keys": { "ed25519": bob.identity_keys().ed25519.to_base64() },
        "type": "m.room_key",
        "content": content,
    }))
    .unwrap();
    let olm_sessions = alice
        .store()
        .get_sessions(&bob.identity_keys().curve25519.to_base64())
        .await
        .unwrap()
        .unwrap();
    let mut olm_session = olm_sessions.lock().await[0].clone();
    let ciphertext = olm_session.encrypt_helper(&plaintext).await.unwrap();
    let event = crate::types::events::ToDeviceEvent::new(
        alice.user_id().to_owned(),
        olm_session.build_encrypted_event(ciphertext, None).await.unwrap(),
    );
    let (decrypted, _) = receive_to_device_event(&bob, &event, &decryption_settings).await;

    match &decrypted[0] {
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::UnableToDecrypt { .. } => {}
        other => panic!("expected unable-to-decrypt, got {other:?}"),
    }

    let counters = bob.room_key_receive_counters();
    assert_eq!(counters.to_device_olm_failed, 1);
    assert_eq!(counters.ingress_direct, 0);
    assert_eq!(counters.merge_accepted_new, 0);
    assert_eq!(counters.merge_invalid_session_key, 0);

    let events = events.lock().unwrap();
    match events.last() {
        Some(RoomKeyDiagnosticEvent::Receive(receive)) => assert_eq!(
            receive.kind,
            RoomKeyReceiveDiagnosticKind::ToDeviceOlmFailed
        ),
        other => panic!("unexpected last event: {other:?}"),
    }
}

#[async_test]
async fn test_receive_diagnostics_never_expose_identifiers_or_material() {
    let (alice, bob) =
        get_machine_pair_with_setup_sessions_test_helper(user_id!("@a:example.org"), user_id!("@b:example.org"), false).await;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    bob.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let room_id = room_id!("!test:example.org");
    let decryption_settings =
        DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
    let event =
        create_and_share_session_with_custom_sender_data(&alice, &bob, room_id, None).await;
    receive_to_device_event(&bob, &event, &decryption_settings).await;

    let counters = bob.room_key_receive_counters();
    let session_id = alice
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            room_id,
            EncryptionSettings::default(),
            SenderData::unknown(),
        )
        .await
        .unwrap()
        .0
        .session_id()
        .to_owned();
    let counters_debug = format!("{counters:?}");
    let events_debug = format!("{:?}", events.lock().unwrap());
    for private in [
        "@a:example.org",
        "@b:example.org",
        "!test:example.org",
        &session_id,
        "INVALID",
        "curve25519:",
        "ed25519:",
    ] {
        assert!(!counters_debug.contains(private), "{private} leaked into counters");
        assert!(!events_debug.contains(private), "{private} leaked into events");
    }
}

