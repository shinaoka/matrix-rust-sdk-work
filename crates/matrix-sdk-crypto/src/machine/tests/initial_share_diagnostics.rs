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

//! Integration tests for initial index-0 key-share diagnostics (issue #509).

use std::{iter, sync::Arc};

use assert_matches2::assert_let;
use matrix_sdk_test::async_test;
use ruma::{
    api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse,
    room_id, user_id,
};

use crate::{
    EncryptionSettings,
    machine::test_helpers::get_machine_pair_with_setup_sessions_test_helper,
    room_key_diagnostics::{
        InitialShareDeviceClass, InitialShareStage, RoomKeyDiagnosticEvent,
        RoomKeyDiagnosticObserver,
    },
};
fn capture_observer(
    events: &Arc<std::sync::Mutex<Vec<RoomKeyDiagnosticEvent>>>,
) -> RoomKeyDiagnosticObserver {
    let captured = Arc::clone(events);
    Arc::new(move |event| captured.lock().unwrap().push(event))
}

fn initial_share_device_events(
    events: &[RoomKeyDiagnosticEvent],
) -> Vec<&crate::room_key_diagnostics::InitialShareDeviceDiagnostic> {
    events
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShare(device) => Some(device),
            _ => None,
        })
        .collect()
}

fn initial_share_session_events(
    events: &[RoomKeyDiagnosticEvent],
) -> Vec<&crate::room_key_diagnostics::InitialShareSessionDiagnostic> {
    events
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareSession(session) => Some(session),
            _ => None,
        })
        .collect()
}

/// Share a fresh session for `room_id` from `sender` to every device of
/// `recipient`, mark the requests as homeserver-accepted, and return the
/// observed events.
async fn share_and_ack(
    sender: &crate::OlmMachine,
    recipient: &crate::OlmMachine,
    room_id: &ruma::RoomId,
) -> Vec<RoomKeyDiagnosticEvent> {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    sender.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let requests = sender
        .share_room_key(room_id, iter::once(recipient.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let before_ack = events.lock().unwrap().clone();
    let response = ToDeviceResponse::new();
    for request in requests {
        sender.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let mut all = before_ack;
    let after = events.lock().unwrap();
    all.extend(after.iter().skip(all.len()).cloned());
    all
}

#[async_test]
async fn test_initial_share_records_index0_outcome_for_every_eligible_device() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");

    let events = share_and_ack(&alice, &bob, &room_id).await;
    let devices = initial_share_device_events(&events);

    // Every stage is observed for exactly the eligible receiver device, in
    // order, keyed by one stable anonymous device alias.
    assert!(!devices.is_empty(), "no initial-share device diagnostics recorded");
    let first_device = devices[0].device;
    let stages: Vec<_> = devices
        .iter()
        .filter(|event| event.device == first_device)
        .map(|event| event.stage)
        .collect();
    let mut iter = stages.iter();
    assert_let!(Some(InitialShareStage::Eligible) = iter.next());
    assert_let!(Some(InitialShareStage::OlmEncrypted) = iter.next());
    assert_let!(Some(InitialShareStage::RequestQueued) = iter.next());
    assert_let!(Some(InitialShareStage::HomeserverAccepted) = iter.next());
    assert_let!(
        Some(InitialShareStage::ShareStateCommitted { message_index: 0 }) = iter.next()
    );
    assert_eq!(iter.next(), None, "unexpected extra stages for the receiver device");

    // The peer device was classified as a peer, never as own.
    for event in devices.iter().filter(|event| event.device == first_device) {
        assert!(
            matches!(
                event.device_class,
                InitialShareDeviceClass::VerifiedPeer | InitialShareDeviceClass::UnverifiedPeer
            ),
            "receiver classified as {:?}",
            event.device_class
        );
    }
}

#[async_test]
async fn test_share_state_is_not_committed_before_the_request_is_acknowledged() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();

    let before_ack = events.lock().unwrap().clone();
    for event in initial_share_device_events(&before_ack) {
        assert!(
            !matches!(event.stage, InitialShareStage::ShareStateCommitted { .. }),
            "share state committed before the request was acknowledged"
        );
        assert!(
            !matches!(event.stage, InitialShareStage::HomeserverAccepted),
            "homeserver acceptance recorded before the request was acknowledged"
        );
    }

    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let after_ack = events.lock().unwrap().clone();
    let committed: Vec<_> = initial_share_device_events(&after_ack)
        .into_iter()
        .filter(|event| matches!(event.stage, InitialShareStage::ShareStateCommitted { .. }))
        .collect();
    assert!(!committed.is_empty(), "no share-state commit recorded after the acknowledgement");
    for event in committed {
        assert_let!(
            InitialShareStage::ShareStateCommitted { message_index: 0 } = event.stage
        );
    }
}

#[async_test]
async fn test_first_encrypted_event_correlates_with_the_initial_session() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }

    let content = ruma::events::room::message::RoomMessageEventContent::text_plain("hello");
    let _ = alice
        .encrypt_room_event(room_id, content)
        .await
        .unwrap();

    let guard = events.lock().unwrap();
    let sessions = initial_share_session_events(&guard);
    assert_eq!(sessions.len(), 1, "the session summary must be emitted exactly once");
    let session = sessions[0];
    assert_eq!(session.first_event_message_index, 0);
    assert!(session.all_initial_shares_settled_first);
    assert_eq!(session.eligible_peer_devices, 1);
    assert_eq!(session.eligible_own_devices, 0);
    assert_eq!(session.index0_shares_committed, 1);
    assert_eq!(session.after_index0_shares_committed, 0);
    assert_eq!(session.homeserver_accepted_devices, 1);
    assert!(session.created_at_index0);

    // The session alias in the summary matches the device-level records.
    let devices = initial_share_device_events(&guard);
    for device in devices {
        assert_eq!(device.session, session.session, "device/session alias mismatch");
    }
}

#[async_test]
async fn test_second_encrypted_event_does_not_emit_another_session_summary() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    for _ in 0..2 {
        let content = ruma::events::room::message::RoomMessageEventContent::text_plain("hello");
        let _ = alice.encrypt_room_event(room_id, content).await.unwrap();
    }

    let guard = events.lock().unwrap();
    let sessions = initial_share_session_events(&guard);
    assert_eq!(sessions.len(), 1);
}

#[async_test]
async fn test_initial_share_with_missing_olm_reports_olm_missing_distinctly() {
    // The machine knows Alice's device from a keys query but has never
    // established an Olm session with it.
    let (alice, _) = crate::machine::test_helpers::get_machine_after_query_test_helper().await;
    let room_id = room_id!("!test:example.org");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let requests = alice
        .share_room_key(
            room_id,
            iter::once(user_id!("@alice:example.org")),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(
        requests.iter().any(|request| request.event_type.to_string() == "m.room_key.withheld"),
        "the missing-Olm device must receive an m.no_olm withheld request"
    );

    let stages: Vec<_> = initial_share_device_events(&events.lock().unwrap())
        .into_iter()
        .map(|event| event.stage)
        .collect();
    assert!(
        stages.contains(&InitialShareStage::OlmMissing),
        "OlmMissing stage missing from {stages:?}"
    );
    assert!(
        !stages.contains(&InitialShareStage::OlmEncrypted),
        "a device without an Olm session must never be reported as encrypted"
    );
}

#[async_test]
async fn test_initial_share_diagnostics_never_expose_identifiers_or_material() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");

    let events = share_and_ack(&alice, &bob, &room_id).await;
    let debug = format!("{events:?}");
    for forbidden in [
        "a:example.org",
        "b:example.org",
        "PEERDEVICE",
        "example.org",
        "test:example.org",
        "@",
        "!test",
    ] {
        assert!(!debug.contains(forbidden), "privacy leak: {forbidden} in {debug}");
    }

    // Olm recovery signals for the same device must reuse the anonymous alias.
    let recovery = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&recovery)));
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let _ids = alice.inner.group_session_manager.unwedged_affected_room_ids(&bob_device);
    let recovery_events = recovery.lock().unwrap().clone();
    let device_aliases: Vec<_> = initial_share_device_events(&events)
        .into_iter()
        .map(|event| event.device)
        .collect();
    let recovery_device = recovery_events.iter().find_map(|event| match event {
        RoomKeyDiagnosticEvent::OlmRecovery(olm) => olm.device,
        _ => None,
    });
    assert!(
        recovery_device.is_some_and(|alias| device_aliases.contains(&alias)),
        "unwedge recovery must correlate by the same device alias"
    );
}

#[async_test]
async fn test_olm_recovery_reshare_correlates_by_device_alias() {
    use crate::room_key_diagnostics::{
        OlmRecoveryReshareOutcome, OlmRecoverySignalOutcome,
    };

    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");

    // Establish the initial share with a recorded device alias.
    let events = share_and_ack(&alice, &bob, &room_id).await;
    let device_alias = initial_share_device_events(&events)[0].device;

    // A subsequent per-room unwedge re-share for the same device must reuse it.
    let recovery = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&recovery)));
    let mut bob_device =
        alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap().inner;
    // Bob's device "unwedges": bump its stored olm_wedging_index on Alice's
    // side, as the SDK does when a fresh inbound session is accepted.
    for _ in 0..10 {
        bob_device.olm_wedging_index.increment();
    }
    alice.store().save_device_data(std::slice::from_ref(&bob_device)).await.unwrap();
    let members = vec![bob.user_id().to_owned()];
    let _ = alice
        .inner
        .group_session_manager
        .reshare_unwedged_room_key(
            &room_id,
            &members,
            EncryptionSettings::default(),
            &bob_device,
        )
        .await;

    let recovery_events = recovery.lock().unwrap().clone();
    let reshare = recovery_events.iter().find_map(|event| match event {
        RoomKeyDiagnosticEvent::OlmRecovery(olm)
            if olm.reshare == Some(OlmRecoveryReshareOutcome::Queued)
                && olm.signal == OlmRecoverySignalOutcome::Observed =>
        {
            Some(olm)
        }
        _ => None,
    });
    assert_let!(Some(reshare) = reshare);
    assert_eq!(reshare.device, Some(device_alias));
}
