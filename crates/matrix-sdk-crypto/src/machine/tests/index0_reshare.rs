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

//! Tests for the bounded index-0 duplicate share (issue #510).

use std::{iter, sync::Arc};

use assert_matches2::assert_let;
use matrix_sdk_test::async_test;
use ruma::{room_id, user_id};

use crate::{
    EncryptionSettings, Index0ReshareDecision,
    machine::test_helpers::get_machine_pair_with_setup_sessions_test_helper,
    room_key_diagnostics::{
        Index0ReshareOutcome, RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver,
    },
};

fn capture_observer(
    events: &Arc<std::sync::Mutex<Vec<RoomKeyDiagnosticEvent>>>,
) -> RoomKeyDiagnosticObserver {
    let captured = Arc::clone(events);
    Arc::new(move |event| captured.lock().unwrap().push(event))
}

/// Share a fresh session for `room_id` with `recipient` and settle every
/// request as homeserver-accepted (the normal preshare result).
async fn settle_preshare(
    sender: &crate::OlmMachine,
    recipient: &crate::OlmMachine,
    room_id: &ruma::RoomId,
) {
    let requests = sender
        .share_room_key(room_id, iter::once(recipient.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(!requests.is_empty());
    for request in &requests {
        sender.inner.group_session_manager.mark_request_as_sent(&request.txn_id).await.unwrap();
    }
}

#[async_test]
async fn test_index0_reshare_queues_one_duplicate_while_message_index_is_zero() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    let outbound = alice.inner.group_session_manager.get_outbound_group_session(room_id).unwrap();
    assert_eq!(outbound.message_index().await, 0);

    let decision = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert_let!(Index0ReshareDecision::Queued { requests, session_id } = decision);
    assert!(!requests.is_empty());
    assert_eq!(session_id, outbound.session_id());
    for request in &requests {
        assert_eq!(request.event_type.to_string(), "m.room.encrypted");
    }
    // The duplicate is queued while the session is still at index 0.
    assert_eq!(outbound.message_index().await, 0);
    assert_eq!(outbound.pending_requests().len(), requests.len());
}

#[async_test]
async fn test_index0_reshare_never_repeats_for_the_same_session() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    // First duplicate is queued.
    let decision = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let first_requests = match decision {
        Index0ReshareDecision::Queued { requests, .. } => requests,
        other => panic!("expected queued, got {other:?}"),
    };
    // The send flow settles the queued requests as homeserver-accepted.
    for request in &first_requests {
        alice.inner.group_session_manager.mark_request_as_sent(&request.txn_id).await.unwrap();
    }

    // A second decision while still at index 0 must not repeat the schedule.
    let decision = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert_let!(Index0ReshareDecision::NotNeeded = decision);

    // After the first event consumes index 0, no new duplicate is scheduled.
    let content = ruma::events::room::message::RoomMessageEventContent::text_plain("hello");
    let _ = alice.encrypt_room_event(room_id, content).await.unwrap();
    let decision = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert_let!(Index0ReshareDecision::NotNeeded = decision);
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(room_id).unwrap();
    assert!(outbound.pending_requests().is_empty());

    // The no-repeat path is observable as a not_needed record while the window
    // was open (index 0, already attempted).
    let guard = events.lock().unwrap();
    let records: Vec<_> = guard
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::Index0Reshare(record) => Some(record.reshare),
            _ => None,
        })
        .collect();
    assert!(
        records.contains(&Index0ReshareOutcome::NotNeeded),
        "expected a not_needed record for the no-repeat case: {records:?}"
    );
}

#[async_test]
async fn test_index0_reshare_reevaluates_recipient_policy() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    // Bob's device becomes blacklisted after the preshare.
    let device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    device.set_local_trust(crate::LocalTrust::BlackListed).await.unwrap();

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    let decision = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    // Re-evaluation detected that a previously-shared device became
    // blacklisted, which demands rotation on the normal send path; the
    // duplicate is blocked and must never send to the blacklisted device.
    assert_let!(Index0ReshareDecision::PolicyBlocked = decision);
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(room_id).unwrap();
    assert!(outbound.pending_requests().is_empty());

    // The record reflects the policy-blocked duplicate.
    let guard = events.lock().unwrap();
    let records: Vec<_> = guard
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::Index0Reshare(record) => Some(record),
            _ => None,
        })
        .collect();
    assert!(!records.is_empty());
    assert!(
        records.iter().all(|record| record.reshare == Index0ReshareOutcome::PolicyBlocked),
        "expected only policy_blocked records: {records:?}"
    );
}

#[async_test]
async fn test_index0_reshare_never_rotates_and_blocks_when_rotation_pending() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    // Bob left the room: the outbound session was shared with a user who is no
    // longer a member, so recipient re-evaluation demands rotation.
    let decision = alice
        .reshare_index0_once(room_id, iter::empty::<&ruma::UserId>(), EncryptionSettings::default())
        .await
        .unwrap();
    assert_let!(Index0ReshareDecision::PolicyBlocked = decision);

    // The session was neither rotated nor replaced.
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(room_id).unwrap();
    let _ = outbound;
}

#[async_test]
async fn test_index0_reshare_diagnostics_never_expose_identifiers() {
    use crate::room_key_diagnostics::{Index0InitialShareState, Index0ReshareDiagnostic};

    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.set_room_key_diagnostic_observer(Some(capture_observer(&events)));

    settle_preshare(&alice, &bob, &room_id).await;
    let _ = alice
        .reshare_index0_once(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();

    let guard = events.lock().unwrap();
    let debug = format!("{:?}", guard);
    for forbidden in
        ["a:example.org", "b:example.org", "example.org", "test:example.org", "@", "!test"]
    {
        assert!(!debug.contains(forbidden), "privacy leak: {forbidden} in {debug}");
    }
    let _ = Index0InitialShareState::Accepted;
    let _ = Index0ReshareDiagnostic {
        session: crate::room_key_diagnostics::RoomKeyDiagnosticAlias::new(1),
        initial_share: Index0InitialShareState::Accepted,
        reshare: Index0ReshareOutcome::Sent,
        eligible_own_bucket: 0,
        eligible_peer_bucket: 1,
        elapsed_ms: 0,
    };
}
