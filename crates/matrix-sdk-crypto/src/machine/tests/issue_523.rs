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

//! Reproductions for the bounded initial Megolm Olm repair (issue #523).

use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
    sync::{Arc, Mutex},
};

use matrix_sdk_test::async_test;
use ruma::{
    api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse, device_id,
    events::room::message::RoomMessageEventContent, room_id, user_id,
};

use crate::{
    CollectStrategy, DeviceData, EncryptionSettings, InitialShareRepairClaimOutcome,
    InitialShareRepairOutcome, InitialShareRepairPreparation, OlmMachine, RoomKeyReshareResult,
    RoomKeyReshareTarget,
    machine::test_helpers::{get_machine_pair, get_machine_pair_with_setup_sessions_test_helper},
    room_key_diagnostics::{RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver},
};

#[async_test]
async fn test_initial_olm_missing_device_is_repaired_before_index_zero() {
    let (alice, bob, one_time_keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523:example.org");

    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }

    let (attempted, claim) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(attempted, InitialShareRepairPreparation::Attempted);
    let (claim_id, claim) = claim.expect("the missing device must be targeted for a claim");
    assert_eq!(claim.one_time_keys.len(), 1);
    assert_eq!(claim.one_time_keys[bob.user_id()].len(), 1);
    assert_eq!(
        claim.one_time_keys[bob.user_id()][bob.device_id()],
        ruma::OneTimeKeyAlgorithm::SignedCurve25519
    );

    let response = ruma::api::client::keys::claim_keys::v3::Response::new(BTreeMap::from([(
        bob.user_id().to_owned(),
        BTreeMap::from([(bob.device_id().to_owned(), one_time_keys)]),
    )]));
    alice.mark_request_as_sent(&claim_id, &response).await.unwrap();

    let repaired = alice
        .reshare_initial_share(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(
        repaired.iter().any(|request| request.event_type.to_string() == "m.room.encrypted"),
        "a successful targeted claim must queue the encrypted index-0 room-key repair"
    );
}

#[async_test]
async fn test_issue_523_fallback_key_claim_repairs_the_same_index_zero_session() {
    let (alice, bob, fallback_keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), true).await;
    let room_id = room_id!("!issue523-fallback:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }

    let (attempted, claim) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(attempted, InitialShareRepairPreparation::Attempted);
    let (claim_id, _claim) = claim.expect("fallback key must be claimed");
    let response = ruma::api::client::keys::claim_keys::v3::Response::new(BTreeMap::from([(
        bob.user_id().to_owned(),
        BTreeMap::from([(bob.device_id().to_owned(), fallback_keys)]),
    )]));
    alice.mark_request_as_sent(&claim_id, &response).await.unwrap();

    let repaired = alice
        .reshare_initial_share(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(repaired.iter().any(|request| request.event_type.to_string() == "m.room.encrypted"));
}

#[async_test]
async fn test_issue_523_empty_claim_remains_an_explicit_missing_olm_result() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-empty:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(initial.iter().any(|request| request.event_type.to_string() == "m.room_key.withheld"));
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }

    let (attempted, claim) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(attempted, InitialShareRepairPreparation::Attempted);
    let (claim_id, _claim) = claim.expect("empty claim still has an explicit request");
    let empty = ruma::api::client::keys::claim_keys::v3::Response::new(BTreeMap::new());
    alice.mark_request_as_sent(&claim_id, &empty).await.unwrap();
    let repaired = alice
        .reshare_initial_share(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(repaired.is_empty(), "an empty claim must not fabricate an encrypted share");
}

#[async_test]
async fn test_issue_523_duplicate_repair_scheduling_is_rejected() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-duplicate:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }

    let first = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    let second = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.0, InitialShareRepairPreparation::Attempted);
    assert_eq!(second.0, InitialShareRepairPreparation::NotNeeded);
    assert!(second.1.is_none());
}

#[async_test]
async fn test_issue_523_wake_is_user_matching_and_single_use() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-wake:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }

    let first = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.0, InitialShareRepairPreparation::Attempted);

    let unrelated_users = BTreeSet::from([user_id!("@carol:example.org").to_owned()]);
    let unrelated = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            true,
            Some(&unrelated_users),
        )
        .await
        .unwrap();
    assert_eq!(unrelated.0, InitialShareRepairPreparation::NotMatchingWake);

    let matching_users = BTreeSet::from([bob.user_id().to_owned()]);
    let matching = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            true,
            Some(&matching_users),
        )
        .await
        .unwrap();
    assert_eq!(matching.0, InitialShareRepairPreparation::Attempted);

    let duplicate = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            true,
            Some(&matching_users),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.0, InitialShareRepairPreparation::NotNeeded);
}

#[async_test]
async fn test_issue_523_invalidated_session_cancels_stale_repair() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-cancelled:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }
    alice.discard_room_key(room_id).await.unwrap();

    let (attempted, claim) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(attempted, InitialShareRepairPreparation::Cancelled);
    assert!(claim.is_none());
}

#[async_test]
async fn test_issue_523_force_reshare_preserves_unable_to_encrypt() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-forced:example.org");
    let initial = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in initial {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }

    let outcome = alice
        .force_reshare_room_key(
            room_id,
            None,
            RoomKeyReshareTarget::AllEligible,
            None,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, RoomKeyReshareResult::UnableToEncrypt { recipient_count: 1 }));
}

#[async_test]
async fn test_issue_523_policy_change_cancels_the_waiting_repair() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-policy:example.org");
    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let (preparation, _) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(preparation, InitialShareRepairPreparation::Attempted);

    let settings = EncryptionSettings {
        sharing_strategy: CollectStrategy::OnlyTrustedDevices,
        ..EncryptionSettings::default()
    };
    assert!(
        !alice
            .validate_initial_share_repair(room_id, iter::once(bob.user_id()), settings)
            .await
            .unwrap()
    );
}

#[async_test]
async fn test_issue_523_healthy_pending_and_committed_devices_are_not_repaired() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@alice:example.org"),
        user_id!("@bob:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!issue523-healthy:example.org");
    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(!requests.is_empty());

    let pending = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(pending.0, InitialShareRepairPreparation::NotNeeded);
    assert!(pending.1.is_none());

    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let committed = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(committed.0, InitialShareRepairPreparation::NotNeeded);
    assert!(committed.1.is_none());
}

#[async_test]
async fn test_issue_523_own_device_is_an_exact_claim_target() {
    let user = user_id!("@alice:example.org");
    let (alice, other_device, _keys) = get_machine_pair(user, user, false).await;
    let room_id = room_id!("!issue523-own:example.org");
    let requests = alice
        .share_room_key(room_id, iter::once(other_device.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }

    let (_, claim) = alice
        .prepare_initial_share_repair(
            room_id,
            iter::once(other_device.user_id()),
            EncryptionSettings::default(),
            false,
            None,
        )
        .await
        .unwrap();
    let (_, claim) = claim.expect("own other device must receive an exact claim");
    assert_eq!(claim.one_time_keys[user].len(), 1);
    assert!(claim.one_time_keys[user].contains_key(other_device.device_id()));
}

#[async_test]
async fn test_issue_523_peer_with_one_healthy_device_remains_user_covered() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@alice:example.org"),
        user_id!("@bob:example.org"),
        false,
    )
    .await;
    let bob_other = OlmMachine::new(bob.user_id(), device_id!("OTHERBOB")).await;
    let bob_other = DeviceData::from_machine_test_helper(&bob_other).await.unwrap();
    alice.store().save_device_data(&[bob_other]).await.unwrap();
    let room_id = room_id!("!issue523-partial-coverage:example.org");
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    alice.set_room_key_diagnostic_observer(Some(Arc::new(move |event| {
        captured.lock().unwrap().push(event);
    })));

    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let expected = alice.current_outbound_group_session_id(room_id).await;
    alice
        .note_initial_share_repair(
            room_id,
            expected.as_deref(),
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            InitialShareRepairClaimOutcome::Empty,
            InitialShareRepairOutcome::Deadline,
        )
        .await
        .unwrap();

    let events = events.lock().unwrap();
    let repair = events
        .iter()
        .find_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareRepair(repair) => Some(repair),
            _ => None,
        })
        .expect("repair diagnostic");
    assert_eq!(repair.peer_users_covered_bucket, 1);
    assert_eq!(repair.peer_users_zero_coverage_bucket, 0);
    assert_eq!(repair.missing_devices_bucket, 1);
}

#[async_test]
async fn test_issue_523_peer_zero_coverage_is_explicit_and_private() {
    let (alice, bob, _keys) =
        get_machine_pair(user_id!("@alice:example.org"), user_id!("@bob:example.org"), false).await;
    let room_id = room_id!("!issue523-coverage:example.org");
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let observer: RoomKeyDiagnosticObserver =
        Arc::new(move |event| captured.lock().unwrap().push(event));
    alice.set_room_key_diagnostic_observer(Some(observer));

    let requests = alice
        .share_room_key(room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let response = ToDeviceResponse::new();
    for request in requests {
        alice.mark_request_as_sent(&request.txn_id, &response).await.unwrap();
    }
    let expected = alice.current_outbound_group_session_id(room_id).await;
    alice
        .note_initial_share_repair(
            room_id,
            expected.as_deref(),
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
            InitialShareRepairClaimOutcome::Empty,
            InitialShareRepairOutcome::Deadline,
        )
        .await
        .unwrap();
    alice.encrypt_room_event(room_id, RoomMessageEventContent::text_plain("first")).await.unwrap();

    let events = events.lock().unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        RoomKeyDiagnosticEvent::InitialShareRepair(repair)
            if repair.first_event_message_index.is_none()
    )));
    let repair = events
        .iter()
        .rev()
        .find_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareRepair(repair) => Some(repair),
            _ => None,
        })
        .expect("repair diagnostic");
    assert_eq!(repair.peer_users_covered_bucket, 0);
    assert_eq!(repair.peer_users_zero_coverage_bucket, 1);
    assert_eq!(repair.missing_devices_bucket, 1);
    assert_eq!(repair.first_event_message_index, Some(0));
    assert!(repair.same_session);
    let debug = format!("{repair:?}");
    for forbidden in ["@alice", "@bob", "issue523", "curve25519", "signed_curve25519"] {
        assert!(!debug.contains(forbidden), "private value leaked: {forbidden}");
    }
}
