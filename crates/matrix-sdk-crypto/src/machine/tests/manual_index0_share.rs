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

//! Tests for the manual index-0 room-key share (issue #538).

use std::{iter, sync::Arc, time::Duration};

use assert_matches2::assert_let;
use matrix_sdk_test::async_test;
use ruma::{
    TransactionId, device_id, events::room::history_visibility::HistoryVisibility, room_id, user_id,
};

use crate::{
    EncryptionSettings, ManualFinalizeStep, ManualIndex0ResendOutcome, ManualIndex0ResendStep,
    ManualIndex0ShareOutcome,
    machine::test_helpers::{
        build_session_for_pair, get_machine_pair_with_setup_sessions_test_helper,
        get_prepared_machine_test_helper,
    },
    olm::{OutboundGroupSession, ShareRequestKind},
    store::{CryptoStore, MemoryStore, types::Changes},
};

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

async fn get_machine_pair_with_removable_alice_store()
-> (crate::OlmMachine, crate::OlmMachine, Arc<MemoryStore>) {
    let (bob, one_time_keys) =
        get_prepared_machine_test_helper(user_id!("@b:example.org"), false).await;
    let alice_store = Arc::new(MemoryStore::new());
    let alice = crate::OlmMachine::with_store(
        user_id!("@a:example.org"),
        device_id!("ALICE2"),
        Arc::clone(&alice_store),
        None,
    )
    .await
    .unwrap();
    let alice_device = crate::DeviceData::from_machine_test_helper(&alice).await.unwrap();
    let bob_device = crate::DeviceData::from_machine_test_helper(&bob).await.unwrap();
    alice.store().save_device_data(&[bob_device]).await.unwrap();
    bob.store().save_device_data(&[alice_device]).await.unwrap();
    let (alice, bob) = build_session_for_pair(alice, bob, one_time_keys).await;
    (alice, bob, alice_store)
}

/// The manual index-0 share queues the index-0 `m.room_key` to the complete
/// eligible set without advancing the message index and without sending a
/// room event (issue #538 required tests 1 and 2).
#[async_test]
async fn test_manual_index0_share_queues_index0_requests_without_advancing_index() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    let (preparation, claim) = alice
        .prepare_manual_index0_share(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none(), "no claim expected while an Olm session is present");
    assert_eq!(preparation.outcome, ManualIndex0ShareOutcome::Completed);

    let step = alice
        .finalize_manual_index0_share(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualFinalizeStep::Ready { requests, summary } = step);
    assert!(!requests.is_empty(), "index-0 share must queue to-device requests");
    assert_eq!(summary.outcome, ManualIndex0ShareOutcome::Completed);
    assert_eq!(summary.message_index_before, Some(0));
    assert_eq!(summary.message_index_after, Some(0));
    assert_eq!(summary.peer_eligible, 1);
    assert_eq!(summary.peer_accepted, 1);
    assert_eq!(summary.peer_missing, 0);
    assert_eq!(summary.peer_users_with_zero_accepted, 0);
    assert!(!summary.room_event_sent);
    assert!(!summary.index0_consumed);

    for request in &requests {
        assert_eq!(request.event_type.to_string(), "m.room.encrypted");
        alice
            .inner
            .group_session_manager
            .mark_manual_request_as_sent(&request.txn_id)
            .await
            .unwrap();
    }

    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    assert_eq!(outbound.message_index().await, 0, "share must not consume index 0");
}

/// The issue-541 resend works after the current outbound index advances and
/// emits an encrypted to-device request without consuming another index.
#[async_test]
async fn test_manual_index0_resend_uses_original_ledger_after_index_advanced() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    assert_eq!(outbound.message_index().await, 1);

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert!(!requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::Completed);
    assert_eq!(summary.message_index_before, Some(1));
    assert_eq!(summary.message_index_after, Some(1));
    assert_eq!(summary.claim, crate::ManualClaimOutcome::NotNeeded);
    assert!(!summary.index0_consumed);
    assert!(requests.iter().all(|request| request.event_type.to_string() == "m.room.encrypted"));
    assert!(outbound.pending_requests().is_empty());
    assert_eq!(outbound.pending_manual_requests().len(), requests.len());
    let restored = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        outbound.pickle().await,
    )
    .unwrap();
    assert!(restored.pending_requests().is_empty());
    assert!(restored.pending_manual_requests().is_empty());
    assert_eq!(outbound.message_index().await, 1);
}

/// Pickle ownership metadata is fail-closed: legacy requests are quarantined
/// from manual recovery and mismatched modern maps discard pending requests.
#[async_test]
async fn test_manual_index0_pickle_ownership_quarantines_legacy_and_mismatch() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-pickle-ownership:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    let requests = match step {
        ManualIndex0ResendStep::Ready { requests, .. } => requests,
        other => panic!("expected queued manual requests, got {other:?}"),
    };
    let request = requests.first().cloned().expect("resend must queue a request");
    outbound.add_request_with_kind(
        TransactionId::new(),
        request.clone(),
        std::collections::BTreeMap::new(),
        ShareRequestKind::Normal,
    );
    outbound.add_request_with_kind(
        TransactionId::new(),
        request,
        std::collections::BTreeMap::new(),
        ShareRequestKind::Manual,
    );

    let mut legacy = outbound.pickle().await;
    legacy.request_kinds = None;
    let restored_legacy = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        legacy,
    )
    .unwrap();
    assert!(!restored_legacy.initial_share_tracking_enabled());
    assert!(restored_legacy.pending_manual_requests().is_empty());
    assert!(!restored_legacy.pending_requests().is_empty());

    let mut mismatched = outbound.pickle().await;
    mismatched.request_kinds = Some(std::collections::BTreeMap::new());
    let restored_mismatched = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        mismatched,
    )
    .unwrap();
    assert!(!restored_mismatched.initial_share_tracking_enabled());
    assert!(restored_mismatched.pending_requests().is_empty());
    assert!(restored_mismatched.pending_manual_requests().is_empty());
}

/// Initial, Normal, and Manual ownership can coexist while the initial batch
/// is pending; only the committed Initial request becomes the ledger.
#[async_test]
async fn test_manual_index0_pickle_interleaves_initial_normal_and_manual() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-pickle-interleaved:example.org");
    let initial_requests = alice
        .share_room_key(&room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let initial_request = initial_requests.first().cloned().expect("initial request");
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    outbound.add_request_with_kind(
        TransactionId::new(),
        initial_request.clone(),
        std::collections::BTreeMap::new(),
        ShareRequestKind::Normal,
    );
    outbound.add_request_with_kind(
        TransactionId::new(),
        initial_request,
        std::collections::BTreeMap::new(),
        ShareRequestKind::Manual,
    );
    alice
        .inner
        .group_session_manager
        .mark_request_as_sent(&initial_requests[0].txn_id)
        .await
        .unwrap();

    assert!(outbound.initial_share_ledger().is_some());
    assert_eq!(outbound.pending_request_ids().len(), 2);
    assert_eq!(outbound.pending_requests().len(), 1);
    assert_eq!(outbound.pending_manual_requests().len(), 1);
    let restored = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        outbound.pickle().await,
    )
    .unwrap();
    assert!(restored.initial_share_tracking_enabled());
    assert!(restored.initial_share_ledger().is_some());
    assert_eq!(restored.pending_request_ids().len(), 1);
    assert!(restored.pending_manual_requests().is_empty());
}

/// Cleanup removes only the owned manual requests and leaves no request that
/// a later automatic preshare could drain.
#[async_test]
async fn test_manual_index0_resend_cleanup_removes_owned_requests() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-cleanup:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::Completed);
    let ids = requests.iter().map(|request| request.txn_id.clone()).collect::<Vec<_>>();
    assert_eq!(outbound.pending_manual_requests().len(), ids.len());

    alice.cleanup_manual_pending_requests(&room_id, &ids, None).await.unwrap();
    assert!(outbound.pending_manual_requests().is_empty());
    assert!(outbound.pending_request_ids().is_empty());
    assert_eq!(alice.current_outbound_group_session_message_index(&room_id).await, Some(1));
}

/// Marking or cleaning a manual request is transactional: a persistence
/// failure restores the in-memory request and leaves the durable request for a
/// later explicit retry.
#[async_test]
async fn test_manual_index0_resend_mark_and_cleanup_roll_back_on_failure() {
    let (alice, bob, alice_store) = get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-mark-cleanup-failure:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    let requests = match step {
        ManualIndex0ResendStep::Ready { requests, .. } => requests,
        other => panic!("expected queued manual requests, got {other:?}"),
    };
    let request_id = requests.first().expect("resend request").txn_id.clone();
    assert_eq!(outbound.pending_manual_requests().len(), 1);

    alice_store.fail_next_save_changes_for_test();
    assert!(alice.mark_manual_request_as_sent(&request_id).await.is_err());
    assert_eq!(outbound.pending_manual_requests().len(), 1);
    let durable = alice_store
        .durable_outbound_group_session_for_test(&room_id)
        .expect("manual request must remain durable after mark failure");
    assert_eq!(durable.requests.len(), 1);
    assert_eq!(
        durable.request_kinds.as_ref().and_then(|kinds| kinds.get(&request_id)),
        Some(&ShareRequestKind::Manual)
    );
    let persisted = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        durable,
    )
    .unwrap();
    assert!(persisted.pending_manual_requests().is_empty());
    assert!(persisted.pending_requests().is_empty());

    alice_store.fail_next_save_changes_for_test();
    assert!(
        alice.cleanup_manual_pending_requests(&room_id, &[request_id.clone()], None).await.is_err()
    );
    assert_eq!(outbound.pending_manual_requests().len(), 1);
    let durable = alice_store
        .durable_outbound_group_session_for_test(&room_id)
        .expect("manual request must remain durable after cleanup failure");
    assert_eq!(durable.requests.len(), 1);
    assert_eq!(
        durable.request_kinds.as_ref().and_then(|kinds| kinds.get(&request_id)),
        Some(&ShareRequestKind::Manual)
    );
    let persisted = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        durable,
    )
    .unwrap();
    assert!(persisted.pending_manual_requests().is_empty());
    assert!(persisted.pending_requests().is_empty());

    alice.cleanup_manual_pending_requests(&room_id, &[request_id], None).await.unwrap();
    assert!(outbound.pending_manual_requests().is_empty());
}

/// Dropping a finalize future while durable persistence is blocked restores the
/// outbound queue and leaves an explicit retry possible.
#[async_test]
async fn test_manual_index0_resend_finalize_cancellation_rolls_back() {
    let (alice, bob, alice_store) = get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-finalize-cancel:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());

    let save_hold = alice_store.hold_save_changes_for_test().await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            alice.finalize_manual_index0_resend(
                preparation,
                iter::once(bob.user_id()),
                EncryptionSettings::default(),
            ),
        )
        .await
        .is_err()
    );
    assert!(outbound.pending_manual_requests().is_empty());
    assert!(outbound.pending_request_ids().is_empty());
    drop(save_hold);

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let retry = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(matches!(retry, ManualIndex0ResendStep::Ready { .. }));
}

/// Dropping mark and cleanup futures while persistence is blocked restores the
/// pending request and its owner-map entry for a later retry.
#[async_test]
async fn test_manual_index0_resend_mark_and_cleanup_cancellation_roll_back() {
    let (alice, bob, alice_store) = get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-mark-cleanup-cancel:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let requests = match alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap()
    {
        ManualIndex0ResendStep::Ready { requests, .. } => requests,
        other => panic!("expected queued manual request, got {other:?}"),
    };
    let request_id = requests.first().expect("manual request").txn_id.clone();
    assert!(alice.inner.group_session_manager.find_request_owner(&request_id).is_some());

    let save_hold = alice_store.hold_save_changes_for_test().await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            alice.mark_manual_request_as_sent(&request_id),
        )
        .await
        .is_err()
    );
    assert_eq!(outbound.pending_manual_requests().len(), 1);
    assert!(alice.inner.group_session_manager.find_request_owner(&request_id).is_some());
    drop(save_hold);
    alice.mark_manual_request_as_sent(&request_id).await.unwrap();
    assert!(alice.inner.group_session_manager.find_request_owner(&request_id).is_none());

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let requests = match alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap()
    {
        ManualIndex0ResendStep::Ready { requests, .. } => requests,
        other => panic!("expected queued manual request, got {other:?}"),
    };
    let request_id = requests.first().expect("manual request").txn_id.clone();

    let save_hold = alice_store.hold_save_changes_for_test().await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            alice.cleanup_manual_pending_requests(
                &room_id,
                std::slice::from_ref(&request_id),
                None
            ),
        )
        .await
        .is_err()
    );
    assert_eq!(outbound.pending_manual_requests().len(), 1);
    assert!(alice.inner.group_session_manager.find_request_owner(&request_id).is_some());
    drop(save_hold);
    alice.cleanup_manual_pending_requests(&room_id, &[request_id], None).await.unwrap();
    assert!(outbound.pending_manual_requests().is_empty());
}

/// A failed/aborted claim clears its expectation so a later explicit retry can
/// build a fresh claim, without leaving manual room-key requests pending.
#[async_test]
async fn test_manual_index0_resend_claim_cleanup_is_retryable() {
    let (alice_before_reload, bob, alice_store) =
        get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-claim-cleanup:example.org");
    settle_preshare(&alice_before_reload, &bob, &room_id).await;
    let sender_key = bob.identity_keys().curve25519.to_base64();
    assert!(alice_store.get_outbound_group_session(&room_id).await.unwrap().is_some());
    assert!(alice_store.remove_sessions_for_test(&sender_key));
    let alice = crate::OlmMachine::with_store(
        user_id!("@a:example.org"),
        device_id!("ALICE2"),
        Arc::clone(&alice_store),
        None,
    )
    .await
    .unwrap();
    let outbound =
        alice.inner.group_session_manager.current_outbound_session(&room_id).await.unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::Completed);
    let (claim_id, claim_request) = claim.expect("the missing Olm session must require a claim");
    assert_eq!(claim_request.one_time_keys[bob.user_id()].len(), 1);
    alice.cleanup_manual_pending_requests(&room_id, &[], Some(&claim_id)).await.unwrap();
    assert!(outbound.pending_manual_requests().is_empty());

    let retry = alice.get_missing_sessions(iter::once(bob.user_id())).await.unwrap();
    let (retry_id, retry_request) = retry.expect("cleanup must permit an explicit retry");
    assert_ne!(retry_id, claim_id);
    assert_eq!(retry_request.one_time_keys[bob.user_id()].len(), 1);
}

/// A persistence failure after staging forwarded keys restores the outbound
/// queue and does not leave a manual request pending for a later reload.
#[async_test]
async fn test_manual_index0_resend_rolls_back_on_persistence_failure() {
    let (alice, bob, alice_store) = get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-persistence-failure:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    alice
        .store()
        .save_changes(Changes {
            outbound_group_sessions: vec![outbound.clone()],
            ..Default::default()
        })
        .await
        .unwrap();
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    alice_store.fail_next_save_changes_for_test();

    let error = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .expect_err("injected persistence failure must abort the resend");
    let _ = error;
    assert!(outbound.pending_manual_requests().is_empty());
    assert!(outbound.pending_request_ids().is_empty());
    assert_eq!(outbound.message_index().await, 1);
    let restored = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        outbound.pickle().await,
    )
    .unwrap();
    assert!(restored.pending_manual_requests().is_empty());
    assert!(restored.pending_request_ids().is_empty());

    let persisted = OutboundGroupSession::from_pickle(
        alice.device_id().to_owned(),
        Arc::new(alice.identity_keys()),
        alice_store
            .durable_outbound_group_session_for_test(&room_id)
            .expect("the pre-failure session must remain persisted"),
    )
    .unwrap();
    assert_eq!(persisted.message_index().await, 1);
    assert!(persisted.pending_manual_requests().is_empty());
    assert!(persisted.pending_request_ids().is_empty());
}

/// A current-member input that is absent from the immutable ledger cannot
/// widen the resend target set.
#[async_test]
async fn test_manual_index0_resend_does_not_widen_to_unshared_user() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-no-widen:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("advance".to_owned()).await;
    let users = [bob.user_id(), user_id!("@new:example.org")];
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            users.iter().copied(),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            users.iter().copied(),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::Completed);
    assert_eq!(summary.peer_eligible, 1);
    assert_eq!(requests.len(), 1);
}

/// An invalidated current session cannot be used for historical recovery.
#[async_test]
async fn test_manual_index0_resend_refuses_invalidated_session() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-invalidated:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    outbound.invalidate_session();
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::PolicyBlocked);
}

/// A history-visibility change requires rotation and blocks historical resend.
#[async_test]
async fn test_manual_index0_resend_refuses_rotation_required_policy() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-policy:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let mut settings = EncryptionSettings::default();
    settings.history_visibility = HistoryVisibility::WorldReadable;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(&room_id, iter::once(bob.user_id()), settings)
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::PolicyBlocked);
}

/// A missing inbound counterpart fails closed even when the outbound session
/// and immutable initial-share ledger are present.
#[async_test]
async fn test_manual_index0_resend_refuses_missing_inbound_counterpart() {
    let (alice, bob, alice_store) = get_machine_pair_with_removable_alice_store().await;
    let room_id = room_id!("!resend-inbound-missing:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    assert!(alice_store.remove_inbound_group_session_for_test(&room_id, outbound.session_id()));

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::InboundSessionMissing);
    assert_eq!(preparation.inbound_first_known_index, None);
    assert!(outbound.pending_manual_requests().is_empty());
}

/// A matching inbound counterpart whose first known index is non-zero is not
/// sufficient proof for historical recovery.
#[async_test]
async fn test_manual_index0_resend_refuses_advanced_inbound_counterpart() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-inbound-advanced:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let inbound = alice
        .store()
        .get_inbound_group_session(&room_id, outbound.session_id())
        .await
        .unwrap()
        .expect("preshare must persist the matching inbound counterpart");
    let advanced =
        crate::olm::InboundGroupSession::from_export(&inbound.export_at_index(1).await).unwrap();
    alice.store().save_inbound_group_sessions(&[advanced]).await.unwrap();

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::InboundIndexAdvanced);
    assert_eq!(preparation.inbound_first_known_index, Some(1));

    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert!(requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::InboundIndexAdvanced);
    assert_eq!(summary.inbound_first_known_index, Some(1));
}

/// A changed Curve25519 identity for a ledger device fails closed before any
/// forwarded key request is staged.
#[async_test]
async fn test_manual_index0_resend_refuses_changed_sender_identity() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-identity-changed:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let replacement = crate::OlmMachine::new(bob.user_id(), bob.device_id()).await;
    let replacement_device =
        crate::DeviceData::from_machine_test_helper(&replacement).await.unwrap();
    alice.store().save_device_data(&[replacement_device]).await.unwrap();

    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::StaleIdentityRefused);
    assert_eq!(preparation.peer_sender_key_changed, 1);

    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert!(requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::StaleIdentityRefused);
    assert_eq!(summary.peer_sender_key_changed, 1);
}

/// A sender identity change after preparation is fenced before forwarded
/// encryption, covering the prepare/finalize TOCTOU boundary.
#[async_test]
async fn test_manual_index0_resend_refuses_identity_changed_after_prepare() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-identity-toctou:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::Completed);

    let replacement = crate::OlmMachine::new(bob.user_id(), bob.device_id()).await;
    let replacement_device =
        crate::DeviceData::from_machine_test_helper(&replacement).await.unwrap();
    alice.store().save_device_data(&[replacement_device]).await.unwrap();

    let step = alice
        .finalize_manual_index0_resend(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualIndex0ResendStep::Ready { requests, summary } = step);
    assert!(requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ResendOutcome::StaleIdentityRefused);
    assert_eq!(summary.peer_sender_key_changed, 1);
}

/// A session whose initial sharing proof has not committed fails closed.
#[async_test]
async fn test_manual_index0_resend_requires_committed_initial_ledger() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!resend-no-proof:example.org");
    let requests = alice
        .share_room_key(&room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(!requests.is_empty());
    let (preparation, claim) = alice
        .prepare_manual_index0_resend(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ResendOutcome::OriginalLedgerMissing);
}

/// A manual index-0 share is refused once the session has advanced past
/// index 0 (issue #538 required test 3).
#[async_test]
async fn test_manual_index0_share_refuses_after_index_consumed() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    // Consume index 0 with a real encryption.
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    let _ = outbound.encrypt_helper("message".to_owned()).await;
    assert_eq!(outbound.message_index().await, 1);

    let (preparation, claim) = alice
        .prepare_manual_index0_share(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ShareOutcome::RefusedIndexAdvanced);

    let step = alice
        .finalize_manual_index0_share(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualFinalizeStep::Ready { requests, summary } = step);
    assert!(requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ShareOutcome::RefusedIndexAdvanced);
}

/// A force-new rotation leaves a fresh session at index 0 (issue #538
/// required test 1): the new outbound session differs from the old one and
/// its message index is 0.
#[async_test]
async fn test_force_new_rotation_leaves_fresh_session_at_index_zero() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!test:example.org");
    settle_preshare(&alice, &bob, &room_id).await;
    let before = alice
        .inner
        .group_session_manager
        .current_outbound_group_session_id(&room_id)
        .await
        .unwrap();

    alice
        .discard_room_key_with_reason(
            &room_id,
            crate::room_key_diagnostics::RoomKeyRotationReason::ExplicitDiscard,
        )
        .await
        .unwrap();
    let requests = alice
        .share_room_key(&room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    for request in &requests {
        alice.inner.group_session_manager.mark_request_as_sent(&request.txn_id).await.unwrap();
    }

    let after = alice
        .inner
        .group_session_manager
        .current_outbound_group_session_id(&room_id)
        .await
        .unwrap();
    assert_ne!(before, after, "discard + preshare must rotate the session");
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    assert_eq!(outbound.message_index().await, 0, "fresh session must be at index 0");
}

/// A manual index-0 share claims one-time keys for eligible devices lacking
/// an Olm session, and the summary keeps the claim outcome visible
/// (issue #538 required test 5).
#[async_test]
async fn test_manual_index0_share_claims_missing_olm_sessions() {
    use std::collections::BTreeMap;

    use matrix_sdk_common::deserialized_responses::WithheldCode;
    use ruma::api::client::keys::claim_keys::v3::Response as ClaimResponse;

    let (alice, bob, one_time_keys) = crate::machine::test_helpers::get_machine_pair(
        user_id!("@alice:example.org"),
        user_id!("@bob:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!manual:example.org");

    // Create the outbound session at index 0 via the normal preshare; bob
    // has no Olm session, so the preshare queues an `m.no_olm` withheld.
    let initial = alice
        .share_room_key(&room_id, iter::once(bob.user_id()), EncryptionSettings::default())
        .await
        .unwrap();
    let to_device_response =
        ruma::api::client::to_device::send_event_to_device::v3::Response::new();
    for request in &initial {
        alice.mark_request_as_sent(&request.txn_id, &to_device_response).await.unwrap();
    }
    let outbound = alice.inner.group_session_manager.get_outbound_group_session(&room_id).unwrap();
    assert_eq!(outbound.message_index().await, 0);

    let (preparation, claim) = alice
        .prepare_manual_index0_share(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_eq!(preparation.outcome, ManualIndex0ShareOutcome::Completed);
    let (claim_id, claim_request) =
        claim.expect("the missing-Olm device must be targeted for a keys-claim");
    assert_eq!(claim_request.one_time_keys[bob.user_id()].len(), 1);

    // The claim response delivers a one-time key; sending and marking it
    // establishes an Olm session for the device.
    let (key_id, key) = one_time_keys.into_iter().next().unwrap();
    let response = ClaimResponse::new(BTreeMap::from([(
        bob.user_id().to_owned(),
        BTreeMap::from([(bob.device_id().to_owned(), BTreeMap::from([(key_id, key)]))]),
    )]));
    alice.mark_request_as_sent(&claim_id, &response).await.unwrap();

    // Finalization now queues the index-0 share to the (now Olm-capable)
    // complete eligible set, reporting the claim as succeeded.
    let step = alice
        .finalize_manual_index0_share(
            preparation,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualFinalizeStep::Ready { requests, summary } = step);
    assert!(!requests.is_empty(), "index-0 share must queue after the claim");
    assert_eq!(summary.outcome, ManualIndex0ShareOutcome::Completed);
    assert_eq!(summary.claim, crate::ManualClaimOutcome::Succeeded);
    assert_eq!(summary.peer_eligible, 1);
    assert_eq!(summary.peer_accepted, 1);
    assert_eq!(summary.peer_missing, 0);

    let _ = WithheldCode::NoOlm;
}

/// Recipient collection is re-evaluated at finalize time: a device that
/// joins (is passed to finalization) after the preparation step is included
/// and claims an Olm session when it lacks one (issue #538 required test 4).
#[async_test]
async fn test_manual_index0_share_re_evaluates_recipients_at_finalize() {
    use ruma::device_id;

    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let carol = crate::OlmMachine::new(user_id!("@c:example.org"), device_id!("CAROL")).await;
    let carol_device = crate::DeviceData::from_machine_test_helper(&carol).await.unwrap();
    alice.store().save_device_data(&[carol_device]).await.unwrap();

    let room_id = room_id!("!manual:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    let (preparation, claim) = alice
        .prepare_manual_index0_share(
            &room_id,
            iter::once(bob.user_id()),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert!(claim.is_none(), "no claim expected while only bob (with an Olm session) is eligible");

    // Finalization is given bob + carol; carol is re-evaluated at this
    // point, is newly eligible, and lacks an Olm session, so a claim is
    // needed for it.
    let step = alice
        .finalize_manual_index0_share(
            preparation,
            [bob.user_id(), carol.user_id()].into_iter(),
            EncryptionSettings::default(),
        )
        .await
        .unwrap();
    assert_let!(ManualFinalizeStep::NeedsClaim { request, .. } = step);
    assert_eq!(request.one_time_keys[carol.user_id()].len(), 1);
}

/// An empty eligible set is refused with `NoRecipients`, not reported as a
/// success with zero recipients (issue #538): crypto excludes the current
/// device, so a creator-only room must not claim a completed share.
#[async_test]
async fn test_manual_index0_share_refuses_empty_eligible_set() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        user_id!("@a:example.org"),
        user_id!("@b:example.org"),
        false,
    )
    .await;
    let room_id = room_id!("!manual:example.org");
    settle_preshare(&alice, &bob, &room_id).await;

    // Prepare with NO recipients at all (empty user iterator).
    let (preparation, claim) = alice
        .prepare_manual_index0_share(&room_id, iter::empty(), EncryptionSettings::default())
        .await
        .unwrap();
    assert!(claim.is_none());
    assert_eq!(preparation.outcome, ManualIndex0ShareOutcome::Completed);

    let step = alice
        .finalize_manual_index0_share(preparation, iter::empty(), EncryptionSettings::default())
        .await
        .unwrap();
    assert_let!(ManualFinalizeStep::Ready { requests, summary } = step);
    assert!(requests.is_empty());
    assert_eq!(summary.outcome, ManualIndex0ShareOutcome::NoRecipients);
    assert_eq!(summary.peer_eligible, 0);
    assert_eq!(summary.own_eligible, 0);
}
