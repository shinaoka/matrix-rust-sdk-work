// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Arc;
use tokio::sync::Barrier;

#[async_test]
async fn test_interrupted_in_room_replay_claim_remains_retryable() {
    let f = fixture().await;
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    f.bob
        .receive_verification_event(&request(
            &f,
            "!one:example.invalid",
            "$interrupted:example.invalid",
        ))
        .await
        .unwrap();
    let (query_id, _) =
        f.bob.inner.identity_manager.users_for_key_query().await.unwrap().pop_first().unwrap();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    f.bob
        .inner
        .verification_machine
        .set_replay_after_claim_pause_for_test(entered.clone(), release);
    let response_json = json!({ "device_keys": { f.alice.user_id(): { f.alice.device_id(): f.keys } }, "failures": {} });
    let machine = f.bob.clone();
    let owner_id = query_id.clone();
    let response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let owner =
        tokio::spawn(
            async move { machine.receive_keys_query_response(&owner_id, &response).await },
        );
    entered.wait().await;
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert_eq!(f.bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert!(incoming.next().now_or_never().is_none());
    keys(&f, &query_id, true).await;
    let delivery = incoming.next().await.unwrap();
    assert_eq!(delivery.flow_id().as_str(), "$interrupted:example.invalid");
    delivery.commit();
    assert!(incoming.next().now_or_never().is_none());
}

#[async_test]
async fn test_wrong_room_cancel_and_to_device_original_alias_do_not_cross_flow_identity() {
    let f = fixture().await;
    keys(&f, &TransactionId::new(), true).await;
    let event = request(&f, "!one:example.invalid", "$room:example.invalid");
    f.bob.receive_verification_event(&event).await.unwrap();
    let cancel: AnyMessageLikeEvent = serde_json::from_value(json!({
        "type": "m.key.verification.cancel", "room_id": "!wrong:example.invalid", "event_id": "$cancel:example.invalid",
        "sender": f.alice.user_id(), "origin_server_ts": MilliSecondsSinceUnixEpoch::now(),
        "content": { "code": "m.user", "reason": "synthetic", "m.relates_to": { "rel_type": "m.reference", "event_id": "$room:example.invalid" } }
    })).unwrap();
    f.bob.receive_verification_event(&cancel).await.unwrap();
    assert!(
        !f.bob
            .get_verification_request(f.alice.user_id(), "$room:example.invalid")
            .unwrap()
            .is_cancelled()
    );

    let g = fixture().await;
    keys(&g, &TransactionId::new(), true).await;
    let to_device = serde_json::from_value(json!({ "type": "m.key.verification.request", "sender": g.alice.user_id(),
        "content": { "from_device": g.alice.device_id(), "transaction_id": "$transport:example.invalid",
            "timestamp": MilliSecondsSinceUnixEpoch::now(), "methods": ["m.sas.v1"] } })).unwrap();
    g.bob.handle_verification_event(&to_device).await;
    g.bob
        .receive_verification_event(&request(
            &g,
            "!one:example.invalid",
            "$transport:example.invalid",
        ))
        .await
        .unwrap();
    let cached =
        g.bob.get_verification_request(g.alice.user_id(), "$transport:example.invalid").unwrap();
    assert!(matches!(cached.flow_id(), FlowId::ToDevice(_)));
    assert!(!cached.is_cancelled());
}

#[async_test]
async fn test_in_room_cancel_fences_replay_during_claim_and_device_lookup() {
    for after_lookup in [false, true] {
        let f = fixture().await;
        let event = request(&f, "!one:example.invalid", "$cancelled:example.invalid");
        let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
        f.bob.receive_verification_event(&event).await.unwrap();
        let (query_id, _) =
            f.bob.inner.identity_manager.users_for_key_query().await.unwrap().pop_first().unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        if after_lookup {
            f.bob.inner.verification_machine.set_request_device_lookup_completed_pause_for_test(
                entered.clone(),
                release.clone(),
            );
        } else {
            f.bob
                .inner
                .verification_machine
                .set_replay_after_claim_pause_for_test(entered.clone(), release.clone());
        }
        let machine = f.bob.clone();
        let response = matrix_sdk_test::ruma_response_from_json(
            &json!({ "device_keys": { f.alice.user_id(): { f.alice.device_id(): f.keys } }, "failures": {} }),
        );
        let owner =
            tokio::spawn(
                async move { machine.receive_keys_query_response(&query_id, &response).await },
            );
        entered.wait().await;
        let cancel = serde_json::from_value(json!({ "type": "m.key.verification.cancel", "room_id": "!one:example.invalid", "event_id": "$cancel:example.invalid",
            "sender": f.alice.user_id(), "origin_server_ts": MilliSecondsSinceUnixEpoch::now(),
            "content": { "code": "m.user", "reason": "synthetic", "m.relates_to": { "rel_type": "m.reference", "event_id": "$cancelled:example.invalid" } } })).unwrap();
        f.bob.receive_verification_event(&cancel).await.unwrap();
        release.wait().await;
        owner.await.unwrap().unwrap();
        assert!(
            incoming.next().now_or_never().is_none(),
            "a cancelled pending request must not be handed to the application"
        );
        assert!(
            f.bob
                .get_verification_request(f.alice.user_id(), "$cancelled:example.invalid")
                .is_none_or(|request| request.is_cancelled())
        );
        f.bob.receive_verification_event(&event).await.unwrap();
        assert!(
            incoming.next().now_or_never().is_none(),
            "a duplicate cannot resurrect a cancelled pending request"
        );
        f.bob
            .receive_verification_event(&request(
                &f,
                "!one:example.invalid",
                "$later:example.invalid",
            ))
            .await
            .unwrap();
        let later = incoming.next().await.unwrap();
        assert_eq!(
            later.flow_id().as_str(),
            "$later:example.invalid",
            "cancelled marker must not block the active FIFO head"
        );
        later.commit();
    }
}

#[async_test]
async fn test_in_room_cancel_fences_initial_known_device_lookup() {
    let f = fixture().await;
    keys(&f, &TransactionId::new(), true).await;
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    f.bob
        .inner
        .verification_machine
        .set_request_device_lookup_completed_pause_for_test(entered.clone(), release.clone());
    let machine = f.bob.clone();
    let event = request(&f, "!one:example.invalid", "$initial:example.invalid");
    let initial = tokio::spawn(async move { machine.receive_verification_event(&event).await });
    entered.wait().await;
    assert!(
        f.bob
            .inner
            .identity_manager
            .users_for_key_query()
            .await
            .unwrap()
            .values()
            .all(|query| !query.device_keys.contains_key(f.alice.user_id())),
        "initial lookup must not schedule a speculative key query"
    );
    let cancel = serde_json::from_value(json!({ "type": "m.key.verification.cancel", "room_id": "!one:example.invalid", "event_id": "$cancel-initial:example.invalid",
        "sender": f.alice.user_id(), "origin_server_ts": MilliSecondsSinceUnixEpoch::now(),
        "content": { "code": "m.user", "reason": "synthetic", "m.relates_to": { "rel_type": "m.reference", "event_id": "$initial:example.invalid" } } })).unwrap();
    f.bob.receive_verification_event(&cancel).await.unwrap();
    release.wait().await;
    initial.await.unwrap().unwrap();
    assert!(
        incoming.next().now_or_never().is_none(),
        "cancel during initial device lookup must fence publication"
    );
    assert!(
        f.bob
            .get_verification_request(f.alice.user_id(), "$initial:example.invalid")
            .is_none_or(|request| request.is_cancelled())
    );
    f.bob
        .receive_verification_event(&request(
            &f,
            "!one:example.invalid",
            "$after-initial:example.invalid",
        ))
        .await
        .unwrap();
    incoming.next().await.unwrap().commit();
}

#[async_test]
async fn test_initial_lookup_abort_and_duplicate_do_not_steal_or_strand_slot() {
    let f = fixture().await;
    keys(&f, &TransactionId::new(), true).await;
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    f.bob
        .inner
        .verification_machine
        .set_request_device_lookup_completed_pause_for_test(entered.clone(), release);
    let event = request(&f, "!one:example.invalid", "$abort-initial:example.invalid");
    let original = event.clone();
    let machine = f.bob.clone();
    let initial = tokio::spawn(async move { machine.receive_verification_event(&event).await });
    entered.wait().await;
    f.bob.receive_verification_event(&original).await.unwrap();
    assert_eq!(
        f.bob.inner.verification_machine.incoming_verification_request_owner_count(),
        1,
        "duplicate cannot consume the initial owner's slot"
    );
    assert!(incoming.next().now_or_never().is_none());
    initial.abort();
    assert!(initial.await.unwrap_err().is_cancelled());
    assert_eq!(
        f.bob.inner.verification_machine.incoming_verification_request_owner_count(),
        0,
        "aborted initial lookup must roll back its exact reservation"
    );
    f.bob.receive_verification_event(&original).await.unwrap();
    incoming.next().await.unwrap().commit();
}
