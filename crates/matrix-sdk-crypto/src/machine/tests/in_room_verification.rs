// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

use futures_util::{FutureExt, StreamExt};
use matrix_sdk_test::async_test;
use ruma::{MilliSecondsSinceUnixEpoch, TransactionId, events::AnyMessageLikeEvent};
use serde_json::{Value, json};

use crate::{
    OlmMachine,
    machine::{test_helpers::get_machine_pair_with_setup_sessions_test_helper, tests},
    store::types::{Changes, DeviceChanges},
    verification::FlowId,
};

struct Fixture {
    alice: OlmMachine,
    bob: OlmMachine,
    keys: Value,
}

async fn fixture() -> Fixture {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;
    let device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let keys = serde_json::to_value(device.as_device_keys()).unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    Fixture { alice, bob, keys }
}

fn request(f: &Fixture, room: &str, id: &str) -> AnyMessageLikeEvent {
    serde_json::from_value(json!({
        "type": "m.room.message", "room_id": room, "event_id": id,
        "sender": f.alice.user_id(), "origin_server_ts": MilliSecondsSinceUnixEpoch::now(),
        "content": { "body": "synthetic request", "msgtype": "m.key.verification.request",
            "to": f.bob.user_id(), "from_device": f.alice.device_id(), "methods": ["m.sas.v1"] }
    }))
    .unwrap()
}

async fn keys(f: &Fixture, query_id: &TransactionId, include: bool) {
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": { f.alice.user_id(): if include { json!({ f.alice.device_id(): f.keys }) } else { json!({}) } },
        "failures": {}
    }));
    f.bob.receive_keys_query_response(query_id, &response).await.unwrap();
}

#[async_test]
async fn test_in_room_unknown_sender_uses_one_claim_and_duplicate_delivery_is_suppressed() {
    let f = fixture().await;
    let event = request(&f, "!one:example.invalid", "$same:example.invalid");
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    f.bob.receive_verification_event(&event).await.unwrap();
    f.bob.receive_verification_event(&event).await.unwrap();
    assert_eq!(f.bob.inner.verification_machine.pending_to_device_request_count(), 1);
    let mut queries = f.bob.inner.identity_manager.users_for_key_query().await.unwrap();
    assert_eq!(queries.len(), 1);
    let (query_id, _) = queries.pop_first().unwrap();
    keys(&f, &query_id, true).await;
    let delivery = incoming.next().await.unwrap();
    assert_eq!(
        delivery.flow_id(),
        &FlowId::InRoom(
            "!one:example.invalid".try_into().unwrap(),
            "$same:example.invalid".try_into().unwrap()
        )
    );
    // Interrupted application handoff releases the same typed queue slot.
    drop(delivery);
    let delivery = incoming.next().await.unwrap();
    delivery.commit();
    keys(&f, &query_id, true).await;
    f.bob.receive_verification_event(&event).await.unwrap();
    assert!(incoming.next().now_or_never().is_none());
    assert_eq!(f.bob.inner.verification_machine.incoming_verification_request_owner_count(), 0);
}

#[async_test]
async fn test_in_room_missing_and_reversed_query_responses_do_not_lose_or_duplicate_request() {
    let f = fixture().await;
    let event = request(&f, "!one:example.invalid", "$query:example.invalid");
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    f.bob.receive_verification_event(&event).await.unwrap();
    let (query_id, _) =
        f.bob.inner.identity_manager.users_for_key_query().await.unwrap().pop_first().unwrap();
    keys(&f, &query_id, false).await;
    assert!(incoming.next().now_or_never().is_none());
    f.bob.receive_verification_event(&event).await.unwrap();
    assert!(
        f.bob
            .inner
            .identity_manager
            .users_for_key_query()
            .await
            .unwrap()
            .values()
            .all(|query| !query.device_keys.contains_key(f.alice.user_id()))
    );
    keys(&f, &TransactionId::new(), true).await;
    incoming.next().await.unwrap().commit();
    keys(&f, &query_id, false).await;
    assert!(incoming.next().now_or_never().is_none());
}

#[async_test]
async fn test_in_room_expiry_is_retained_through_sender_key_recovery() {
    let f = fixture().await;
    let event = request(&f, "!one:example.invalid", "$expired:example.invalid");
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    f.bob.receive_verification_event(&event).await.unwrap();
    let (query_id, _) =
        f.bob.inner.identity_manager.users_for_key_query().await.unwrap().pop_first().unwrap();
    f.bob.inner.verification_machine.expire_pending_to_device_requests_for_test();
    keys(&f, &query_id, true).await;
    assert!(incoming.next().now_or_never().is_none());
    assert!(
        f.bob.get_verification_request(f.alice.user_id(), "$expired:example.invalid").is_none()
    );
    assert_eq!(f.bob.inner.verification_machine.pending_to_device_request_count(), 0);
}

#[async_test]
async fn test_room_and_transport_aliases_cannot_redirect_an_existing_request() {
    let f = fixture().await;
    keys(&f, &TransactionId::new(), true).await;
    let event = request(&f, "!one:example.invalid", "$collision:example.invalid");
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    f.bob.receive_verification_event(&event).await.unwrap();
    let first = incoming.next().await.unwrap();
    let original = first.flow_id().clone();
    first.commit();
    f.bob
        .receive_verification_event(&request(
            &f,
            "!wrong:example.invalid",
            "$collision:example.invalid",
        ))
        .await
        .unwrap();
    let to_device = serde_json::from_value(json!({
        "type": "m.key.verification.request", "sender": f.alice.user_id(),
        "content": { "from_device": f.alice.device_id(), "transaction_id": "$collision:example.invalid",
            "timestamp": MilliSecondsSinceUnixEpoch::now(), "methods": ["m.sas.v1"] }
    })).unwrap();
    f.bob.handle_verification_event(&to_device).await;
    let cached =
        f.bob.get_verification_request(f.alice.user_id(), "$collision:example.invalid").unwrap();
    assert_eq!(cached.flow_id(), &original);
    assert!(!cached.is_cancelled());
    assert!(incoming.next().now_or_never().is_none());
}

#[path = "in_room_verification_cancellation.rs"]
mod cancellation;

#[path = "in_room_verification_initial_races.rs"]
mod initial_races;
