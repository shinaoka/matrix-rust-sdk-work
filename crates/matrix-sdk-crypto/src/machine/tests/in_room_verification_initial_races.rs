// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::types::requests::AnyOutgoingRequest;
use std::sync::Arc;
use tokio::sync::Barrier;

#[async_test]
async fn test_initial_unknown_lookup_observes_overlapping_committed_sender_keys() {
    let f = fixture().await;
    let mut incoming = f.bob.subscribe_to_incoming_verification_requests();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    f.bob
        .inner
        .verification_machine
        .set_request_device_lookup_completed_pause_for_test(entered.clone(), release.clone());
    let event = request(&f, "!one:example.invalid", "$initial-keys:example.invalid");
    let machine = f.bob.clone();
    let initial = tokio::spawn(async move { machine.receive_verification_event(&event).await });
    entered.wait().await;
    keys(&f, &TransactionId::new(), true).await;
    assert!(
        incoming.next().now_or_never().is_none(),
        "a response cannot steal the active initial lookup reservation"
    );
    release.wait().await;
    initial.await.unwrap().unwrap();
    incoming.next().await.unwrap().commit();
    assert_eq!(
        f.bob.inner.verification_machine.incoming_verification_request_owner_count(),
        0,
        "a stale initial None must not recreate a pending FIFO head"
    );
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
    f.bob
        .receive_verification_event(&request(
            &f,
            "!one:example.invalid",
            "$after-keys:example.invalid",
        ))
        .await
        .unwrap();
    incoming.next().await.unwrap().commit();
}

#[async_test]
async fn test_full_incoming_owner_rejects_room_request_without_lookup_or_extra_slot() {
    let f = fixture().await;
    for index in 0..32 {
        f.bob
            .receive_verification_event(&request(
                &f,
                "!one:example.invalid",
                &format!("$full{index}:example.invalid"),
            ))
            .await
            .unwrap();
    }
    let (query_id, _) = f.bob.inner.identity_manager.users_for_key_query().await.unwrap().pop_first().unwrap();
    keys(&f, &query_id, true).await;
    assert_eq!(f.bob.inner.verification_machine.incoming_verification_request_owner_count(), 32);
    let event = request(&f, "!overflow:example.invalid", "$overflow:example.invalid");
    f.bob.receive_verification_event(&event).await.unwrap();
    assert_eq!(f.bob.inner.verification_machine.incoming_verification_request_owner_count(), 32);
    assert!(
        f.bob.get_verification_request(f.alice.user_id(), "$overflow:example.invalid").is_none(),
        "capacity rejection never materializes an unowned request"
    );
    let cancellations = f.bob.inner.verification_machine.outgoing_messages().into_iter().filter(|request| matches!(request.request(),
        AnyOutgoingRequest::RoomMessage(room) if room.room_id.as_str() == "!overflow:example.invalid" && matches!(room.content.as_ref(), ruma::events::AnyMessageLikeEventContent::KeyVerificationCancel(cancel)
            if cancel.relates_to.event_id.as_str() == "$overflow:example.invalid" && cancel.code == ruma::events::key::verification::cancel::CancelCode::UnexpectedMessage))).count();
    assert_eq!(
        cancellations, 1,
        "overflow is rejected using the normal room-message outgoing queue"
    );
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
    let before = f.bob.inner.verification_machine.outgoing_messages().len();
    let mut other = request(&f, "!other:example.invalid", "$other:example.invalid");
    if let AnyMessageLikeEvent::RoomMessage(ruma::events::MessageLikeEvent::Original(event)) = &mut other {
        if let ruma::events::room::message::MessageType::VerificationRequest(content) = &mut event.content.msgtype {
            content.to = "@other:example.invalid".try_into().unwrap();
        }
    }
    f.bob.receive_verification_event(&other).await.unwrap();
    assert_eq!(
        f.bob.inner.verification_machine.outgoing_messages().len(),
        before,
        "a request addressed to another user is ignored before capacity rejection"
    );
}

#[async_test]
async fn test_legacy_start_only_sas_ignores_wrong_room_cancel_and_done() {
    let f = fixture().await;
    keys(&f, &TransactionId::new(), true).await;
    let bob_device =
        f.alice.get_device(f.bob.user_id(), f.bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) = bob_device.start_verification().await.unwrap();
    let mut start =
        crate::verification::tests::request_to_event(f.alice.user_id(), &request.into());
    if let crate::types::events::ToDeviceEvents::KeyVerificationStart(event) = &mut start {
        event.content.transaction_id = "$legacy:example.invalid".into();
    } else {
        panic!("legacy start fixture should contain a start event")
    }
    f.bob.handle_verification_event(&start).await;
    assert!(f.bob.get_verification_request(f.alice.user_id(), "$legacy:example.invalid").is_none());
    let sas = f
        .bob
        .get_verification(f.alice.user_id(), "$legacy:example.invalid")
        .unwrap()
        .sas_v1()
        .unwrap();
    for kind in ["cancel", "done"] {
        let mut content = json!({ "m.relates_to": { "rel_type": "m.reference", "event_id": "$legacy:example.invalid" } });
        if kind == "cancel" {
            content["code"] = json!("m.user");
            content["reason"] = json!("synthetic");
        }
        let event = serde_json::from_value(json!({ "type": format!("m.key.verification.{kind}"), "room_id": "!wrong:example.invalid", "event_id": "$wrong:example.invalid",
            "sender": f.alice.user_id(), "origin_server_ts": MilliSecondsSinceUnixEpoch::now(), "content": content })).unwrap();
        f.bob.receive_verification_event(&event).await.unwrap();
    }
    assert!(!sas.is_cancelled());
    assert!(!sas.is_done());
}
