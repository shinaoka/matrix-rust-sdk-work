#![cfg(feature = "e2e-encryption")]

//! Integration tests for the bounded index-0 duplicate share (issue #510).

use std::{sync::Arc, time::Duration};

use tokio::sync::broadcast;

use matrix_sdk::{
    Client,
    encryption::{Index0ReshareOutcome, RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver},
    test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory, test_json};
use ruma::{
    RoomVersionId, device_id, events::room::message::RoomMessageEventContent, room_id, user_id,
};
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{method, path_regex},
};

const TO_DEVICE_PATH: &str = r"^/_matrix/client/.*/sendToDevice/m.room.encrypted/.*";
const ROOM_SEND_PATH: &str = r"^/_matrix/client/.*/rooms/.*/send/m.room.encrypted/.*";

fn capture_observer(
    events: &Arc<std::sync::Mutex<Vec<RoomKeyDiagnosticEvent>>>,
) -> RoomKeyDiagnosticObserver {
    let captured = Arc::clone(events);
    Arc::new(move |event| captured.lock().unwrap().push(event))
}

fn index0_reshare_outcomes(events: &[RoomKeyDiagnosticEvent]) -> Vec<Index0ReshareOutcome> {
    events
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::Index0Reshare(record) => Some(record.reshare),
            _ => None,
        })
        .collect()
}

/// Alice and Bob know each other's devices; Alice joins an encrypted room with
/// Bob as a member. Returns the server, Alice, the room id, and the observer.
async fn setup_encrypted_room()
-> (MatrixMockServer, Client, ruma::OwnedRoomId, Arc<std::sync::Mutex<Vec<RoomKeyDiagnosticEvent>>>)
{
    let server = MatrixMockServer::new().await;
    server.mock_crypto_endpoints_preset().await;

    let alice_user_id = user_id!("@alice:example.org");
    let bob_user_id = user_id!("@bob:example.org");
    let alice_device_id = device_id!("ALICEDEVICE");
    let bob_device_id = device_id!("BOBDEVICE");

    // Alice runs with the bounded index-0 duplicate share enabled.
    let alice = server
        .client_builder_for_crypto_end_to_end(alice_user_id, alice_device_id)
        .on_builder(|builder| builder.with_index0_duplicate_share(true))
        .build()
        .await;
    let bob = server.client_builder_for_crypto_end_to_end(bob_user_id, bob_device_id).build().await;
    server.exchange_e2ee_identities(&alice, &bob).await;

    let room_id = room_id!("!test:example.org");

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    alice.encryption().set_room_key_diagnostic_observer(Some(capture_observer(&events))).await;

    let event_factory = EventFactory::new().sender(alice_user_id).room(room_id);
    server
        .mock_sync()
        .ok_and_run(&alice, |builder| {
            builder.add_joined_room(
                JoinedRoomBuilder::new(room_id)
                    .add_state_event(event_factory.create(alice_user_id, RoomVersionId::V1))
                    .add_state_event(event_factory.room_encryption())
                    .add_state_event(event_factory.member(alice_user_id).into_raw())
                    .add_state_event(event_factory.member(bob_user_id).into_raw()),
            );
        })
        .await;

    server
        .mock_get_members()
        .ok(vec![
            event_factory.member(alice_user_id).into_raw(),
            event_factory.member(bob_user_id).into_raw(),
        ])
        .mount()
        .await;

    (server, alice, room_id.to_owned(), events)
}

#[async_test]
async fn test_manual_index0_room_resend_preserves_index_and_sends_to_device_key() {
    let (server, alice, room_id, _events) = setup_encrypted_room().await;

    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .expect(3)
        .named("initial_duplicate_and_manual_resend")
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .named("advance_room_message")
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
        &room,
    )
    .await
    .unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("advance")).await.unwrap();
    let before = room.current_outbound_group_session_message_index().await.unwrap();
    assert_eq!(before, Some(1));

    let (_sender, mut cancellation) = broadcast::channel(1);
    let summary = room.resend_index0_room_key(&mut cancellation, || true).await.unwrap();
    assert_eq!(summary.outcome, matrix_sdk_base::crypto::ManualIndex0ResendOutcome::Completed);
    assert_eq!(summary.message_index_before, before);
    assert_eq!(summary.message_index_after, before);
    assert!(!summary.room_event_sent);
    assert!(!summary.index0_consumed);
}

#[async_test]
async fn test_manual_index0_room_resend_failure_cleans_pending_requests() {
    let (server, alice, room_id, _events) = setup_encrypted_room().await;
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(move |_request: &Request| {
            let attempt = attempts_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 2 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY)
            }
        })
        .expect(4)
        .named("failed_then_retried_manual_resend")
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
        &room,
    )
    .await
    .unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("advance")).await.unwrap();
    let before = room.current_outbound_group_session_message_index().await.unwrap();

    let (_sender, mut cancellation) = broadcast::channel(1);
    let failed = room.resend_index0_room_key(&mut cancellation, || true).await.unwrap();
    assert_eq!(failed.outcome, matrix_sdk_base::crypto::ManualIndex0ResendOutcome::Failed);
    assert_eq!(failed.message_index_before, before);
    assert_eq!(failed.message_index_after, before);

    let (_sender, mut cancellation) = broadcast::channel(1);
    let retried = room.resend_index0_room_key(&mut cancellation, || true).await.unwrap();
    assert_eq!(retried.outcome, matrix_sdk_base::crypto::ManualIndex0ResendOutcome::Completed);
    assert_eq!(retried.message_index_before, before);
    assert_eq!(retried.message_index_after, before);
}

#[async_test]
async fn test_manual_index0_room_resend_deadline_cleans_pending_requests() {
    let (server, alice, room_id, _events) = setup_encrypted_room().await;
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);
    let manual_request_seen = Arc::new(tokio::sync::Notify::new());
    let manual_request_seen_clone = Arc::clone(&manual_request_seen);
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(move |_request: &Request| {
            let attempt = attempts_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 2 {
                manual_request_seen_clone.notify_one();
                ResponseTemplate::new(200)
                    .set_body_json(&*test_json::EMPTY)
                    .set_delay(Duration::from_secs(3600))
            } else {
                ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY)
            }
        })
        .expect(3)
        .named("deadline_manual_resend")
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
        &room,
    )
    .await
    .unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("advance")).await.unwrap();
    let before = room.current_outbound_group_session_message_index().await.unwrap();

    tokio::time::pause();
    let (_sender, mut cancellation) = broadcast::channel(1);
    let resend = tokio::spawn({
        let room = room.clone();
        async move { room.resend_index0_room_key(&mut cancellation, || true).await.unwrap() }
    });
    manual_request_seen.notified().await;
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    let expired = resend.await.unwrap();
    assert_eq!(expired.outcome, matrix_sdk_base::crypto::ManualIndex0ResendOutcome::Deadline);
    assert_eq!(expired.message_index_before, before);
    assert_eq!(expired.message_index_after, before);
}

#[async_test]
async fn test_first_room_event_queues_exactly_one_index0_duplicate() {
    let (server, alice, room_id, events) = setup_encrypted_room().await;

    // The preshare produces one to-device room-key request and the bounded
    // duplicate produces exactly one more; the second message produces none.
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .expect(2)
        .named("send_to_device")
        .mount(server.server())
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(2)
        .named("send_room_message")
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
        &room,
    )
    .await
    .unwrap();
    let content = RoomMessageEventContent::text_plain("first");
    let _ = room.send(content).await.unwrap().response;

    let guard = events.lock().unwrap();
    let outcomes = index0_reshare_outcomes(&guard);
    assert!(
        outcomes.contains(&Index0ReshareOutcome::Sent),
        "expected the duplicate to be reported as sent: {outcomes:?}"
    );
    // The first event still encrypted at message index 0.
    let first_event_indices: Vec<_> = guard
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareSession(record) => {
                Some(record.first_event_message_index)
            }
            _ => None,
        })
        .collect();
    assert_eq!(first_event_indices, vec![0]);
    drop(guard);

    // A second message must not schedule another duplicate: the to-device
    // expectation above is already exhausted, so a duplicate send here would
    // fail the mock verification.
    let content = RoomMessageEventContent::text_plain("second");
    let _ = room.send(content).await.unwrap().response;

    let outcomes = index0_reshare_outcomes(&events.lock().unwrap());
    assert_eq!(
        outcomes.iter().filter(|outcome| **outcome == Index0ReshareOutcome::Sent).count(),
        1,
        "the second message must not schedule another duplicate: {outcomes:?}"
    );
}

#[async_test]
async fn test_duplicate_send_failure_never_downgrades_the_first_event() {
    let (server, alice, room_id, events) = setup_encrypted_room().await;

    // A stateful responder: the preshare succeeds, the duplicate fails, and
    // the follow-up preshare after that test-only boundary also succeeds.
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(move |_request: &Request| {
            if attempts_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY)
            }
        })
        .mount(server.server())
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .named("send_room_message")
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
        &room,
    )
    .await
    .unwrap();
    let content = RoomMessageEventContent::text_plain("first");
    let _ = room.send(content).await.unwrap().response;

    // The duplicate was attempted, failed, and never downgraded the message.
    assert!(
        attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "the duplicate must have been attempted after the preshare"
    );
    let outcomes = index0_reshare_outcomes(&events.lock().unwrap());
    assert!(
        outcomes.contains(&Index0ReshareOutcome::Failed),
        "expected a failed duplicate record: {outcomes:?}"
    );
    // The first event still encrypted at index 0.
    let indices: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareSession(record) => {
                Some(record.first_event_message_index)
            }
            _ => None,
        })
        .collect();
    assert_eq!(indices, vec![0]);
}

#[async_test]
async fn test_duplicate_deadline_is_bounded_with_controlled_time() {
    let (server, alice, room_id, events) = setup_encrypted_room().await;

    // The preshare's to-device request settles immediately; the duplicate's
    // response is delayed far beyond its 1.5s deadline so the deadline always
    // fires first, deterministically, without any wall-clock sleep. The
    // follow-up preshare after that test-only boundary settles immediately.
    let duplicate_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let duplicate_attempts_clone = Arc::clone(&duplicate_attempts);
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(move |_request: &Request| {
            match duplicate_attempts_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY),
                1 => ResponseTemplate::new(200)
                    .set_body_json(&*test_json::EMPTY)
                    .set_delay(Duration::from_secs(3600)),
                _ => ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY),
            }
        })
        .expect(3)
        .named("send_to_device")
        .mount(server.server())
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .named("send_room_message")
        .mount(server.server())
        .await;

    // Controlled time: no wall-clock sleep is used anywhere in this test.
    tokio::time::pause();
    let room = alice.get_room(&room_id).unwrap();
    let send = tokio::spawn(async move {
        matrix_sdk::room::futures::ensure_room_encryption_ready_with_index0_duplicate_share_for_testing(
            &room,
        )
        .await?;
        let content = RoomMessageEventContent::text_plain("first");
        room.send(content).await.map(|result| result.response)
    });

    // The preshare to-device request settles immediately.
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    // The duplicate's 1.5s deadline elapses well before its (delayed)
    // response, so the attempt records `deadline` and the send proceeds.
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    // The room event send completes.
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::time::advance(Duration::from_millis(1)).await;

    let _ = send.await.expect("send task panicked").expect("room send failed");

    let outcomes = index0_reshare_outcomes(&events.lock().unwrap());
    assert!(
        outcomes.contains(&Index0ReshareOutcome::Deadline),
        "expected a deadline record: {outcomes:?}"
    );
    let indices: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            RoomKeyDiagnosticEvent::InitialShareSession(record) => {
                Some(record.first_event_message_index)
            }
            _ => None,
        })
        .collect();
    assert_eq!(indices, vec![0]);
}
