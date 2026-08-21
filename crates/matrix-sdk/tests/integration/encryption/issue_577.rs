#![cfg(feature = "e2e-encryption")]

//! Integration reproductions for new-session encryption readiness (issue #577).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use matrix_sdk::{
    Client,
    encryption::{RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver},
    test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory, test_json};
use ruma::{
    RoomVersionId, device_id, events::room::message::RoomMessageEventContent, room_id, user_id,
};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

const ROOM_SEND_PATH: &str = r"^/_matrix/client/.*/rooms/.*/send/m.room.encrypted/.*";

async fn setup_room()
-> (MatrixMockServer, Client, ruma::OwnedRoomId, Arc<Mutex<Vec<RoomKeyDiagnosticEvent>>>) {
    let server = MatrixMockServer::new().await;
    server.mock_crypto_endpoints_preset().await;
    let alice_user_id = user_id!("@alice:example.org");
    let bob_user_id = user_id!("@bob:example.org");
    let alice = server
        .client_builder_for_crypto_end_to_end(alice_user_id, device_id!("ALICEDEVICE"))
        .on_builder(|builder| builder.with_encryption_sync_readiness(true))
        .build()
        .await;
    let bob = server
        .client_builder_for_crypto_end_to_end(bob_user_id, device_id!("BOBDEVICE"))
        .build()
        .await;
    server.exchange_e2ee_identities(&alice, &bob).await;
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&diagnostics);
    let observer: RoomKeyDiagnosticObserver = Arc::new(move |event| {
        captured.lock().unwrap().push(event);
    });
    alice.encryption().set_room_key_diagnostic_observer(Some(observer)).await;

    let room_id = room_id!("!issue577:example.org");
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
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/.*/sendToDevice/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    (server, alice, room_id.to_owned(), diagnostics)
}

async fn wait_for_index_zero(client: &Client, room_id: &ruma::RoomId) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let room = client.get_room(room_id).expect("joined room");
            if room.current_outbound_group_session_message_index().await.unwrap() == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial pre-share created an index-0 session");
}

#[async_test]
async fn test_first_event_waits_for_current_encryption_generation() {
    let (server, alice, room_id, diagnostics) = setup_room().await;
    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .expect("joined room")
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });

    wait_for_index_zero(&alice, &room_id).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path().contains("/send/m.room.encrypted/"))
            .count(),
        0,
        "the room event must not be sent while encryption readiness is pending"
    );

    generation.mark_received();
    send.await.expect("send task panicked").expect("send succeeds after readiness");
    assert_eq!(
        alice
            .get_room(&room_id)
            .unwrap()
            .current_outbound_group_session_message_index()
            .await
            .unwrap(),
        Some(1)
    );
    assert!(diagnostics.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::EncryptionReadiness(record)
                if record.outcome == matrix_sdk::encryption::EncryptionReadinessOutcome::Ready
                    && record.sync
                        == matrix_sdk::encryption::EncryptionReadinessSyncState::Received
                    && record.query
                        == matrix_sdk::encryption::EncryptionReadinessQueryState::Accepted
                    && !record.retryable
        )
    }));
    let requests = server.server().received_requests().await.unwrap();
    let full_query = requests
        .iter()
        .rev()
        .find(|request| request.url.path().ends_with("/keys/query"))
        .expect("readiness full query");
    let full_query: serde_json::Value =
        serde_json::from_slice(&full_query.body).expect("query JSON");
    assert!(full_query["device_keys"].get("@alice:example.org").is_some());
    assert!(full_query["device_keys"].get("@bob:example.org").is_some());
    let query_count =
        requests.iter().filter(|request| request.url.path().ends_with("/keys/query")).count();
    alice
        .get_room(&room_id)
        .unwrap()
        .send(RoomMessageEventContent::text_plain("second"))
        .await
        .expect("ready unchanged session bypasses the full query");
    assert_eq!(
        server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path().ends_with("/keys/query"))
            .count(),
        query_count,
        "a matching Ready session must not run a per-message full query"
    );
}

#[async_test]
async fn test_full_query_discovers_clean_tracked_users_new_device_before_index_zero() {
    let (server, alice, room_id, _diagnostics) = setup_room().await;
    let bob_second = server
        .client_builder_for_crypto_end_to_end(user_id!("@bob:example.org"), device_id!("BOBSECOND"))
        .build()
        .await;
    server.mock_sync().ok_and_run(&bob_second, |_| {}).await;

    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    generation.mark_received();
    alice
        .get_room(&room_id)
        .unwrap()
        .send(RoomMessageEventContent::text_plain("first"))
        .await
        .expect("full query and second pre-share settle before the event");

    let requests = server.server().received_requests().await.unwrap();
    assert!(
        requests.iter().filter(|request| request.url.path().contains("/sendToDevice/")).any(
            |request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("to-device JSON");
                body["messages"]["@bob:example.org"].get("BOBSECOND").is_some()
            }
        ),
        "the second standard pre-share must target the device discovered by the full query"
    );
    assert_eq!(
        alice
            .get_room(&room_id)
            .unwrap()
            .current_outbound_group_session_message_index()
            .await
            .unwrap(),
        Some(1)
    );
}

#[async_test]
async fn test_key_query_failure_is_typed_and_does_not_consume_index_zero() {
    let (server, alice, room_id, diagnostics) = setup_room().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/_matrix/client/.*/keys/query$"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": "synthetic"
        })))
        .with_priority(1)
        .mount(server.server())
        .await;
    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    generation.mark_received();
    let error = alice
        .get_room(&room_id)
        .unwrap()
        .send(RoomMessageEventContent::text_plain("first"))
        .await
        .expect_err("authoritative query must fail the fence");
    assert!(matches!(
        error,
        matrix_sdk::Error::EncryptionReadiness(error)
            if error.stage() == matrix_sdk::EncryptionReadinessStage::KeyQuery
    ));
    assert_eq!(
        alice
            .get_room(&room_id)
            .unwrap()
            .current_outbound_group_session_message_index()
            .await
            .unwrap(),
        Some(0)
    );
    assert!(diagnostics.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::EncryptionReadiness(record)
                if record.outcome
                    == matrix_sdk::encryption::EncryptionReadinessOutcome::KeyQuery
                    && record.query
                        == matrix_sdk::encryption::EncryptionReadinessQueryState::Failed
                    && record.active_members_bucket == 2
                    && record.retryable
        )
    }));
}

#[async_test]
async fn test_send_queue_keeps_readiness_failure_pending_and_recoverable() {
    let (server, alice, room_id, _diagnostics) = setup_room().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/_matrix/client/.*/keys/query$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": "synthetic"
        })))
        .with_priority(1)
        .mount(server.server())
        .await;
    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    generation.mark_received();
    let room = alice.get_room(&room_id).unwrap();
    let queue = room.send_queue();
    let mut errors = alice.send_queue().subscribe_errors();
    queue
        .send(RoomMessageEventContent::text_plain("queued").into())
        .await
        .expect("queued local echo");

    let report = tokio::time::timeout(Duration::from_secs(3), errors.recv())
        .await
        .expect("readiness failure reported")
        .expect("error channel open");
    assert_eq!(report.room_id, room_id);
    assert!(report.is_recoverable);
    assert!(!queue.is_enabled());
    let (pending, _) = queue.subscribe().await.expect("pending local echoes");
    assert_eq!(pending.len(), 1, "recoverable readiness failure stays pending");
    assert_eq!(
        server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path().contains("/send/m.room.encrypted/"))
            .count(),
        0
    );
}

#[async_test]
async fn test_in_flight_query_deadline_is_reported_truthfully() {
    let (server, alice, room_id, diagnostics) = setup_room().await;
    let query_count_before = server
        .server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path().ends_with("/keys/query"))
        .count();
    Mock::given(method("POST"))
        .and(path_regex(r"^/_matrix/client/.*/keys/query$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(serde_json::json!({ "device_keys": {} })),
        )
        .with_priority(1)
        .mount(server.server())
        .await;
    tokio::time::pause();
    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    generation.mark_received();
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .expect("joined room")
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    let mut query_started = false;
    for _ in 0..1_000 {
        query_started = server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path().ends_with("/keys/query"))
            .count()
            > query_count_before;
        if query_started {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(query_started, "authoritative query entered the in-flight state");
    tokio::time::advance(Duration::from_secs(11)).await;
    let error = send.await.expect("send task").expect_err("fence deadline");
    assert!(matches!(
        error,
        matrix_sdk::Error::EncryptionReadiness(error)
            if error.stage() == matrix_sdk::EncryptionReadinessStage::Deadline
    ));
    assert!(diagnostics.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::EncryptionReadiness(record)
                if record.outcome == matrix_sdk::encryption::EncryptionReadinessOutcome::Deadline
                    && record.query
                        == matrix_sdk::encryption::EncryptionReadinessQueryState::InProgress
                    && record.retryable
        )
    }));
}

#[async_test]
async fn test_deadline_is_typed_retryable_and_does_not_consume_index_zero() {
    let (server, alice, room_id, diagnostics) = setup_room().await;
    tokio::time::pause();
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .expect("joined room")
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    wait_for_index_zero(&alice, &room_id).await;
    let mut initial_share_accepted = false;
    for _ in 0..1_000 {
        initial_share_accepted = diagnostics.lock().unwrap().iter().any(|event| {
            matches!(
                event,
                RoomKeyDiagnosticEvent::InitialShare(record)
                    if matches!(
                        record.stage,
                        matrix_sdk::encryption::InitialShareStage::ShareStateCommitted {
                            message_index: 0
                        }
                    )
            )
        });
        if initial_share_accepted {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(initial_share_accepted, "initial standard pre-share accepted");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(11)).await;
    let error = send.await.expect("send task panicked").expect_err("readiness deadline");
    assert!(
        matches!(
            &error,
            matrix_sdk::Error::EncryptionReadiness(error)
                if error.stage() == matrix_sdk::EncryptionReadinessStage::Deadline
        ),
        "unexpected readiness failure: {error:?}"
    );
    assert_eq!(
        alice
            .get_room(&room_id)
            .unwrap()
            .current_outbound_group_session_message_index()
            .await
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path().contains("/send/m.room.encrypted/"))
            .count(),
        0
    );
    assert!(diagnostics.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::EncryptionReadiness(record)
                if record.outcome == matrix_sdk::encryption::EncryptionReadinessOutcome::Deadline
                    && record.query
                        == matrix_sdk::encryption::EncryptionReadinessQueryState::NotStarted
                    && record.retryable
        )
    }));
}

#[async_test]
async fn test_cancelled_first_fence_leaves_resident_session_unfenced_for_retry() {
    let (server, alice, room_id, _diagnostics) = setup_room().await;
    let mut generation = alice.begin_encryption_sync_generation().expect("enabled readiness");
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let first = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .expect("joined room")
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    wait_for_index_zero(&alice, &room_id).await;
    first.abort();
    let _ = first.await;
    assert_eq!(
        alice
            .get_room(&room_id)
            .unwrap()
            .current_outbound_group_session_message_index()
            .await
            .unwrap(),
        Some(0),
        "cancellation must not consume index zero"
    );

    let request_count_before = server.server().received_requests().await.unwrap().len();
    generation.mark_received();
    alice
        .get_room(&room_id)
        .unwrap()
        .send(RoomMessageEventContent::text_plain("retry"))
        .await
        .expect("resident unfenced session is fenced on retry");
    let requests = server.server().received_requests().await.unwrap();
    assert!(
        requests[request_count_before..]
            .iter()
            .any(|request| request.url.path().ends_with("/keys/query")),
        "retry must run the authoritative query instead of bypassing an unchanged session"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path().contains("/send/m.room.encrypted/"))
            .count(),
        1
    );
}
