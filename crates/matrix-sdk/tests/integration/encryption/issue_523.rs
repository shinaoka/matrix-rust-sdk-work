#![cfg(feature = "e2e-encryption")]

//! Integration reproductions for the bounded initial-share repair (issue #523).

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use matrix_sdk::{
    Client,
    encryption::{RoomKeyDiagnosticEvent, RoomKeyDiagnosticObserver},
    test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::{
    JoinedRoomBuilder, LeftRoomBuilder, async_test, event_factory::EventFactory, test_json,
};
use ruma::{
    RoomVersionId, device_id, events::room::message::RoomMessageEventContent, room_id, user_id,
};
use serde_json::{Value, json};
use tokio::sync::Notify;
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{method, path_regex},
};

const CLAIM_PATH: &str = r"^/_matrix/client/.*/keys/claim$";
const TO_DEVICE_PATH: &str = r"^/_matrix/client/.*/sendToDevice/m.room_key.withheld/.*";
const ROOM_SEND_PATH: &str = r"^/_matrix/client/.*/rooms/.*/send/m.room.encrypted/.*";

async fn setup_room(
    exhaust_one_time_keys: bool,
) -> (MatrixMockServer, Client, ruma::OwnedRoomId, Arc<Mutex<Vec<RoomKeyDiagnosticEvent>>>) {
    let server = MatrixMockServer::new().await;
    server.mock_crypto_endpoints_preset().await;
    let alice_user_id = user_id!("@alice:example.org");
    let bob_user_id = user_id!("@bob:example.org");
    let alice_device_id = device_id!("ALICEDEVICE");
    let bob_device_id = device_id!("BOBDEVICE");
    let alice =
        server.client_builder_for_crypto_end_to_end(alice_user_id, alice_device_id).build().await;
    let bob = server.client_builder_for_crypto_end_to_end(bob_user_id, bob_device_id).build().await;
    server.exchange_e2ee_identities(&alice, &bob).await;

    let room_id = room_id!("!issue523:example.org");
    let event_factory = EventFactory::new().sender(alice_user_id).room(room_id);
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let observer: RoomKeyDiagnosticObserver = Arc::new(move |event| {
        captured.lock().unwrap().push(event);
    });
    alice.encryption().set_room_key_diagnostic_observer(Some(observer)).await;
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
    if exhaust_one_time_keys {
        server.exhaust_one_time_keys(bob_user_id.to_owned(), bob_device_id.to_owned());
    }
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
async fn test_issue_523_matching_device_key_wake_runs_one_targeted_repair() {
    let (server, alice, room_id, events) = setup_room(false).await;
    let claims = Arc::new(Mutex::new(Vec::<Value>::new()));
    let claim_wake = Arc::new(Notify::new());
    let claims_for_mock = Arc::clone(&claims);
    let claim_wake_for_mock = Arc::clone(&claim_wake);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |request: &Request| {
            let mut claims = claims_for_mock.lock().unwrap();
            claims.push(serde_json::from_slice(&request.body).expect("claim body is JSON"));
            claim_wake_for_mock.notify_one();
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .up_to_n_times(2)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/.*/sendToDevice/m.room.encrypted/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .unwrap()
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    claim_wake.notified().await;
    claim_wake.notified().await;

    server
        .mock_sync()
        .ok_and_run(&alice, |builder| {
            builder.add_change_device(user_id!("@bob:example.org"));
        })
        .await;

    let _ = send.await.expect("send task panicked").expect("room send failed");
    let claims = claims.lock().unwrap();
    assert!(claims.len() >= 2, "the normal and immediate repair claims must run");
    assert!(claims.iter().all(|claim| {
        claim["one_time_keys"]["@bob:example.org"]
            .as_object()
            .is_some_and(|devices| devices.contains_key("BOBDEVICE"))
    }));
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.repair == matrix_sdk::encryption::InitialShareRepairOutcome::Settled
        )
    }));
}

#[async_test]
async fn test_issue_523_empty_claim_is_retried_before_the_first_event() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claims = Arc::new(Mutex::new(Vec::<Value>::new()));
    let claims_for_mock = Arc::clone(&claims);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |request: &Request| {
            claims_for_mock
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&request.body).expect("claim body is JSON"));
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("first")).await.unwrap();
    let claims = claims.lock().unwrap();
    assert!(claims.len() >= 2, "normal claim and targeted repair claim must both run");
    for claim in claims.iter() {
        let devices = claim["one_time_keys"]["@bob:example.org"]
            .as_object()
            .expect("claim must target Bob's devices");
        assert_eq!(devices.len(), 1, "the repair must remain device-targeted");
        assert!(devices.contains_key("BOBDEVICE"));
    }
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
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.claim == matrix_sdk::encryption::InitialShareRepairClaimOutcome::Empty
        )
    }));
}

#[async_test]
async fn test_issue_523_unmatched_repair_wake_respects_the_deadline() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claims = Arc::new(Mutex::new(Vec::<Value>::new()));
    let claim_wake = Arc::new(Notify::new());
    let claims_for_mock = Arc::clone(&claims);
    let claim_wake_for_mock = Arc::clone(&claim_wake);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |request: &Request| {
            claims_for_mock
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&request.body).expect("claim body is JSON"));
            claim_wake_for_mock.notify_one();
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    let room_send_attempts = Arc::new(AtomicUsize::new(0));
    let room_send_attempts_for_mock = Arc::clone(&room_send_attempts);
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(move |_request: &Request| {
            room_send_attempts_for_mock.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID)
        })
        .mount(server.server())
        .await;

    tokio::time::pause();
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .unwrap()
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    claim_wake.notified().await;
    claim_wake.notified().await;

    server
        .mock_sync()
        .ok_and_run(&alice, |builder| {
            builder.add_change_device(user_id!("@carol:example.org"));
        })
        .await;
    tokio::task::yield_now().await;
    assert_eq!(room_send_attempts.load(Ordering::SeqCst), 0);

    tokio::time::advance(Duration::from_millis(1500)).await;
    let _ = send.await.expect("send task panicked").expect("room send failed");
    assert_eq!(room_send_attempts.load(Ordering::SeqCst), 1);
    let claims = claims.lock().unwrap();
    assert_eq!(
        claims
            .iter()
            .filter(|claim| claim["one_time_keys"]["@bob:example.org"]
                .as_object()
                .is_some_and(|devices| devices.contains_key("BOBDEVICE")))
            .count(),
        2,
        "an unrelated wake must not schedule another Bob repair"
    );
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.repair == matrix_sdk::encryption::InitialShareRepairOutcome::Deadline
        )
    }));
}

#[async_test]
async fn test_issue_523_concurrent_first_events_share_one_repair_fence() {
    let (server, alice, room_id, _events) = setup_room(true).await;
    let claims = Arc::new(AtomicUsize::new(0));
    let claims_for_mock = Arc::clone(&claims);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |_request: &Request| {
            claims_for_mock.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    let room_sends = Arc::new(AtomicUsize::new(0));
    let room_sends_for_mock = Arc::clone(&room_sends);
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(move |_request: &Request| {
            room_sends_for_mock.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID)
        })
        .mount(server.server())
        .await;

    tokio::time::pause();
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let sends = tokio::spawn(async move {
        let first_room = send_client.get_room(&send_room_id).unwrap();
        let second_room = first_room.clone();
        tokio::join!(
            first_room.send(RoomMessageEventContent::text_plain("first")),
            second_room.send(RoomMessageEventContent::text_plain("second")),
        )
    });
    while claims.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    assert_eq!(room_sends.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_millis(1499)).await;
    tokio::task::yield_now().await;
    assert_eq!(room_sends.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::time::resume();
    let (first, second) = sends.await.expect("send task panicked");
    first.expect("first room send failed");
    second.expect("second room send failed");
    assert_eq!(room_sends.load(Ordering::SeqCst), 2);
    assert_eq!(claims.load(Ordering::SeqCst), 2, "the repair claim must be shared");
}

#[async_test]
async fn test_issue_523_room_leave_cancels_waiting_repair() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claim_wake = Arc::new(Notify::new());
    let claim_wake_for_mock = Arc::clone(&claim_wake);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |_request: &Request| {
            claim_wake_for_mock.notify_one();
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(0)
        .mount(server.server())
        .await;

    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .unwrap()
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    claim_wake.notified().await;
    claim_wake.notified().await;
    server.sync_room(&alice, LeftRoomBuilder::new(&room_id)).await;

    assert!(send.await.expect("send task panicked").is_err());
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.repair == matrix_sdk::encryption::InitialShareRepairOutcome::Cancelled
        )
    }));
}

#[async_test]
async fn test_issue_523_logout_cancels_waiting_repair() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claims = Arc::new(AtomicUsize::new(0));
    let claims_for_mock = Arc::clone(&claims);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |_request: &Request| {
            claims_for_mock.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/_matrix/client/.*/logout$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .unwrap()
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    while claims.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    alice.logout().await.unwrap();
    send.await.expect("send task panicked").expect("room send failed");
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.repair == matrix_sdk::encryption::InitialShareRepairOutcome::Cancelled
        )
    }));
}

#[async_test]
async fn test_issue_523_unusable_claim_key_is_classified_invalid() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claims = Arc::new(AtomicUsize::new(0));
    let claims_for_mock = Arc::clone(&claims);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |_request: &Request| {
            claims_for_mock.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "one_time_keys": {
                    "@bob:example.org": {
                        "BOBDEVICE": {
                            "signed_curve25519:invalid": {
                                "key": "invalid",
                                "signatures": {
                                    "@bob:example.org": { "ed25519:BOBDEVICE": "invalid" }
                                }
                            }
                        }
                    }
                }
            }))
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    tokio::time::pause();
    let send_client = alice.clone();
    let send_room_id = room_id.clone();
    let send = tokio::spawn(async move {
        send_client
            .get_room(&send_room_id)
            .unwrap()
            .send(RoomMessageEventContent::text_plain("first"))
            .await
    });
    while claims.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(1500)).await;
    tokio::time::resume();
    send.await.expect("send task panicked").expect("room send failed");
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.claim == matrix_sdk::encryption::InitialShareRepairClaimOutcome::Invalid
        )
    }));
}

#[async_test]
async fn test_issue_523_repair_claim_network_failure_is_closed_and_send_stays_encrypted() {
    let (server, alice, room_id, events) = setup_room(true).await;
    let claims = Arc::new(AtomicUsize::new(0));
    let claims_for_mock = Arc::clone(&claims);
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(move |_request: &Request| {
            if claims_for_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} }))
            } else {
                ResponseTemplate::new(500)
            }
        })
        .with_priority(1)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(TO_DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .expect(1)
        .mount(server.server())
        .await;

    let room = alice.get_room(&room_id).unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("first")).await.unwrap();
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.claim
                    == matrix_sdk::encryption::InitialShareRepairClaimOutcome::NetworkFailed
                    && record.repair
                        == matrix_sdk::encryption::InitialShareRepairOutcome::Failed
        )
    }));
}

#[async_test]
async fn test_issue_523_available_otk_repairs_the_room_key_before_index_zero() {
    let (server, alice, room_id, events) = setup_room(false).await;
    Mock::given(method("POST"))
        .and(path_regex(CLAIM_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "one_time_keys": {} })))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(server.server())
        .await;
    let encrypted_to_device = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let encrypted_to_device_for_mock = Arc::clone(&encrypted_to_device);
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/.*/sendToDevice/m.room.encrypted/.*"))
        .respond_with(move |_request: &Request| {
            encrypted_to_device_for_mock.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY)
        })
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/.*/sendToDevice/m.room_key.withheld/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EMPTY))
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(ROOM_SEND_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*test_json::EVENT_ID))
        .mount(server.server())
        .await;

    let request_start = server.server().received_requests().await.unwrap().len();
    let room = alice.get_room(&room_id).unwrap();
    let _ = room.send(RoomMessageEventContent::text_plain("first")).await.unwrap();
    assert_eq!(
        encrypted_to_device.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the targeted repair replaces the blind #510 duplicate"
    );
    let requests = server.server().received_requests().await.unwrap();
    let paths: Vec<_> =
        requests[request_start..].iter().map(|request| request.url.path().to_owned()).collect();
    let repair_claim = paths
        .iter()
        .rposition(|path| path.ends_with("/keys/claim"))
        .expect("targeted repair claim");
    let repaired_room_key = paths
        .iter()
        .position(|path| path.contains("/sendToDevice/m.room.encrypted/"))
        .expect("repaired m.room_key");
    let first_event = paths
        .iter()
        .position(|path| path.contains("/rooms/") && path.contains("/send/m.room.encrypted/"))
        .expect("first encrypted room event");
    assert!(repair_claim < repaired_room_key && repaired_room_key < first_event, "{paths:?}");
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
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RoomKeyDiagnosticEvent::InitialShareRepair(record)
                if record.claim == matrix_sdk::encryption::InitialShareRepairClaimOutcome::Accepted
                    && record.first_event_message_index == Some(0)
        )
    }));
}
