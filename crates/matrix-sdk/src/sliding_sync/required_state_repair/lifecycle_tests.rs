use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

use super::*;

#[tokio::test]
async fn timeout_is_one_global_budget_and_does_not_retry_or_discard_original_events() {
    let (server, client, room) = fixture().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/state/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_delay(Duration::from_secs(5)).set_body_json(full(
                &room,
                "m.room.topic",
                json!({"topic":"late"}),
                "$late:localhost",
            )),
        )
        .expect(2)
        .mount(server.server())
        .await;
    let mut response = response(&room, &["m.room.topic", "m.room.power_levels"]);
    let original = response_json(&response);
    let started = std::time::Instant::now();
    repair(&client, &requested(), &BTreeSet::new(), &mut response).await;
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(response_json(&response), original);
    client.process_sliding_sync_test_helper(&response, &requested()).await.unwrap();
}

#[tokio::test]
async fn real_response_owner_repairs_after_caller_abort_without_holding_global_store_lock() {
    let (server, client, room) = fixture().await;
    let sync = client.sliding_sync("repair-owner").unwrap().build().await.unwrap();
    let mut settings = v5::request::RoomSubscription::default();
    settings.required_state = vec![(StateEventType::RoomTopic, String::new())];
    sync.add_room_subscriptions(&[&room], Some(settings), false);
    let first = response_json(&response(&room, &["m.room.topic"]));
    let mut second = response(&room, &[]);
    second.pos = "newer-position".into();
    second.rooms.get_mut(&room).unwrap().required_state.push(
        Raw::new(&full(&room, "m.room.topic", json!({"topic":"next response"}), "$next:localhost"))
            .unwrap()
            .cast_unchecked(),
    );
    let second = response_json(&second);
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    Mock::given(method("POST"))
        .and(path_regex(r".*/sync$"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    first.clone()
                } else {
                    second.clone()
                },
            )
        })
        .expect(2)
        .mount(server.server())
        .await;
    let observed = Arc::new(Notify::new());
    let started = observed.notified();
    let notify = observed.clone();
    let fetched = full(&room, "m.room.topic", json!({"topic":"GET current"}), "$get:localhost");
    Mock::given(method("GET"))
        .and(path_regex(r".*/state/m.room.topic/?$"))
        .respond_with(move |_: &wiremock::Request| {
            notify.notify_one();
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(fetched.clone())
        })
        .expect(1)
        .mount(server.server())
        .await;
    let first_sync = sync.clone();
    let task = tokio::spawn(async move { first_sync.sync_once().await });
    tokio::time::timeout(Duration::from_secs(2), started).await.unwrap();
    assert!(
        client.base_client().state_store_lock().try_lock().is_ok(),
        "repair HTTP cannot hold global store lock"
    );
    assert!(
        sync.inner.position.try_lock().is_err(),
        "existing position owner still orders response processing"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // A following response cannot start until the detached first commit drains.
    sync.sync_once().await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(client.get_room(&room).unwrap().topic().as_deref(), Some("next response"));
}
