use matrix_sdk_test::JoinedRoomBuilder;
use ruma::{events::room::topic::RoomTopicEventContent, room_id};
use serde_json::{Value, json};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{header, method, path_regex, query_param},
};

use super::*;
use crate::test_utils::mocks::MatrixMockServer;

pub(super) async fn fixture() -> (MatrixMockServer, Client, OwnedRoomId) {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;
    let id = room_id!("!repair:localhost").to_owned();
    server.sync_joined_room(&client, &id).await;
    (server, client, id)
}
pub(super) fn full(room: &OwnedRoomId, kind: &str, content: Value, id: &str) -> Value {
    json!({"room_id":room,"type":kind,"state_key":"","event_id":id,"sender":"@example:localhost","origin_server_ts":1,"content":content})
}
pub(super) fn response(room: &OwnedRoomId, kinds: &[&str]) -> v5::Response {
    let mut response = v5::Response::new("repair-pos".into());
    let mut update = v5::response::Room::new();
    for kind in kinds {
        update.timeline.push(
            Raw::new(&full(room, kind, json!({}), "$historical:localhost"))
                .unwrap()
                .cast_unchecked(),
        );
    }
    response.rooms.insert(room.clone(), update);
    response
}
pub(super) fn requested() -> RequestedRequiredStates {
    RequestedRequiredStates::new(
        vec![
            (StateEventType::RoomTopic, String::new()),
            (StateEventType::RoomPowerLevels, String::new()),
        ],
        Default::default(),
    )
}
pub(super) async fn mock_get(server: &MatrixMockServer, kind: &str, event: Value) {
    Mock::given(method("GET"))
        .and(path_regex(format!(r".*/state/{kind}/?$")))
        .and(query_param("format", "event"))
        .and(header("authorization", "Bearer 1234"))
        .respond_with(ResponseTemplate::new(200).set_body_json(event))
        .expect(1)
        .mount(server.server())
        .await;
}

#[tokio::test]
async fn missing_requested_topic_and_power_levels_use_current_server_events_and_normal_commit() {
    let (server, client, room) = fixture().await;
    let own = client.user_id().unwrap();
    let denied = full(
        &room,
        "m.room.power_levels",
        json!({"users":{(own.as_str()):0},"state_default":50}),
        "$denied:localhost",
    );
    let mut create = full(
        &room,
        "m.room.create",
        json!({"creator":"@creator:localhost","room_version":"11"}),
        "$create:localhost",
    );
    create["sender"] = json!("@creator:localhost");
    server
        .mock_sync()
        .ok_and_run(&client, |builder| {
            builder.add_joined_room(
                JoinedRoomBuilder::new(&room)
                    .add_state_event(Raw::<AnySyncStateEvent>::from_json(
                        serde_json::value::to_raw_value(&create).unwrap(),
                    ))
                    .add_state_event(Raw::<AnySyncStateEvent>::from_json(
                        serde_json::value::to_raw_value(&denied).unwrap(),
                    )),
            );
        })
        .await;
    let before = client.get_room(&room).unwrap();
    assert!(
        !before
            .power_levels_or_default()
            .await
            .user_can_send_state(before.own_user_id(), StateEventType::RoomTopic)
    );
    mock_get(
        &server,
        "m.room.topic",
        full(&room, "m.room.topic", json!({"topic":"remote current"}), "$current-topic:localhost"),
    )
    .await;
    mock_get(
        &server,
        "m.room.power_levels",
        full(
            &room,
            "m.room.power_levels",
            json!({"users":{(own.as_str()):0},"state_default":50,"events":{"m.room.topic":0}}),
            "$current-power:localhost",
        ),
    )
    .await;
    let mut response = response(&room, &["m.room.topic", "m.room.power_levels"]);
    repair(&client, &requested(), &BTreeSet::from([room.clone()]), &mut response).await;
    assert_eq!(response.rooms[&room].required_state.len(), 2);
    client.process_sliding_sync_test_helper(&response, &requested()).await.unwrap();
    let room = client.get_room(&room).unwrap();
    assert_eq!(room.topic().as_deref(), Some("remote current"));
    let power =
        room.power_levels().await.expect("repaired power levels and creator are inspectable");
    assert!(power.user_can_send_state(room.own_user_id(), StateEventType::RoomTopic));
    assert!(!power.user_can_send_state(room.own_user_id(), StateEventType::RoomName));
    let canonical_power = room
        .get_state_event_static::<ruma::events::room::power_levels::RoomPowerLevelsEventContent>()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        canonical_power.deserialize().unwrap().event_id().unwrap().as_str(),
        "$current-power:localhost"
    );
    assert!(
        room.power_levels_or_default()
            .await
            .user_can_send_state(room.own_user_id(), StateEventType::RoomTopic)
    );
    assert!(
        !room
            .power_levels_or_default()
            .await
            .user_can_send_state(room.own_user_id(), StateEventType::RoomName)
    );
    assert_eq!(
        room.get_state_event_static::<RoomTopicEventContent>()
            .await
            .unwrap()
            .unwrap()
            .deserialize()
            .unwrap()
            .event_id()
            .unwrap()
            .as_str(),
        "$current-topic:localhost"
    );
}

#[tokio::test]
async fn supplied_canonical_and_unrequested_or_crypto_state_never_trigger_gets() {
    let (server, client, room) = fixture().await;
    let mut response = response(
        &room,
        &["m.room.topic", "m.room.power_levels", "m.room.member", "m.room.encryption"],
    );
    let canonical =
        Raw::new(&full(&room, "m.room.topic", json!({"topic":"provided"}), "$provided:localhost"))
            .unwrap()
            .cast_unchecked();
    response.rooms.get_mut(&room).unwrap().required_state.push(canonical);
    let selected = RequestedRequiredStates::new(
        vec![
            (StateEventType::RoomTopic, String::new()),
            (StateEventType::RoomEncryption, String::new()),
            (StateEventType::RoomMember, "*".into()),
        ],
        Default::default(),
    );
    repair(&client, &selected, &BTreeSet::new(), &mut response).await;
    assert_eq!(response.rooms[&room].required_state.len(), 1);
    assert!(
        server
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method != "GET" || !request.url.path().contains("/state/"))
    );
}

#[tokio::test]
async fn malformed_or_failed_repairs_preserve_original_response_and_other_successes() {
    let (server, client, room) = fixture().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/state/m.room.power_levels/?$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(server.server())
        .await;
    mock_get(
        &server,
        "m.room.topic",
        full(&room, "m.room.topic", json!({"topic":"authoritative"}), "$valid:localhost"),
    )
    .await;
    let mut response = response(&room, &["m.room.topic", "m.room.power_levels"]);
    let original = response_json(&response);
    repair(&client, &requested(), &BTreeSet::new(), &mut response).await;
    assert_eq!(response.rooms[&room].required_state.len(), 1);
    assert_eq!(
        response_json(&response)["rooms"][room.as_str()]["timeline"],
        original["rooms"][room.as_str()]["timeline"]
    );
    client.process_sliding_sync_test_helper(&response, &requested()).await.unwrap();
    assert_eq!(client.get_room(&room).unwrap().topic().as_deref(), Some("authoritative"));
}

#[tokio::test]
async fn validation_rejects_wrong_scope_content_missing_id_and_oversize() {
    let (_server, _client, room) = fixture().await;
    let candidate = Candidate { room: room.clone(), kind: StateEventType::RoomTopic };
    let valid = full(&room, "m.room.topic", json!({"topic":"current"}), "$valid:localhost");
    for invalid in [
        {
            let mut v = valid.clone();
            v["room_id"] = json!("!other:localhost");
            v
        },
        {
            let mut v = valid.clone();
            v["type"] = json!("m.room.name");
            v
        },
        {
            let mut v = valid.clone();
            v["state_key"] = json!("other");
            v
        },
        {
            let mut v = valid.clone();
            v.as_object_mut().unwrap().remove("event_id");
            v
        },
        {
            let mut v = valid.clone();
            v["content"] = json!({"topic":12});
            v
        },
        full(
            &room,
            "m.room.topic",
            json!({"topic":"x".repeat(MAX_EVENT_BYTES)}),
            "$oversize:localhost",
        ),
    ] {
        assert!(validated(Raw::new(&invalid).unwrap().cast_unchecked(), &candidate).is_none());
    }
    assert!(validated(Raw::new(&valid).unwrap().cast_unchecked(), &candidate).is_some());
}

#[tokio::test]
async fn candidates_are_unique_bounded_and_prioritize_explicit_rooms() {
    let (server, client, room) = fixture().await;
    let mut response = response(&room, &["m.room.topic", "m.room.topic", "m.room.power_levels"]);
    for index in 0..8 {
        let id: OwnedRoomId = format!("!other-{index}:localhost").parse().unwrap();
        server.sync_joined_room(&client, &id).await;
        response.rooms.extend(self::response(&id, &["m.room.topic", "m.room.power_levels"]).rooms);
    }
    let result = candidates(&client, &requested(), &BTreeSet::from([room.clone()]), &response);
    assert_eq!(result.len(), MAX_REPAIRS);
    assert!(result.iter().take(2).all(|candidate| candidate.room == room));
    let unique: BTreeSet<_> =
        result.iter().map(|candidate| (&candidate.room, &candidate.kind)).collect();
    assert_eq!(unique.len(), result.len());
}

#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;

fn response_json(response: &v5::Response) -> Value {
    json!({"pos": response.pos, "rooms": response.rooms})
}

#[tokio::test]
async fn nonjoined_or_leaving_room_is_never_repaired() {
    let (_server, client, room) = fixture().await;
    let mut response = response(&room, &["m.room.topic"]);
    let mut left = full(&room, "m.room.member", json!({"membership":"leave"}), "$left:localhost");
    left["state_key"] = json!(client.user_id().unwrap());
    response
        .rooms
        .get_mut(&room)
        .unwrap()
        .required_state
        .push(Raw::from_json(serde_json::value::to_raw_value(&left).unwrap()));
    assert!(candidates(&client, &requested(), &BTreeSet::new(), &response).is_empty());
    let unknown = room_id!("!unknown:localhost").to_owned();
    assert!(
        candidates(
            &client,
            &requested(),
            &BTreeSet::new(),
            &self::response(&unknown, &["m.room.topic"])
        )
        .is_empty()
    );
}

#[tokio::test]
async fn unknown_token_does_not_refresh_repeat_or_change_session() {
    let server = MatrixMockServer::new().await;
    let client =
        server.client_builder().on_builder(|builder| builder.handle_refresh_tokens()).build().await;
    client.auth_ctx().set_session_tokens(crate::SessionTokens {
        access_token: "1234".into(),
        refresh_token: Some("synthetic-refresh".into()),
    });
    let room = room_id!("!repair-auth:localhost").to_owned();
    server.sync_joined_room(&client, &room).await;
    let mut changes = client.subscribe_to_session_changes();
    Mock::given(method("GET"))
        .and(path_regex(r".*/state/m.room.topic/?$"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"errcode":"M_UNKNOWN_TOKEN","error":"synthetic"})),
        )
        .expect(1)
        .mount(server.server())
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/refresh$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server.server())
        .await;
    let mut response = response(&room, &["m.room.topic"]);
    repair(&client, &requested(), &BTreeSet::new(), &mut response).await;
    assert!(response.rooms[&room].required_state.is_empty());
    assert!(changes.try_recv().is_err());
    assert!(client.access_token().is_some());
}
