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

//! Starting an event-focused timeline from the room cache, instead of
//! `/context`.

use matrix_sdk::{
    event_cache::{
        EventFocusThreadMode, EventLocalWindow, RoomLiveTailRefreshCancellation,
        RoomTimelineGapProjectionId,
    },
    linked_chunk::{ChunkIdentifier, LinkedChunkId, Position, Update},
    store::StoreConfig,
    test_utils::mocks::{
        MatrixMockServer, RoomContextResponseTemplate, RoomMessagesResponseTemplate,
    },
};
use matrix_sdk_base::event_cache::{
    Gap,
    store::{EventCacheStore, MemoryStore},
};
use matrix_sdk_common::cross_process_lock::CrossProcessLockConfig;
use matrix_sdk_test::{JoinedRoomBuilder, User, async_test, event_factory::EventFactory};
use ruma::{event_id, room_id};

fn window_event_ids(window: &EventLocalWindow) -> Vec<String> {
    window.events.iter().map(|event| event.event_id().unwrap().to_string()).collect()
}

/// The room holds the focused event inside a run bounded by two gaps, so the
/// timeline can start from those events: no `/context`, and both ends still
/// paginate through the gap tokens.
#[async_test]
async fn test_event_focused_starts_from_the_local_window_without_context() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let room_id = room_id!("!local-seed:example.org");
    let f = EventFactory::new().room(room_id).sender(User::Alice);

    // A live tail, with a backwards token: `[Gap(older), Items($a1, $a2)]`.
    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id)
                .set_timeline_prev_batch("older")
                .add_timeline_event(f.text_msg("a1").event_id(event_id!("$a1")))
                .add_timeline_event(f.text_msg("a2").event_id(event_id!("$a2"))),
        )
        .await;

    let event_cache = client.event_cache().unwrap();
    let (room_event_cache, _drop_handles) = event_cache.room(room_id).await.unwrap();

    // A live-tail refresh that shares no event with the cached suffix commits
    // the authoritative page as a detached tail, keeping its token as an
    // explicit historical gap: `[…, Items($a1, $a2), Gap(detached),
    // Items($d1, $d2)]`.
    server
        .mock_room_messages()
        .match_limit(8)
        .ok(RoomMessagesResponseTemplate::default().end_token("detached").events(vec![
            f.text_msg("d2").event_id(event_id!("$d2")).into_raw_timeline(),
            f.text_msg("d1").event_id(event_id!("$d1")).into_raw_timeline(),
        ]))
        .mock_once()
        .mount()
        .await;

    room_event_cache
        .pagination()
        .refresh_live_tail_with_projection(
            8,
            RoomTimelineGapProjectionId { actor_generation: 41, repair_generation: 1 },
            RoomLiveTailRefreshCancellation::new(),
        )
        .await
        .unwrap();

    // The window itself: the run that holds `$a2`, bounded by the two tokens.
    let window = room_event_cache
        .find_event_local_window(event_id!("$a2"))
        .await
        .unwrap()
        .expect("$a2 is in a contiguous run of the room cache");
    assert_eq!(window_event_ids(&window), ["$a1", "$a2"]);
    assert_eq!(window.target_index, 1);
    assert_eq!(window.prev_token.as_deref(), Some("older"));
    assert_eq!(window.next_token.as_deref(), Some("detached"));

    // Any `/context` request would be a regression: the events are right there.
    server
        .mock_room_event_context()
        .room(room_id)
        .ok(RoomContextResponseTemplate::new(f.text_msg("never asked").into_event()))
        .expect(0)
        .mount()
        .await;

    let (focused, _drop_handles) = event_cache
        .event_focused(
            room_id,
            event_id!("$a2"),
            EventFocusThreadMode::Automatic { hide_threaded_events: false },
            5,
        )
        .await
        .unwrap();

    let event_ids: Vec<_> = focused
        .events()
        .await
        .unwrap()
        .iter()
        .map(|event| event.event_id().unwrap().to_string())
        .collect();
    assert_eq!(event_ids, ["$a1", "$a2"], "the timeline starts from the local window");

    assert!(!focused.hit_timeline_start().await.unwrap(), "the window has an older token");
    assert!(!focused.hit_timeline_end().await.unwrap(), "the window has a newer token");

    // Backwards, through the front gap.
    server
        .mock_room_messages()
        .match_from("older")
        .ok(RoomMessagesResponseTemplate::default().events(vec![
            // Reverse topological order, as `/messages dir=b` returns them.
            f.text_msg("older2").event_id(event_id!("$older2")),
            f.text_msg("older1").event_id(event_id!("$older1")),
        ]))
        .mock_once()
        .mount()
        .await;

    let outcome = focused.paginate_backwards(10).await.unwrap();
    assert!(outcome.hit_end_of_timeline, "the response carried no further token");
    assert!(focused.hit_timeline_start().await.unwrap());

    // Forwards, through the back gap. The window's newer token is the detached
    // page's: paginating forwards asks the server for what comes after it.
    server
        .mock_room_messages()
        .match_from("detached")
        .ok(RoomMessagesResponseTemplate::default()
            .end_token("further")
            .events(vec![f.text_msg("x1").event_id(event_id!("$x1"))]))
        .mock_once()
        .mount()
        .await;

    let outcome = focused.paginate_forwards(10).await.unwrap();
    assert!(!outcome.hit_end_of_timeline);

    let event_ids: Vec<_> = focused
        .events()
        .await
        .unwrap()
        .iter()
        .map(|event| event.event_id().unwrap().to_string())
        .collect();
    assert_eq!(
        event_ids,
        ["$older1", "$older2", "$a1", "$a2", "$x1"],
        "both pagination directions worked from the seeded window"
    );

    // And `/context` was never called.
    server.verify_and_reset().await;
}

/// The focused event is not loaded in the room: the timeline asks `/context`.
#[async_test]
async fn test_event_focused_falls_back_to_context_for_an_event_the_room_does_not_hold() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let room_id = room_id!("!local-seed-missing:example.org");
    let f = EventFactory::new().room(room_id).sender(User::Alice);

    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id)
                .set_timeline_limited()
                .set_timeline_prev_batch("older")
                .add_timeline_event(f.text_msg("a1").event_id(event_id!("$a1"))),
        )
        .await;

    let event_cache = client.event_cache().unwrap();
    let (room_event_cache, _drop_handles) = event_cache.room(room_id).await.unwrap();

    assert!(
        room_event_cache.find_event_local_window(event_id!("$not-synced")).await.unwrap().is_none(),
        "an event the room never loaded has no local window"
    );

    server
        .mock_room_event_context()
        .room(room_id)
        .ok(RoomContextResponseTemplate::new(
            f.text_msg("target").event_id(event_id!("$not-synced")).into_event(),
        )
        .events_before(vec![f.text_msg("before").event_id(event_id!("$before")).into_event()])
        .events_after(vec![f.text_msg("after").event_id(event_id!("$after")).into_event()])
        .start("context-start")
        .end("context-end"))
        .expect(1)
        .mount()
        .await;

    let (focused, _drop_handles) = event_cache
        .event_focused(
            room_id,
            event_id!("$not-synced"),
            EventFocusThreadMode::Automatic { hide_threaded_events: false },
            5,
        )
        .await
        .unwrap();

    let event_ids: Vec<_> = focused
        .events()
        .await
        .unwrap()
        .iter()
        .map(|event| event.event_id().unwrap().to_string())
        .collect();
    assert_eq!(event_ids, ["$before", "$not-synced", "$after"]);

    server.verify_and_reset().await;
}

/// The run that holds the focused event starts after a chunk the cache has not
/// loaded, so its older end has no token: the timeline asks `/context` rather
/// than pretend the timeline starts there.
#[async_test]
async fn test_event_focused_falls_back_to_context_when_the_local_window_is_gapped() {
    let room_id = room_id!("!local-seed-gapped:example.org");
    let f = EventFactory::new().room(room_id).sender(User::Alice);

    // The store holds `[Items($a1), Gap("middle"), Items($b1)]`; only the last
    // chunk is loaded, so the gap before it is not.
    let event_cache_store = MemoryStore::new();
    event_cache_store
        .handle_linked_chunk_updates(
            LinkedChunkId::Room(room_id),
            vec![
                Update::NewItemsChunk { previous: None, new: ChunkIdentifier::new(0), next: None },
                Update::PushItems {
                    at: Position::new(ChunkIdentifier::new(0), 0),
                    items: vec![f.text_msg("a1").event_id(event_id!("$a1")).into_event()],
                },
                Update::NewGapChunk {
                    previous: Some(ChunkIdentifier::new(0)),
                    new: ChunkIdentifier::new(1),
                    next: None,
                    gap: Gap { token: "middle".to_owned() },
                },
                Update::NewItemsChunk {
                    previous: Some(ChunkIdentifier::new(1)),
                    new: ChunkIdentifier::new(2),
                    next: None,
                },
                Update::PushItems {
                    at: Position::new(ChunkIdentifier::new(2), 0),
                    items: vec![f.text_msg("b1").event_id(event_id!("$b1")).into_event()],
                },
            ],
        )
        .await
        .unwrap();

    let server = MatrixMockServer::new().await;
    let client = server
        .client_builder()
        .on_builder(move |builder| {
            builder.store_config(
                StoreConfig::new(CrossProcessLockConfig::MultiProcess {
                    holder_name: "foo".to_owned(),
                })
                .event_cache_store(event_cache_store),
            )
        })
        .build()
        .await;

    server.sync_joined_room(&client, room_id).await;

    let event_cache = client.event_cache().unwrap();
    let (room_event_cache, _drop_handles) = event_cache.room(room_id).await.unwrap();

    // The event is loaded…
    assert!(room_event_cache.find_event(event_id!("$b1")).await.unwrap().is_some());
    // …but the run it sits in cannot be paginated backwards from where it
    // starts.
    assert!(
        room_event_cache.find_event_local_window(event_id!("$b1")).await.unwrap().is_none(),
        "a run behind an unloaded chunk is not a usable start"
    );

    server
        .mock_room_event_context()
        .room(room_id)
        .ok(RoomContextResponseTemplate::new(
            f.text_msg("b1").event_id(event_id!("$b1")).into_event(),
        )
        .events_before(vec![f.text_msg("a1").event_id(event_id!("$a1")).into_event()])
        .start("context-start")
        .end("context-end"))
        .expect(1)
        .mount()
        .await;

    let (focused, _drop_handles) = event_cache
        .event_focused(
            room_id,
            event_id!("$b1"),
            EventFocusThreadMode::Automatic { hide_threaded_events: false },
            5,
        )
        .await
        .unwrap();

    let event_ids: Vec<_> = focused
        .events()
        .await
        .unwrap()
        .iter()
        .map(|event| event.event_id().unwrap().to_string())
        .collect();
    assert_eq!(event_ids, ["$a1", "$b1"]);

    server.verify_and_reset().await;
}

/// A threaded focused event, and any forced-thread timeline, still needs
/// `/context`: the room's window is the room's timeline, not the thread's.
#[async_test]
async fn test_event_focused_keeps_context_for_a_threaded_target() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let room_id = room_id!("!local-seed-thread:example.org");
    let f = EventFactory::new().room(room_id).sender(User::Alice);
    let thread_root = event_id!("$thread_root");
    let reply = event_id!("$thread_reply");

    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id)
                .add_timeline_event(f.text_msg("root").event_id(thread_root))
                .add_timeline_event(
                    f.text_msg("reply").in_thread(thread_root, thread_root).event_id(reply),
                ),
        )
        .await;

    let event_cache = client.event_cache().unwrap();
    let (room_event_cache, _drop_handles) = event_cache.room(room_id).await.unwrap();

    // The reply is loaded, inside a usable run of the room…
    assert!(
        room_event_cache.find_event_local_window(reply).await.unwrap().is_some(),
        "precondition: the threaded event has a local window"
    );

    // …but the timeline it needs is the thread's, which only `/context` can
    // locate. Both thread modes ask for it.
    server
        .mock_room_event_context()
        .room(room_id)
        .ok(RoomContextResponseTemplate::new(
            f.text_msg("reply").in_thread(thread_root, thread_root).event_id(reply).into_event(),
        )
        .events_before(vec![f.text_msg("root").event_id(thread_root).into_event()])
        .start("context-start")
        .end("context-end"))
        .expect(2)
        .mount()
        .await;

    let _ = event_cache
        .event_focused(
            room_id,
            reply,
            EventFocusThreadMode::Automatic { hide_threaded_events: false },
            5,
        )
        .await
        .unwrap();
    let _ = event_cache
        .event_focused(room_id, reply, EventFocusThreadMode::ForceThread, 5)
        .await
        .unwrap();

    server.verify_and_reset().await;
}
