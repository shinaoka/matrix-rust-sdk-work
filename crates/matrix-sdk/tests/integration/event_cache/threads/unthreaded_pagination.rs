// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

use matrix_sdk::{
    assert_let_timeout,
    event_cache::{
        RoomTimelineGapProjectionId, RoomTimelineGapRepairBudget, RoomTimelineGapRepairOutcome,
    },
    test_utils::mocks::{MatrixMockServer, RoomMessagesResponseTemplate},
};
use matrix_sdk_test::{JoinedRoomBuilder, User, async_test, event_factory::EventFactory};
use ruma::{
    event_id,
    events::receipt::{ReceiptThread, ReceiptType},
    room_id,
};

#[async_test]
async fn test_room_history_resolves_thread_receipt_without_reading_later_reply() {
    for (receipt_type, targeted) in [
        (ReceiptType::Read, false),
        (ReceiptType::ReadPrivate, false),
        (ReceiptType::Read, true),
        (ReceiptType::ReadPrivate, true),
    ] {
        let server = MatrixMockServer::new().await;
        let client = super::client_with_threading_support(&server).await;
        let cache = client.event_cache().unwrap();
        let room_id = room_id!("!receipt:example.invalid");
        let root = event_id!("$root");
        let target = event_id!("$covered-main");
        let own = client.user_id().unwrap();
        let f = EventFactory::new().room(room_id).sender(User::Alice);
        server.sync_joined_room(&client, room_id).await;
        let (room, _room_handles) = cache.room(room_id).await.unwrap();
        let (thread, _thread_handles) = cache.thread(room_id, root).await.unwrap();
        let (_, mut updates) = thread.subscribe().await.unwrap();
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(f.text_msg("root").event_id(root))
                    .add_timeline_event(
                        f.text_msg("first").event_id(event_id!("$reply1")).in_thread(root, root),
                    )
                    .add_timeline_event(
                        f.text_msg("second").event_id(event_id!("$reply2")).in_thread(root, root),
                    ),
            )
            .await;
        assert_let_timeout!(Ok(_) = updates.recv());
        assert_eq!(thread.num_unread_messages().await.unwrap(), 2);

        // The room has an unresolved gap after the two older replies.
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .set_timeline_limited()
                    .set_timeline_prev_batch("before-tail")
                    .add_timeline_event(f.text_msg("tail").event_id(event_id!("$tail"))),
            )
            .await;
        while updates.try_recv().is_ok() {}
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_receipt(
                    f.read_receipts()
                        .add(target, own, receipt_type.clone(), ReceiptThread::Unthreaded)
                        .into_event(),
                ),
            )
            .await;
        assert_let_timeout!(Ok(_) = updates.recv());
        assert_eq!(thread.num_unread_messages().await.unwrap(), 2);
        while updates.try_recv().is_ok() {}
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("later").event_id(event_id!("$reply3")).in_thread(root, root),
                ),
            )
            .await;
        assert_let_timeout!(Ok(_) = updates.recv());
        assert_eq!(thread.num_unread_messages().await.unwrap(), 3);
        while updates.try_recv().is_ok() {}
        let mut info_updates = thread.subscribe_to_thread_info().await.unwrap();

        // Only room pagination reveals the receipt target, between reply2 and reply3.
        server
            .mock_room_messages()
            .match_limit(20)
            .ok(RoomMessagesResponseTemplate::default().events(vec![
                f.text_msg("covered main").event_id(target),
                f.text_msg("second").event_id(event_id!("$reply2")).in_thread(root, root),
            ]))
            .expect(1)
            .mount()
            .await;
        if targeted {
            let pagination = room.pagination();
            let inspection = pagination.inspect_timeline_gaps().await.unwrap();
            let result = pagination
                .repair_timeline_gap_with_projection(
                    inspection.gaps.last().unwrap(),
                    RoomTimelineGapRepairBudget { event_limit: 20, cached_chunk_limit: 8 },
                    RoomTimelineGapProjectionId { actor_generation: 1, repair_generation: 1 },
                )
                .await
                .unwrap();
            assert!(matches!(
                result.outcome,
                RoomTimelineGapRepairOutcome::StartReached { .. }
                    | RoomTimelineGapRepairOutcome::BoundariesJoined { .. }
                    | RoomTimelineGapRepairOutcome::Progress { .. }
            ));
        } else {
            let outcome = room.pagination().run_backwards_once(20).await.unwrap();
            assert!(outcome.events.iter().any(|event| event.event_id() == Some(target)));
        }
        assert_eq!(thread.num_unread_messages().await.unwrap(), 1, "{receipt_type}");
        assert_let_timeout!(Some(info) = info_updates.next());
        assert_eq!(info.read_receipts.num_unread, 1);
        assert_eq!(info.read_receipts.latest_active.unwrap().event_id, event_id!("$reply2"));
        assert!(updates.is_empty(), "refresh must not manufacture a receipt or thread event");
    }
}
