// Copyright 2026 The Matrix.org Foundation C.I.C.
// Licensed under the Apache License, Version 2.0.

use matrix_sdk_crypto::{
    Account,
    store::{CryptoStore, types::Changes},
};
use matrix_sdk_test::async_test;
use ruma::{device_id, room_id, user_id};

#[async_test]
async fn test_bounded_room_inventory_rejects_overflow_before_unpickling() {
    let directory = tempfile::tempdir().unwrap();
    let store =
        super::SqliteCryptoStore::open(directory.path(), Some("synthetic-store-passphrase"))
            .await
            .unwrap();
    let account =
        Account::with_device_id(user_id!("@member:example.invalid"), device_id!("DEVICE"));
    let room = room_id!("!history:example.invalid");
    let (_, first) = account.create_group_session_pair_with_defaults(room).await;
    let (_, second) = account.create_group_session_pair_with_defaults(room).await;
    let (_, other) =
        account.create_group_session_pair_with_defaults(room_id!("!other:example.invalid")).await;
    store
        .save_changes(Changes {
            inbound_group_sessions: vec![first, second, other],
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(store.get_bounded_room_sessions(room, 0).await.unwrap().is_none());
    assert!(store.get_bounded_room_sessions(room, 1).await.unwrap().is_none());
    assert_eq!(store.get_bounded_room_sessions(room, 2).await.unwrap().unwrap().len(), 2);
    assert!(
        store
            .get_bounded_room_sessions(room_id!("!absent:example.invalid"), 0)
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    store.close().await.unwrap();
}
