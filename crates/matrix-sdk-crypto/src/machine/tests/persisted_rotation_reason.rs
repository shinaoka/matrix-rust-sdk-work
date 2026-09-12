// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use std::sync::Arc;

use matrix_sdk_test::async_test;
use ruma::{device_id, room_id, user_id};
use serde::Serialize;

use crate::{
    EncryptionSettings, OlmMachineBuilder,
    olm::SenderData,
    room_key_diagnostics::RoomKeyRotationReason,
    store::{CryptoStore, MemoryStore},
};

const PERSISTED_ROTATION_REASONS_KEY: &str = "koushi.room_key_rotation_reasons.v1";

#[async_test]
async fn test_persisted_rotation_reason_survives_machine_replacement() {
    let store = Arc::new(MemoryStore::new());
    let machine = OlmMachineBuilder::new(
        user_id!("@persisted:example.invalid"),
        device_id!("PERSISTED"),
    )
    .with_crypto_store(store.clone())
    .build()
    .await
    .unwrap();

    let initial_room = room_id!("!initial:example.invalid");
    let (initial, _) = machine
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            initial_room,
            EncryptionSettings::default(),
            SenderData::unknown(),
        )
        .await
        .unwrap();
    let initial_session = initial.session_id().to_owned();

    let expiry_room = room_id!("!expiry:example.invalid");
    let mut expiring_settings = EncryptionSettings::default();
    expiring_settings.rotation_period_msgs = 1;
    let (expiring, _) = machine
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            expiry_room,
            expiring_settings.clone(),
            SenderData::unknown(),
        )
        .await
        .unwrap();
    expiring.encrypt_helper("{}".to_owned()).await;
    let (expired, _) = machine
        .inner
        .group_session_manager
        .get_or_create_outbound_session(expiry_room, expiring_settings, SenderData::unknown())
        .await
        .unwrap();
    let expired_session = expired.session_id().to_owned();

    let reload_room = room_id!("!reload:example.invalid");
    let _ = machine
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            reload_room,
            EncryptionSettings::default(),
            SenderData::unknown(),
        )
        .await
        .unwrap();
    machine
        .discard_room_key_with_reason(reload_room, RoomKeyRotationReason::FullMemberListReload)
        .await
        .unwrap();
    let (reloaded, _) = machine
        .inner
        .group_session_manager
        .get_or_create_outbound_session(
            reload_room,
            EncryptionSettings::default(),
            SenderData::unknown(),
        )
        .await
        .unwrap();
    let reloaded_session = reloaded.session_id().to_owned();

    drop(machine);
    let restored = OlmMachineBuilder::new(
        user_id!("@persisted:example.invalid"),
        device_id!("PERSISTED"),
    )
    .with_crypto_store(store)
    .build()
    .await
    .unwrap();

    assert_eq!(
        restored.room_key_rotation_reason(initial_room, &initial_session),
        Some(RoomKeyRotationReason::Initial)
    );
    assert_eq!(
        restored.room_key_rotation_reason(expiry_room, &expired_session),
        Some(RoomKeyRotationReason::ExpiredMessageCount)
    );
    assert_eq!(
        restored.room_key_rotation_reason(reload_room, &reloaded_session),
        Some(RoomKeyRotationReason::FullMemberListReload)
    );
    assert_eq!(restored.room_key_rotation_reason(initial_room, &expired_session), None);
}

#[derive(Serialize)]
struct UnknownPersistedRotationReasons {
    version: u8,
    entries: Vec<()>,
}

#[async_test]
async fn test_invalid_persisted_rotation_reasons_fail_closed() {
    let store = Arc::new(MemoryStore::new());
    for invalid in [
        b"not-message-pack".to_vec(),
        rmp_serde::to_vec_named(&UnknownPersistedRotationReasons {
            version: 2,
            entries: Vec::new(),
        })
        .unwrap(),
        vec![0; 128 * 1024 + 1],
    ] {
        store.set_custom_value(PERSISTED_ROTATION_REASONS_KEY, invalid).await.unwrap();
        let machine = OlmMachineBuilder::new(
            user_id!("@invalid:example.invalid"),
            device_id!("INVALID"),
        )
        .with_crypto_store(store.clone())
        .build()
        .await
        .expect("invalid attribution must not block the crypto machine");
        assert_eq!(
            machine.room_key_rotation_reason(room_id!("!unknown:example.invalid"), "unknown"),
            None
        );
    }
}
