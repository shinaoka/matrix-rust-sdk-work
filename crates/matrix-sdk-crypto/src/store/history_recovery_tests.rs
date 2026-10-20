// Copyright 2026 The Matrix.org Foundation C.I.C.
// Licensed under the Apache License, Version 2.0.

use matrix_sdk_test::async_test;
use ruma::{device_id, room_id, user_id};
use vodozemac::megolm::GroupSession;

use crate::{
    Account, LocalTrust, OlmMachine,
    machine::test_helpers::{
        create_signed_device_of_unverified_user, create_signed_device_of_verified_user,
        create_unsigned_device,
    },
    olm::{ForwarderData, InboundGroupSession, PrivateCrossSigningIdentity, SenderData},
    types::EventEncryptionAlgorithm,
};

async fn fixture() -> (OlmMachine, OlmMachine, crate::Device, crate::Device) {
    let source = OlmMachine::new(user_id!("@source:example.invalid"), device_id!("SOURCE")).await;
    let receiver =
        OlmMachine::new(user_id!("@receiver:example.invalid"), device_id!("RECEIVER")).await;
    let account = Account::with_device_id(receiver.user_id(), receiver.device_id());
    let own = PrivateCrossSigningIdentity::for_account(
        &account,
        #[cfg(feature = "experimental-x509-identity-verification")]
        None,
    )
    .await
    .unwrap();
    let sender = Account::with_device_id(source.user_id(), source.device_id());
    let identity = PrivateCrossSigningIdentity::new(source.user_id().to_owned());
    let unverified =
        create_signed_device_of_unverified_user(sender.device_keys().clone(), &identity).await;
    let verified =
        create_signed_device_of_verified_user(sender.device_keys().clone(), &identity, &own).await;
    let keys = source.identity_keys();
    let session = InboundGroupSession::new(
        keys.curve25519,
        keys.ed25519,
        room_id!("!shared:example.invalid"),
        &GroupSession::new(Default::default()).session_key(),
        SenderData::unknown(),
        None,
        EventEncryptionAlgorithm::MegolmV1AesSha2,
        None,
        true,
    )
    .unwrap();
    source.store().save_inbound_group_sessions(&[session]).await.unwrap();
    (source, receiver, verified, unverified)
}

#[async_test]
async fn test_import_accepts_cross_signed_unverified_forwarder_without_promoting_trust() {
    let (source, receiver, _, unverified) = fixture().await;
    let room = room_id!("!shared:example.invalid");
    assert!(matches!(SenderData::from_device(&unverified), SenderData::SenderUnverified(_)));
    for expected in [1, 0] {
        let bundle = source
            .store()
            .build_bounded_shared_history_bundle(room, 4, 65536)
            .await
            .unwrap()
            .unwrap();
        let imported = receiver
            .store()
            .import_room_key_bundle_from_device(room, &unverified, bundle)
            .await
            .unwrap()
            .expect("cross-signed unverified forwarder must be accepted");
        assert_eq!(imported.imported_count, expected);
    }
    let sessions = receiver.store().get_inbound_group_sessions_by_room_id(room).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert!(matches!(sessions[0].forwarder_data, Some(ForwarderData::SenderUnverified(_))));
    assert!(matches!(SenderData::from_device(&unverified), SenderData::SenderUnverified(_)));
}

#[async_test]
async fn test_bounded_export_refuses_count_and_byte_overflow() {
    let (source, _, _, _) = fixture().await;
    let room = room_id!("!shared:example.invalid");
    assert!(
        source.store().build_bounded_shared_history_bundle(room, 0, 65536).await.unwrap().is_none()
    );
    assert!(
        source.store().build_bounded_shared_history_bundle(room, 4, 1).await.unwrap().is_none()
    );
    assert_eq!(
        source
            .store()
            .build_bounded_shared_history_bundle(room, 4, 65536)
            .await
            .unwrap()
            .unwrap()
            .room_keys
            .len(),
        1
    );
}

#[async_test]
async fn test_export_never_includes_sessions_without_shared_history() {
    let (source, _, _, _) = fixture().await;
    let keys = source.identity_keys();
    let room = room_id!("!shared:example.invalid");
    let private = InboundGroupSession::new(
        keys.curve25519,
        keys.ed25519,
        room,
        &GroupSession::new(Default::default()).session_key(),
        SenderData::unknown(),
        None,
        EventEncryptionAlgorithm::MegolmV1AesSha2,
        None,
        false,
    )
    .unwrap();
    let private_id = private.session_id().to_owned();
    source.store().save_inbound_group_sessions(&[private]).await.unwrap();
    let bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    assert_eq!(bundle.room_keys.len(), 1);
    assert_ne!(bundle.room_keys[0].session_id, private_id);
}

#[async_test]
async fn test_import_rejects_unsigned_blocked_or_changed_identity_and_is_room_scoped() {
    let (source, receiver, verified, unverified) = fixture().await;
    let room = room_id!("!shared:example.invalid");
    let unsigned = create_unsigned_device(unverified.as_device_keys().clone());
    unsigned.set_local_trust(LocalTrust::Verified).await.unwrap();
    let bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    assert!(
        receiver
            .store()
            .import_room_key_bundle_from_device(room, &unsigned, bundle)
            .await
            .unwrap()
            .is_none()
    );
    unverified
        .device_owner_identity
        .as_ref()
        .unwrap()
        .other()
        .unwrap()
        .mark_as_previously_verified();
    assert!(matches!(SenderData::from_device(&unverified), SenderData::VerificationViolation(_)));
    let bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    assert!(
        receiver
            .store()
            .import_room_key_bundle_from_device(room, &unverified, bundle)
            .await
            .unwrap()
            .is_none()
    );
    let bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    assert!(
        receiver
            .store()
            .import_room_key_bundle_from_device(
                room_id!("!other:example.invalid"),
                &verified,
                bundle
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(receiver.store().get_inbound_group_sessions_by_room_id(room).await.unwrap().is_empty());
    // A good entry followed by a wrong-room entry must not partially import.
    let mut bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    let mut wrong_room = source
        .store()
        .build_bounded_shared_history_bundle(room, 4, 65536)
        .await
        .unwrap()
        .unwrap()
        .room_keys
        .remove(0);
    wrong_room.room_id = room_id!("!other:example.invalid").to_owned();
    bundle.room_keys.push(wrong_room);
    assert!(
        receiver
            .store()
            .import_room_key_bundle_from_device(room, &verified, bundle)
            .await
            .unwrap()
            .is_none()
    );
    assert!(receiver.store().get_inbound_group_sessions_by_room_id(room).await.unwrap().is_empty());
    let bundle =
        source.store().build_bounded_shared_history_bundle(room, 4, 65536).await.unwrap().unwrap();
    verified.set_local_trust(LocalTrust::BlackListed).await.unwrap();
    assert!(
        receiver
            .store()
            .import_room_key_bundle_from_device(room, &verified, bundle)
            .await
            .unwrap()
            .is_none()
    );
    verified.set_local_trust(LocalTrust::Unset).await.unwrap();
    for expected in [1, 0] {
        let bundle = source
            .store()
            .build_bounded_shared_history_bundle(room, 4, 65536)
            .await
            .unwrap()
            .unwrap();
        let imported = receiver
            .store()
            .import_room_key_bundle_from_device(room, &verified, bundle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(imported.imported_count, expected);
    }
    assert_eq!(
        receiver.store().get_inbound_group_sessions_by_room_id(room).await.unwrap().len(),
        1
    );
}
