// Copyright 2026 The Matrix.org Foundation C.I.C.
// Licensed under the Apache License, Version 2.0.

use matrix_sdk_base::crypto::{olm::SenderData, vodozemac::Ed25519SecretKey};
use ruma::{device_id, user_id};

use super::same_forwarder_identity;

fn unverified(master: u8) -> SenderData {
    SenderData::sender_unverified(
        user_id!("@forwarder:example.invalid"),
        device_id!("FORWARDER"),
        Ed25519SecretKey::from_slice(&[master; 32]).public_key(),
    )
}

#[test]
fn a_master_change_with_the_same_user_and_device_is_rejected() {
    assert!(same_forwarder_identity(&unverified(1), &unverified(1)));
    assert!(!same_forwarder_identity(&unverified(1), &unverified(2)));
}

#[test]
fn verification_can_upgrade_without_changing_the_pinned_owner() {
    let old = unverified(1);
    let SenderData::SenderUnverified(owner) = old.clone() else { unreachable!() };
    let verified = SenderData::SenderVerified(owner.clone());
    assert!(same_forwarder_identity(&old, &verified));
    assert!(same_forwarder_identity(&verified, &verified));
    assert!(!same_forwarder_identity(&old, &SenderData::VerificationViolation(owner)));
    assert!(!same_forwarder_identity(&old, &SenderData::unknown()));
    assert!(!same_forwarder_identity(&SenderData::unknown(), &old));
}
