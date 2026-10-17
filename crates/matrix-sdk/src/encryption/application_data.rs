// Copyright 2026 The Matrix.org Foundation C.I.C.
// Licensed under the Apache License, Version 2.0.

use matrix_sdk_base::crypto::types::room_history::RoomKeyBundle;
use ruma::RoomId;

use super::{Device, Encryption, RoomKeyImportResult};
use crate::{Error, Result};

impl Encryption {
    /// Read application metadata from the crypto store. Encryption at rest
    /// follows the crypto-store configuration, unlike state-store custom data.
    pub async fn application_crypto_data(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let olm = self.client.olm_machine().await;
        let olm = olm.as_ref().ok_or(Error::NoOlmMachine)?;
        Ok(olm.store().get_value(&format!("application:{key}")).await?)
    }

    /// Persist application metadata in the crypto store. Empty data removes the
    /// namespaced value idempotently, avoiding accumulation of empty cache
    /// rows.
    pub async fn set_application_crypto_data(&self, key: &str, data: &[u8]) -> Result<()> {
        let olm = self.client.olm_machine().await;
        let olm = olm.as_ref().ok_or(Error::NoOlmMachine)?;
        if data.is_empty() {
            olm.store().remove_custom_value(&format!("application:{key}")).await?;
            return Ok(());
        }
        Ok(olm.store().set_value(&format!("application:{key}"), &data).await?)
    }

    /// Build a bundle containing only sessions eligible for sharing history.
    pub async fn shared_history_bundle(
        &self,
        room_id: &RoomId,
        max_keys: usize,
        max_bytes: usize,
    ) -> Result<Option<RoomKeyBundle>> {
        let olm = self.client.olm_machine().await;
        let olm = olm.as_ref().ok_or(Error::NoOlmMachine)?;
        Ok(olm.store().build_bounded_shared_history_bundle(room_id, max_keys, max_bytes).await?)
    }

    /// Import a bundle forwarded by a currently verified device. Authorization
    /// of the room and correlation of the authenticated transport are the
    /// caller's responsibility. Provenance and merge ordering remain
    /// crypto-store owned.
    pub async fn import_verified_history_bundle(
        &self,
        room_id: &RoomId,
        device: &Device,
        bundle: RoomKeyBundle,
    ) -> Result<Option<RoomKeyImportResult>> {
        let olm = self.client.olm_machine().await;
        let olm = olm.as_ref().ok_or(Error::NoOlmMachine)?;
        // Resolve through this client's store rather than trusting a Device
        // supplied from another Client instance.
        let Some(curve) = device.curve25519_key() else { return Ok(None) };
        let Some(current) = olm.get_device(device.user_id(), device.device_id(), None).await?
        else {
            return Ok(None);
        };
        if current.is_blacklisted()
            || current.ed25519_key() != device.ed25519_key()
            || current.curve25519_key() != Some(curve)
        {
            return Ok(None);
        }
        Ok(olm.store().import_verified_room_key_bundle(room_id, &current, bundle).await?)
    }
}
