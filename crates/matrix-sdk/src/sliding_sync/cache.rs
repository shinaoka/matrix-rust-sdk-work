//! Cache utilities.
//!
//! A `SlidingSync` instance can be stored in a cache, and restored from the
//! same cache. It helps to define what it sometimes called a “cold start”, or a
//!  “fast start”.

use std::collections::BTreeMap;

use matrix_sdk_base::{StateStore, StoreError};
use matrix_sdk_common::timer;
use ruma::{OwnedRoomId, UserId, api::client::sync::sync_events::v5 as http};
use tracing::{info, trace, warn};

use super::{FrozenSlidingSyncList, SlidingSync, SlidingSyncPositionMarkers};
#[cfg(doc)]
use crate::sliding_sync::SlidingSyncList;
use crate::{Client, Result, sliding_sync::SlidingSyncListCachePolicy};

/// Be careful: as this is used as a storage key; changing it requires migrating
/// data!
pub(super) fn format_storage_key_prefix(id: &str, user_id: &UserId) -> String {
    format!("sliding_sync_store::{id}::{user_id}")
}

/// Be careful: as this is used as a storage key; changing it requires migrating
/// data!
#[cfg(feature = "e2e-encryption")]
fn format_storage_key_for_sliding_sync(storage_key: &str) -> String {
    format!("{storage_key}::instance")
}

/// Be careful: as this is used as a storage key; changing it requires migrating
/// data!
fn format_storage_key_for_sliding_sync_list(storage_key: &str, list_name: &str) -> String {
    format!("{storage_key}::list::{list_name}")
}

/// Remove a previous [`SlidingSyncList`] cache entry from the state store.
async fn remove_cached_list(
    storage: &dyn StateStore<Error = StoreError>,
    storage_key: &str,
    list_name: &str,
) {
    let storage_key_for_list = format_storage_key_for_sliding_sync_list(storage_key, list_name);
    let _ = storage.remove_custom_value(storage_key_for_list.as_bytes()).await;
}

/// Store the `SlidingSync`'s state in the storage.
pub(super) async fn store_sliding_sync_state(
    sliding_sync: &SlidingSync,
    _position: &SlidingSyncPositionMarkers,
) -> Result<()> {
    let storage_key = &sliding_sync.inner.storage_key;

    trace!(storage_key, "Saving a `SlidingSync` to the state store");
    let storage = sliding_sync.inner.client.state_store();

    #[cfg(feature = "e2e-encryption")]
    {
        let position = _position;
        let instance_storage_key = format_storage_key_for_sliding_sync(storage_key);

        // FIXME (TERRIBLE HACK): we want to save `pos` in a cross-process safe manner,
        // with both processes sharing the same database backend; that needs to
        // go in the crypto process store at the moment, but should be fixed
        // later on.
        if let Some(olm_machine) = &*sliding_sync.inner.client.olm_machine().await {
            // Room subscriptions are server-side state scoped to this `pos`.
            // Persist both in one record so a resumed session does not treat
            // previously covered rooms as fresh subscriptions and invalidate
            // their member snapshots. A record without a position never
            // carries a coverage claim.
            let room_subscriptions = position
                .pos
                .as_ref()
                .map(|_| sliding_sync.inner.room_subscriptions.read().unwrap().clone())
                .unwrap_or_default();
            let pos_blob = serde_json::to_vec(&FrozenSlidingSyncPos {
                pos: position.pos.clone(),
                room_subscriptions,
            })?;
            olm_machine.store().set_custom_value(&instance_storage_key, pos_blob).await?;
        }
    }

    // Write every `SlidingSyncList` that's configured for caching into the store.
    let frozen_lists = {
        sliding_sync
            .inner
            .lists
            .read()
            .await
            .iter()
            .filter(|(_, list)| matches!(list.cache_policy(), SlidingSyncListCachePolicy::Enabled))
            .map(|(list_name, list)| {
                Ok((
                    format_storage_key_for_sliding_sync_list(storage_key, list_name),
                    serde_json::to_vec(&FrozenSlidingSyncList::freeze(list))?,
                ))
            })
            .collect::<Result<Vec<_>, crate::Error>>()?
    };

    for (storage_key_for_list, frozen_list) in frozen_lists {
        trace!(storage_key_for_list, "Saving a `SlidingSyncList`");

        storage.set_custom_value(storage_key_for_list.as_bytes(), frozen_list).await?;
    }

    Ok(())
}

/// Try to restore a single [`SlidingSyncList`] from the cache.
///
/// If it fails to deserialize for some reason, invalidate the cache entry.
pub(super) async fn restore_sliding_sync_list(
    storage: &dyn StateStore<Error = StoreError>,
    storage_key: &str,
    list_name: &str,
) -> Result<Option<FrozenSlidingSyncList>> {
    let _timer = timer!(format!("loading list from DB {list_name}"));

    let storage_key_for_list = format_storage_key_for_sliding_sync_list(storage_key, list_name);

    match storage
        .get_custom_value(storage_key_for_list.as_bytes())
        .await?
        .map(|custom_value| serde_json::from_slice::<FrozenSlidingSyncList>(&custom_value))
    {
        Some(Ok(frozen_list)) => {
            // List has been found and successfully deserialized.
            trace!(list_name, "successfully read the list from cache");
            return Ok(Some(frozen_list));
        }

        Some(Err(_)) => {
            // List has been found, but it wasn't possible to deserialize it. It's declared
            // as obsolete. The main reason might be that the internal representation of a
            // `SlidingSyncList` might have changed. Instead of considering this as a strong
            // error, we remove the entry from the cache and keep the list in its initial
            // state.
            warn!(
                list_name,
                "failed to deserialize the list from the cache, it is obsolete; removing the cache entry!"
            );
            // Let's clear the list and stop here.
            remove_cached_list(storage, storage_key, list_name).await;
        }

        None => {
            // A missing cache doesn't make anything obsolete.
            // We just do nothing here.
            trace!(list_name, "failed to find the list in the cache");
        }
    }

    Ok(None)
}

/// Fields restored during [`restore_sliding_sync_state`].
#[derive(Default)]
pub(super) struct RestoredFields {
    pub to_device_token: Option<String>,
    pub pos: Option<String>,
    pub room_subscriptions: BTreeMap<OwnedRoomId, http::request::RoomSubscription>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToDeviceTokenFormat {
    Absent,
    Sliding,
    Legacy,
}

fn classify_to_device_token(token: Option<String>) -> (Option<String>, ToDeviceTokenFormat) {
    match token {
        None => (None, ToDeviceTokenFormat::Absent),
        Some(token) if !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit()) => {
            (Some(token), ToDeviceTokenFormat::Sliding)
        }
        Some(_) => (None, ToDeviceTokenFormat::Legacy),
    }
}

/// A sliding sync position marker that can be persisted or restored from a
/// store.
#[cfg(feature = "e2e-encryption")]
#[derive(serde::Serialize, serde::Deserialize)]
struct FrozenSlidingSyncPos {
    #[serde(skip_serializing_if = "Option::is_none")]
    pos: Option<String>,
    /// Added after the original pos-only format. Old records deserialize to an
    /// empty map and therefore retain the conservative startup behaviour.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    room_subscriptions: BTreeMap<OwnedRoomId, http::request::RoomSubscription>,
}

/// Restore the `SlidingSync`'s state from what is stored in the storage.
///
/// If one cache is obsolete (corrupted, and cannot be deserialized or
/// anything), the entire `SlidingSync` cache is removed.
pub(super) async fn restore_sliding_sync_state(
    _client: &Client,
    _storage_key: &str,
) -> Result<Option<RestoredFields>> {
    #[cfg(not(feature = "e2e-encryption"))]
    return Ok(Some(Default::default()));

    #[cfg(feature = "e2e-encryption")]
    {
        let _timer = timer!(format!("loading sliding sync {_storage_key} state from DB"));

        let mut restored_fields = RestoredFields::default();

        if let Some(olm_machine) = &*_client.olm_machine().await {
            let (to_device_token, token_format) =
                classify_to_device_token(olm_machine.store().next_batch_token().await?);
            restored_fields.to_device_token = to_device_token;

            match token_format {
                ToDeviceTokenFormat::Absent => {
                    trace!("Couldn't read the previous to-device token from the crypto store")
                }
                ToDeviceTokenFormat::Sliding => {
                    trace!("Restored a Sliding Sync to-device token from the crypto store")
                }
                ToDeviceTokenFormat::Legacy => info!(
                    to_device_token_format = "legacy",
                    legacy_to_device_token_migration_applied = true,
                    "Ignored a classic-sync token before a Sliding Sync request"
                ),
            }

            let instance_storage_key = format_storage_key_for_sliding_sync(_storage_key);

            if let Ok(Some(blob)) =
                olm_machine.store().get_custom_value(&instance_storage_key).await
                && let Ok(frozen_pos) = serde_json::from_slice::<FrozenSlidingSyncPos>(&blob)
            {
                trace!("Successfully read the `Sliding Sync` pos from the crypto store cache");
                restored_fields.pos = frozen_pos.pos;
                if restored_fields.pos.is_some() {
                    restored_fields.room_subscriptions = frozen_pos.room_subscriptions;
                }
            }
        }

        Ok(Some(restored_fields))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use matrix_sdk_test::async_test;
    #[cfg(feature = "e2e-encryption")]
    use ruma::room_id;

    #[cfg(feature = "e2e-encryption")]
    use super::format_storage_key_for_sliding_sync;
    use super::{
        super::SlidingSyncList, format_storage_key_for_sliding_sync_list,
        format_storage_key_prefix, restore_sliding_sync_state, store_sliding_sync_state,
    };
    use crate::{Result, test_utils::logged_in_client};

    #[test]
    fn sliding_sync_to_device_token_classification() {
        use super::{ToDeviceTokenFormat, classify_to_device_token};

        assert_eq!(classify_to_device_token(None), (None, ToDeviceTokenFormat::Absent));
        assert_eq!(
            classify_to_device_token(Some("42".to_owned())),
            (Some("42".to_owned()), ToDeviceTokenFormat::Sliding)
        );

        for legacy in ["s123_4_5", "", "１２"] {
            assert_eq!(
                classify_to_device_token(Some(legacy.to_owned())),
                (None, ToDeviceTokenFormat::Legacy)
            );
        }
    }

    #[cfg(feature = "e2e-encryption")]
    #[test]
    fn legacy_pos_only_record_has_no_subscription_coverage() {
        let frozen: super::FrozenSlidingSyncPos =
            serde_json::from_str(r#"{"pos":"legacy"}"#).expect("legacy record must decode");
        assert_eq!(frozen.pos.as_deref(), Some("legacy"));
        assert!(frozen.room_subscriptions.is_empty());
    }

    #[allow(clippy::await_holding_lock)]
    #[async_test]
    async fn test_sliding_sync_can_be_stored_and_restored() -> Result<()> {
        let client = logged_in_client(Some("https://foo.bar".to_owned())).await;

        let store = client.state_store();

        let sync_id = "test-sync-id";
        let storage_key = format_storage_key_prefix(sync_id, client.user_id().unwrap());

        // Store entries don't exist.
        assert!(
            store
                .get_custom_value(
                    format_storage_key_for_sliding_sync_list(&storage_key, "list_foo").as_bytes()
                )
                .await?
                .is_none()
        );

        assert!(
            store
                .get_custom_value(
                    format_storage_key_for_sliding_sync_list(&storage_key, "list_bar").as_bytes()
                )
                .await?
                .is_none()
        );

        // Create a new `SlidingSync` instance, and store it.
        let storage_key = {
            let sliding_sync = client
                .sliding_sync(sync_id)?
                .add_cached_list(SlidingSyncList::builder("list_foo"))
                .await?
                .add_list(SlidingSyncList::builder("list_bar"))
                .build()
                .await?;

            // Modify both lists, so we can check expected caching behavior later.
            {
                let lists = sliding_sync.inner.lists.write().await;

                let list_foo = lists.get("list_foo").unwrap();
                list_foo.set_maximum_number_of_rooms(Some(42));

                let list_bar = lists.get("list_bar").unwrap();
                list_bar.set_maximum_number_of_rooms(Some(1337));
            }

            let position_guard = sliding_sync.inner.position.lock().await;
            assert!(sliding_sync.cache_to_storage(&position_guard).await.is_ok());

            storage_key
        };

        // Store entries now exist for `list_foo`.
        assert!(
            store
                .get_custom_value(
                    format_storage_key_for_sliding_sync_list(&storage_key, "list_foo").as_bytes()
                )
                .await?
                .is_some()
        );

        // But not for `list_bar`.
        assert!(
            store
                .get_custom_value(
                    format_storage_key_for_sliding_sync_list(&storage_key, "list_bar").as_bytes()
                )
                .await?
                .is_none()
        );

        // Create a new `SlidingSync`, and it should be read from the cache.
        let max_number_of_room_stream = Arc::new(RwLock::new(None));
        let cloned_stream = max_number_of_room_stream.clone();
        let sliding_sync = client
            .sliding_sync(sync_id)?
            .add_cached_list(SlidingSyncList::builder("list_foo").once_built(move |list| {
                // In the `once_built()` handler, nothing has been read from the cache yet.
                assert_eq!(list.maximum_number_of_rooms(), None);

                let mut stream = cloned_stream.write().unwrap();
                *stream = Some(list.maximum_number_of_rooms_stream());
                list
            }))
            .await?
            .add_list(SlidingSyncList::builder("list_bar"))
            .build()
            .await?;

        // Check the list' state.
        {
            let lists = sliding_sync.inner.lists.read().await;

            // This one was cached.
            let list_foo = lists.get("list_foo").unwrap();
            assert_eq!(list_foo.maximum_number_of_rooms(), Some(42));

            // This one wasn't.
            let list_bar = lists.get("list_bar").unwrap();
            assert_eq!(list_bar.maximum_number_of_rooms(), None);
        }

        // The maximum number of rooms reloaded from the cache should have been
        // published.
        {
            let mut stream =
                max_number_of_room_stream.write().unwrap().take().expect("stream must be set");
            let initial_max_number_of_rooms =
                stream.next().await.expect("stream must have emitted something");
            assert_eq!(initial_max_number_of_rooms, Some(42));
        }

        Ok(())
    }

    #[cfg(feature = "e2e-encryption")]
    #[async_test]
    async fn test_sliding_sync_high_level_cache_and_restore() -> Result<()> {
        let client = logged_in_client(Some("https://foo.bar".to_owned())).await;

        let sync_id = "test-sync-id";
        let storage_key_prefix = format_storage_key_prefix(sync_id, client.user_id().unwrap());
        let full_storage_key = format_storage_key_for_sliding_sync(&storage_key_prefix);
        let sliding_sync = client.sliding_sync(sync_id)?.build().await?;
        let restored_room_id = room_id!("!restored:example.org");

        // At first, there's nothing in both stores.
        if let Some(olm_machine) = &*client.base_client().olm_machine().await {
            let store = olm_machine.store();
            assert!(store.next_batch_token().await?.is_none());
        }

        let state_store = client.state_store();
        assert!(state_store.get_custom_value(full_storage_key.as_bytes()).await?.is_none());

        // Emulate some data to be cached.
        let pos = "pos".to_owned();
        {
            let mut position_guard = sliding_sync.inner.position.lock().await;
            position_guard.pos = Some(pos.clone());
            sliding_sync.subscribe_to_rooms(&[restored_room_id], None, false);

            // Then, we can correctly cache the sliding sync instance.
            store_sliding_sync_state(&sliding_sync, &position_guard).await?;
        }

        // Ok, forget about the sliding sync, let's recreate one from scratch.
        drop(sliding_sync);

        let restored_fields = restore_sliding_sync_state(&client, &storage_key_prefix)
            .await?
            .expect("must have restored sliding sync fields");

        // After restoring, to-device token could be read.
        assert_eq!(restored_fields.pos.unwrap(), pos);
        assert_eq!(restored_fields.room_subscriptions.len(), 1);
        assert!(restored_fields.room_subscriptions.contains_key(restored_room_id));

        let restored_sync = client.sliding_sync(sync_id)?.share_pos().build().await?;
        assert!(restored_sync.has_restored_room_subscriptions());
        assert!(restored_sync.subscribed_rooms().contains(restored_room_id));

        let retained = restored_sync.reconcile_subscriptions(&[restored_room_id], None, false);
        assert!(!retained.changed);
        assert!(retained.added.is_empty());
        assert!(retained.retained.contains(restored_room_id));

        let added_room_id = room_id!("!added:example.org");
        let expanded =
            restored_sync.reconcile_subscriptions(&[restored_room_id, added_room_id], None, false);
        assert!(expanded.changed);
        assert!(expanded.retained.contains(restored_room_id));
        assert!(expanded.added.contains(added_room_id));

        // Expiration invalidates the position and its coverage claim together.
        restored_sync.expire_session().await;
        assert!(!restored_sync.has_restored_room_subscriptions());
        assert!(restored_sync.subscribed_rooms().is_empty());
        let after_expiry = client.sliding_sync(sync_id)?.share_pos().build().await?;
        assert!(after_expiry.inner.position.lock().await.pos.is_none());
        assert!(!after_expiry.has_restored_room_subscriptions());
        assert!(after_expiry.subscribed_rooms().is_empty());

        // Test the "migration" path: assume a missing to-device token in crypto store,
        // but present in a former state store.

        // For our sanity, check no to-device token has been saved in the database.
        {
            let olm_machine = client.base_client().olm_machine().await;
            let olm_machine = olm_machine.as_ref().unwrap();
            assert!(olm_machine.store().next_batch_token().await?.is_none());
        }

        Ok(())
    }
}
