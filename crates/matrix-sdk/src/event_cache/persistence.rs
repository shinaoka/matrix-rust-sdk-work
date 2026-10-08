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
//
// Modified for the Koushi desktop fork (cache-only search verification); see
// docs/upstream/matrix-rust-sdk-feedback.md in the Koushi repository.

use std::collections::{HashMap, HashSet};

use matrix_sdk_base::{
    deserialized_responses::{TimelineEventKind, UnsignedEventLocation},
    event_cache::{Event, Gap, store::EventCacheStoreLockGuard},
    executor::spawn,
    linked_chunk::{ChunkMetadata, LinkedChunkId, OwnedLinkedChunkId, Update},
};
use ruma::{EventId, RoomId, events::relation::RelationType, serde::Raw};
use tokio::sync::broadcast::Sender;
use tracing::trace;

use super::{
    EventCacheError, Result,
    caches::{
        EventLocation, event_linked_chunk::EventLinkedChunk, room::RoomEventCacheLinkedChunkUpdate,
    },
};

/// Load a linked chunk's full metadata, making sure the chunks are
/// correct according to their links.
///
/// Returns `None` if there's no such linked chunk in the store, or an
/// error if the linked chunk is malformed.
pub(super) async fn load_linked_chunk_metadata(
    store_guard: &EventCacheStoreLockGuard,
    linked_chunk_id: LinkedChunkId<'_>,
) -> Result<Option<Vec<ChunkMetadata>>> {
    let mut all_chunks = store_guard
        .load_all_chunks_metadata(linked_chunk_id)
        .await
        .map_err(EventCacheError::from)?;

    if all_chunks.is_empty() {
        // There are no chunks, so there's nothing to do.
        return Ok(None);
    }

    // Transform the vector into a hashmap, for quick lookup of the predecessors.
    let chunk_map: HashMap<_, _> = all_chunks.iter().map(|meta| (meta.identifier, meta)).collect();

    // Find a last chunk.
    let mut iter = all_chunks.iter().filter(|meta| meta.next.is_none());
    let Some(last) = iter.next() else {
        return Err(EventCacheError::InvalidLinkedChunkMetadata {
            details: "no last chunk found".to_owned(),
        });
    };

    // There must at most one last chunk.
    if let Some(other_last) = iter.next() {
        return Err(EventCacheError::InvalidLinkedChunkMetadata {
            details: format!(
                "chunks {} and {} both claim to be last chunks",
                last.identifier.index(),
                other_last.identifier.index()
            ),
        });
    }

    // Rewind the chain back to the first chunk, and do some checks at the same
    // time.
    let mut seen = HashSet::new();
    let mut current = last;
    loop {
        // If we've already seen this chunk, there's a cycle somewhere.
        if !seen.insert(current.identifier) {
            return Err(EventCacheError::InvalidLinkedChunkMetadata {
                details: format!(
                    "cycle detected in linked chunk at {}",
                    current.identifier.index()
                ),
            });
        }

        let Some(prev_id) = current.previous else {
            // If there's no previous chunk, we're done.
            if seen.len() != all_chunks.len() {
                return Err(EventCacheError::InvalidLinkedChunkMetadata {
                    details: format!(
                        "linked chunk likely has multiple components: {} chunks seen through the chain of predecessors, but {} expected",
                        seen.len(),
                        all_chunks.len()
                    ),
                });
            }
            break;
        };

        // If the previous chunk is not in the map, then it's unknown
        // and missing.
        let Some(pred_meta) = chunk_map.get(&prev_id) else {
            return Err(EventCacheError::InvalidLinkedChunkMetadata {
                details: format!(
                    "missing predecessor {} chunk for {}",
                    prev_id.index(),
                    current.identifier.index()
                ),
            });
        };

        // If the previous chunk isn't connected to the next, then the link is invalid.
        if pred_meta.next != Some(current.identifier) {
            return Err(EventCacheError::InvalidLinkedChunkMetadata {
                details: format!(
                    "chunk {}'s next ({:?}) doesn't match the current chunk ({})",
                    pred_meta.identifier.index(),
                    pred_meta.next.map(|chunk_id| chunk_id.index()),
                    current.identifier.index()
                ),
            });
        }

        current = *pred_meta;
    }

    // At this point, `current` is the identifier of the first chunk.
    //
    // Reorder the resulting vector, by going through the chain of `next` links, and
    // swapping items into their final position.
    //
    // Invariant in this loop: all items in [0..i[ are in their final, correct
    // position.
    let mut current = current.identifier;

    for i in 0..all_chunks.len() {
        // Find the target metadata.
        let j = all_chunks
            .iter()
            .rev()
            .position(|meta| meta.identifier == current)
            .map(|j| all_chunks.len() - 1 - j)
            .expect("the target chunk must be present in the metadata");

        if i != j {
            all_chunks.swap(i, j);
        }

        if let Some(next) = all_chunks[i].next {
            current = next;
        }
    }

    Ok(Some(all_chunks))
}

/// Propagate linked chunk updates to the store and to the linked chunk update
/// observers.
pub(super) async fn send_updates_to_store(
    store: &EventCacheStoreLockGuard,
    linked_chunk_id: OwnedLinkedChunkId,
    linked_chunk_update_sender: &Sender<RoomEventCacheLinkedChunkUpdate>,
    mut updates: Vec<Update<Event, Gap>>,
) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }

    // Invariant: what search verification reads must equal what the timeline
    // renders. Drop mutable bundled relation summaries, but retain the replacement
    // event and its own encryption metadata, otherwise a bundle-only edit has no
    // surviving content after reconstruction and the index/read disagree.
    // It is a candidate, not proof of the latest edit: consumers must validate and
    // compare it with ordinary related events.
    for update in updates.iter_mut() {
        match update {
            Update::PushItems { items, .. } => strip_relations_from_events(items),
            Update::ReplaceItem { item, .. } => strip_relations_from_event(item),
            // Other update kinds don't involve adding new events.
            Update::NewItemsChunk { .. }
            | Update::NewGapChunk { .. }
            | Update::RemoveChunk(_)
            | Update::RemoveItem { .. }
            | Update::DetachLastItems { .. }
            | Update::StartReattachItems
            | Update::EndReattachItems
            | Update::Clear => {}
        }
    }

    // Spawn a task to make sure that all the changes are effectively forwarded to
    // the store, even if the call to this method gets aborted.
    //
    // The store cross-process locking involves an actual mutex, which ensures that
    // storing updates happens in the expected order.

    let store = store.clone();
    let cloned_updates = updates.clone();
    let cloned_linked_chunk_id = linked_chunk_id.clone();

    spawn(async move {
        trace!(updates = ?cloned_updates, "sending linked chunk updates to the store");

        store.handle_linked_chunk_updates(cloned_linked_chunk_id.as_ref(), cloned_updates).await?;
        trace!("linked chunk updates applied");

        Result::Ok(())
    })
    .await
    .expect("joining failed")?;

    // Forward that the store got updated to observers.
    let _ = linked_chunk_update_sender
        .send(RoomEventCacheLinkedChunkUpdate { linked_chunk_id, updates });

    Ok(())
}

/// Strip bundled summaries, retaining replacement candidates.
fn strip_relations_from_events(items: &mut [Event]) {
    for ev in items.iter_mut() {
        strip_relations_from_event(ev);
    }
}

/// Strip bundled summaries and their metadata, retaining the replacement pair.
fn strip_relations_from_event(ev: &mut Event) {
    match &mut ev.kind {
        TimelineEventKind::Decrypted(decrypted) => {
            if let Some(metadata) = &mut decrypted.unsigned_encryption_info {
                metadata.retain(|location, _| *location == UnsignedEventLocation::RelationsReplace);
                if metadata.is_empty() {
                    decrypted.unsigned_encryption_info = None;
                }
            }

            // Retain only the replacement candidate in the raw envelope.
            strip_relations_if_present(&mut decrypted.event);
        }

        TimelineEventKind::UnableToDecrypt { event, .. }
        | TimelineEventKind::PlainText { event } => {
            strip_relations_if_present(event);
        }
    }
}

/// Remove bundled summaries, retaining only the replacement candidate.
fn strip_relations_if_present<T>(event: &mut Raw<T>) {
    // Use a closure that returns an option so we can quickly short-circuit.
    let mut closure = || -> Option<()> {
        let mut val: serde_json::Value = event.deserialize_as().ok()?;
        let unsigned = val.get_mut("unsigned")?;
        let unsigned_obj = unsigned.as_object_mut()?;
        let relations = unsigned_obj.get_mut("m.relations")?;
        if let Some(relations) = relations.as_object_mut() {
            relations.retain(|key, _| key == "m.replace");
            if relations.is_empty() {
                unsigned_obj.remove("m.relations");
            }
        } else {
            unsigned_obj.remove("m.relations");
        }
        *event = Raw::new(&val).ok()?.cast_unchecked();
        None
    };
    let _ = closure();
}

/// Find a single event, first in-memory, then in-store.
pub async fn find_event(
    event_id: &EventId,
    room_id: &RoomId,
    event_linked_chunk: &EventLinkedChunk,
    store: &EventCacheStoreLockGuard,
) -> Result<Option<(EventLocation, Event)>> {
    // There are supposedly fewer events loaded in memory than in the store. Let's
    // start by looking up in the `EventLinkedChunk`.
    for (position, event) in event_linked_chunk.revents() {
        if event.event_id() == Some(event_id) {
            return Ok(Some((EventLocation::Memory(position), event.clone())));
        }
    }

    Ok(store.find_event(room_id, event_id).await?.map(|event| (EventLocation::Store, event)))
}

/// Find an event and all its relations in the persisted storage.
///
/// This goes straight to the database, as a simplification; we don't
/// expect to need to have to look up in memory events, or that
/// all the related events are actually loaded.
///
/// The related events are sorted like this:
/// - events saved out-of-band with `save_events` (if this method exists on the
///   cache calling this function) will be located at the beginning of the
///   array.
/// - events present in the linked chunk (be it in memory or in the database)
///   will be sorted according to their ordering in the linked chunk.
pub async fn find_event_with_relations(
    event_id: &EventId,
    room_id: &RoomId,
    filters: Option<Vec<RelationType>>,
    event_linked_chunk: &EventLinkedChunk,
    store: &EventCacheStoreLockGuard,
) -> Result<Option<(Event, Vec<Event>)>> {
    // First, hit storage to get the target event and its related events.
    let found = store.find_event(room_id, event_id).await?;

    let Some(target) = found else {
        // We haven't found the event: return early.
        return Ok(None);
    };

    // Then, find the transitive closure of all the related events.
    let related =
        find_event_relations(event_id, room_id, filters, event_linked_chunk, store).await?;

    Ok(Some((target, related)))
}

/// Find all relations for an event in the persisted storage.
///
/// This goes straight to the database, as a simplification; we don't
/// expect to need to have to look up in memory events, or that
/// all the related events are actually loaded.
///
/// The related events are sorted like this:
/// - events saved out-of-band with `save_events` (if this method exists on the
///   cache calling this function) will be located at the beginning of the
///   array.
/// - events present in the linked chunk (be it in memory or in the database)
///   will be sorted according to their ordering in the linked chunk.
pub async fn find_event_relations(
    event_id: &EventId,
    room_id: &RoomId,
    filters: Option<Vec<RelationType>>,
    event_linked_chunk: &EventLinkedChunk,
    store: &EventCacheStoreLockGuard,
) -> Result<Vec<Event>> {
    // Initialize the stack with all the related events, to find the
    // transitive closure of all the related events.
    let mut related = store.find_event_relations(room_id, event_id, filters.as_deref()).await?;
    let mut stack = related
        .iter()
        .filter_map(|(event, _pos)| event.event_id().map(ToOwned::to_owned))
        .collect::<Vec<_>>();

    // Also keep track of already seen events, in case there's a loop in the
    // relation graph.
    let mut already_seen = HashSet::new();
    already_seen.insert(event_id.to_owned());

    let mut num_iters = 1;

    // Find the related event for each previously-related event.
    while let Some(event_id) = stack.pop() {
        if !already_seen.insert(event_id.clone()) {
            // Skip events we've already seen.
            continue;
        }

        let other_related =
            store.find_event_relations(room_id, &event_id, filters.as_deref()).await?;

        stack.extend(
            other_related
                .iter()
                .filter_map(|(event, _pos)| event.event_id().map(ToOwned::to_owned)),
        );
        related.extend(other_related);

        num_iters += 1;
    }

    trace!(num_related = %related.len(), num_iters, "computed transitive closure of related events");

    // Sort the results by their positions in the linked chunk, if available.
    //
    // If an event doesn't have a known position, it goes to the start of the array.
    related.sort_by(|(_, lhs), (_, rhs)| {
        use std::cmp::Ordering;

        match (lhs, rhs) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(lhs), Some(rhs)) => {
                let lhs = event_linked_chunk.event_order(*lhs);
                let rhs = event_linked_chunk.event_order(*rhs);

                // The events should have a definite position, but in the case they don't,
                // still consider that not having a position means you'll end at the start
                // of the array.
                match (lhs, rhs) {
                    (None, None) => Ordering::Equal,
                    (None, Some(_)) => Ordering::Less,
                    (Some(_), None) => Ordering::Greater,
                    (Some(lhs), Some(rhs)) => lhs.cmp(&rhs),
                }
            }
        }
    });

    // Keep only the events, not their positions.
    let related = related.into_iter().map(|(event, _pos)| event).collect();

    Ok(related)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use matrix_sdk_base::deserialized_responses::{
        AlgorithmInfo, DecryptedRoomEvent, EncryptionInfo, TimelineEvent, UnableToDecryptInfo,
        UnableToDecryptReason, UnsignedDecryptionResult, VerificationState,
    };

    use super::*;

    #[test]
    fn persistence_keeps_only_replacement_envelope_and_its_own_metadata() {
        let value = serde_json::json!({
            "type":"m.room.message", "event_id":"$root", "room_id":"!room:localhost",
            "sender":"@member:localhost", "origin_server_ts":50,
            "content":{"msgtype":"m.text", "body":"original"},
            "unsigned":{"age":5, "m.relations":{
                "m.replace":{"type":"m.room.encrypted", "event_id":"$edit",
                    "sender":"@member:localhost", "origin_server_ts":100,
                    "content":{"algorithm":"m.megolm.v1.aes-sha2", "ciphertext":"synthetic",
                        "session_id":"child", "sender_key":"synthetic", "device_id":"TEST"}},
                "m.thread":{"count":2}, "m.annotation":{"chunk":[]}
            }}
        });
        let raw = Raw::new(&value).unwrap();
        let mut plaintext = TimelineEvent::from_plaintext(raw.clone().cast_unchecked());
        strip_relations_from_event(&mut plaintext);
        let persisted: serde_json::Value = plaintext.raw().deserialize_as().unwrap();
        assert_eq!(persisted["unsigned"]["age"], 5);
        assert_eq!(persisted["unsigned"]["m.relations"].as_object().unwrap().len(), 1);
        assert_eq!(
            persisted["unsigned"]["m.relations"]["m.replace"],
            value["unsigned"]["m.relations"]["m.replace"]
        );
        for keep_child in [false, true] {
            let info = || {
                UnsignedDecryptionResult::UnableToDecrypt(UnableToDecryptInfo {
                    session_id: Some("child".to_owned()),
                    reason: UnableToDecryptReason::Unknown,
                })
            };
            let mut metadata =
                BTreeMap::from([(UnsignedEventLocation::RelationsThreadLatestEvent, info())]);
            if keep_child {
                metadata.insert(UnsignedEventLocation::RelationsReplace, info());
            }
            // Synthetic proof metadata, not a key-exchange/decryption fixture.
            let mut event = TimelineEvent::from_decrypted(
                DecryptedRoomEvent {
                    event: raw.clone().cast_unchecked(),
                    encryption_info: Arc::new(EncryptionInfo {
                        sender: ruma::user_id!("@member:localhost").to_owned(),
                        sender_device: None,
                        forwarder: None,
                        verification_state: VerificationState::Verified,
                        algorithm_info: AlgorithmInfo::MegolmV1AesSha2 {
                            curve25519_key: "synthetic".to_owned(),
                            sender_claimed_keys: BTreeMap::new(),
                            session_id: Some("root".to_owned()),
                        },
                    }),
                    unsigned_encryption_info: Some(metadata),
                },
                None,
            );
            strip_relations_from_event(&mut event);
            let metadata = event.kind.unsigned_encryption_map();
            assert_eq!(metadata.is_some(), keep_child);
            if let Some(metadata) = metadata {
                assert_eq!(metadata.len(), 1);
                assert!(metadata.contains_key(&UnsignedEventLocation::RelationsReplace));
            }
            assert!(event.bundled_replacement().unwrap().kind.is_utd());
        }
        let mut thread_only =
            Raw::new(&serde_json::json!({"unsigned":{"m.relations":{"m.thread":{"count":2}}}}))
                .unwrap();
        strip_relations_if_present(&mut thread_only);
        let stripped: serde_json::Value = thread_only.deserialize_as().unwrap();
        assert!(stripped["unsigned"].get("m.relations").is_none());
    }
}
