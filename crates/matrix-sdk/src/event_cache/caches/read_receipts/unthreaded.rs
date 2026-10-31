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

use std::collections::HashMap;

use matrix_sdk_base::{
    event_cache::store::EventCacheStoreLockGuard, linked_chunk::LinkedChunkId,
    read_receipts::ReadReceipts,
};
use ruma::{UserId, events::receipt::ReceiptThread};

use super::{ALL_RECEIPT_TYPES, ThreadReadReceiptEventFilter};
use crate::event_cache::{
    Result, caches::event_linked_chunk::EventLinkedChunk, persistence::load_linked_chunk_metadata,
};

/// Project room-wide receipts onto the loaded thread without inventing order.
/// Run after each history update, even with an active threaded receipt.
pub(in crate::event_cache::caches) async fn add_unthreaded_thread_boundaries(
    own_user_id: &UserId,
    filter: &ThreadReadReceiptEventFilter<'_>,
    events: &EventLinkedChunk,
    store: &EventCacheStoreLockGuard,
    receipts: &mut ReadReceipts,
) -> Result<()> {
    let thread_ids = events.events().filter_map(|(_, event)| event.event_id()).collect::<Vec<_>>();
    let mut outside_targets = Vec::new();
    for receipt_type in ALL_RECEIPT_TYPES {
        let Some((target, _)) = filter
            .state_store
            .get_user_room_receipt_event(
                filter.room_id,
                receipt_type,
                &ReceiptThread::Unthreaded,
                own_user_id,
            )
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        if thread_ids.contains(&target.as_ref()) {
            receipts.pending.push(target);
        } else {
            // Retain unresolved outside targets so their later arrival wakes the thread.
            receipts.pending.push(target.clone());
            outside_targets.push(target);
        }
    }
    if outside_targets.is_empty() || thread_ids.is_empty() {
        return Ok(());
    }

    let room_chunk = LinkedChunkId::Room(filter.room_id);
    let ids = thread_ids
        .iter()
        .map(|id| (*id).to_owned())
        .chain(outside_targets.iter().cloned())
        .collect();
    let positions = store
        .filter_duplicated_events(room_chunk, ids)
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();
    let Some(metadata) = load_linked_chunk_metadata(store, room_chunk).await? else {
        return Ok(());
    };
    // Chunk identifiers are not chronological; the validated chain is.
    let ranks = metadata
        .iter()
        .enumerate()
        .map(|(rank, chunk)| (chunk.identifier, rank))
        .collect::<HashMap<_, _>>();
    let order = |id: &ruma::EventId| {
        let position = positions.get(id)?;
        Some((*ranks.get(&position.chunk_identifier())?, position.index()))
    };
    for target in outside_targets {
        let Some(boundary) = order(&target) else { continue };
        if let Some((id, _)) = thread_ids
            .iter()
            .filter_map(|id| {
                let position = order(id)?;
                (position <= boundary).then_some((*id, position))
            })
            .max_by_key(|(_, position)| *position)
        {
            receipts.pending.push(id.to_owned());
        }
    }
    Ok(())
}
