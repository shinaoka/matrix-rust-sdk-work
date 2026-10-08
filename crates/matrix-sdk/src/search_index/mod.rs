// Copyright 2025 The Matrix.org Foundation C.I.C.
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

//! The search index is an abstraction layer in the matrix-sdk for the
//! matrix-sdk-search crate. It provides a [`SearchIndex`] which wraps
//! multiple [`RoomIndex`].

use std::{collections::hash_map::HashMap, path::PathBuf, sync::Arc};

use futures_util::future::join_all;
use matrix_sdk_base::{
    check_validity_of_replacement_events, deserialized_responses::TimelineEvent,
};
use matrix_sdk_search::{
    config::SearchIndexConfig,
    error::IndexError,
    index::{
        IndexableEvent, RoomIndex, RoomIndexOperation, SearchCursor, builder::RoomIndexBuilder,
    },
};
use ruma::{
    EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId,
    events::{
        AnySyncMessageLikeEvent, AnySyncTimelineEvent,
        poll::{
            start::SyncPollStartEvent,
            unstable_start::{SyncUnstablePollStartEvent, UnstablePollStartEventContent},
        },
        room::{
            message::{MessageType, OriginalSyncRoomMessageEvent, Relation, SyncRoomMessageEvent},
            redaction::SyncRoomRedactionEvent,
        },
        sticker::SyncStickerEvent,
    },
    room_version_rules::RedactionRules,
};
use tokio::sync::{Mutex, MutexGuard};
use tracing::{debug, warn};

use crate::event_cache::{EventCacheError, RoomEventCache};

type Password = String;

/// Type of location to store [`RoomIndex`]
#[derive(Clone, Debug)]
pub enum SearchIndexStoreKind {
    /// Store unencrypted in file system folder
    UnencryptedDirectory(PathBuf),
    // Matrix desktop fork patch surface: callers need to supply a custom
    // SearchIndexConfig so desktop search can use alternate tokenizers.
    /// Store unencrypted in a file system folder with a custom index config,
    /// such as an ngram tokenizer for substring search.
    UnencryptedDirectoryWithConfig(PathBuf, SearchIndexConfig),
    /// Store encrypted in file system folder
    EncryptedDirectory(PathBuf, Password),
    /// Store encrypted in a file system folder with a custom index config,
    /// such as an ngram tokenizer for substring search.
    EncryptedDirectoryWithConfig(PathBuf, Password, SearchIndexConfig),
    /// Store in memory
    InMemory,
    /// Store in memory with a custom index config for alternate tokenization
    /// or other search settings.
    InMemoryWithConfig(SearchIndexConfig),
}

impl SearchIndexStoreKind {
    // Matrix desktop fork patch surface: CJK desktop search needs substring
    // matching while preserving the SDK's encrypted on-disk search store.
    /// Convenience constructor for encrypted on-disk indexes using an ngram
    /// tokenizer, which improves substring matching for languages such as CJK.
    pub fn encrypted_directory_ngram(
        path: PathBuf,
        password: Password,
        min_gram: usize,
        max_gram: usize,
    ) -> Result<Self, matrix_sdk_search::config::NgramConfigError> {
        Ok(Self::EncryptedDirectoryWithConfig(
            path,
            password,
            SearchIndexConfig::ngram(min_gram, max_gram)?,
        ))
    }
}

/// Object that handles inteeraction with [`RoomIndex`]'s for search
#[derive(Clone, Debug)]
pub struct SearchIndex {
    /// HashMap that links each joined room to its RoomIndex
    room_indexes: Arc<Mutex<HashMap<OwnedRoomId, RoomIndex>>>,

    /// Base directory that stores the directories for each RoomIndex
    search_index_store_kind: SearchIndexStoreKind,
}

impl SearchIndex {
    /// Create a new [`SearchIndex`]
    pub fn new(
        room_indexes: Arc<Mutex<HashMap<OwnedRoomId, RoomIndex>>>,
        search_index_store_kind: SearchIndexStoreKind,
    ) -> Self {
        Self { room_indexes, search_index_store_kind }
    }

    /// Acquire [`SearchIndexGuard`] for this [`SearchIndex`].
    pub async fn lock(&self) -> SearchIndexGuard<'_> {
        SearchIndexGuard {
            index_map: self.room_indexes.lock().await,
            search_index_store_kind: &self.search_index_store_kind,
        }
    }
}

/// Object that represents an acquired [`SearchIndex`].
#[derive(Debug)]
pub struct SearchIndexGuard<'a> {
    /// Guard around the [`RoomIndex`] map
    index_map: MutexGuard<'a, HashMap<OwnedRoomId, RoomIndex>>,

    /// Base directory that stores the directories for each RoomIndex
    search_index_store_kind: &'a SearchIndexStoreKind,
}

impl SearchIndexGuard<'_> {
    fn create_index(&self, room_id: &RoomId) -> Result<RoomIndex, IndexError> {
        let index = match self.search_index_store_kind {
            SearchIndexStoreKind::UnencryptedDirectory(path) => {
                RoomIndexBuilder::new_on_disk(path.to_path_buf(), room_id).unencrypted().build()?
            }
            // Matrix desktop fork patch surface: config-bearing store kinds
            // must pass the injected config into RoomIndexBuilder before
            // selecting storage/encryption.
            SearchIndexStoreKind::UnencryptedDirectoryWithConfig(path, config) => {
                RoomIndexBuilder::new_on_disk(path.to_path_buf(), room_id)
                    .config(config.clone())
                    .unencrypted()
                    .build()?
            }
            SearchIndexStoreKind::EncryptedDirectory(path, password) => {
                RoomIndexBuilder::new_on_disk(path.to_path_buf(), room_id)
                    .encrypted(password)
                    .build()?
            }
            SearchIndexStoreKind::EncryptedDirectoryWithConfig(path, password, config) => {
                RoomIndexBuilder::new_on_disk(path.to_path_buf(), room_id)
                    .config(config.clone())
                    .encrypted(password)
                    .build()?
            }
            SearchIndexStoreKind::InMemory => RoomIndexBuilder::new_in_memory(room_id).build(),
            SearchIndexStoreKind::InMemoryWithConfig(config) => {
                RoomIndexBuilder::new_in_memory(room_id).config(config.clone()).build()
            }
        };
        Ok(index)
    }

    /// Handle a [`RoomIndexOperation`] in the [`RoomIndex`] of a given
    /// [`RoomId`]
    ///
    /// This which will add/remove/edit an event in the index based on the
    /// event type.
    ///
    /// Prefer [`SearchIndexGuard::bulk_execute`] for multiple operations.
    pub(crate) fn execute(
        &mut self,
        operation: RoomIndexOperation,
        room_id: &RoomId,
    ) -> Result<(), IndexError> {
        if !self.index_map.contains_key(room_id) {
            let index = self.create_index(room_id)?;
            self.index_map.insert(room_id.to_owned(), index);
        }

        let index = self.index_map.get_mut(room_id).expect("index should exist");

        index.execute(operation)
    }

    /// Handle a [`RoomIndexOperation`] in the [`RoomIndex`] of a given
    /// [`RoomId`]
    ///
    /// This which will add/remove/edit an event in the index based on the
    /// event type.
    pub(crate) fn bulk_execute(
        &mut self,
        operations: Vec<RoomIndexOperation>,
        room_id: &RoomId,
    ) -> Result<(), IndexError> {
        if !self.index_map.contains_key(room_id) {
            let index = self.create_index(room_id)?;
            self.index_map.insert(room_id.to_owned(), index);
        }

        let index = self.index_map.get_mut(room_id).expect("index should exist");

        index.bulk_execute(operations)
    }

    /// Search a [`Room`]'s index for the query and return at most
    /// max_number_of_results results.
    pub(crate) fn search(
        &mut self,
        query: &str,
        max_number_of_results: usize,
        pagination_offset: Option<usize>,
        room_id: &RoomId,
    ) -> Result<Vec<(f32, OwnedEventId)>, IndexError> {
        if !self.index_map.contains_key(room_id) {
            let index = self.create_index(room_id)?;
            self.index_map.insert(room_id.to_owned(), index);
        }

        let index = self.index_map.get_mut(room_id).expect("index should exist");

        index.search(query, max_number_of_results, pagination_offset)
    }

    /// Page a [`Room`]'s index with `query` treated as literal text, newest
    /// first.
    ///
    /// Returns at most `max_number_of_results` matches strictly older than
    /// `cursor`. Unlike [`SearchIndexGuard::search`], no offset is used, so
    /// memory stays bounded by the page size regardless of history depth.
    pub(crate) fn search_literal_page(
        &mut self,
        query: &str,
        max_number_of_results: usize,
        cursor: Option<SearchCursor>,
        room_id: &RoomId,
    ) -> Result<Vec<SearchCursor>, IndexError> {
        if !self.index_map.contains_key(room_id) {
            let index = self.create_index(room_id)?;
            self.index_map.insert(room_id.to_owned(), index);
        }

        let index = self.index_map.get_mut(room_id).expect("index should exist");

        index.search_literal_page(query, max_number_of_results, cursor)
    }

    /// Given a [`TimelineEvent`] this function will derive a
    /// [`RoomIndexOperation`], if it should be handled, and execute it;
    /// returning the result.
    ///
    /// Prefer [`SearchIndexGuard::bulk_handle_timeline_event`] for multiple
    /// events.
    pub async fn handle_timeline_event(
        &mut self,
        event: TimelineEvent,
        room_cache: &RoomEventCache,
        room_id: &RoomId,
        redaction_rules: &RedactionRules,
    ) -> Result<(), IndexError> {
        if let Some(index_operation) =
            parse_timeline_event(room_cache, event, redaction_rules).await?
        {
            self.execute(index_operation, room_id)
        } else {
            Ok(())
        }
    }

    /// Run [`SearchIndexGuard::handle_timeline_event`] for multiple
    /// [`TimelineEvent`].
    pub async fn bulk_handle_timeline_event<T>(
        &mut self,
        events: T,
        room_cache: &RoomEventCache,
        room_id: &RoomId,
        redaction_rules: &RedactionRules,
    ) -> Result<(), IndexError>
    where
        T: Iterator<Item = TimelineEvent>,
    {
        let futures = events.map(|ev| parse_timeline_event(room_cache, ev, redaction_rules));

        let prepared = join_all(futures).await.into_iter().collect::<Result<Vec<_>, _>>()?;
        let operations = prepared.into_iter().flatten().collect();

        self.bulk_execute(operations, room_id)
    }
}

/// Given an event id this function returns the most recent edit on said event
/// or the event itself if there are no edits.
async fn get_most_recent_edit(
    cache: &RoomEventCache,
    original: &EventId,
) -> Result<Option<OriginalSyncRoomMessageEvent>, EventCacheError> {
    use ruma::events::{AnySyncTimelineEvent, relation::RelationType};

    let Some((stored_original, mut related)) =
        cache.find_event_with_relations(original, Some(vec![RelationType::Replacement])).await?
    else {
        debug!("Couldn't find relations for {}", original);
        return Ok(None);
    };

    // Invariant: what search verification reads must equal what the timeline
    // renders. The UI renders the bundled replacement, so a bundle-only edit must
    // be a candidate here too; otherwise the index and the read disagree.
    //
    // Prefer the loaded root's latest envelope over a possibly older stored
    // candidate.
    let original_ev = cache.find_event(original).await?.unwrap_or(stored_original);
    if let Some(bundle) = original_ev.bundled_replacement()
        && !bundle.kind.is_utd()
        && let Some(id) = bundle.event_id()
        && !cache.redacted_event_ids(&[id.to_owned()]).await?.contains(id)
    {
        related.push(*bundle);
    }

    // Cache relations are ordered by linked-chunk position, not edit time.
    // Choose the greatest raw timestamp and event ID among visible valid edits;
    // a malformed or invalid newer edit must not hide an earlier valid version.
    let mut latest_valid: Option<OriginalSyncRoomMessageEvent> = None;
    for edit in &related {
        if edit.kind.is_utd() {
            continue;
        }
        if check_validity_of_replacement_events(
            original_ev.raw(),
            original_ev.encryption_info().map(|info| &**info),
            edit.raw(),
            edit.encryption_info().map(|info| &**info),
        )
        .is_err()
        {
            continue;
        }

        if let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(latest))) =
            edit.raw().deserialize()
            && let Some(latest) = latest.as_original()
            && latest_valid.as_ref().is_none_or(|current| {
                (latest.origin_server_ts, &latest.event_id)
                    > (current.origin_server_ts, &current.event_id)
            })
        {
            latest_valid = Some(latest.clone());
        }
    }
    if latest_valid.is_some() {
        return Ok(latest_valid);
    }

    Ok(match original_ev.raw().deserialize() {
        Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(latest))) => {
            latest.as_original().cloned()
        }
        _ => None,
    })
}

/// The most recent visible content for a cached message.
///
/// Produced by the cache-only resolver from the persistent event cache (no
/// network), with edits and redactions already resolved, so search
/// verification never reads stale pre-edit text.
///
/// Only room messages and stickers resolve. Polls are indexed but stay
/// excluded: their visible content can be replaced or ended, and resolving the
/// initial question would surface text the poll no longer shows.
#[derive(Clone)]
pub struct ResolvedMessage {
    /// The original (root) event id this message's display identity uses.
    pub event_id: OwnedEventId,
    /// The event id whose content is current; an edit id when the message has
    /// been edited.
    pub current_event_id: OwnedEventId,
    /// The sender of the message, from the resolved content.
    pub sender: OwnedUserId,
    /// Origin server timestamp of the resolved content, in milliseconds.
    pub timestamp_millis: Option<u64>,
    /// Visible message text: the body of a text-like message, or the caption of
    /// a media message.
    pub body: Option<String>,
    /// Filename of a media message.
    ///
    /// The index stores the filename as searchable text too, but resolution
    /// reports it separately so a filename match keeps its own match field.
    pub attachment_filename: Option<String>,
}

impl std::fmt::Debug for ResolvedMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedMessage")
            .field("event_id", &"EventId(..)")
            .field("current_event_id", &"EventId(..)")
            .field("sender", &"UserId(..)")
            .field("timestamp_millis", &self.timestamp_millis)
            .field("body", &self.body.as_ref().map(|_| "MessageBody(..)"))
            .field(
                "attachment_filename",
                &self.attachment_filename.as_ref().map(|_| "AttachmentFilename(..)"),
            )
            .finish()
    }
}

/// Resolve a message to its current visible content, reading only the local
/// event cache. Returns `None` when the event is missing or redacted.
///
/// Redacting the latest edit removes the edited document; it does not fall back
/// to an earlier edit version, because the cached redacted edit no longer
/// carries its relation. Clients that need that fallback must re-derive it from
/// their own durable relations.
pub(crate) async fn resolve_cached_message(
    cache: &RoomEventCache,
    event_id: &EventId,
) -> Result<Option<ResolvedMessage>, EventCacheError> {
    let Some(cached) = cache.find_event(event_id).await? else {
        return Ok(None);
    };
    if timeline_event_is_redacted(&cached) {
        return Ok(None);
    }

    let Ok(AnySyncTimelineEvent::MessageLike(event)) = cached.raw().deserialize() else {
        return Ok(None);
    };

    // A sticker's descriptive text is indexed, so it must resolve too; otherwise
    // the candidate is dropped and a previously findable sticker disappears.
    if let AnySyncMessageLikeEvent::Sticker(sticker) = event {
        let Some(original) = sticker.as_original() else {
            return Ok(None);
        };
        let body = original.content.body.clone();
        return Ok(Some(ResolvedMessage {
            event_id: original.event_id.clone(),
            current_event_id: original.event_id.clone(),
            sender: original.sender.clone(),
            timestamp_millis: Some(original.origin_server_ts.get().into()),
            body: Some(body.clone()),
            // A sticker carries one piece of text: the index writes it as the
            // searchable content and the crawler exposes it as both caption and
            // filename, so resolution reports it the same way and the caller's
            // content policy governs it identically.
            attachment_filename: Some(body),
        }));
    }

    let AnySyncMessageLikeEvent::RoomMessage(message) = event else {
        return Ok(None);
    };

    // A candidate id may be an edit event; resolve from the original message so
    // the newest valid edit wins either way.
    let original_id = message
        .as_original()
        .and_then(|original| match &original.content.relates_to {
            Some(Relation::Replacement(replacement)) => Some(replacement.event_id.clone()),
            _ => None,
        })
        .unwrap_or_else(|| event_id.to_owned());

    // Reject a redacted root even when the caller supplied one of its edit ids:
    // a surviving edit must not resurrect a message whose original was redacted.
    let Some(root) = cache.find_event(&original_id).await? else {
        return Ok(None);
    };
    if timeline_event_is_redacted(&root) {
        return Ok(None);
    }

    let Some(resolved) = get_most_recent_edit(cache, &original_id).await? else {
        return Ok(None);
    };

    let (body, attachment_filename) = resolved_text(visible_msgtype(&resolved));
    if body.is_none() && attachment_filename.is_none() {
        return Ok(None);
    }

    Ok(Some(ResolvedMessage {
        event_id: original_id,
        current_event_id: resolved.event_id.clone(),
        sender: resolved.sender.clone(),
        timestamp_millis: Some(resolved.origin_server_ts.get().into()),
        body,
        attachment_filename,
    }))
}

/// Whether a cached timeline event carries a redaction.
fn timeline_event_is_redacted(event: &TimelineEvent) -> bool {
    #[derive(serde::Deserialize)]
    struct Unsigned {
        redacted_because: Option<serde_json::Value>,
    }

    match event.raw().get_field::<Unsigned>("unsigned") {
        Ok(Some(unsigned)) => unsigned.redacted_because.is_some(),
        Ok(None) => false,
        // A malformed unsigned block cannot be trusted; fail closed.
        Err(_) => true,
    }
}

/// The message type carrying the currently visible content: the replacement's
/// `m.new_content` for an edit, otherwise the event's own content.
fn visible_msgtype(event: &OriginalSyncRoomMessageEvent) -> &MessageType {
    match &event.content.relates_to {
        Some(Relation::Replacement(replacement)) => &replacement.new_content.msgtype,
        _ => &event.content.msgtype,
    }
}

/// Indexable text for a media message: its filename plus any caption.
fn media_body(filename: &str, caption: Option<&str>) -> String {
    match caption {
        Some(caption) => format!("{filename} {caption}"),
        None => filename.to_owned(),
    }
}

/// Extract the searchable text from a room message, or `None` if its type
/// carries no text to index.
fn room_message_body(msgtype: &MessageType) -> Option<String> {
    match msgtype {
        MessageType::Text(content) => Some(content.body.clone()),
        MessageType::Emote(content) => Some(content.body.clone()),
        MessageType::Notice(content) => Some(content.body.clone()),
        MessageType::ServerNotice(content) => Some(content.body.clone()),
        MessageType::Location(content) => Some(content.body.clone()),
        MessageType::Image(content) => Some(media_body(content.filename(), content.caption())),
        MessageType::Video(content) => Some(media_body(content.filename(), content.caption())),
        MessageType::Audio(content) => Some(media_body(content.filename(), content.caption())),
        MessageType::File(content) => Some(media_body(content.filename(), content.caption())),
        _ => None,
    }
}

/// Split the visible content of a room message into text and, for media
/// messages, the filename.
///
/// The index stores the union of both, so a match may come from either; the
/// resolved reader keeps them apart so callers can report which field matched.
fn resolved_text(msgtype: &MessageType) -> (Option<String>, Option<String>) {
    match msgtype {
        MessageType::Image(content) => {
            (content.caption().map(ToOwned::to_owned), Some(content.filename().to_owned()))
        }
        MessageType::Video(content) => {
            (content.caption().map(ToOwned::to_owned), Some(content.filename().to_owned()))
        }
        MessageType::Audio(content) => {
            (content.caption().map(ToOwned::to_owned), Some(content.filename().to_owned()))
        }
        MessageType::File(content) => {
            (content.caption().map(ToOwned::to_owned), Some(content.filename().to_owned()))
        }
        _ => (room_message_body(msgtype), None),
    }
}

/// Build an [`IndexableEvent`] from a room message, or `None` if its type
/// carries no searchable text.
fn indexable_from_room_message(
    event: &OriginalSyncRoomMessageEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
    addressable_event_id: OwnedEventId,
) -> Option<IndexableEvent> {
    let body = room_message_body(visible_msgtype(event))?;
    let original_event_id = match &event.content.relates_to {
        Some(Relation::Replacement(replacement)) => replacement.event_id.clone(),
        _ => event.event_id.clone(),
    };

    Some(IndexableEvent::new(
        addressable_event_id,
        original_event_id,
        event.sender.clone(),
        timestamp,
        body,
    ))
}

/// Keep an edit-primary document only when that cache entry can route
/// resolution to its root. A missing/UTD/redacted/malformed child needs the
/// addressable root.
async fn addressable_message_id(
    event: &OriginalSyncRoomMessageEvent,
    cache: &RoomEventCache,
) -> Result<OwnedEventId, IndexError> {
    let Some(Relation::Replacement(replacement)) = &event.content.relates_to else {
        return Ok(event.event_id.clone());
    };
    if let Some(cached) =
        cache.find_event(&event.event_id).await.map_err(|_| IndexError::EventPreparationFailed)?
        && !cached.kind.is_utd()
        && let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(cached))) =
            cached.raw().deserialize()
        && let Some(cached) = cached.as_original()
        && matches!(&cached.content.relates_to, Some(Relation::Replacement(target)) if target.event_id == replacement.event_id)
    {
        return Ok(event.event_id.clone());
    }
    Ok(replacement.event_id.clone())
}

/// If the given [`OriginalSyncRoomMessageEvent`] is an edit we make an
/// [`RoomIndexOperation::Edit`] with the new most recent version of the
/// original.
async fn handle_possible_edit(
    event: &OriginalSyncRoomMessageEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
    cache: &RoomEventCache,
) -> Result<Option<RoomIndexOperation>, IndexError> {
    if let Some(Relation::Replacement(replacement_data)) = &event.content.relates_to {
        let recent = get_most_recent_edit(cache, &replacement_data.event_id)
            .await
            .map_err(|_| IndexError::EventPreparationFailed)?;
        let operation = if let Some(recent) = recent {
            let id = addressable_message_id(&recent, cache).await?;
            indexable_from_room_message(&recent, timestamp, id)
                .map_or(RoomIndexOperation::Noop, |indexable| {
                    RoomIndexOperation::Edit(replacement_data.event_id.clone(), indexable)
                })
        } else {
            RoomIndexOperation::Noop
        };
        return Ok(Some(operation));
    }
    Ok(None)
}

/// Refresh the canonical root's document with the currently visible message.
async fn handle_room_message(
    event: SyncRoomMessageEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
    cache: &RoomEventCache,
) -> Result<Option<RoomIndexOperation>, IndexError> {
    let Some(event) = event.as_original() else {
        return Ok(None);
    };
    if let Some(operation) = handle_possible_edit(event, timestamp, cache).await? {
        return Ok(Some(operation));
    }
    let recent = get_most_recent_edit(cache, &event.event_id)
        .await
        .map_err(|_| IndexError::EventPreparationFailed)?;
    let Some(recent) = recent else {
        return Ok(None);
    };
    let id = addressable_message_id(&recent, cache).await?;
    Ok(indexable_from_room_message(&recent, timestamp, id)
        .map(|indexable| RoomIndexOperation::Edit(event.event_id.clone(), indexable)))
}

/// Return a [`RoomIndexOperation`] removing a redacted event from the index, or
/// re-adding the most recent remaining version if an edit was redacted.
async fn handle_room_redaction(
    event: SyncRoomRedactionEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
    cache: &RoomEventCache,
    rules: &RedactionRules,
) -> Result<Option<RoomIndexOperation>, IndexError> {
    let Some(redacted_event_id) = event.redacts(rules) else {
        return Ok(None);
    };

    // If the redacted event was a room message edit, re-add the most recent
    // remaining version instead of just removing it.
    if let Some(redacted_event) =
        cache.find_event(redacted_event_id).await.map_err(|_| IndexError::EventPreparationFailed)?
        && let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
            redacted_event,
        ))) = redacted_event.raw().deserialize()
        && let Some(redacted_event) = redacted_event.as_original()
        && let Some(operation) = handle_possible_edit(redacted_event, timestamp, cache).await?
    {
        return Ok(Some(operation));
    }

    // Otherwise remove the redacted event from the index. This covers plain
    // messages, stickers and polls.
    Ok(Some(RoomIndexOperation::Remove(redacted_event_id.to_owned())))
}

/// Return a [`RoomIndexOperation::Add`] indexing a sticker's descriptive text.
fn handle_sticker(
    event: SyncStickerEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
) -> Option<RoomIndexOperation> {
    let event = event.as_original()?;

    Some(RoomIndexOperation::Add(IndexableEvent::new(
        event.event_id.clone(),
        event.event_id.clone(),
        event.sender.clone(),
        timestamp,
        event.content.body.clone(),
    )))
}

/// Return a [`RoomIndexOperation::Add`] indexing an unstable poll's question
/// and answers.
///
/// ponytail: only indexes the initial `New` poll — edits (`Replacement`) and
/// poll ends are ignored. Add edit handling if editing a poll needs to update
/// search results.
fn handle_unstable_poll_start(
    event: SyncUnstablePollStartEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
) -> Option<RoomIndexOperation> {
    let event = event.as_original()?;

    let UnstablePollStartEventContent::New(content) = &event.content else {
        return None;
    };

    let block = &content.poll_start;
    let mut body = block.question.text.clone();
    for answer in block.answers.iter() {
        body.push(' ');
        body.push_str(&answer.text);
    }

    Some(RoomIndexOperation::Add(IndexableEvent::new(
        event.event_id.clone(),
        event.event_id.clone(),
        event.sender.clone(),
        timestamp,
        body,
    )))
}

/// Return a [`RoomIndexOperation::Add`] indexing a stable poll's question and
/// answers.
///
/// ponytail: like [`handle_unstable_poll_start`], edits and poll ends are
/// ignored — only the initial poll is indexed.
fn handle_poll_start(
    event: SyncPollStartEvent,
    timestamp: Option<MilliSecondsSinceUnixEpoch>,
) -> Option<RoomIndexOperation> {
    let event = event.as_original()?;

    // Skip poll edits, matching the unstable poll handling.
    if let Some(Relation::Replacement(_)) = &event.content.relates_to {
        return None;
    }

    let block = &event.content.poll;
    let mut body = block.question.text.find_plain()?.to_owned();
    for answer in block.answers.iter() {
        if let Some(text) = answer.text.find_plain() {
            body.push(' ');
            body.push_str(text);
        }
    }

    Some(RoomIndexOperation::Add(IndexableEvent::new(
        event.event_id.clone(),
        event.event_id.clone(),
        event.sender.clone(),
        timestamp,
        body,
    )))
}

/// Prepare a [`TimelineEvent`] into a [`RoomIndexOperation`] for search
/// indexing.
async fn parse_timeline_event(
    cache: &RoomEventCache,
    event: TimelineEvent,
    redaction_rules: &RedactionRules,
) -> Result<Option<RoomIndexOperation>, IndexError> {
    use ruma::events::AnySyncTimelineEvent;

    if event.kind.is_utd() {
        return Ok(None);
    }

    let timestamp = event.timestamp();

    Ok(match event.raw().deserialize() {
        Ok(event) => match event {
            AnySyncTimelineEvent::MessageLike(event) => match event {
                AnySyncMessageLikeEvent::RoomMessage(event) => {
                    return handle_room_message(event, timestamp, cache).await;
                }
                AnySyncMessageLikeEvent::RoomRedaction(event) => {
                    return handle_room_redaction(event, timestamp, cache, redaction_rules).await;
                }
                AnySyncMessageLikeEvent::Sticker(event) => handle_sticker(event, timestamp),
                AnySyncMessageLikeEvent::PollStart(event) => handle_poll_start(event, timestamp),
                AnySyncMessageLikeEvent::UnstablePollStart(event) => {
                    handle_unstable_poll_start(event, timestamp)
                }
                _ => None,
            },
            AnySyncTimelineEvent::State(_) => None,
        },

        Err(e) => {
            warn!("failed to parse event: {e:?}");
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use matrix_sdk_search::{
        config::SearchIndexConfig,
        index::{IndexableEvent, RoomIndexOperation},
    };
    use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory};
    use ruma::{
        event_id,
        events::{
            AnySyncMessageLikeEvent,
            room::message::{MessageType, RoomMessageEventContentWithoutRelation},
        },
        room_id, user_id,
    };
    use tokio::sync::Mutex;

    use super::{SearchIndex, SearchIndexStoreKind, parse_timeline_event};
    use crate::test_utils::mocks::MatrixMockServer;

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_sync_message_is_indexed() {
        let mock_server = MatrixMockServer::new().await;
        let client = mock_server.client_builder().build().await;

        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!room_id:localhost");
        let event_id = event_id!("$event_id:localost");
        let user_id = user_id!("@user_id:localost");

        let event_factory = EventFactory::new();
        let room = mock_server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    event_factory
                        .text_msg("this is a sentence")
                        .event_id(event_id)
                        .sender(user_id)
                        .into_raw_sync(),
                ]),
            )
            .await;

        let response = room.search("this", 5, None).await.expect("search should have 1 result");

        assert_eq!(response.len(), 1, "unexpected numbers of responses: {response:?}");
        assert_eq!(response[0].1, event_id, "event id doesn't match: {response:?}");
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_search_index_store_kind_can_configure_ngram_tokenizer() {
        let room_id = room_id!("!room_id:localhost");
        let event_id = event_id!("$event_id:localhost");
        let user_id = user_id!("@user_id:localhost");
        let index = SearchIndex::new(
            Arc::new(Mutex::new(HashMap::new())),
            SearchIndexStoreKind::InMemoryWithConfig(
                SearchIndexConfig::ngram(2, 4).expect("ngram bounds should be valid"),
            ),
        );
        let event = EventFactory::new()
            .room(room_id)
            .sender(user_id)
            .text_msg("再アンケートです")
            .event_id(event_id)
            .into_any_sync_message_like_event();
        let AnySyncMessageLikeEvent::RoomMessage(event) = event else {
            panic!("expected room message event");
        };
        let event = event.as_original().expect("message should be original").clone();
        let MessageType::Text(content) = &event.content.msgtype else {
            panic!("expected a text message");
        };
        let indexable = IndexableEvent::new(
            event.event_id.clone(),
            event.event_id.clone(),
            event.sender.clone(),
            Some(event.origin_server_ts),
            content.body.clone(),
        );

        let mut guard = index.lock().await;
        guard
            .execute(RoomIndexOperation::Add(indexable), room_id)
            .expect("event should be indexed");

        let results =
            guard.search("アンケート", 10, None, room_id).expect("ngram search should run");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, event_id);
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_sync_media_message_is_indexed() {
        use ruma::owned_mxc_uri;

        let mock_server = MatrixMockServer::new().await;
        let client = mock_server.client_builder().build().await;

        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!room_id:localhost");
        let image_id = event_id!("$image_id:localhost");
        let file_id = event_id!("$file_id:localhost");
        let user_id = user_id!("@user_id:localhost");

        let f = EventFactory::new();
        let room = mock_server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.image("holiday_beach.jpg".to_owned(), owned_mxc_uri!("mxc://localhost/1"))
                        .caption(Some("sunset over the ocean".to_owned()), None)
                        .event_id(image_id)
                        .sender(user_id)
                        .into_raw_sync(),
                    f.image("quarterly_report.pdf".to_owned(), owned_mxc_uri!("mxc://localhost/2"))
                        .event_id(file_id)
                        .sender(user_id)
                        .into_raw_sync(),
                ]),
            )
            .await;

        // The caption is indexed.
        let response = room.search("sunset", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for caption search: {response:?}");
        assert_eq!(response[0].1, image_id, "event id doesn't match: {response:?}");

        // The filename is indexed.
        let response = room.search("holiday_beach", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for filename search: {response:?}");
        assert_eq!(response[0].1, image_id, "event id doesn't match: {response:?}");

        // A media message without a caption still indexes its filename.
        let response = room.search("quarterly_report", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for filename search: {response:?}");
        assert_eq!(response[0].1, file_id, "event id doesn't match: {response:?}");
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_sync_sticker_and_poll_are_indexed() {
        use ruma::{events::room::ImageInfo, owned_mxc_uri};

        let mock_server = MatrixMockServer::new().await;
        let client = mock_server.client_builder().build().await;

        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!room_id:localhost");
        let sticker_id = event_id!("$sticker_id:localhost");
        let poll_id = event_id!("$poll_id:localhost");
        let user_id = user_id!("@user_id:localhost");

        let f = EventFactory::new().room(room_id).sender(user_id);
        let room = mock_server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![
                    f.sticker(
                        "a waving cat",
                        ImageInfo::new(),
                        owned_mxc_uri!("mxc://localhost/1"),
                    )
                    .event_id(sticker_id)
                    .into_raw_sync(),
                    f.poll_start("fallback", "favourite cheese?", vec!["comté", "gruyère"])
                        .event_id(poll_id)
                        .into_raw_sync(),
                ]),
            )
            .await;

        // The sticker's description is indexed.
        let response = room.search("waving", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for sticker search: {response:?}");
        assert_eq!(response[0].1, sticker_id, "event id doesn't match: {response:?}");

        // The poll question is indexed.
        let response = room.search("cheese", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for poll question search: {response:?}");
        assert_eq!(response[0].1, poll_id, "event id doesn't match: {response:?}");

        // The poll answers are indexed.
        let response = room.search("gruyère", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for poll answer search: {response:?}");
        assert_eq!(response[0].1, poll_id, "event id doesn't match: {response:?}");
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_sync_stable_poll_is_indexed() {
        use ruma::events::{
            message::TextContentBlock,
            poll::start::{PollAnswer, PollAnswers, PollContentBlock, PollStartEventContent},
        };

        let mock_server = MatrixMockServer::new().await;
        let client = mock_server.client_builder().build().await;

        client.event_cache().subscribe().unwrap();

        let room_id = room_id!("!room_id:localhost");
        let poll_id = event_id!("$stable_poll_id:localhost");
        let user_id = user_id!("@user_id:localhost");

        let answers: PollAnswers = vec![
            PollAnswer::new("0".to_owned(), TextContentBlock::plain("comté")),
            PollAnswer::new("1".to_owned(), TextContentBlock::plain("gruyère")),
        ]
        .try_into()
        .unwrap();
        let poll = PollContentBlock::new(TextContentBlock::plain("favourite cheese?"), answers);
        let content = PollStartEventContent::new(TextContentBlock::plain("fallback"), poll);

        let f = EventFactory::new().room(room_id).sender(user_id);
        let room = mock_server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_bulk(vec![f.event(content).event_id(poll_id).into_raw_sync()]),
            )
            .await;

        // The poll question is indexed.
        let response = room.search("cheese", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for poll question search: {response:?}");
        assert_eq!(response[0].1, poll_id, "event id doesn't match: {response:?}");

        // The poll answers are indexed.
        let response = room.search("gruyère", 5, None).await.unwrap();
        assert_eq!(response.len(), 1, "unexpected results for poll answer search: {response:?}");
        assert_eq!(response[0].1, poll_id, "event id doesn't match: {response:?}");
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_search_index_edit_ordering() {
        let room_id = room_id!("!room_id:localhost");
        let dummy_id = event_id!("$dummy");
        let edit1_id = event_id!("$edit1");
        let edit2_id = event_id!("$edit2");
        let edit3_id = event_id!("$edit3");
        let original_id = event_id!("$original");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let event_cache = client.event_cache();
        event_cache.subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;

        let f = EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));

        // Indexable dummy message required because RoomIndex is initialised lazily.
        let dummy = f.text_msg("dummy").event_id(dummy_id);

        let original = f.text_msg("This is a message").event_id(original_id);

        let edit1 = f
            .text_msg("* A new message")
            .edit(original_id, RoomMessageEventContentWithoutRelation::text_plain("A new message"))
            .event_id(edit1_id);

        let edit2 = f
            .text_msg("* An even newer message")
            .edit(
                original_id,
                RoomMessageEventContentWithoutRelation::text_plain("An even newer message"),
            )
            .event_id(edit2_id);

        let edit3 = f
            .text_msg("* The newest message")
            .edit(
                original_id,
                RoomMessageEventContentWithoutRelation::text_plain("The newest message"),
            )
            .event_id(edit3_id);

        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(dummy)
                    .add_timeline_event(edit1)
                    .add_timeline_event(edit2),
            )
            .await;

        let results = room.search("message", 3, None).await.unwrap();

        assert_eq!(results.len(), 0, "Search should return 0 results, got {results:?}");

        // Adding the original after some pending edits should add the latest edit
        // instead of the original.
        server
            .sync_room(&client, JoinedRoomBuilder::new(room_id).add_timeline_event(original))
            .await;

        let results = room.search("message", 3, None).await.unwrap();

        assert_eq!(results.len(), 1, "Search should return 1 result, got {results:?}");
        assert_eq!(
            results[0].1, edit2_id,
            "Search should return latest edit, got {:?}",
            results[0].1
        );

        // Editing the original after it exists and there has been another edit should
        // delete the previous edits and add this one
        server.sync_room(&client, JoinedRoomBuilder::new(room_id).add_timeline_event(edit3)).await;

        let results = room.search("message", 3, None).await.unwrap();

        assert_eq!(results.len(), 1, "Search should return 1 result, got {results:?}");
        assert_eq!(
            results[0].1, edit3_id,
            "Search should return latest edit, got {:?}",
            results[0].1
        );
    }

    #[cfg(all(feature = "experimental-search", feature = "sqlite"))]
    #[async_test]
    async fn test_cached_resolution_propagates_relations_storage_failure() {
        let directory = tempfile::tempdir().unwrap();
        let server = MatrixMockServer::new().await;
        let client = server
            .client_builder()
            .on_builder(|builder| {
                builder.sqlite_store(directory.path(), Some("synthetic-store-passphrase"))
            })
            .build()
            .await;
        client.event_cache().subscribe().unwrap();
        let room_id = room_id!("!relations:localhost");
        let root = event_id!("$root:localhost");
        let room = server.sync_joined_room(&client, room_id).await;
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@member:localhost"));
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(f.text_msg("synthetic original").event_id(root)),
            )
            .await;
        assert!(room.resolve_cached_message(root).await.unwrap().is_some());
        // Keep the lease alive so the loaded root and its redaction proof remain
        // readable while the encrypted backend's relations read fails.
        let _store_guard = client.event_cache_store().lock().await.unwrap();
        client.event_cache_store().close().await.unwrap();
        assert!(cache.find_event(root).await.unwrap().is_some());
        assert!(cache.redacted_event_ids(&[root.to_owned()]).await.unwrap().is_empty());
        assert!(
            cache
                .find_event_with_relations(
                    root,
                    Some(vec![ruma::events::relation::RelationType::Replacement])
                )
                .await
                .is_err()
        );
        assert!(room.resolve_cached_message(root).await.is_err());
        let index =
            SearchIndex::new(Arc::new(Mutex::new(HashMap::new())), SearchIndexStoreKind::InMemory);
        let mut index = index.lock().await;
        let rules = room.clone_info().room_version_rules_or_default().redaction;
        let message = f.text_msg("synthetic original").event_id(root).into_event();
        assert!(
            index.handle_timeline_event(message.clone(), &cache, room_id, &rules).await.is_err(),
            "single acknowledged preparation must not silently succeed"
        );
        let sticker = f
            .sticker(
                "batchneedle",
                Default::default(),
                ruma::owned_mxc_uri!("mxc://example.invalid/sticker"),
            )
            .event_id(event_id!("$batch-sticker:localhost"))
            .into_event();
        assert!(
            index
                .bulk_handle_timeline_event(
                    vec![sticker.clone(), message.clone()].into_iter(),
                    &cache,
                    room_id,
                    &rules
                )
                .await
                .is_err(),
            "one failed preparation must fail the whole acknowledgement"
        );
        assert!(
            index.search("batchneedle", 10, None, room_id).unwrap().is_empty(),
            "no partial batch commit"
        );
        client.event_cache_store().reopen().await.unwrap();
        assert!(room.resolve_cached_message(root).await.unwrap().is_some());
        index
            .bulk_handle_timeline_event(vec![sticker, message].into_iter(), &cache, room_id, &rules)
            .await
            .unwrap();
        assert_eq!(index.search("batchneedle", 10, None, room_id).unwrap().len(), 1);
    }

    /// Resolving a candidate id returns the newest valid edit's content, and
    /// resolving the edit id itself returns the same original identity.
    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_resolve_cached_message_returns_latest_edit_content() {
        let room_id = room_id!("!room_id:localhost");
        let original_id = event_id!("$resolve_original");
        let edit_id = event_id!("$resolve_edit");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let f = EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));

        let original = f.text_msg("This is a message").event_id(original_id);
        let edit = f
            .text_msg("* An edited message")
            .edit(
                original_id,
                RoomMessageEventContentWithoutRelation::text_plain("An edited message"),
            )
            .event_id(edit_id);

        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(original)
                    .add_timeline_event(edit),
            )
            .await;

        let resolved = room
            .resolve_cached_message(original_id)
            .await
            .expect("cache lookup")
            .expect("message should resolve");
        assert_eq!(resolved.body.as_deref(), Some("An edited message"));
        assert_eq!(resolved.attachment_filename, None);
        assert_eq!(resolved.current_event_id, edit_id.to_owned());
        assert_eq!(resolved.event_id, original_id.to_owned());

        let resolved_from_edit = room
            .resolve_cached_message(edit_id)
            .await
            .expect("cache lookup")
            .expect("edit should resolve to the message");
        assert_eq!(resolved_from_edit.body.as_deref(), Some("An edited message"));
        assert_eq!(resolved_from_edit.event_id, original_id.to_owned());
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_cached_replacement_order_is_not_linked_chunk_order() {
        for (newer_ts, older_ts) in
            [(200_u64, 100_u64), (100, 100), (4_100_000_000_000, 4_000_000_000_000)]
        {
            let room_id = room_id!("!edit_order:localhost");
            let root = event_id!("$order-root");
            let newer = event_id!("$order-z");
            let older = event_id!("$order-a");
            let server = MatrixMockServer::new().await;
            let client = server.client_builder().build().await;
            client.event_cache().subscribe().unwrap();
            let room = server.sync_joined_room(&client, room_id).await;
            let f = EventFactory::new().room(room_id).sender(user_id!("@member:localhost"));
            server
                .sync_room(
                    &client,
                    JoinedRoomBuilder::new(room_id)
                        .add_timeline_event(f.text_msg("original").server_ts(50_u64).event_id(root))
                        .add_timeline_event(
                            f.text_msg("* newer").server_ts(newer_ts).event_id(newer).edit(
                                root,
                                RoomMessageEventContentWithoutRelation::text_plain("newer"),
                            ),
                        )
                        .add_timeline_event(
                            f.text_msg("* older").server_ts(older_ts).event_id(older).edit(
                                root,
                                RoomMessageEventContentWithoutRelation::text_plain("older"),
                            ),
                        ),
                )
                .await;
            let resolved = room.resolve_cached_message(root).await.unwrap().unwrap();
            assert_eq!(resolved.body.as_deref(), Some("newer"));
            assert_eq!(resolved.current_event_id, newer);
        }
    }

    #[cfg(feature = "sqlite")]
    #[async_test]
    async fn test_bundled_only_index_candidate_is_addressable_and_replaces_the_root() {
        let room_id = room_id!("!bundle_index:localhost");
        let root = event_id!("$bundle-index-root");
        let edit = event_id!("$bundle-index-edit");
        let directory = tempfile::tempdir().unwrap();
        let server = MatrixMockServer::new().await;
        let client = server
            .client_builder()
            .on_builder(|builder| {
                builder.sqlite_store(directory.path(), Some("synthetic-store-passphrase"))
            })
            .build()
            .await;
        client.event_cache().subscribe().unwrap();
        let room = server.sync_joined_room(&client, room_id).await;
        let (cache, _handles) = room.event_cache().await.unwrap();
        let sender = user_id!("@member:localhost");
        let f = EventFactory::new().room(room_id).sender(sender);
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("originalneedle")
                        .server_ts(50_u64)
                        .event_id(root)
                        .with_bundled_edit(
                            f.text_msg("* currentneedle").server_ts(100_u64).event_id(edit).edit(
                                root,
                                RoomMessageEventContentWithoutRelation::text_plain("currentneedle"),
                            ),
                        ),
                ),
            )
            .await;
        assert!(cache.find_event(edit).await.unwrap().is_none());
        let index =
            SearchIndex::new(Arc::new(Mutex::new(HashMap::new())), SearchIndexStoreKind::InMemory);
        let mut index = index.lock().await;
        // Existing primary-root document from before the bundled replacement.
        index
            .execute(
                RoomIndexOperation::Add(IndexableEvent::new(
                    root.to_owned(),
                    root.to_owned(),
                    sender.to_owned(),
                    None,
                    "originalneedle".to_owned(),
                )),
                room_id,
            )
            .unwrap();
        assert_eq!(
            index.search_literal_page("originalneedle", 10, None, room_id).unwrap().len(),
            1
        );
        index
            .handle_timeline_event(
                cache.find_event(root).await.unwrap().unwrap(),
                &cache,
                room_id,
                &room.clone_info().room_version_rules_or_default().redaction,
            )
            .await
            .unwrap();
        let candidates = index.search_literal_page("currentneedle", 10, None, room_id).unwrap();
        assert_eq!(candidates.len(), 1, "acknowledged indexing must publish the current literal");
        assert_eq!(candidates[0].event_id, root);
        let resolved = room.resolve_cached_message(&candidates[0].event_id).await.unwrap().unwrap();
        assert_eq!(resolved.body.as_deref(), Some("currentneedle"));
        assert_eq!(resolved.current_event_id, edit);
        assert!(index.search_literal_page("originalneedle", 10, None, room_id).unwrap().is_empty());
        // This lookup bypasses the loaded memory root, as reconstruction does.
        let (stored, _) = cache
            .find_event_with_relations(
                root,
                Some(vec![ruma::events::relation::RelationType::Replacement]),
            )
            .await
            .unwrap()
            .unwrap();
        let restored: matrix_sdk_base::deserialized_responses::TimelineEvent =
            serde_json::from_value(serde_json::to_value(stored).unwrap()).unwrap();
        let child = restored
            .bundled_replacement()
            .expect("ordinary sync persistence must retain the sole current replacement candidate");
        assert_eq!(child.event_id(), Some(edit));
    }

    #[async_test]
    async fn test_duplicate_root_bundle_refreshes_current_content() {
        let room_id = room_id!("!duplicate_bundle:localhost");
        let root = event_id!("$duplicate-bundle-root");
        let edit = event_id!("$duplicate-bundle-edit");
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();
        let room = server.sync_joined_room(&client, room_id).await;
        let f = EventFactory::new().room(room_id).sender(user_id!("@member:localhost"));
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("originalneedle").server_ts(50_u64).event_id(root),
                ),
            )
            .await;
        assert_eq!(
            room.resolve_cached_message(root).await.unwrap().unwrap().body.as_deref(),
            Some("originalneedle")
        );
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("originalneedle")
                        .server_ts(50_u64)
                        .event_id(root)
                        .with_bundled_edit(
                            f.text_msg("* currentneedle").server_ts(100_u64).event_id(edit).edit(
                                root,
                                RoomMessageEventContentWithoutRelation::text_plain("currentneedle"),
                            ),
                        ),
                ),
            )
            .await;
        assert_eq!(
            room.resolve_cached_message(root).await.unwrap().unwrap().body.as_deref(),
            Some("currentneedle"),
            "duplicate identity must not discard new replacement evidence"
        );
    }

    #[cfg(feature = "sqlite")]
    #[async_test]
    async fn test_decoded_bundle_with_cached_utd_child_uses_addressable_root_in_both_preparations()
    {
        use std::collections::BTreeMap;

        use matrix_sdk_base::deserialized_responses::{
            AlgorithmInfo, DecryptedRoomEvent, EncryptionInfo, TimelineEvent, UnableToDecryptInfo,
            UnableToDecryptReason, UnsignedDecryptionResult, UnsignedEventLocation,
            VerificationState,
        };

        for prepare_edit in [false, true] {
            let room_id = room_id!("!bundle_utd:localhost");
            let root = event_id!("$bundle-utd-root");
            let edit = event_id!("$bundle-utd-edit");
            let sender = user_id!("@member:localhost");
            let directory = tempfile::tempdir().unwrap();
            let server = MatrixMockServer::new().await;
            let client = server
                .client_builder()
                .on_builder(|builder| {
                    builder.sqlite_store(directory.path(), Some("synthetic-store-passphrase"))
                })
                .build()
                .await;
            client.event_cache().subscribe().unwrap();
            let room = server.sync_joined_room(&client, room_id).await;
            let (cache, _handles) = room.event_cache().await.unwrap();
            let f = EventFactory::new().room(room_id).sender(sender);
            let info = |session: &str| {
                Arc::new(EncryptionInfo {
                    sender: sender.to_owned(),
                    sender_device: None,
                    forwarder: None,
                    algorithm_info: AlgorithmInfo::MegolmV1AesSha2 {
                        curve25519_key: format!("synthetic-{session}"),
                        sender_claimed_keys: BTreeMap::new(),
                        session_id: Some(session.to_owned()),
                    },
                    verification_state: VerificationState::Verified,
                })
            };
            let root_info = info("root-session");
            let child_info = info("child-session");
            let cached_root = TimelineEvent::from_decrypted(
                DecryptedRoomEvent {
                    event: f
                        .text_msg("originalneedle")
                        .server_ts(50_u64)
                        .event_id(root)
                        .with_bundled_edit(
                            f.text_msg("* currentneedle").server_ts(100_u64).event_id(edit).edit(
                                root,
                                RoomMessageEventContentWithoutRelation::text_plain("currentneedle"),
                            ),
                        )
                        .into_raw(),
                    encryption_info: root_info,
                    unsigned_encryption_info: Some(BTreeMap::from([(
                        UnsignedEventLocation::RelationsReplace,
                        UnsignedDecryptionResult::Decrypted(child_info.clone()),
                    )])),
                },
                None,
            );
            let embedded = *cached_root.bundled_replacement().unwrap();
            assert!(Arc::ptr_eq(embedded.encryption_info().unwrap(), &child_info));
            let ciphertext = ruma::serde::Raw::from_json_string(
                serde_json::json!({
                    "type": "m.room.encrypted", "event_id": edit, "room_id": room_id,
                    "sender": sender, "origin_server_ts": 100,
                    "content": {"algorithm":"m.megolm.v1.aes-sha2", "ciphertext":"synthetic",
                        "device_id":"TEST", "sender_key":"synthetic", "session_id":"child-session"},
                })
                .to_string(),
            )
            .unwrap();
            let utd = TimelineEvent::from_utd(
                ciphertext,
                UnableToDecryptInfo {
                    session_id: Some("child-session".to_owned()),
                    reason: UnableToDecryptReason::Unknown,
                },
            );
            let store = match client.event_cache_store().lock().await.unwrap() {
                matrix_sdk_base::event_cache::store::EventCacheStoreLockState::Clean(store)
                | matrix_sdk_base::event_cache::store::EventCacheStoreLockState::Dirty(store) => {
                    store
                }
            };
            store.save_event(room_id, cached_root.clone()).await.unwrap();
            store.save_event(room_id, utd).await.unwrap();
            drop(store);
            assert!(
                cache.events().await.unwrap().is_empty(),
                "root must be read from storage, not a loaded timeline"
            );
            client.event_cache_store().close().await.unwrap();
            client.event_cache_store().reopen().await.unwrap();
            let restored = cache.find_event(root).await.unwrap().unwrap();
            let restored_child = restored.bundled_replacement().unwrap();
            assert!(matches!(
                &restored_child.encryption_info().unwrap().algorithm_info,
                AlgorithmInfo::MegolmV1AesSha2 { session_id, .. } if session_id.as_deref() == Some("child-session")
            ));
            assert!(cache.find_event(edit).await.unwrap().unwrap().kind.is_utd());
            assert!(room.resolve_cached_message(edit).await.unwrap().is_none());
            let index = SearchIndex::new(
                Arc::new(Mutex::new(HashMap::new())),
                SearchIndexStoreKind::InMemory,
            );
            let mut index = index.lock().await;
            index
                .handle_timeline_event(
                    if prepare_edit { *restored_child } else { restored },
                    &cache,
                    room_id,
                    &room.clone_info().room_version_rules_or_default().redaction,
                )
                .await
                .unwrap();
            let candidates = index.search_literal_page("currentneedle", 10, None, room_id).unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].event_id, root);
            let resolved =
                room.resolve_cached_message(&candidates[0].event_id).await.unwrap().unwrap();
            assert_eq!(resolved.body.as_deref(), Some("currentneedle"));
            assert_eq!(resolved.current_event_id, edit);
        }
    }

    #[async_test]
    async fn test_absent_bundled_child_requires_positive_redaction_to_be_excluded() {
        let room_id = room_id!("!bundle_redaction:localhost");
        let root = event_id!("$bundle-redaction-root");
        let edit = event_id!("$bundle-redaction-edit");
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();
        let room = server.sync_joined_room(&client, room_id).await;
        let (cache, _handles) = room.event_cache().await.unwrap();
        let f = EventFactory::new().room(room_id).sender(user_id!("@member:localhost"));
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.text_msg("originalneedle").event_id(root).with_bundled_edit(
                        f.text_msg("* currentneedle").event_id(edit).edit(
                            root,
                            RoomMessageEventContentWithoutRelation::text_plain("currentneedle"),
                        ),
                    ),
                ),
            )
            .await;
        assert!(cache.find_event(edit).await.unwrap().is_none());
        assert_eq!(
            room.resolve_cached_message(root).await.unwrap().unwrap().body.as_deref(),
            Some("currentneedle")
        );
        let index =
            SearchIndex::new(Arc::new(Mutex::new(HashMap::new())), SearchIndexStoreKind::InMemory);
        let mut index = index.lock().await;
        let rules = room.clone_info().room_version_rules_or_default().redaction;
        index
            .handle_timeline_event(
                cache.find_event(root).await.unwrap().unwrap(),
                &cache,
                room_id,
                &rules,
            )
            .await
            .unwrap();
        assert_eq!(index.search_literal_page("currentneedle", 10, None, room_id).unwrap().len(), 1);
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.redaction(edit).event_id(event_id!("$bundle-child-redaction")),
                ),
            )
            .await;
        assert!(cache.redacted_event_ids(&[edit.to_owned()]).await.unwrap().contains(edit));
        assert_eq!(
            room.resolve_cached_message(root).await.unwrap().unwrap().body.as_deref(),
            Some("originalneedle")
        );
        index
            .handle_timeline_event(
                cache.find_event(root).await.unwrap().unwrap(),
                &cache,
                room_id,
                &rules,
            )
            .await
            .unwrap();
        assert_eq!(
            index.search_literal_page("originalneedle", 10, None, room_id).unwrap().len(),
            1,
            "acknowledged refresh must replace a root-keyed edit with surviving content"
        );
        assert!(index.search_literal_page("currentneedle", 10, None, room_id).unwrap().is_empty());
    }

    #[async_test]
    async fn test_resolve_cached_message_returns_a_sticker_description() {
        use ruma::{events::room::ImageInfo, owned_mxc_uri};

        let room_id = room_id!("!sticker_room:localhost");
        let sticker_id = event_id!("$resolve_sticker");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let f = EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));

        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.sticker(
                        "a waving cat",
                        ImageInfo::new(),
                        owned_mxc_uri!("mxc://localhost/1"),
                    )
                    .event_id(sticker_id),
                ),
            )
            .await;

        // Stickers are indexed, so they must resolve: a candidate that resolves
        // to `None` is dropped and a previously findable sticker disappears.
        let resolved = room
            .resolve_cached_message(sticker_id)
            .await
            .expect("cache lookup")
            .expect("sticker should resolve");
        assert_eq!(resolved.event_id, sticker_id.to_owned());
        assert_eq!(resolved.current_event_id, sticker_id.to_owned());
        assert_eq!(resolved.body.as_deref(), Some("a waving cat"));
        // One piece of text: reported as both the caption and the filename, the
        // way the crawler and the index expose it.
        assert_eq!(resolved.attachment_filename.as_deref(), Some("a waving cat"));
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_resolve_cached_message_splits_media_caption_and_filename() {
        use ruma::owned_mxc_uri;

        let room_id = room_id!("!media_room:localhost");
        let image_id = event_id!("$media_image");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let f = EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));

        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_event(
                    f.image("holiday_beach.jpg".to_owned(), owned_mxc_uri!("mxc://localhost/1"))
                        .caption(Some("sunset over the ocean".to_owned()), None)
                        .event_id(image_id),
                ),
            )
            .await;

        let resolved = room
            .resolve_cached_message(image_id)
            .await
            .expect("cache lookup")
            .expect("media message should resolve");

        // A caption match and a filename match report different fields, so the
        // index text is split back apart on resolution.
        assert_eq!(resolved.body.as_deref(), Some("sunset over the ocean"));
        assert_eq!(resolved.attachment_filename.as_deref(), Some("holiday_beach.jpg"));
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_resolve_cached_message_returns_none_for_unknown_event() {
        let room_id = room_id!("!room_id:localhost");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;

        let resolved =
            room.resolve_cached_message(event_id!("$missing")).await.expect("cache lookup");
        assert!(resolved.is_none(), "unknown events must not resolve: {resolved:?}");
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_resolve_cached_message_rejects_redacted_root_through_edit_id() {
        let room_id = room_id!("!room_id:localhost");
        let original_id = event_id!("$redact_original");
        let edit_id = event_id!("$redact_edit");
        let redaction_id = event_id!("$redact_event");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        client.event_cache().subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let f = EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));

        let original = f.text_msg("Original message").event_id(original_id);
        let edit = f
            .text_msg("* Edited message")
            .edit(original_id, RoomMessageEventContentWithoutRelation::text_plain("Edited message"))
            .event_id(edit_id);
        let redaction = f.redaction(original_id).event_id(redaction_id);

        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id)
                    .add_timeline_event(original)
                    .add_timeline_event(edit)
                    .add_timeline_event(redaction),
            )
            .await;

        // Resolving the original is rejected, and a surviving edit id must not
        // resurrect the redacted message.
        assert!(room.resolve_cached_message(original_id).await.unwrap().is_none());
        assert!(
            room.resolve_cached_message(edit_id).await.unwrap().is_none(),
            "a surviving edit must not resurrect a redacted original"
        );
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_search_index_redaction_removes_redacted_event_when_cache_misses() {
        let room_id = room_id!("!room_id:localhost");
        let redacted_id = event_id!("$redacted");
        let redaction_id = event_id!("$redaction");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let event_cache = client.event_cache();
        event_cache.subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let (room_cache, _drop_handles) = room.event_cache().await.unwrap();

        let event_factory =
            EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));
        let redaction = event_factory.redaction(redacted_id).event_id(redaction_id).into_event();
        let redaction_rules = room.clone_info().room_version_rules_or_default().redaction;

        let operation =
            parse_timeline_event(&room_cache, redaction, &redaction_rules).await.unwrap();

        match operation {
            Some(RoomIndexOperation::Remove(event_id)) => assert_eq!(event_id, redacted_id),
            other => panic!("expected remove operation for redacted event id, got {other:?}"),
        }
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_search_index_redaction_preserves_edit_aware_cache_hit() {
        let room_id = room_id!("!room_id:localhost");
        let original_id = event_id!("$original");
        let edit_id = event_id!("$edit");
        let redaction_id = event_id!("$redaction");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let event_cache = client.event_cache();
        event_cache.subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;
        let (room_cache, _drop_handles) = room.event_cache().await.unwrap();

        let event_factory =
            EventFactory::new().room(room_id).sender(user_id!("@user_id:localhost"));
        let original =
            event_factory.text_msg("Original message").event_id(original_id).into_raw_sync();
        let edit = event_factory
            .text_msg("* Edited message")
            .edit(original_id, RoomMessageEventContentWithoutRelation::text_plain("Edited message"))
            .event_id(edit_id)
            .into_raw_sync();
        server
            .sync_room(
                &client,
                JoinedRoomBuilder::new(room_id).add_timeline_bulk(vec![original, edit]),
            )
            .await;

        // The redaction is parsed without being committed to the cache, so the
        // unredacted edit stays resolvable there: redacting an edit must re-add the
        // most recent remaining version of the original message.
        let redaction = event_factory.redaction(edit_id).event_id(redaction_id).into_event();
        let redaction_rules = room.clone_info().room_version_rules_or_default().redaction;

        let operation =
            parse_timeline_event(&room_cache, redaction, &redaction_rules).await.unwrap();

        match operation {
            Some(RoomIndexOperation::Edit(event_id, latest_edit)) => {
                assert_eq!(event_id, original_id);
                // `IndexableEvent`'s fields are crate-private to matrix-sdk-search, so
                // its public `Debug` output is the way to identify the re-added event.
                assert!(
                    format!("{latest_edit:?}").contains(edit_id.as_str()),
                    "expected the latest edit to be re-indexed: {latest_edit:?}"
                );
            }
            other => panic!("expected edit operation for cached redacted edit, got {other:?}"),
        }
    }

    #[cfg(feature = "experimental-search")]
    #[async_test]
    async fn test_search_index_ignores_cross_sender_edit() {
        let room_id = room_id!("!room_id:localhost");
        let original_id = event_id!("$original");
        let edit_id = event_id!("$edit");

        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let event_cache = client.event_cache();
        event_cache.subscribe().unwrap();

        let room = server.sync_joined_room(&client, room_id).await;

        let f = EventFactory::new().room(room_id);

        let original =
            f.text_msg("original alpha").sender(user_id!("@alice:localhost")).event_id(original_id);

        // An edit from a different user than the original sender is not a valid
        // replacement and must be ignored.
        let malicious_edit = f
            .text_msg("* malicious beta")
            .edit(original_id, RoomMessageEventContentWithoutRelation::text_plain("malicious beta"))
            .sender(user_id!("@bob:localhost"))
            .event_id(edit_id);

        server
            .sync_room(&client, JoinedRoomBuilder::new(room_id).add_timeline_event(original))
            .await;

        // The original message is indexed.
        let results = room.search("alpha", 3, None).await.unwrap();
        assert_eq!(results.len(), 1, "Original should be indexed, got {results:?}");
        assert_eq!(results[0].1, original_id, "unexpected event id: {results:?}");

        server
            .sync_room(&client, JoinedRoomBuilder::new(room_id).add_timeline_event(malicious_edit))
            .await;

        // The forged edit's content must not be indexed.
        let results = room.search("beta", 3, None).await.unwrap();
        assert_eq!(results.len(), 0, "Cross-sender edit should be ignored, got {results:?}");

        // The original message stays indexed.
        let results = room.search("alpha", 3, None).await.unwrap();
        assert_eq!(results.len(), 1, "Original should stay indexed, got {results:?}");
        assert_eq!(results[0].1, original_id, "unexpected event id: {results:?}");
    }
}
