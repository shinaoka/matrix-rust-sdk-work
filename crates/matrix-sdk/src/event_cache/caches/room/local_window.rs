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

//! The contiguous run of in-memory events around one event.

use matrix_sdk_base::event_cache::Event;
use matrix_sdk_common::linked_chunk::ChunkContent;
use ruma::EventId;

use super::super::event_linked_chunk::EventLinkedChunk;

/// A contiguous run of in-memory events of a room, around one event.
///
/// "Contiguous" means the run contains no gap: between any two of its
/// consecutive entries the room holds nothing it is missing. Its two ends are
/// therefore either the boundary of the room timeline or a pagination gap,
/// which is what makes the run usable as the starting point of a timeline: both
/// ends can be paginated from, and no event is silently skipped.
///
/// The run is as large as the room cache has loaded, so it is neither capped
/// nor centered on the target. A run whose older end is a chunk the cache has
/// not loaded yet is not returned at all: that end has no pagination token, so
/// paging from it is impossible, and pretending the timeline starts there would
/// be wrong.
#[derive(Clone, Debug)]
pub struct EventLocalWindow {
    /// The events of the run, oldest first.
    pub events: Vec<Event>,

    /// The index of the requested event inside [`Self::events`].
    pub target_index: usize,

    /// The pagination token of the gap immediately before the run.
    ///
    /// `None` means the run starts at the oldest event of the timeline.
    pub prev_token: Option<String>,

    /// The pagination token of the gap immediately after the run.
    ///
    /// `None` means the run ends at the newest event the room cache knows
    /// about; nothing newer is loaded, but a newer event may arrive later.
    pub next_token: Option<String>,
}

/// Where a run starts, from the point of view of backwards pagination.
enum RunStart {
    /// The first chunk of the linked chunk, with nothing older to load.
    TimelineStart,

    /// A gap chunk, with the token to paginate older events from.
    Token(String),

    /// A chunk the cache has not loaded: no token is known for its predecessor.
    Unknown,
}

/// Return the contiguous run of in-memory events of `chunk` that contains
/// `event_id`.
///
/// Returns `None` if the event is not in memory, or if the run containing it
/// starts after a chunk that has not been loaded (see [`EventLocalWindow`]).
pub(super) fn window_around(
    chunk: &EventLinkedChunk,
    event_id: &EventId,
) -> Option<EventLocalWindow> {
    // Split the in-memory chunks into runs separated by gaps.
    let mut runs: Vec<(RunStart, Vec<&Event>)> = Vec::new();

    let mut start = if chunk.first_chunk().is_definitive_head() {
        RunStart::TimelineStart
    } else {
        RunStart::Unknown
    };

    let mut current: Option<Vec<&Event>> = None;

    for linked_chunk in chunk.chunks() {
        match linked_chunk.content() {
            ChunkContent::Gap(gap) => {
                if let Some(events) = current.take() {
                    runs.push((start, events));
                }

                start = RunStart::Token(gap.token.clone());
            }

            // An empty items chunk (the trailing sentinel, typically) breaks
            // nothing: it belongs to the run it sits in.
            ChunkContent::Items(items) => {
                current.get_or_insert_with(Vec::new).extend(items.iter());
            }
        }
    }

    if let Some(events) = current.take() {
        runs.push((start, events));
    }

    let run_index = runs
        .iter()
        .position(|(_, events)| events.iter().any(|event| event.event_id() == Some(event_id)))?;

    // The gap that ends this run is the one the next run starts after.
    let next_token = match runs.get(run_index + 1).map(|(start, _)| start) {
        Some(RunStart::Token(token)) => Some(token.clone()),
        _ => None,
    };

    let (start, events) = runs.swap_remove(run_index);

    let target_index = events.iter().position(|event| event.event_id() == Some(event_id))?;

    let prev_token = match start {
        RunStart::TimelineStart => None,
        RunStart::Token(token) => Some(token),
        RunStart::Unknown => return None,
    };

    Some(EventLocalWindow {
        events: events.into_iter().cloned().collect(),
        target_index,
        prev_token,
        next_token,
    })
}

#[cfg(test)]
mod tests {
    use matrix_sdk_base::event_cache::Gap;
    use matrix_sdk_test::event_factory::EventFactory;
    use ruma::room_id;

    use super::*;

    fn event_factory() -> EventFactory {
        EventFactory::new()
            .room(room_id!("!local-window:example.org"))
            .sender(ruma::user_id!("@alice:example.org"))
    }

    /// Build a chunk out of `[(gap token before, events…), …]` descriptors; the
    /// first entry's token is unused, since nothing precedes it.
    fn chunk_of(spec: &[(&str, Vec<&str>)]) -> EventLinkedChunk {
        let factory = event_factory();
        let mut chunk = EventLinkedChunk::new();

        for (index, (gap_token, events)) in spec.iter().enumerate() {
            if index > 0 {
                chunk.push_gap(Gap { token: (*gap_token).to_owned() });
            }

            chunk.push_events(events.iter().map(|event_id| {
                factory.text_msg("hello").event_id(&EventId::parse(*event_id).unwrap()).into_event()
            }));
        }

        chunk
    }

    #[test]
    fn a_run_between_two_gaps_keeps_both_tokens() {
        let chunk = chunk_of(&[
            ("older", vec!["$a1", "$a2"]),
            ("middle", vec!["$b1", "$b2", "$b3"]),
            ("newer", vec!["$c1"]),
        ]);

        let window = window_around(&chunk, &EventId::parse("$b2").unwrap()).unwrap();

        let event_ids: Vec<_> =
            window.events.iter().map(|event| event.event_id().unwrap().to_owned()).collect();
        assert_eq!(event_ids, ["$b1", "$b2", "$b3"]);
        assert_eq!(window.target_index, 1);
        assert_eq!(window.prev_token.as_deref(), Some("middle"));
        assert_eq!(window.next_token.as_deref(), Some("newer"));
    }

    #[test]
    fn the_newest_run_has_no_next_token() {
        let chunk = chunk_of(&[("older", vec!["$a1"]), ("middle", vec!["$b1", "$b2"])]);

        let window = window_around(&chunk, &EventId::parse("$b1").unwrap()).unwrap();

        assert_eq!(window.prev_token.as_deref(), Some("middle"));
        assert_eq!(window.next_token, None, "the run reaches the newest loaded event");
    }

    #[test]
    fn the_oldest_run_of_a_complete_chunk_starts_the_timeline() {
        let chunk = chunk_of(&[("", vec!["$a1", "$a2"]), ("middle", vec!["$b1"])]);

        let window = window_around(&chunk, &EventId::parse("$a2").unwrap()).unwrap();

        assert_eq!(window.prev_token, None, "nothing older than the first chunk is missing");
        assert_eq!(window.next_token.as_deref(), Some("middle"));
    }

    #[test]
    fn an_event_that_is_not_in_memory_has_no_window() {
        let chunk = chunk_of(&[("", vec!["$a1"])]);

        assert!(window_around(&chunk, &EventId::parse("$unknown").unwrap()).is_none());
    }
}
