// Copyright 2024 The Matrix.org Foundation C.I.C.
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

//! Bounded, newest-first search paging.
//!
//! Offset-based paging makes Tantivy collect `offset + limit` documents per
//! page, so deep pages allocate memory proportional to the number of skipped
//! hits. This collector instead keeps only the newest `limit` candidates that
//! are strictly older than a caller cursor. Ordering is by `(date, event_id)`,
//! so paging stays exact and bounded even when many events share a timestamp.

use std::{cmp::Ordering, collections::BinaryHeap};

use ruma::{EventId, OwnedEventId};
use tantivy::{
    DateTime, DocAddress, Score, SegmentOrdinal, TantivyError,
    collector::{Collector, SegmentCollector},
    columnar::StrColumn,
    fastfield::Column,
};

/// Exclusive upper bound for a page: results are strictly older than this
/// `(timestamp, event_id)` pair, newest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchCursor {
    /// Milliseconds since the Unix epoch of the boundary event.
    pub timestamp_millis: i64,
    /// Event id of the boundary event, used as the `(date, event_id)` tiebreak.
    pub event_id: OwnedEventId,
}

/// A collected candidate, ordered by recency: larger timestamp first, then
/// larger event id, so a `Reverse` min-heap keeps the newest `limit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) timestamp_millis: i64,
    pub(crate) event_id: String,
    pub(crate) doc_address: DocAddress,
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.timestamp_millis, &self.event_id).cmp(&(other.timestamp_millis, &other.event_id))
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Collects the newest `limit` matches strictly older than `cursor`.
pub(crate) struct CursorTopCollector {
    pub(crate) limit: usize,
    pub(crate) cursor: Option<SearchCursor>,
}

impl Collector for CursorTopCollector {
    type Fruit = Vec<Candidate>;
    type Child = CursorSegmentCollector;

    fn for_segment(
        &self,
        segment_local_id: SegmentOrdinal,
        segment: &tantivy::SegmentReader,
    ) -> tantivy::Result<Self::Child> {
        let date_col = segment.fast_fields().date("date")?;
        let event_id_col = segment.fast_fields().str("event_id")?.ok_or_else(|| {
            TantivyError::SchemaError(
                "the `event_id` field must be a fast field for cursor paging".to_owned(),
            )
        })?;

        Ok(CursorSegmentCollector {
            limit: self.limit,
            cursor: self.cursor.clone(),
            segment_ord: segment_local_id,
            date_col,
            event_id_col,
            heap: BinaryHeap::new(),
            scratch: String::new(),
        })
    }

    fn requires_scoring(&self) -> bool {
        false
    }

    fn merge_fruits(&self, segment_fruits: Vec<Vec<Candidate>>) -> tantivy::Result<Vec<Candidate>> {
        let mut all: Vec<Candidate> = segment_fruits.into_iter().flatten().collect();
        all.sort_by(|a, b| b.cmp(a));
        all.truncate(self.limit);
        Ok(all)
    }
}

pub(crate) struct CursorSegmentCollector {
    limit: usize,
    cursor: Option<SearchCursor>,
    segment_ord: SegmentOrdinal,
    date_col: Column<DateTime>,
    event_id_col: StrColumn,
    heap: BinaryHeap<std::cmp::Reverse<Candidate>>,
    scratch: String,
}

impl SegmentCollector for CursorSegmentCollector {
    type Fruit = Vec<Candidate>;

    fn collect(&mut self, doc: u32, _score: Score) {
        let Some(date) = self.date_col.first(doc) else {
            return;
        };
        let Some(ord) = self.event_id_col.term_ords(doc).next() else {
            return;
        };
        self.scratch.clear();
        if !self.event_id_col.ord_to_str(ord, &mut self.scratch).unwrap_or(false) {
            return;
        }

        let timestamp_millis = date.into_timestamp_millis();
        if let Some(cursor) = &self.cursor
            && (timestamp_millis, self.scratch.as_str())
                >= (cursor.timestamp_millis, cursor.event_id.as_str())
        {
            return;
        }

        let candidate = Candidate {
            timestamp_millis,
            event_id: self.scratch.clone(),
            doc_address: DocAddress::new(self.segment_ord, doc),
        };

        if self.heap.len() < self.limit {
            self.heap.push(std::cmp::Reverse(candidate));
        } else if let Some(std::cmp::Reverse(worst)) = self.heap.peek()
            && candidate > *worst
        {
            self.heap.pop();
            self.heap.push(std::cmp::Reverse(candidate));
        }
    }

    fn harvest(self) -> Self::Fruit {
        let mut candidates: Vec<Candidate> =
            self.heap.into_iter().map(|std::cmp::Reverse(candidate)| candidate).collect();
        candidates.sort_by(|a, b| b.cmp(a));
        candidates
    }
}

/// Parse a collected event id, keeping candidates in `(timestamp, event_id)`
/// order and dropping malformed ids like the offset-based path does.
pub(crate) fn candidate_cursor(candidate: &Candidate) -> Option<SearchCursor> {
    match EventId::parse(&candidate.event_id) {
        Ok(event_id) => Some(SearchCursor {
            timestamp_millis: candidate.timestamp_millis,
            event_id: event_id.to_owned(),
        }),
        Err(err) => {
            tracing::error!("error while parsing event_id from search result: {err:?}");
            None
        }
    }
}
