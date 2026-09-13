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

//! Private-data-free activation counters for the incoming-verification-request
//! protections.
//!
//! These counters answer "did the protections for rare conditions fire?", which
//! ordinary use alone cannot show. They hold counts only: no user, device, room
//! or event identifiers, and no event content.
//!
//! The counters are process-wide because the replay paths that increment them
//! are not all reachable from a single owner: the request state machine drives
//! some of them from `RequestState`, and the bounded delivery queue drives the
//! others from its lease guards.

use std::sync::atomic::{AtomicU64, Ordering};

/// How often the incoming-verification-request protections activated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IncomingVerificationRequestProtectionCounters {
    /// Requests that arrived from a sender device whose keys were unknown, so
    /// delivery waited for a key query.
    pub unknown_sender_deferred: u64,
    /// Key-query completions that made a claimed request replayable again.
    pub key_query_replays: u64,
    /// Deliveries released without an application commit; the request stayed in
    /// the bounded queue and is offered again later.
    pub released_deliveries: u64,
    /// Repeated SAS start events rejected because a remote SAS was already
    /// adopted for the same peer, device and flow.
    pub suppressed_sas_start_replays: u64,
}

static UNKNOWN_SENDER_DEFERRED: AtomicU64 = AtomicU64::new(0);
static KEY_QUERY_REPLAYS: AtomicU64 = AtomicU64::new(0);
static RELEASED_DELIVERIES: AtomicU64 = AtomicU64::new(0);
static SUPPRESSED_SAS_START_REPLAYS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn note_unknown_sender_deferred() {
    UNKNOWN_SENDER_DEFERRED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_key_query_replay() {
    KEY_QUERY_REPLAYS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_released_delivery() {
    RELEASED_DELIVERIES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_suppressed_sas_start_replay() {
    SUPPRESSED_SAS_START_REPLAYS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot the protection counters.
///
/// The counters are process-wide and contain counts only.
pub fn incoming_verification_request_protection_counters()
-> IncomingVerificationRequestProtectionCounters {
    IncomingVerificationRequestProtectionCounters {
        unknown_sender_deferred: UNKNOWN_SENDER_DEFERRED.load(Ordering::Relaxed),
        key_query_replays: KEY_QUERY_REPLAYS.load(Ordering::Relaxed),
        released_deliveries: RELEASED_DELIVERIES.load(Ordering::Relaxed),
        suppressed_sas_start_replays: SUPPRESSED_SAS_START_REPLAYS.load(Ordering::Relaxed),
    }
}

/// Reset the protection counters. Only available with the `testing` feature, so
/// that a test can observe the counters it produces.
#[cfg(feature = "testing")]
pub fn reset_incoming_verification_request_protection_counters() {
    UNKNOWN_SENDER_DEFERRED.store(0, Ordering::Relaxed);
    KEY_QUERY_REPLAYS.store(0, Ordering::Relaxed);
    RELEASED_DELIVERIES.store(0, Ordering::Relaxed);
    SUPPRESSED_SAS_START_REPLAYS.store(0, Ordering::Relaxed);
}
