// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Privacy-preserving, typed room-key lifecycle diagnostics.
//!
//! Raw Matrix identifiers never leave this module. They are mapped to
//! process-local ordinals owned by one [`OlmMachine`](crate::OlmMachine).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use ruma::{DeviceId, RoomId, TransactionId, UserId};

/// A process-local anonymous identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoomKeyDiagnosticAlias(u64);

impl RoomKeyDiagnosticAlias {
    /// Return the anonymous ordinal. This number has meaning only for the
    /// lifetime of the current crypto machine.
    pub fn ordinal(self) -> u64 {
        self.0
    }
}

/// The lifecycle stage of an incoming room-key request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncomingRoomKeyRequestStage {
    /// The to-device request entered the crypto machine.
    Received,
    /// Its action and algorithm were classified.
    Classified,
    /// The requested inbound session was looked up.
    SessionLookup,
    /// Device trust and original-recipient authorization were evaluated.
    AuthorizationDecided,
    /// Handling reached a terminal or explicitly queued outcome.
    Outcome,
}

/// Request or cancellation action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyRequestAction {
    /// A key was requested.
    Request,
    /// A previous request was cancelled.
    Cancellation,
    /// The SDK did not understand the action.
    Unknown,
}

/// Relationship between the requester and this account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyRequesterScope {
    /// Another device belonging to this account.
    Own,
    /// A device belonging to another account.
    Peer,
    /// The relationship could not be established safely.
    Unknown,
}

/// Requesting-device classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyRequesterDeviceState {
    /// This exact device; such requests are ignored.
    Current,
    /// A verified device belonging to this account.
    VerifiedOwn,
    /// An unverified device belonging to this account.
    UnverifiedOwn,
    /// A known peer device.
    KnownPeer,
    /// No matching device was found.
    Unknown,
}

/// Whether a request targets the active outbound session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedRoomKeySession {
    /// The requested session is active now.
    Current,
    /// The requested session differs from the active session.
    Historical,
    /// There is no safe active-session comparison.
    Unknown,
}

/// Closed result of responder-side request handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncomingRoomKeyRequestOutcome {
    /// No terminal outcome has been reached at this stage.
    None,
    /// A forwarded key request was created.
    Forwarded,
    /// Handling is queued until an Olm session exists.
    QueuedForOlm,
    /// A cancellation was processed.
    Cancelled,
    /// A request sent by this exact device was ignored.
    IgnoredSelf,
    /// Policy or authorization refused the request.
    Refused,
    /// The requested inbound session does not exist.
    MissingSession,
    /// The requested algorithm is unsupported.
    UnsupportedAlgorithm,
    /// Automatic forwarding is disabled.
    ForwardingDisabled,
    /// An SDK operation failed.
    SdkError,
}

/// Closed refusal classification. It intentionally contains no raw error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyRefusalReason {
    /// No refusal occurred.
    None,
    /// Rotation removed historical outbound recipient proof.
    MissingOldOutboundProof,
    /// The peer was not an original recipient.
    NotOriginalRecipient,
    /// An own device was not verified.
    UntrustedOwnDevice,
    /// The requesting device changed its sender key.
    ChangedSenderKey,
    /// The requesting device is unknown.
    UnknownDevice,
    /// The algorithm is unsupported.
    UnsupportedAlgorithm,
    /// Forwarding is disabled.
    ForwardingDisabled,
    /// The inbound session is absent.
    MissingInboundSession,
    /// An Olm session is absent; handling was queued.
    MissingOlmSession,
    /// A private SDK error occurred.
    SdkError,
}

/// A typed, privacy-safe incoming room-key diagnostic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingRoomKeyRequestDiagnostic {
    /// Lifecycle stage.
    pub stage: IncomingRoomKeyRequestStage,
    /// Request action.
    pub action: RoomKeyRequestAction,
    /// Anonymous request correlation.
    pub request: RoomKeyDiagnosticAlias,
    /// Requester relationship.
    pub requester_scope: RoomKeyRequesterScope,
    /// Anonymous peer correlation, absent for own/unknown users.
    pub requester_user: Option<RoomKeyDiagnosticAlias>,
    /// Anonymous device correlation.
    pub requester_device: RoomKeyDiagnosticAlias,
    /// Device trust/ownership state.
    pub requester_device_state: RoomKeyRequesterDeviceState,
    /// Anonymous room correlation, when the action carries one.
    pub room: Option<RoomKeyDiagnosticAlias>,
    /// Anonymous requested-session correlation, when available.
    pub requested_session: Option<RoomKeyDiagnosticAlias>,
    /// Active-versus-historical classification.
    pub requested_session_kind: RequestedRoomKeySession,
    /// Whether the inbound session exists, when lookup occurred.
    pub inbound_session_present: Option<bool>,
    /// Whether matching current outbound authorization proof exists.
    pub matching_outbound_proof_present: Option<bool>,
    /// Closed handling result.
    pub outcome: IncomingRoomKeyRequestOutcome,
    /// Closed local refusal reason.
    pub refusal_reason: RoomKeyRefusalReason,
    /// Whether a forwarded/withheld response was created.
    pub response_created: Option<bool>,
    /// Time since this request was first observed.
    pub elapsed_ms: u64,
}

/// Why a new outbound Megolm session was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyRotationReason {
    /// First observed session for the room.
    Initial,
    /// The time limit was reached.
    ExpiredTime,
    /// The message-count limit was reached.
    ExpiredMessageCount,
    /// Membership or device state invalidated the prior session.
    MembershipOrDeviceChange,
    /// Encryption settings changed.
    EncryptionSettingsChanged,
    /// An explicit discard invalidated the prior session.
    ExplicitDiscard,
    /// No session was found in the store.
    StoreMissing,
    /// The prior session was invalidated for an unclassified reason.
    Invalidated,
    /// The SDK cannot safely distinguish the cause.
    Unknown,
}

/// Result of creating a new session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyCreationOutcome {
    /// A new session was created.
    Created,
    /// An existing session was reused.
    Reused,
    /// Session creation failed.
    Failed,
}

/// First sharing state of a newly-created session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyFirstShareOutcome {
    /// Sharing has not completed yet.
    Pending,
    /// Sharing completed.
    Sent,
    /// Sharing failed.
    Failed,
    /// Sharing state is unavailable.
    Unknown,
}

/// A typed, privacy-safe outbound Megolm boundary event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomKeyRotationDiagnostic {
    /// Anonymous room correlation.
    pub room: RoomKeyDiagnosticAlias,
    /// Prior session correlation, if one was observed.
    pub previous_session: Option<RoomKeyDiagnosticAlias>,
    /// New session correlation, if creation succeeded.
    pub new_session: Option<RoomKeyDiagnosticAlias>,
    /// Closed rotation reason.
    pub reason: RoomKeyRotationReason,
    /// Closed creation result.
    pub creation_outcome: RoomKeyCreationOutcome,
    /// First sharing result at the time of this record.
    pub first_share_outcome: RoomKeyFirstShareOutcome,
    /// Whether a safe first-send correlation was available.
    pub first_send_correlation_present: bool,
    /// Creation elapsed time.
    pub elapsed_ms: u64,
}

/// Room-key diagnostic event emitted by the crypto machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomKeyDiagnosticEvent {
    /// Incoming request lifecycle.
    IncomingRequest(IncomingRoomKeyRequestDiagnostic),
    /// Outbound Megolm creation/rotation boundary.
    Rotation(RoomKeyRotationDiagnostic),
    /// Receive-side room-key lifecycle outcome.
    Receive(RoomKeyReceiveDiagnostic),
}

/// The kind of incoming encrypted room-key event, once the decrypted payload
/// is classified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyIngressKind {
    /// A direct `m.room_key` to-device event.
    Direct,
    /// An `m.forwarded_room_key` to-device event.
    Forwarded,
}

/// Closed outcome of the forwarded-room-key authorization gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedRoomKeyAuthOutcome {
    /// No matching outstanding key request exists for the forwarded key.
    RejectedNoMatchingRequest,
    /// The sender device is unknown or not an eligible verified own device.
    RejectedUntrustedSender,
    /// The forwarded payload uses an unsupported algorithm.
    UnsupportedAlgorithm,
    /// The forwarded key passed authorization and reached the merge stage.
    Accepted,
}

/// Closed Megolm merge acceptance decision.
///
/// These are *acceptance* decisions made by the store; persistence happens
/// later at a save boundary. Persistence success is observable through the
/// post-save room-key broadcast; persistence failure is reported as
/// [`RoomKeyMergeDecision::StoreFailed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyMergeDecision {
    /// No prior session existed; the new session was accepted for storage.
    AcceptedNew,
    /// A prior session exists and the incoming copy was accepted as better.
    AcceptedImproved,
    /// The incoming copy is equal to the stored one and was ignored.
    DuplicateIgnored,
    /// The incoming copy is worse than the stored one and was ignored.
    WorseIgnored,
    /// The incoming ratchet does not connect to the stored one; rejected.
    UnconnectedRejected,
    /// The incoming session key is invalid and cannot be parsed.
    InvalidSessionKey,
    /// Persisting accepted sessions failed at the save boundary.
    StoreFailed,
}

/// A receive-side room-key lifecycle outcome, closed and privacy-safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyReceiveDiagnosticKind {
    /// An encrypted room-key event was observed after Olm decryption.
    RoomKeyIngress { kind: RoomKeyIngressKind },
    /// An encrypted to-device event failed Olm decryption.
    ToDeviceOlmFailed,
    /// An Olm session was detected as wedged during to-device decryption.
    ToDeviceOlmWedged,
    /// A to-device event from a dehydrated device was rejected.
    ToDeviceDehydratedRejected,
    /// A malformed/unsupported encrypted to-device payload was dropped.
    ToDeviceMalformed,
    /// A room-key payload used an unsupported algorithm.
    RoomKeyUnsupportedAlgorithm,
    /// A forwarded room key hit the authorization gate.
    ForwardedRoomKeyAuth { outcome: ForwardedRoomKeyAuthOutcome },
    /// A Megolm merge acceptance decision was made.
    Merge { decision: RoomKeyMergeDecision },
}

/// A typed, privacy-safe receive-side room-key diagnostic event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomKeyReceiveDiagnostic {
    /// The closed outcome token.
    pub kind: RoomKeyReceiveDiagnosticKind,
}

/// Aggregate privacy-safe counters for receive-side room-key handling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoomKeyReceiveCounters {
    /// Direct `m.room_key` events observed after Olm decryption.
    pub ingress_direct: u64,
    /// `m.forwarded_room_key` events observed after Olm decryption.
    pub ingress_forwarded: u64,
    /// Encrypted to-device events that failed Olm decryption.
    pub to_device_olm_failed: u64,
    /// Olm sessions detected as wedged during to-device decryption.
    pub to_device_olm_wedged: u64,
    /// To-device events rejected because the sender is dehydrated.
    pub to_device_dehydrated_rejected: u64,
    /// Malformed/unsupported encrypted to-device payloads dropped.
    pub to_device_malformed: u64,
    /// Room-key payloads with an unsupported algorithm.
    pub room_key_unsupported_algorithm: u64,
    /// Forwarded keys rejected because no matching request exists.
    pub forwarded_rejected_no_matching_request: u64,
    /// Forwarded keys rejected because the sender is untrusted.
    pub forwarded_rejected_untrusted_sender: u64,
    /// Forwarded keys with an unsupported algorithm.
    pub forwarded_unsupported_algorithm: u64,
    /// Forwarded keys that passed authorization.
    pub forwarded_accepted: u64,
    /// New sessions accepted for storage.
    pub merge_accepted_new: u64,
    /// Existing sessions accepted as improved.
    pub merge_accepted_improved: u64,
    /// Duplicate copies benignly ignored.
    pub merge_duplicate_ignored: u64,
    /// Worse copies ignored.
    pub merge_worse_ignored: u64,
    /// Unconnected ratchets rejected.
    pub merge_unconnected_rejected: u64,
    /// Invalid session keys rejected.
    pub merge_invalid_session_key: u64,
    /// Accepted sessions that failed to persist.
    pub merge_store_failed: u64,
}

impl RoomKeyReceiveCounters {
    fn apply(&mut self, kind: RoomKeyReceiveDiagnosticKind) {
        match kind {
            RoomKeyReceiveDiagnosticKind::RoomKeyIngress {
                kind: RoomKeyIngressKind::Direct,
            } => self.ingress_direct += 1,
            RoomKeyReceiveDiagnosticKind::RoomKeyIngress {
                kind: RoomKeyIngressKind::Forwarded,
            } => self.ingress_forwarded += 1,
            RoomKeyReceiveDiagnosticKind::ToDeviceOlmFailed => self.to_device_olm_failed += 1,
            RoomKeyReceiveDiagnosticKind::ToDeviceOlmWedged => self.to_device_olm_wedged += 1,
            RoomKeyReceiveDiagnosticKind::ToDeviceDehydratedRejected => {
                self.to_device_dehydrated_rejected += 1
            }
            RoomKeyReceiveDiagnosticKind::ToDeviceMalformed => self.to_device_malformed += 1,
            RoomKeyReceiveDiagnosticKind::RoomKeyUnsupportedAlgorithm => {
                self.room_key_unsupported_algorithm += 1
            }
            RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
                outcome: ForwardedRoomKeyAuthOutcome::RejectedNoMatchingRequest,
            } => self.forwarded_rejected_no_matching_request += 1,
            RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
                outcome: ForwardedRoomKeyAuthOutcome::RejectedUntrustedSender,
            } => self.forwarded_rejected_untrusted_sender += 1,
            RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
                outcome: ForwardedRoomKeyAuthOutcome::UnsupportedAlgorithm,
            } => self.forwarded_unsupported_algorithm += 1,
            RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
                outcome: ForwardedRoomKeyAuthOutcome::Accepted,
            } => self.forwarded_accepted += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::AcceptedNew,
            } => self.merge_accepted_new += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::AcceptedImproved,
            } => self.merge_accepted_improved += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::DuplicateIgnored,
            } => self.merge_duplicate_ignored += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::WorseIgnored,
            } => self.merge_worse_ignored += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::UnconnectedRejected,
            } => self.merge_unconnected_rejected += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::InvalidSessionKey,
            } => self.merge_invalid_session_key += 1,
            RoomKeyReceiveDiagnosticKind::Merge {
                decision: RoomKeyMergeDecision::StoreFailed,
            } => self.merge_store_failed += 1,
        }
    }
}

/// Observer called synchronously with privacy-safe typed events.
pub type RoomKeyDiagnosticObserver = Arc<dyn Fn(RoomKeyDiagnosticEvent) + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct RoomKeyDiagnosticHub(Arc<Mutex<RoomKeyDiagnosticState>>);

impl std::fmt::Debug for RoomKeyDiagnosticHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKeyDiagnosticHub(..)")
    }
}

#[derive(Default)]
struct RoomKeyDiagnosticState {
    observer: Option<RoomKeyDiagnosticObserver>,
    rooms: BTreeMap<String, RoomKeyDiagnosticAlias>,
    sessions: BTreeMap<(String, String), RoomKeyDiagnosticAlias>,
    requests: BTreeMap<(String, String, String), RequestDiagnosticState>,
    peers: BTreeMap<String, RoomKeyDiagnosticAlias>,
    devices: BTreeMap<(String, String), RoomKeyDiagnosticAlias>,
    active_sessions: BTreeMap<String, String>,
    pending_discard_reasons: BTreeMap<String, RoomKeyRotationReason>,
    next_room: u64,
    next_session: u64,
    next_request: u64,
    next_peer: u64,
    next_device: u64,
    receive_counters: RoomKeyReceiveCounters,
}

struct RequestDiagnosticState {
    alias: RoomKeyDiagnosticAlias,
    first_seen: Instant,
}

impl RoomKeyDiagnosticHub {
    pub(crate) fn set_observer(&self, observer: Option<RoomKeyDiagnosticObserver>) {
        lock(&self.0).observer = observer;
    }

    /// Record a receive-side room-key outcome: increment the matching
    /// aggregate counter and notify the observer with the typed event.
    pub(crate) fn emit_receive(&self, kind: RoomKeyReceiveDiagnosticKind) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            state.receive_counters.apply(kind);
            (state.observer.clone(), RoomKeyReceiveDiagnostic { kind })
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::Receive(event));
        }
    }

    /// Snapshot of the aggregate receive-side counters.
    pub(crate) fn receive_counters(&self) -> RoomKeyReceiveCounters {
        lock(&self.0).receive_counters
    }

    pub(crate) fn note_discard(&self, room_id: &RoomId, reason: RoomKeyRotationReason) {
        lock(&self.0).pending_discard_reasons.insert(room_id.as_str().to_owned(), reason);
    }

    pub(crate) fn classify_rotation_reason(
        &self,
        room_id: &RoomId,
        expired_time: bool,
        expired_messages: bool,
        invalidated: bool,
        had_session: bool,
    ) -> RoomKeyRotationReason {
        let mut state = lock(&self.0);
        if let Some(reason) = state.pending_discard_reasons.remove(room_id.as_str()) {
            return reason;
        }
        if expired_messages {
            RoomKeyRotationReason::ExpiredMessageCount
        } else if expired_time {
            RoomKeyRotationReason::ExpiredTime
        } else if invalidated {
            RoomKeyRotationReason::Invalidated
        } else if had_session || state.active_sessions.contains_key(room_id.as_str()) {
            RoomKeyRotationReason::StoreMissing
        } else {
            RoomKeyRotationReason::Initial
        }
    }

    pub(crate) fn emit_rotation(
        &self,
        room_id: &RoomId,
        previous_session_id: Option<&str>,
        new_session_id: Option<&str>,
        reason: RoomKeyRotationReason,
        creation_outcome: RoomKeyCreationOutcome,
        elapsed_ms: u64,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let room = room_alias(&mut state, room_id);
            let previous_session =
                previous_session_id.map(|session| session_alias(&mut state, room_id, session));
            let new_session = new_session_id.map(|session| {
                state.active_sessions.insert(room_id.as_str().to_owned(), session.to_owned());
                session_alias(&mut state, room_id, session)
            });
            let event = RoomKeyRotationDiagnostic {
                room,
                previous_session,
                new_session,
                reason,
                creation_outcome,
                first_share_outcome: RoomKeyFirstShareOutcome::Pending,
                first_send_correlation_present: false,
                elapsed_ms,
            };
            (state.observer.clone(), event)
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::Rotation(event));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_request(
        &self,
        stage: IncomingRoomKeyRequestStage,
        action: RoomKeyRequestAction,
        sender: &UserId,
        requesting_device: &DeviceId,
        request_id: &TransactionId,
        own_user: &UserId,
        own_device: &DeviceId,
        room_and_session: Option<(&RoomId, &str)>,
        requested_session_kind: RequestedRoomKeySession,
        requester_device_state: RoomKeyRequesterDeviceState,
        inbound_session_present: Option<bool>,
        matching_outbound_proof_present: Option<bool>,
        outcome: IncomingRoomKeyRequestOutcome,
        refusal_reason: RoomKeyRefusalReason,
        response_created: Option<bool>,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let request_key = (
                sender.as_str().to_owned(),
                requesting_device.as_str().to_owned(),
                request_id.as_str().to_owned(),
            );
            let request = if let Some(request) = state.requests.get(&request_key) {
                request.alias
            } else {
                state.next_request += 1;
                let request = RequestDiagnosticState {
                    alias: RoomKeyDiagnosticAlias(state.next_request),
                    first_seen: Instant::now(),
                };
                let alias = request.alias;
                state.requests.insert(request_key.clone(), request);
                alias
            };
            let elapsed_ms = state
                .requests
                .get(&request_key)
                .map(|request| {
                    request.first_seen.elapsed().as_millis().min(u64::MAX as u128) as u64
                })
                .unwrap_or(0);
            let requester_scope = if sender == own_user {
                RoomKeyRequesterScope::Own
            } else {
                RoomKeyRequesterScope::Peer
            };
            let requester_user =
                if sender == own_user { None } else { Some(peer_alias(&mut state, sender)) };
            let requester_device = device_alias(&mut state, sender, requesting_device);
            let (room, requested_session) =
                room_and_session.map_or((None, None), |(room_id, session_id)| {
                    (
                        Some(room_alias(&mut state, room_id)),
                        Some(session_alias(&mut state, room_id, session_id)),
                    )
                });
            let requester_device_state = if sender == own_user && requesting_device == own_device {
                RoomKeyRequesterDeviceState::Current
            } else {
                requester_device_state
            };
            let event = IncomingRoomKeyRequestDiagnostic {
                stage,
                action,
                request,
                requester_scope,
                requester_user,
                requester_device,
                requester_device_state,
                room,
                requested_session,
                requested_session_kind,
                inbound_session_present,
                matching_outbound_proof_present,
                outcome,
                refusal_reason,
                response_created,
                elapsed_ms,
            };
            (state.observer.clone(), event)
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::IncomingRequest(event));
        }
    }
}

fn room_alias(state: &mut RoomKeyDiagnosticState, room_id: &RoomId) -> RoomKeyDiagnosticAlias {
    if let Some(alias) = state.rooms.get(room_id.as_str()) {
        *alias
    } else {
        state.next_room += 1;
        let alias = RoomKeyDiagnosticAlias(state.next_room);
        state.rooms.insert(room_id.as_str().to_owned(), alias);
        alias
    }
}

fn session_alias(
    state: &mut RoomKeyDiagnosticState,
    room_id: &RoomId,
    session_id: &str,
) -> RoomKeyDiagnosticAlias {
    let key = (room_id.as_str().to_owned(), session_id.to_owned());
    if let Some(alias) = state.sessions.get(&key) {
        *alias
    } else {
        state.next_session += 1;
        let alias = RoomKeyDiagnosticAlias(state.next_session);
        state.sessions.insert(key, alias);
        alias
    }
}

fn peer_alias(state: &mut RoomKeyDiagnosticState, user_id: &UserId) -> RoomKeyDiagnosticAlias {
    if let Some(alias) = state.peers.get(user_id.as_str()) {
        *alias
    } else {
        state.next_peer += 1;
        let alias = RoomKeyDiagnosticAlias(state.next_peer);
        state.peers.insert(user_id.as_str().to_owned(), alias);
        alias
    }
}

fn device_alias(
    state: &mut RoomKeyDiagnosticState,
    user_id: &UserId,
    device_id: &DeviceId,
) -> RoomKeyDiagnosticAlias {
    let key = (user_id.as_str().to_owned(), device_id.as_str().to_owned());
    if let Some(alias) = state.devices.get(&key) {
        *alias
    } else {
        state.next_device += 1;
        let alias = RoomKeyDiagnosticAlias(state.next_device);
        state.devices.insert(key, alias);
        alias
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruma::{OwnedTransactionId, device_id, room_id, user_id};

    #[test]
    fn aliases_are_stable_per_machine_and_restart_from_one() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        let request_id = OwnedTransactionId::from("PRIVATE-REQUEST");
        for _ in 0..2 {
            hub.emit_request(
                IncomingRoomKeyRequestStage::Received,
                RoomKeyRequestAction::Request,
                user_id!("@peer:example.invalid"),
                device_id!("PRIVATE-DEVICE"),
                &request_id,
                user_id!("@own:example.invalid"),
                device_id!("OWN"),
                Some((room_id!("!private:example.invalid"), "PRIVATE-SESSION")),
                RequestedRoomKeySession::Unknown,
                RoomKeyRequesterDeviceState::KnownPeer,
                None,
                None,
                IncomingRoomKeyRequestOutcome::None,
                RoomKeyRefusalReason::None,
                None,
            );
        }

        let events = lock(&events);
        let RoomKeyDiagnosticEvent::IncomingRequest(first) = &events[0] else { panic!() };
        let RoomKeyDiagnosticEvent::IncomingRequest(second) = &events[1] else { panic!() };
        assert_eq!(first.request, second.request);
        assert_eq!(first.room, second.room);
        assert_eq!(first.requested_session, second.requested_session);

        let fresh = RoomKeyDiagnosticHub::default();
        assert_eq!(
            room_alias(&mut lock(&fresh.0), room_id!("!other:example.invalid")).ordinal(),
            1
        );
    }

    #[test]
    fn debug_output_contains_no_private_identifiers() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));
        let request_id = OwnedTransactionId::from("PRIVATE-REQUEST");
        hub.emit_request(
            IncomingRoomKeyRequestStage::Outcome,
            RoomKeyRequestAction::Request,
            user_id!("@private-user:example.invalid"),
            device_id!("PRIVATE-DEVICE"),
            &request_id,
            user_id!("@own:example.invalid"),
            device_id!("OWN"),
            Some((room_id!("!private-room:example.invalid"), "PRIVATE-SESSION")),
            RequestedRoomKeySession::Historical,
            RoomKeyRequesterDeviceState::KnownPeer,
            Some(true),
            Some(false),
            IncomingRoomKeyRequestOutcome::Refused,
            RoomKeyRefusalReason::MissingOldOutboundProof,
            Some(false),
        );
        let debug = format!("{:?}", lock(&events));
        for private in
            ["private-user", "PRIVATE-DEVICE", "PRIVATE-REQUEST", "private-room", "PRIVATE-SESSION"]
        {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn request_session_alias_matches_the_prior_rotation_boundary() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));
        hub.emit_rotation(
            room_id!("!private:example.invalid"),
            None,
            Some("PRIVATE-SESSION"),
            RoomKeyRotationReason::Initial,
            RoomKeyCreationOutcome::Created,
            2,
        );
        let request_id = OwnedTransactionId::from("PRIVATE-REQUEST");
        hub.emit_request(
            IncomingRoomKeyRequestStage::SessionLookup,
            RoomKeyRequestAction::Request,
            user_id!("@peer:example.invalid"),
            device_id!("PRIVATE-DEVICE"),
            &request_id,
            user_id!("@own:example.invalid"),
            device_id!("OWN"),
            Some((room_id!("!private:example.invalid"), "PRIVATE-SESSION")),
            RequestedRoomKeySession::Current,
            RoomKeyRequesterDeviceState::KnownPeer,
            Some(true),
            Some(true),
            IncomingRoomKeyRequestOutcome::None,
            RoomKeyRefusalReason::None,
            None,
        );
        let events = lock(&events);
        let RoomKeyDiagnosticEvent::Rotation(rotation) = &events[0] else { panic!() };
        let RoomKeyDiagnosticEvent::IncomingRequest(request) = &events[1] else { panic!() };
        assert_eq!(rotation.new_session, request.requested_session);
    }

    #[test]
    fn rotation_reason_prefers_explicit_causes_and_never_guesses_from_timing() {
        let hub = RoomKeyDiagnosticHub::default();
        let room = room_id!("!private:example.invalid");
        hub.note_discard(room, RoomKeyRotationReason::MembershipOrDeviceChange);
        assert_eq!(
            hub.classify_rotation_reason(room, true, true, true, true),
            RoomKeyRotationReason::MembershipOrDeviceChange
        );
        assert_eq!(
            hub.classify_rotation_reason(room, false, true, false, true),
            RoomKeyRotationReason::ExpiredMessageCount
        );
        assert_eq!(
            hub.classify_rotation_reason(room, true, false, false, true),
            RoomKeyRotationReason::ExpiredTime
        );
        assert_eq!(
            hub.classify_rotation_reason(room, false, false, true, true),
            RoomKeyRotationReason::Invalidated
        );
    }

    #[test]
    fn receive_counters_accumulate_and_observer_gets_every_event() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        hub.emit_receive(RoomKeyReceiveDiagnosticKind::RoomKeyIngress {
            kind: RoomKeyIngressKind::Direct,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::RoomKeyIngress {
            kind: RoomKeyIngressKind::Forwarded,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ToDeviceOlmFailed);
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ToDeviceOlmWedged);
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ToDeviceDehydratedRejected);
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ToDeviceMalformed);
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::RoomKeyUnsupportedAlgorithm);
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
            outcome: ForwardedRoomKeyAuthOutcome::RejectedNoMatchingRequest,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
            outcome: ForwardedRoomKeyAuthOutcome::RejectedUntrustedSender,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
            outcome: ForwardedRoomKeyAuthOutcome::UnsupportedAlgorithm,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
            outcome: ForwardedRoomKeyAuthOutcome::Accepted,
        });
        for decision in [
            RoomKeyMergeDecision::AcceptedNew,
            RoomKeyMergeDecision::AcceptedImproved,
            RoomKeyMergeDecision::DuplicateIgnored,
            RoomKeyMergeDecision::WorseIgnored,
            RoomKeyMergeDecision::UnconnectedRejected,
            RoomKeyMergeDecision::InvalidSessionKey,
            RoomKeyMergeDecision::StoreFailed,
        ] {
            hub.emit_receive(RoomKeyReceiveDiagnosticKind::Merge { decision });
        }

        let counters = hub.receive_counters();
        assert_eq!(counters.ingress_direct, 1);
        assert_eq!(counters.ingress_forwarded, 1);
        assert_eq!(counters.to_device_olm_failed, 1);
        assert_eq!(counters.to_device_olm_wedged, 1);
        assert_eq!(counters.to_device_dehydrated_rejected, 1);
        assert_eq!(counters.to_device_malformed, 1);
        assert_eq!(counters.room_key_unsupported_algorithm, 1);
        assert_eq!(counters.forwarded_rejected_no_matching_request, 1);
        assert_eq!(counters.forwarded_rejected_untrusted_sender, 1);
        assert_eq!(counters.forwarded_unsupported_algorithm, 1);
        assert_eq!(counters.forwarded_accepted, 1);
        assert_eq!(counters.merge_accepted_new, 1);
        assert_eq!(counters.merge_accepted_improved, 1);
        assert_eq!(counters.merge_duplicate_ignored, 1);
        assert_eq!(counters.merge_worse_ignored, 1);
        assert_eq!(counters.merge_unconnected_rejected, 1);
        assert_eq!(counters.merge_invalid_session_key, 1);
        assert_eq!(counters.merge_store_failed, 1);

        let events = lock(&events);
        assert_eq!(events.len(), 18);
        for event in events.iter() {
            assert!(matches!(event, RoomKeyDiagnosticEvent::Receive(_)));
        }
    }

    #[test]
    fn receive_diagnostics_contain_no_private_identifiers() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        hub.emit_receive(RoomKeyReceiveDiagnosticKind::RoomKeyIngress {
            kind: RoomKeyIngressKind::Direct,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::Merge {
            decision: RoomKeyMergeDecision::AcceptedNew,
        });
        hub.emit_receive(RoomKeyReceiveDiagnosticKind::ForwardedRoomKeyAuth {
            outcome: ForwardedRoomKeyAuthOutcome::RejectedNoMatchingRequest,
        });

        let debug = format!("{:?}", lock(&events));
        assert!(!debug.contains("room"));
        assert!(!debug.contains("user"));
        assert!(!debug.contains("device"));
        assert!(!debug.contains("session"));
        assert!(!debug.contains("PRIVATE"));
        assert!(!debug.contains("@"));
        assert!(!debug.contains("!"));
    }
}
