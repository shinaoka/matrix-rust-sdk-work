// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Privacy-preserving, typed room-key lifecycle diagnostics.
//!
//! Raw Matrix identifiers never leave this module. They are mapped to
//! process-local ordinals owned by one [`OlmMachine`](crate::OlmMachine).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use ruma::{DeviceId, RoomId, TransactionId, UserId};

/// A process-local anonymous identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoomKeyDiagnosticAlias(u64);

impl RoomKeyDiagnosticAlias {
    /// Create an alias from an explicit process-local ordinal. Used by
    /// diagnostics consumers that mirror SDK events in tests.
    pub const fn new(ordinal: u64) -> Self {
        Self(ordinal)
    }

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
    /// A full member-list reload invalidated the prior session, but its trigger is unknown.
    FullMemberListReload,
    /// A new Sliding Sync room subscription forced a full member-list reload.
    RoomSubscription,
    /// A limited sync response forced a full member-list reload.
    LimitedSyncResponse,
    /// Sharing the current room key failed, so it was discarded before retry.
    KeyShareFailure,
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
    /// Time between the authoritative discard and this replacement-session
    /// boundary, when the rotation followed an explicit discard.
    pub discard_elapsed_ms: Option<u64>,
    /// Creation elapsed time.
    pub elapsed_ms: u64,
}

/// Closed outcome of discarding an outbound Megolm session after a full
/// member-list reload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomKeyMemberReloadDiscardOutcome {
    /// An active outbound session was invalidated.
    Discarded,
    /// No active outbound session existed.
    NoActiveSession,
    /// The crypto store operation failed.
    SdkError,
}

/// Privacy-safe context captured around a full member-list reload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoomKeyMemberReloadContext {
    /// Whether the member list was complete immediately before the first
    /// process-local invalidation, if that provenance is available.
    pub members_were_synced_before_invalidation: Option<bool>,
    /// Number of invalidation marks observed before this reload.
    pub invalidation_count: u32,
    /// Time from the first observed invalidation to this reload boundary.
    pub invalidation_age_ms: Option<u64>,
    /// Homeserver `/members` request duration, when measured by the caller.
    pub request_elapsed_ms: Option<u64>,
    /// Number of member events returned. The observer receives only a bucket.
    pub response_member_count: usize,
    /// Local response-processing duration before the discard operation.
    pub processing_elapsed_ms: u64,
}

/// A typed, privacy-safe full-member-reload and Megolm-discard boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomKeyMemberReloadDiagnostic {
    /// Anonymous room correlation shared with the later rotation boundary.
    pub room: RoomKeyDiagnosticAlias,
    /// Closed reason retained from the member invalidation.
    pub reason: RoomKeyRotationReason,
    /// Whether members were complete before the first invalidation, when known.
    pub members_were_synced_before_invalidation: Option<bool>,
    /// Invalidation count bucket: 0, 1, 2-5, 6-20, or 21+.
    pub invalidation_count_bucket: u8,
    /// Time from first invalidation to reload, when process-local provenance exists.
    pub invalidation_age_ms: Option<u64>,
    /// Homeserver `/members` request duration, when available.
    pub request_elapsed_ms: Option<u64>,
    /// Response member-count bucket: 0, 1, 2-5, 6-20, or 21+.
    pub response_member_count_bucket: u8,
    /// Local processing duration before the discard boundary.
    pub processing_elapsed_ms: u64,
    /// Closed discard result.
    pub discard_outcome: RoomKeyMemberReloadDiscardOutcome,
}

/// Room-key diagnostic event emitted by the crypto machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomKeyDiagnosticEvent {
    /// Incoming request lifecycle.
    IncomingRequest(IncomingRoomKeyRequestDiagnostic),
    /// Outbound Megolm creation/rotation boundary.
    Rotation(RoomKeyRotationDiagnostic),
    /// Full member-list reload and the resulting outbound-session discard.
    MemberReload(RoomKeyMemberReloadDiagnostic),
    /// Receive-side room-key lifecycle outcome.
    Receive(RoomKeyReceiveDiagnostic),
    /// Post-unwedge recovery re-share outcome (issue #477).
    OlmRecovery(OlmRecoveryDiagnostic),
    /// Per-device initial-share lifecycle stage (issue #509).
    InitialShare(InitialShareDeviceDiagnostic),
    /// Session-scoped initial-share summary at first event encryption (issue
    /// #509).
    InitialShareSession(InitialShareSessionDiagnostic),
    /// Bounded index-0 duplicate-share record (issue #510).
    Index0Reshare(Index0ReshareDiagnostic),
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
    RoomKeyIngress {
        /// Direct or forwarded kind.
        kind: RoomKeyIngressKind,
    },
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
    ForwardedRoomKeyAuth {
        /// The closed authorization outcome.
        outcome: ForwardedRoomKeyAuthOutcome,
    },
    /// A Megolm merge acceptance decision was made.
    Merge {
        /// The closed merge decision.
        decision: RoomKeyMergeDecision,
    },
}

/// A typed, privacy-safe receive-side room-key diagnostic event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomKeyReceiveDiagnostic {
    /// The closed outcome token.
    pub kind: RoomKeyReceiveDiagnosticKind,
}

/// Closed outcome of the post-unwedge recovery re-share (issue #477).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OlmRecoverySignalOutcome {
    /// The unwedge signal was observed for a known device.
    Observed,
    /// The unwedge signal was ignored: unknown device.
    IgnoredUnknownDevice,
    /// The unwedge signal was ignored: dehydrated device.
    IgnoredDehydrated,
    /// The recovery pass failed.
    Failed,
}

/// Closed outcome of a per-room post-unwedge re-share (issue #477).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OlmRecoveryReshareOutcome {
    /// The re-share was queued.
    Queued,
    /// A re-share was already pending for the device.
    AlreadyPending,
    /// No matching active session was shared with the device.
    NoMatchingSession,
    /// Recipient policy or pending rotation blocked the re-share.
    PolicyBlocked,
    /// The re-share failed.
    Failed,
}

/// A typed, privacy-safe post-unwedge recovery diagnostic (issue #477).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OlmRecoveryDiagnostic {
    /// The signal outcome token.
    pub signal: OlmRecoverySignalOutcome,
    /// The per-room re-share outcome token.
    pub reshare: Option<OlmRecoveryReshareOutcome>,
    /// Matching active outbound-session count bucket.
    pub matching_sessions_bucket: u8,
    /// Anonymous device correlation (issue #509). Present when the signal or
    /// re-share is tied to one device; matches the device alias used by the
    /// initial-share diagnostics.
    pub device: Option<RoomKeyDiagnosticAlias>,
}

/// Device-policy class for initial-share diagnostics (issue #509).
///
/// A closed token describing how the device was classified by the sharing
/// policy. It never contains identifiers or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialShareDeviceClass {
    /// A verified device belonging to this account.
    VerifiedOwn,
    /// An unverified device belonging to this account.
    UnverifiedOwn,
    /// A verified device belonging to another account.
    VerifiedPeer,
    /// An unverified device belonging to another account.
    UnverifiedPeer,
    /// A dehydrated device (excluded from sharing).
    Dehydrated,
    /// The class could not be established safely.
    Unknown,
}

/// Per-device lifecycle stage of the initial room-key share (issue #509).
///
/// Stages are closed tokens; a device may observe several stages in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialShareStage {
    /// Policy selected this device as an eligible recipient.
    Eligible,
    /// No Olm session was available, so a one-time-key claim was needed and
    /// an `m.no_olm` withheld notice was queued.
    OlmMissing,
    /// The room key was successfully encrypted with Olm for this device.
    OlmEncrypted,
    /// Olm encryption for this device failed.
    OlmEncryptionFailed,
    /// The device was withheld by recipient policy.
    Withheld,
    /// The to-device request carrying the key was queued.
    RequestQueued,
    /// The homeserver accepted the to-device request. This is not a
    /// recipient-side decryption acknowledgement.
    HomeserverAccepted,
    /// A to-device send attempt failed. The request may be retried and later
    /// reach [`InitialShareStage::HomeserverAccepted`].
    RequestFailed,
    /// The device's share-state was committed for the session at the given
    /// Megolm message index.
    ShareStateCommitted {
        /// The message index at which the key was shared with the device.
        message_index: u32,
    },
}

/// A typed, privacy-safe per-device initial-share diagnostic (issue #509).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialShareDeviceDiagnostic {
    /// Anonymous session correlation.
    pub session: RoomKeyDiagnosticAlias,
    /// Anonymous device correlation, stable across initial share, unwedge
    /// re-share, and `m.room_key_request` diagnostics for this runtime.
    pub device: RoomKeyDiagnosticAlias,
    /// Device-policy class.
    pub device_class: InitialShareDeviceClass,
    /// Lifecycle stage reached.
    pub stage: InitialShareStage,
    /// Time since this session's initial share was first observed.
    pub elapsed_ms: u64,
}

/// A typed, privacy-safe session-scoped initial-share summary (issue #509),
/// emitted once when the first room event is encrypted for the session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialShareSessionDiagnostic {
    /// Anonymous session correlation.
    pub session: RoomKeyDiagnosticAlias,
    /// Message index of the first encrypted room event.
    pub first_event_message_index: u32,
    /// Whether every eligible initial share had settled (no pending to-device
    /// requests) before the first event was encrypted.
    pub all_initial_shares_settled_first: bool,
    /// Pending to-device request count bucket at first-event time.
    pub pending_requests_bucket: u8,
    /// Number of eligible own devices.
    pub eligible_own_devices: u32,
    /// Number of eligible peer devices.
    pub eligible_peer_devices: u32,
    /// Devices whose share-state was committed at message index 0.
    pub index0_shares_committed: u32,
    /// Devices whose share-state was committed after index 0.
    pub after_index0_shares_committed: u32,
    /// Devices whose to-device request was accepted by the homeserver.
    pub homeserver_accepted_devices: u32,
    /// Whether the session was at message index 0 when first shared (true
    /// when no committed share contradicts it).
    pub created_at_index0: bool,
    /// Time since this session's initial share was first observed.
    pub elapsed_ms: u64,
}

/// Closed state of the initial index-0 share at the duplicate-share decision
/// point (issue #510).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Index0InitialShareState {
    /// Every eligible device settled its index-0 share.
    Accepted,
    /// Some eligible device did not settle (pending or failed).
    Failed,
    /// Every eligible device was withheld by policy.
    Withheld,
    /// No eligible recipient existed.
    NoRecipients,
}

/// Closed outcome of the bounded index-0 duplicate share (issue #510).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Index0ReshareOutcome {
    /// The duplicate to-device requests were sent and accepted by the
    /// homeserver. This is not a recipient decryption proof.
    Sent,
    /// The bounded deadline expired before the duplicate settled.
    Deadline,
    /// The attempt was cancelled by a fenced identity change (rotation,
    /// discard, leave, or runtime replacement).
    Cancelled,
    /// Recipient policy blocked the duplicate (e.g. rotation pending).
    PolicyBlocked,
    /// The duplicate send failed.
    Failed,
    /// No duplicate was needed (already attempted, or no eligible
    /// recipients).
    NotNeeded,
}

/// A typed, privacy-safe bounded index-0 duplicate-share record (issue #510).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Index0ReshareDiagnostic {
    /// Anonymous session correlation.
    pub session: RoomKeyDiagnosticAlias,
    /// Closed initial-share state at the decision point.
    pub initial_share: Index0InitialShareState,
    /// Closed duplicate-share outcome.
    pub reshare: Index0ReshareOutcome,
    /// Eligible own-device count bucket.
    pub eligible_own_bucket: u8,
    /// Eligible peer-device count bucket.
    pub eligible_peer_bucket: u8,
    /// Time since this session's initial share was first observed.
    pub elapsed_ms: u64,
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
            RoomKeyReceiveDiagnosticKind::RoomKeyIngress { kind: RoomKeyIngressKind::Direct } => {
                self.ingress_direct += 1
            }
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
            RoomKeyReceiveDiagnosticKind::Merge { decision: RoomKeyMergeDecision::AcceptedNew } => {
                self.merge_accepted_new += 1
            }
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
            RoomKeyReceiveDiagnosticKind::Merge { decision: RoomKeyMergeDecision::StoreFailed } => {
                self.merge_store_failed += 1
            }
        }
    }
}

/// Aggregate privacy-safe counters for post-unwedge recovery (issue #477).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OlmRecoveryCounters {
    /// Unwedge signals observed for known devices.
    pub signal_observed: u64,
    /// Unwedge signals ignored because the device is unknown.
    pub signal_ignored_unknown_device: u64,
    /// Unwedge signals ignored because the device is dehydrated.
    pub signal_ignored_dehydrated: u64,
    /// Recovery signal processing failures.
    pub signal_failed: u64,
    /// Matching active outbound-session count buckets.
    pub matching_sessions_bucket_0: u64,
    /// Matching count bucket: exactly one session.
    pub matching_sessions_bucket_1: u64,
    /// Matching count bucket: 2-5 sessions.
    pub matching_sessions_bucket_2_to_5: u64,
    /// Matching count bucket: 6-20 sessions.
    pub matching_sessions_bucket_6_to_20: u64,
    /// Matching count bucket: 21+ sessions.
    pub matching_sessions_bucket_21_plus: u64,
    /// Re-shares queued.
    pub reshare_queued: u64,
    /// Re-shares skipped because one was already pending.
    pub reshare_already_pending: u64,
    /// Re-shares skipped because no matching session was shared with the device.
    pub reshare_no_matching_session: u64,
    /// Re-shares blocked by recipient policy or pending rotation.
    pub reshare_policy_blocked: u64,
    /// Re-shares that failed.
    pub reshare_failed: u64,
}

impl OlmRecoveryCounters {
    fn record_matching_bucket(&mut self, count: usize) {
        match count {
            0 => self.matching_sessions_bucket_0 += 1,
            1 => self.matching_sessions_bucket_1 += 1,
            2..=5 => self.matching_sessions_bucket_2_to_5 += 1,
            6..=20 => self.matching_sessions_bucket_6_to_20 += 1,
            _ => self.matching_sessions_bucket_21_plus += 1,
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
    pending_discards: BTreeMap<String, PendingRoomKeyDiscard>,
    next_room: u64,
    next_session: u64,
    next_request: u64,
    next_peer: u64,
    next_device: u64,
    receive_counters: RoomKeyReceiveCounters,
    olm_recovery_counters: OlmRecoveryCounters,
    /// Device-policy class observed at initial-share eligibility (issue #509).
    device_classes: BTreeMap<RoomKeyDiagnosticAlias, InitialShareDeviceClass>,
    /// Per-session initial-share tallies (issue #509).
    initial_shares: BTreeMap<(String, String), InitialShareState>,
    /// Per-(room, session) one-shot flag for the bounded index-0 duplicate
    /// share (issue #510).
    index0_reshare_attempted: BTreeSet<(String, String)>,
}

struct PendingRoomKeyDiscard {
    reason: RoomKeyRotationReason,
    noted_at: Instant,
}

pub(crate) struct RoomKeyRotationClassification {
    pub(crate) reason: RoomKeyRotationReason,
    pub(crate) discard_elapsed_ms: Option<u64>,
}

/// Per-session initial-share tally (issue #509).
#[derive(Default)]
struct InitialShareState {
    first_seen: Option<Instant>,
    eligible_own: u32,
    eligible_peer: u32,
    eligible_devices: BTreeSet<RoomKeyDiagnosticAlias>,
    withheld_devices: BTreeSet<RoomKeyDiagnosticAlias>,
    index0_committed: u32,
    after0_committed: u32,
    min_committed_index: Option<u32>,
    accepted_devices: BTreeSet<RoomKeyDiagnosticAlias>,
    first_event_reported: bool,
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

    /// Record a post-unwedge recovery signal outcome (issue #477): update the
    /// matching aggregate counter and notify the observer.
    pub(crate) fn emit_olm_recovery_signal(
        &self,
        device: Option<(&UserId, &DeviceId)>,
        outcome: OlmRecoverySignalOutcome,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            match outcome {
                OlmRecoverySignalOutcome::Observed => {
                    state.olm_recovery_counters.signal_observed += 1
                }
                OlmRecoverySignalOutcome::IgnoredUnknownDevice => {
                    state.olm_recovery_counters.signal_ignored_unknown_device += 1
                }
                OlmRecoverySignalOutcome::IgnoredDehydrated => {
                    state.olm_recovery_counters.signal_ignored_dehydrated += 1
                }
                OlmRecoverySignalOutcome::Failed => state.olm_recovery_counters.signal_failed += 1,
            }
            (
                state.observer.clone(),
                OlmRecoveryDiagnostic {
                    signal: outcome,
                    reshare: None,
                    matching_sessions_bucket: 0,
                    device: device
                        .map(|(user_id, device_id)| device_alias(&mut state, user_id, device_id)),
                },
            )
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::OlmRecovery(event));
        }
    }

    /// Record a post-unwedge per-room re-share outcome (issue #477).
    pub(crate) fn emit_olm_recovery_reshare(
        &self,
        device: Option<(&UserId, &DeviceId)>,
        signal: OlmRecoverySignalOutcome,
        matching_sessions: usize,
        reshare: OlmRecoveryReshareOutcome,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            state.olm_recovery_counters.record_matching_bucket(matching_sessions);
            match reshare {
                OlmRecoveryReshareOutcome::Queued => {
                    state.olm_recovery_counters.reshare_queued += 1
                }
                OlmRecoveryReshareOutcome::AlreadyPending => {
                    state.olm_recovery_counters.reshare_already_pending += 1
                }
                OlmRecoveryReshareOutcome::NoMatchingSession => {
                    state.olm_recovery_counters.reshare_no_matching_session += 1
                }
                OlmRecoveryReshareOutcome::PolicyBlocked => {
                    state.olm_recovery_counters.reshare_policy_blocked += 1
                }
                OlmRecoveryReshareOutcome::Failed => {
                    state.olm_recovery_counters.reshare_failed += 1
                }
            }
            (
                state.observer.clone(),
                OlmRecoveryDiagnostic {
                    signal,
                    reshare: Some(reshare),
                    matching_sessions_bucket: matching_bucket_token(matching_sessions),
                    device: device
                        .map(|(user_id, device_id)| device_alias(&mut state, user_id, device_id)),
                },
            )
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::OlmRecovery(event));
        }
    }

    /// Record a per-device initial-share lifecycle stage (issue #509):
    /// increment nothing here (aggregates live on the Koushi side), cache the
    /// device-policy class, and notify the observer.
    pub(crate) fn emit_initial_share_device(
        &self,
        room_id: &RoomId,
        session_id: &str,
        user_id: &UserId,
        device_id: &DeviceId,
        device_class: InitialShareDeviceClass,
        stage: InitialShareStage,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let session = session_alias(&mut state, room_id, session_id);
            let device = device_alias(&mut state, user_id, device_id);
            // Callers without `DeviceData` pass `Unknown`; fall back to the
            // class cached by the `Eligible` emission for this device.
            let device_class = if device_class == InitialShareDeviceClass::Unknown {
                state
                    .device_classes
                    .get(&device)
                    .copied()
                    .unwrap_or(InitialShareDeviceClass::Unknown)
            } else {
                state.device_classes.insert(device, device_class);
                device_class
            };
            let tally = state
                .initial_shares
                .entry((room_id.as_str().to_owned(), session_id.to_owned()))
                .or_default();
            if tally.first_seen.is_none() {
                tally.first_seen = Some(Instant::now());
            }
            match stage {
                InitialShareStage::Eligible => match device_class {
                    InitialShareDeviceClass::VerifiedOwn
                    | InitialShareDeviceClass::UnverifiedOwn => {
                        if tally.eligible_devices.insert(device) {
                            tally.eligible_own += 1;
                        }
                    }
                    InitialShareDeviceClass::VerifiedPeer
                    | InitialShareDeviceClass::UnverifiedPeer => {
                        if tally.eligible_devices.insert(device) {
                            tally.eligible_peer += 1;
                        }
                    }
                    InitialShareDeviceClass::Dehydrated | InitialShareDeviceClass::Unknown => {}
                },
                InitialShareStage::ShareStateCommitted { message_index } => {
                    tally.min_committed_index = Some(
                        tally
                            .min_committed_index
                            .map_or(message_index, |min| min.min(message_index)),
                    );
                    if message_index == 0 {
                        tally.index0_committed += 1;
                    } else {
                        tally.after0_committed += 1;
                    }
                }
                InitialShareStage::Withheld => {
                    tally.withheld_devices.insert(device);
                }
                InitialShareStage::HomeserverAccepted => {
                    tally.accepted_devices.insert(device);
                }
                _ => {}
            }
            let elapsed_ms = tally
                .first_seen
                .map(|first| first.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0);
            (
                state.observer.clone(),
                InitialShareDeviceDiagnostic { session, device, device_class, stage, elapsed_ms },
            )
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::InitialShare(event));
        }
    }

    /// Record the session-scoped initial-share summary (issue #509). Emitted
    /// at most once per session, when its first room event is encrypted.
    pub(crate) fn emit_initial_share_session(
        &self,
        room_id: &RoomId,
        session_id: &str,
        first_event_message_index: u32,
        pending_requests: usize,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let session = session_alias(&mut state, room_id, session_id);
            let tally = state
                .initial_shares
                .entry((room_id.as_str().to_owned(), session_id.to_owned()))
                .or_default();
            if tally.first_seen.is_none() {
                tally.first_seen = Some(Instant::now());
            }
            if tally.first_event_reported {
                return;
            }
            tally.first_event_reported = true;
            let elapsed_ms = tally
                .first_seen
                .map(|first| first.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0);
            let event = InitialShareSessionDiagnostic {
                session,
                first_event_message_index,
                all_initial_shares_settled_first: pending_requests == 0,
                pending_requests_bucket: matching_bucket_token(pending_requests),
                eligible_own_devices: tally.eligible_own,
                eligible_peer_devices: tally.eligible_peer,
                index0_shares_committed: tally.index0_committed,
                after_index0_shares_committed: tally.after0_committed,
                homeserver_accepted_devices: tally.accepted_devices.len() as u32,
                created_at_index0: tally.min_committed_index.is_none_or(|index| index == 0),
                elapsed_ms,
            };
            (state.observer.clone(), event)
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::InitialShareSession(event));
        }
    }

    /// Whether the bounded index-0 duplicate share was already attempted for
    /// this (room, session) pair (issue #510).
    pub(crate) fn index0_reshare_attempted(&self, room_id: &RoomId, session_id: &str) -> bool {
        lock(&self.0)
            .index0_reshare_attempted
            .contains(&(room_id.as_str().to_owned(), session_id.to_owned()))
    }

    /// Mark the bounded index-0 duplicate share as attempted (issue #510). At
    /// most one attempt is made per (room, session) pair per runtime.
    pub(crate) fn mark_index0_reshare_attempted(&self, room_id: &RoomId, session_id: &str) {
        lock(&self.0)
            .index0_reshare_attempted
            .insert((room_id.as_str().to_owned(), session_id.to_owned()));
    }

    /// Record a bounded index-0 duplicate-share outcome (issue #510): derive
    /// the closed initial-share state and eligible count buckets from the
    /// session tally and notify the observer.
    pub(crate) fn note_index0_reshare(
        &self,
        room_id: &RoomId,
        session_id: &str,
        outcome: Index0ReshareOutcome,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let session = session_alias(&mut state, room_id, session_id);
            let tally =
                state.initial_shares.get(&(room_id.as_str().to_owned(), session_id.to_owned()));
            let eligible_own = tally.map_or(0, |tally| tally.eligible_own);
            let eligible_peer = tally.map_or(0, |tally| tally.eligible_peer);
            let eligible = eligible_own + eligible_peer;
            let committed =
                tally.map_or(0, |tally| tally.index0_committed + tally.after0_committed);
            let withheld = tally.map_or(0, |tally| tally.withheld_devices.len() as u32);
            let initial_share = if eligible == 0 {
                Index0InitialShareState::NoRecipients
            } else if withheld == eligible {
                Index0InitialShareState::Withheld
            } else if committed == eligible {
                Index0InitialShareState::Accepted
            } else {
                Index0InitialShareState::Failed
            };
            let elapsed_ms = tally
                .and_then(|tally| tally.first_seen)
                .map(|first| first.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0);
            (
                state.observer.clone(),
                Index0ReshareDiagnostic {
                    session,
                    initial_share,
                    reshare: outcome,
                    eligible_own_bucket: matching_bucket_token(eligible_own as usize),
                    eligible_peer_bucket: matching_bucket_token(eligible_peer as usize),
                    elapsed_ms,
                },
            )
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::Index0Reshare(event));
        }
    }

    /// Snapshot of the aggregate post-unwedge recovery counters.
    pub(crate) fn olm_recovery_counters(&self) -> OlmRecoveryCounters {
        lock(&self.0).olm_recovery_counters
    }

    pub(crate) fn emit_member_reload(
        &self,
        room_id: &RoomId,
        reason: RoomKeyRotationReason,
        context: RoomKeyMemberReloadContext,
        discard_outcome: RoomKeyMemberReloadDiscardOutcome,
    ) {
        let (observer, event) = {
            let mut state = lock(&self.0);
            let room = room_alias(&mut state, room_id);
            let event = RoomKeyMemberReloadDiagnostic {
                room,
                reason,
                members_were_synced_before_invalidation: context
                    .members_were_synced_before_invalidation,
                invalidation_count_bucket: matching_bucket_token(
                    context.invalidation_count as usize,
                ),
                invalidation_age_ms: context.invalidation_age_ms,
                request_elapsed_ms: context.request_elapsed_ms,
                response_member_count_bucket: matching_bucket_token(context.response_member_count),
                processing_elapsed_ms: context.processing_elapsed_ms,
                discard_outcome,
            };
            (state.observer.clone(), event)
        };
        if let Some(observer) = observer {
            observer(RoomKeyDiagnosticEvent::MemberReload(event));
        }
    }

    pub(crate) fn note_discard(&self, room_id: &RoomId, reason: RoomKeyRotationReason) {
        lock(&self.0).pending_discards.insert(
            room_id.as_str().to_owned(),
            PendingRoomKeyDiscard { reason, noted_at: Instant::now() },
        );
    }

    pub(crate) fn classify_rotation_reason(
        &self,
        room_id: &RoomId,
        expired_time: bool,
        expired_messages: bool,
        invalidated: bool,
        had_session: bool,
    ) -> RoomKeyRotationClassification {
        let mut state = lock(&self.0);
        if let Some(discard) = state.pending_discards.remove(room_id.as_str()) {
            return RoomKeyRotationClassification {
                reason: discard.reason,
                discard_elapsed_ms: Some(
                    discard.noted_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
                ),
            };
        }
        let reason = if expired_messages {
            RoomKeyRotationReason::ExpiredMessageCount
        } else if expired_time {
            RoomKeyRotationReason::ExpiredTime
        } else if invalidated {
            RoomKeyRotationReason::Invalidated
        } else if had_session || state.active_sessions.contains_key(room_id.as_str()) {
            RoomKeyRotationReason::StoreMissing
        } else {
            RoomKeyRotationReason::Initial
        };
        RoomKeyRotationClassification { reason, discard_elapsed_ms: None }
    }

    pub(crate) fn emit_rotation(
        &self,
        room_id: &RoomId,
        previous_session_id: Option<&str>,
        new_session_id: Option<&str>,
        reason: RoomKeyRotationReason,
        creation_outcome: RoomKeyCreationOutcome,
        discard_elapsed_ms: Option<u64>,
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
                discard_elapsed_ms,
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

fn matching_bucket_token(count: usize) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2..=5 => 2,
        6..=20 => 3,
        _ => 4,
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
            None,
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
            hub.classify_rotation_reason(room, true, true, true, true).reason,
            RoomKeyRotationReason::MembershipOrDeviceChange
        );
        assert_eq!(
            hub.classify_rotation_reason(room, false, true, false, true).reason,
            RoomKeyRotationReason::ExpiredMessageCount
        );
        assert_eq!(
            hub.classify_rotation_reason(room, true, false, false, true).reason,
            RoomKeyRotationReason::ExpiredTime
        );
        assert_eq!(
            hub.classify_rotation_reason(room, false, false, true, true).reason,
            RoomKeyRotationReason::Invalidated
        );
    }

    #[test]
    fn member_reload_and_following_rotation_share_anonymous_room_correlation() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));
        let room = room_id!("!private-member-reload:example.invalid");

        hub.emit_member_reload(
            room,
            RoomKeyRotationReason::RoomSubscription,
            RoomKeyMemberReloadContext {
                members_were_synced_before_invalidation: Some(true),
                invalidation_count: 2,
                invalidation_age_ms: Some(42),
                request_elapsed_ms: Some(17),
                response_member_count: 26,
                processing_elapsed_ms: 3,
            },
            RoomKeyMemberReloadDiscardOutcome::Discarded,
        );
        hub.note_discard(room, RoomKeyRotationReason::RoomSubscription);
        let classification = hub.classify_rotation_reason(room, false, false, true, true);
        hub.emit_rotation(
            room,
            Some("PRIVATE-OLD-SESSION"),
            Some("PRIVATE-NEW-SESSION"),
            classification.reason,
            RoomKeyCreationOutcome::Created,
            classification.discard_elapsed_ms,
            2,
        );

        let events = lock(&events);
        let RoomKeyDiagnosticEvent::MemberReload(reload) = &events[0] else { panic!() };
        let RoomKeyDiagnosticEvent::Rotation(rotation) = &events[1] else { panic!() };
        assert_eq!(reload.room, rotation.room);
        assert_eq!(reload.reason, RoomKeyRotationReason::RoomSubscription);
        assert_eq!(reload.invalidation_count_bucket, 2);
        assert_eq!(reload.response_member_count_bucket, 4);
        assert_eq!(reload.discard_outcome, RoomKeyMemberReloadDiscardOutcome::Discarded);
        assert!(rotation.discard_elapsed_ms.is_some());

        let debug = format!("{events:?}");
        for private in ["private-member-reload", "PRIVATE-OLD-SESSION", "PRIVATE-NEW-SESSION"] {
            assert!(!debug.contains(private), "privacy leak: {debug}");
        }
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

    #[test]
    fn initial_share_stages_are_distinct_and_never_expose_identifiers() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        let room = room_id!("!private-room:example.invalid");
        let user = user_id!("@private-user:example.invalid");
        let device = device_id!("PRIVATE-DEVICE");
        let stages = [
            InitialShareStage::Eligible,
            InitialShareStage::OlmMissing,
            InitialShareStage::OlmEncrypted,
            InitialShareStage::OlmEncryptionFailed,
            InitialShareStage::Withheld,
            InitialShareStage::RequestQueued,
            InitialShareStage::HomeserverAccepted,
            InitialShareStage::RequestFailed,
            InitialShareStage::ShareStateCommitted { message_index: 0 },
            InitialShareStage::ShareStateCommitted { message_index: 3 },
        ];
        for stage in stages {
            hub.emit_initial_share_device(
                room,
                "PRIVATE-SESSION",
                user,
                device,
                InitialShareDeviceClass::VerifiedPeer,
                stage,
            );
        }

        let captured = lock(&events);
        let device_events: Vec<_> = captured
            .iter()
            .filter_map(|event| match event {
                RoomKeyDiagnosticEvent::InitialShare(event) => Some(event),
                _ => None,
            })
            .collect();
        assert_eq!(device_events.len(), stages.len());
        for (event, stage) in device_events.iter().zip(stages.iter()) {
            assert_eq!(&event.stage, stage);
            assert_eq!(event.device_class, InitialShareDeviceClass::VerifiedPeer);
            assert_eq!(event.session, device_events[0].session);
            assert_eq!(event.device, device_events[0].device);
        }

        let debug = format!("{:?}", captured);
        for private in [
            "private-user",
            "PRIVATE-DEVICE",
            "PRIVATE-SESSION",
            "private-room",
            "example.invalid",
            "@",
            "!",
        ] {
            assert!(!debug.contains(private), "privacy leak: {private}");
        }
    }

    #[test]
    fn initial_share_session_record_aggregates_device_stages() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        let room = room_id!("!private-room:example.invalid");
        let own = user_id!("@own:example.invalid");
        let peer = user_id!("@peer:example.invalid");

        // One own device and one peer device are eligible.
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            own,
            device_id!("OWN-DEVICE"),
            InitialShareDeviceClass::VerifiedOwn,
            InitialShareStage::Eligible,
        );
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            peer,
            device_id!("PEER-DEVICE"),
            InitialShareDeviceClass::VerifiedPeer,
            InitialShareStage::Eligible,
        );
        // One peer device commits at index 0 and one at index 2; the own
        // device's request is homeserver-accepted.
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            peer,
            device_id!("PEER-DEVICE"),
            InitialShareDeviceClass::Unknown,
            InitialShareStage::HomeserverAccepted,
        );
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            peer,
            device_id!("PEER-DEVICE"),
            InitialShareDeviceClass::Unknown,
            InitialShareStage::ShareStateCommitted { message_index: 0 },
        );
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            peer,
            device_id!("PEER-DEVICE-2"),
            InitialShareDeviceClass::Unknown,
            InitialShareStage::ShareStateCommitted { message_index: 2 },
        );
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            own,
            device_id!("OWN-DEVICE"),
            InitialShareDeviceClass::Unknown,
            InitialShareStage::HomeserverAccepted,
        );

        hub.emit_initial_share_session(room, "PRIVATE-SESSION", 0, 0);
        hub.emit_initial_share_session(room, "PRIVATE-SESSION", 5, 1);

        let captured = lock(&events);
        let sessions: Vec<_> = captured
            .iter()
            .filter_map(|event| match event {
                RoomKeyDiagnosticEvent::InitialShareSession(event) => Some(event),
                _ => None,
            })
            .collect();
        assert_eq!(sessions.len(), 1, "the session summary must be emitted at most once");
        let session = sessions[0];
        assert_eq!(session.first_event_message_index, 0);
        assert!(session.all_initial_shares_settled_first);
        assert_eq!(session.eligible_own_devices, 1);
        assert_eq!(session.eligible_peer_devices, 1);
        assert_eq!(session.index0_shares_committed, 1);
        assert_eq!(session.after_index0_shares_committed, 1);
        assert_eq!(session.homeserver_accepted_devices, 2);
        assert!(session.created_at_index0);

        // A second summary for the same session is never emitted, and the
        // debug output stays free of identifiers.
        let debug = format!("{:?}", captured);
        for private in ["private-user", "PRIVATE-SESSION", "private-room", "@", "!"] {
            assert!(!debug.contains(private), "privacy leak: {private}");
        }
    }

    #[test]
    fn initial_share_class_falls_back_to_the_eligible_class() {
        let hub = RoomKeyDiagnosticHub::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        hub.set_observer(Some(Arc::new(move |event| lock(&captured).push(event))));

        let room = room_id!("!private-room:example.invalid");
        let user = user_id!("@private-user:example.invalid");
        let device = device_id!("PRIVATE-DEVICE");
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            user,
            device,
            InitialShareDeviceClass::UnverifiedPeer,
            InitialShareStage::Eligible,
        );
        // Later stages are emitted without a `DeviceData`; the class must be
        // preserved from the `Eligible` emission.
        hub.emit_initial_share_device(
            room,
            "PRIVATE-SESSION",
            user,
            device,
            InitialShareDeviceClass::Unknown,
            InitialShareStage::HomeserverAccepted,
        );

        let captured = lock(&events);
        let device_events: Vec<_> = captured
            .iter()
            .filter_map(|event| match event {
                RoomKeyDiagnosticEvent::InitialShare(event) => Some(event),
                _ => None,
            })
            .collect();
        assert_eq!(device_events.len(), 2);
        assert_eq!(device_events[1].device_class, InitialShareDeviceClass::UnverifiedPeer);
    }
}
