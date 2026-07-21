// Copyright 2020 The Matrix.org Foundation C.I.C.
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

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use futures_util::{StreamExt, stream};
use matrix_sdk_common::locks::RwLock as StdRwLock;
use ruma::{
    DeviceId, EventId, MilliSecondsSinceUnixEpoch, OwnedDeviceId, OwnedTransactionId, OwnedUserId,
    RoomId, SecondsSinceUnixEpoch, TransactionId, UInt, UserId,
    events::{
        AnyToDeviceEvent, AnyToDeviceEventContent, ToDeviceEvent,
        key::verification::{
            VerificationMethod, cancel::CancelCode, request::ToDeviceKeyVerificationRequestEvent,
        },
    },
    serde::Raw,
    uint,
};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, instrument, trace, warn};

use super::{
    FlowId, Verification, VerificationResult, VerificationStore,
    cache::{RequestInfo, VerificationCache},
    event_enums::{AnyEvent, AnyVerificationContent, OutgoingContent, RequestContent},
    requests::VerificationRequest,
    sas::Sas,
};
use crate::{
    DeviceData, OtherUserIdentityData,
    olm::{PrivateCrossSigningIdentity, StaticAccountData},
    store::{CryptoStoreError, CryptoStoreWrapper},
    types::events::ToDeviceEvents,
    types::requests::{
        OutgoingRequest, OutgoingVerificationRequest, RoomMessageRequest, ToDeviceRequest,
    },
};

const MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS: usize = 32;

#[derive(Clone)]
struct PendingToDeviceVerificationRequest {
    event: ToDeviceKeyVerificationRequestEvent,
    state: PendingToDeviceVerificationRequestState,
    committed_update_generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PendingToDeviceVerificationRequestState {
    #[default]
    NeedsQuery,
    QueryInFlight,
    WaitingForExternalUpdate,
    ResponseClaimed {
        token: u64,
        observed_generation: u64,
    },
    ReplayClaimed {
        response_token: u64,
        replay_token: u64,
        observed_generation: u64,
    },
}

impl PendingToDeviceVerificationRequestState {
    fn is_claimed(self) -> bool {
        matches!(self, Self::ResponseClaimed { .. } | Self::ReplayClaimed { .. })
    }
}

impl fmt::Debug for PendingToDeviceVerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PendingToDeviceVerificationRequest").finish_non_exhaustive()
    }
}

pub(crate) enum VerificationEventResult {
    Handled,
    UnknownSenderQueued { sender: OwnedUserId, query_needed: bool },
    RequestMaterialized(VerificationRequest),
}

enum PreparedIncomingVerificationRequest {
    Terminal(VerificationEventResult),
    Ready(VerificationRequest),
}

enum VerificationRequestInsertion {
    Existing { request: VerificationRequest, incoming_to_device: bool },
    Inserted { request: VerificationRequest, incoming_to_device: bool },
}

#[derive(Clone, Debug)]
struct CachedVerificationRequest {
    request: VerificationRequest,
    incoming_to_device: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum IncomingVerificationRequestPublicationState {
    #[default]
    Unclaimed,
    Claimed {
        generation: u64,
        token: u64,
    },
}

#[derive(Clone, Debug)]
struct IncomingVerificationRequestPublication {
    key: PendingToDeviceVerificationRequestKey,
    request: VerificationRequest,
    state: IncomingVerificationRequestPublicationState,
}

#[derive(Clone, Debug)]
enum IncomingVerificationRequestEntry {
    Pending(PendingToDeviceVerificationRequest),
    Publication(IncomingVerificationRequestPublication),
}

#[derive(Debug, Default)]
struct IncomingVerificationRequestOwner {
    entries: VecDeque<IncomingVerificationRequestEntry>,
    subscriber_generation: Option<u64>,
}

impl IncomingVerificationRequestOwner {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn pending(&self) -> impl Iterator<Item = &PendingToDeviceVerificationRequest> {
        self.entries.iter().filter_map(|entry| match entry {
            IncomingVerificationRequestEntry::Pending(pending) => Some(pending),
            IncomingVerificationRequestEntry::Publication(_) => None,
        })
    }

    fn pending_mut(&mut self) -> impl Iterator<Item = &mut PendingToDeviceVerificationRequest> {
        self.entries.iter_mut().filter_map(|entry| match entry {
            IncomingVerificationRequestEntry::Pending(pending) => Some(pending),
            IncomingVerificationRequestEntry::Publication(_) => None,
        })
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.pending().count()
    }

    fn retain_pending(
        &mut self,
        mut retain: impl FnMut(&PendingToDeviceVerificationRequest) -> bool,
    ) -> bool {
        let previous_len = self.entries.len();
        self.entries.retain(|entry| match entry {
            IncomingVerificationRequestEntry::Pending(pending) => retain(pending),
            IncomingVerificationRequestEntry::Publication(_) => true,
        });
        self.entries.len() != previous_len
    }

    fn pending_position(&self, key: &PendingToDeviceVerificationRequestKey) -> Option<usize> {
        self.entries.iter().position(|entry| {
            matches!(
                entry,
                IncomingVerificationRequestEntry::Pending(pending)
                    if PendingToDeviceVerificationRequestKey::from(pending) == *key
            )
        })
    }

    fn publication_position(&self, key: &PendingToDeviceVerificationRequestKey) -> Option<usize> {
        self.entries.iter().position(|entry| {
            matches!(
                entry,
                IncomingVerificationRequestEntry::Publication(publication)
                    if publication.key == *key
            )
        })
    }
}

impl VerificationRequestInsertion {
    #[cfg(test)]
    fn into_request(self) -> VerificationRequest {
        match self {
            Self::Existing { request, .. } | Self::Inserted { request, .. } => request,
        }
    }

    fn into_request_and_provenance(self) -> (VerificationRequest, bool) {
        match self {
            Self::Existing { request, incoming_to_device }
            | Self::Inserted { request, incoming_to_device } => (request, incoming_to_device),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingToDeviceVerificationRequestKey {
    sender: OwnedUserId,
    transaction_id: OwnedTransactionId,
}

impl PendingToDeviceVerificationRequestKey {
    fn new(sender: &UserId, transaction_id: &str) -> Self {
        Self { sender: sender.to_owned(), transaction_id: OwnedTransactionId::from(transaction_id) }
    }
}

impl From<&PendingToDeviceVerificationRequest> for PendingToDeviceVerificationRequestKey {
    fn from(pending: &PendingToDeviceVerificationRequest) -> Self {
        Self {
            sender: pending.event.sender.clone(),
            transaction_id: pending.event.content.transaction_id.clone(),
        }
    }
}

impl From<&ToDeviceKeyVerificationRequestEvent> for PendingToDeviceVerificationRequestKey {
    fn from(event: &ToDeviceKeyVerificationRequestEvent) -> Self {
        Self { sender: event.sender.clone(), transaction_id: event.content.transaction_id.clone() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingToDeviceVerificationRequestClaimKind {
    Replay,
}

struct PendingToDeviceVerificationRequestClaim {
    owner: Arc<StdRwLock<IncomingVerificationRequestOwner>>,
    publication_changed: watch::Sender<u64>,
    key: PendingToDeviceVerificationRequestKey,
    token: u64,
    response_token: u64,
    kind: PendingToDeviceVerificationRequestClaimKind,
    active: bool,
}

pub(crate) struct PendingToDeviceKeyQueryResponseClaim {
    owner: Arc<StdRwLock<IncomingVerificationRequestOwner>>,
    token: u64,
    active: bool,
}

impl PendingToDeviceKeyQueryResponseClaim {
    pub(crate) fn token(&self) -> u64 {
        self.token
    }

    pub(crate) fn finish_waiting_for_external_update(&mut self) -> bool {
        let mut owner = self.owner.write();
        let mut replay_needed = false;
        for pending in owner.pending_mut() {
            if let PendingToDeviceVerificationRequestState::ResponseClaimed {
                token,
                observed_generation,
            } = pending.state
                && token == self.token
            {
                if pending.committed_update_generation > observed_generation {
                    pending.state = PendingToDeviceVerificationRequestState::ResponseClaimed {
                        token,
                        observed_generation: pending.committed_update_generation,
                    };
                    replay_needed = true;
                } else {
                    pending.state =
                        PendingToDeviceVerificationRequestState::WaitingForExternalUpdate;
                }
            }
        }
        if !replay_needed {
            self.active = false;
        }
        replay_needed
    }

    pub(crate) fn release_for_retry(&mut self) {
        self.release_to_needs_query();
        self.active = false;
    }

    fn release_to_needs_query(&self) {
        let mut owner = self.owner.write();
        for pending in owner.pending_mut() {
            let owned_by_response = match pending.state {
                PendingToDeviceVerificationRequestState::ResponseClaimed { token, .. } => {
                    token == self.token
                }
                PendingToDeviceVerificationRequestState::ReplayClaimed {
                    response_token, ..
                } => response_token == self.token,
                _ => false,
            };
            if owned_by_response {
                pending.state = PendingToDeviceVerificationRequestState::NeedsQuery;
            }
        }
    }
}

impl Drop for PendingToDeviceKeyQueryResponseClaim {
    fn drop(&mut self) {
        if self.active {
            self.release_to_needs_query();
        }
    }
}

impl PendingToDeviceVerificationRequestClaim {
    fn state_matches(&self, state: PendingToDeviceVerificationRequestState) -> bool {
        match (self.kind, state) {
            (
                PendingToDeviceVerificationRequestClaimKind::Replay,
                PendingToDeviceVerificationRequestState::ReplayClaimed {
                    response_token,
                    replay_token,
                    ..
                },
            ) => response_token == self.response_token && replay_token == self.token,
            _ => false,
        }
    }

    fn finish(&mut self) {
        let mut owner = self.owner.write();
        let removed = owner.retain_pending(|pending| {
            let is_key = pending.event.sender == self.key.sender
                && pending.event.content.transaction_id == self.key.transaction_id;
            !is_key || !self.state_matches(pending.state)
        });
        self.active = false;
        drop(owner);
        if removed {
            notify_watch(&self.publication_changed);
        }
    }

    fn release_to_response_claim(&mut self) {
        let mut owner = self.owner.write();
        if let Some(pending) = owner.pending_mut().find(|pending| {
            pending.event.sender == self.key.sender
                && pending.event.content.transaction_id == self.key.transaction_id
        }) && let PendingToDeviceVerificationRequestState::ReplayClaimed {
            response_token,
            replay_token,
            observed_generation,
        } = pending.state
            && response_token == self.response_token
            && replay_token == self.token
        {
            pending.state = PendingToDeviceVerificationRequestState::ResponseClaimed {
                token: self.response_token,
                observed_generation,
            };
        }
        self.active = false;
    }

    fn publish(
        &mut self,
        request: VerificationRequest,
        publishable: bool,
        changed: &watch::Sender<u64>,
    ) {
        let mut owner = self.owner.write();
        let position = owner.entries.iter().position(|entry| {
            matches!(
                entry,
                IncomingVerificationRequestEntry::Pending(pending)
                    if pending.event.sender == self.key.sender
                        && pending.event.content.transaction_id == self.key.transaction_id
                        && self.state_matches(pending.state)
            )
        });
        if let Some(position) = position {
            if publishable && owner.publication_position(&self.key).is_none() {
                owner.entries[position] = IncomingVerificationRequestEntry::Publication(
                    IncomingVerificationRequestPublication {
                        key: self.key.clone(),
                        request,
                        state: IncomingVerificationRequestPublicationState::Unclaimed,
                    },
                );
            } else {
                owner.entries.remove(position);
            }
        }
        self.active = false;
        drop(owner);
        notify_watch(changed);
    }
}

impl Drop for PendingToDeviceVerificationRequestClaim {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let mut owner = self.owner.write();
        if let Some(pending) = owner.pending_mut().find(|pending| {
            pending.event.sender == self.key.sender
                && pending.event.content.transaction_id == self.key.transaction_id
        }) && self.state_matches(pending.state)
        {
            pending.state = PendingToDeviceVerificationRequestState::NeedsQuery;
        }
    }
}

/// Lease for a materialized incoming to-device verification request.
///
/// Polling only claims the stable queue head. Callers commit after their final
/// application handoff succeeds. Dropping the lease releases the claim in
/// place, without removing or reordering the bounded queue slot.
pub struct IncomingVerificationRequestDelivery {
    request: VerificationRequest,
    owner: Arc<StdRwLock<IncomingVerificationRequestOwner>>,
    publication_changed: watch::Sender<u64>,
    key: PendingToDeviceVerificationRequestKey,
    generation: u64,
    token: u64,
    active: bool,
}

impl fmt::Debug for IncomingVerificationRequestDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("IncomingVerificationRequestDelivery").finish_non_exhaustive()
    }
}

impl IncomingVerificationRequestDelivery {
    /// The stable materialized verification request handle.
    pub fn request(&self) -> &VerificationRequest {
        &self.request
    }

    /// Commit successful application delivery of the request.
    pub fn commit(mut self) {
        let mut owner = self.owner.write();
        if owner.entries.front().is_some_and(|entry| {
            matches!(
                entry,
                IncomingVerificationRequestEntry::Publication(publication)
                    if publication.key == self.key
                        && publication.state
                            == (IncomingVerificationRequestPublicationState::Claimed {
                                generation: self.generation,
                                token: self.token,
                            })
            )
        }) {
            owner.entries.pop_front();
        }
        self.active = false;
        drop(owner);
        notify_watch(&self.publication_changed);
    }
}

impl Deref for IncomingVerificationRequestDelivery {
    type Target = VerificationRequest;

    fn deref(&self) -> &Self::Target {
        self.request()
    }
}

impl Drop for IncomingVerificationRequestDelivery {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut owner = self.owner.write();
        if let Some(IncomingVerificationRequestEntry::Publication(publication)) =
            owner.entries.front_mut()
            && publication.key == self.key
            && publication.state
                == (IncomingVerificationRequestPublicationState::Claimed {
                    generation: self.generation,
                    token: self.token,
                })
        {
            publication.state = IncomingVerificationRequestPublicationState::Unclaimed;
        }
        drop(owner);
        notify_watch(&self.publication_changed);
    }
}

fn notify_watch(sender: &watch::Sender<u64>) {
    sender.send_modify(|generation| *generation = generation.wrapping_add(1));
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct VerificationMachineTestPause {
    entered: Arc<tokio::sync::Barrier>,
    release: Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct VerificationMachineTestHooks {
    replay_after_claim: StdRwLock<Option<VerificationMachineTestPause>>,
    request_device_lookup_completed: StdRwLock<Option<VerificationMachineTestPause>>,
    publication_after_claim: StdRwLock<Option<VerificationMachineTestPause>>,
    request_insert_before_write: StdRwLock<Option<Arc<std::sync::Barrier>>>,
}

#[derive(Clone, Debug)]
pub struct VerificationMachine {
    pub(crate) store: VerificationStore,
    verifications: VerificationCache,
    requests: Arc<StdRwLock<HashMap<OwnedUserId, HashMap<String, CachedVerificationRequest>>>>,
    // Lock order: never acquire `requests` while holding this owner lock, or this
    // owner lock while holding `requests`. No owner guard may cross an await.
    incoming_verification_request_owner: Arc<StdRwLock<IncomingVerificationRequestOwner>>,
    next_pending_to_device_request_claim_token: Arc<AtomicU64>,
    next_pending_to_device_key_query_response_claim_token: Arc<AtomicU64>,
    next_incoming_verification_request_subscriber_generation: Arc<AtomicU64>,
    next_incoming_verification_request_delivery_token: Arc<AtomicU64>,
    incoming_verification_request_changed: watch::Sender<u64>,
    #[cfg(test)]
    pending_replay_failure_after: Arc<AtomicIsize>,
    #[cfg(test)]
    fail_next_verification_request_device_lookup: Arc<AtomicBool>,
    #[cfg(test)]
    fail_next_post_key_query_recovery_cache_acquisition: Arc<AtomicBool>,
    #[cfg(test)]
    test_hooks: Arc<VerificationMachineTestHooks>,
}

impl VerificationMachine {
    pub(crate) fn new(
        account: StaticAccountData,
        identity: Arc<Mutex<PrivateCrossSigningIdentity>>,
        store: Arc<CryptoStoreWrapper>,
    ) -> Self {
        let (incoming_verification_request_changed, _) = watch::channel(0);
        Self {
            store: VerificationStore { account, private_identity: identity, inner: store },
            verifications: VerificationCache::new(),
            requests: Default::default(),
            incoming_verification_request_owner: Default::default(),
            next_pending_to_device_request_claim_token: Default::default(),
            next_pending_to_device_key_query_response_claim_token: Default::default(),
            next_incoming_verification_request_subscriber_generation: Default::default(),
            next_incoming_verification_request_delivery_token: Default::default(),
            incoming_verification_request_changed,
            #[cfg(test)]
            pending_replay_failure_after: Arc::new(AtomicIsize::new(-1)),
            #[cfg(test)]
            fail_next_verification_request_device_lookup: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_post_key_query_recovery_cache_acquisition: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            test_hooks: Default::default(),
        }
    }

    pub(crate) fn subscribe_to_incoming_verification_requests(
        &self,
    ) -> impl futures_core::Stream<Item = IncomingVerificationRequestDelivery> + Unpin + use<> {
        let generation = self
            .next_incoming_verification_request_subscriber_generation
            .fetch_add(1, AtomicOrdering::Relaxed);
        self.incoming_verification_request_owner.write().subscriber_generation = Some(generation);
        notify_watch(&self.incoming_verification_request_changed);

        let machine = self.clone();
        let changed = self.incoming_verification_request_changed.subscribe();
        stream::unfold(
            (machine, generation, changed),
            |(machine, generation, mut changed)| async move {
                loop {
                    let claimed = {
                        let mut owner = machine.incoming_verification_request_owner.write();
                        if owner.subscriber_generation != Some(generation) {
                            return None;
                        }
                        match owner.entries.front_mut() {
                            None => None,
                            Some(IncomingVerificationRequestEntry::Publication(publication))
                                if publication.state
                                    == IncomingVerificationRequestPublicationState::Unclaimed =>
                            {
                                let token = machine
                                    .next_incoming_verification_request_delivery_token
                                    .fetch_add(1, AtomicOrdering::Relaxed);
                                publication.state =
                                    IncomingVerificationRequestPublicationState::Claimed {
                                        generation,
                                        token,
                                    };
                                Some((publication.key.clone(), publication.request.clone(), token))
                            }
                            Some(
                                IncomingVerificationRequestEntry::Pending(_)
                                | IncomingVerificationRequestEntry::Publication(_),
                            ) => None,
                        }
                    };

                    let Some((key, request, token)) = claimed else {
                        changed.changed().await.ok()?;
                        continue;
                    };

                    #[cfg(test)]
                    machine.pause_publication_after_claim_for_test().await;

                    let delivery = IncomingVerificationRequestDelivery {
                        request,
                        owner: machine.incoming_verification_request_owner.clone(),
                        publication_changed: machine.incoming_verification_request_changed.clone(),
                        key,
                        generation,
                        token,
                        active: true,
                    };
                    return Some((delivery, (machine, generation, changed)));
                }
            },
        )
        .boxed()
    }

    pub(crate) fn own_user_id(&self) -> &UserId {
        &self.store.account.user_id
    }

    pub(crate) fn own_device_id(&self) -> &DeviceId {
        &self.store.account.device_id
    }

    pub(crate) fn request_to_device_verification(
        &self,
        user_id: &UserId,
        recipient_devices: Vec<OwnedDeviceId>,
        methods: Option<Vec<VerificationMethod>>,
    ) -> (VerificationRequest, OutgoingVerificationRequest) {
        let flow_id = FlowId::from(TransactionId::new());

        let verification = VerificationRequest::new(
            self.verifications.clone(),
            self.store.clone(),
            flow_id,
            user_id,
            recipient_devices,
            methods,
        );

        self.insert_request(verification.clone());

        let request = verification.request_to_device();

        (verification, request.into())
    }

    pub fn request_verification(
        &self,
        identity: &OtherUserIdentityData,
        room_id: &RoomId,
        request_event_id: &EventId,
        methods: Option<Vec<VerificationMethod>>,
    ) -> VerificationRequest {
        let flow_id = FlowId::InRoom(room_id.to_owned(), request_event_id.to_owned());

        let request = VerificationRequest::new(
            self.verifications.clone(),
            self.store.clone(),
            flow_id,
            identity.user_id(),
            vec![],
            methods,
        );

        self.insert_request(request.clone());

        request
    }

    pub async fn start_sas(
        &self,
        device: DeviceData,
    ) -> Result<(Sas, OutgoingVerificationRequest), CryptoStoreError> {
        let identities = self.store.get_identities(device.clone()).await?;
        let (sas, content) = Sas::start(identities, TransactionId::new(), true, None, None);

        let request = match content {
            OutgoingContent::Room(r, c) => {
                RoomMessageRequest { room_id: r, txn_id: TransactionId::new(), content: c }.into()
            }
            OutgoingContent::ToDevice(c) => {
                let request = ToDeviceRequest::with_id(
                    device.user_id(),
                    device.device_id().to_owned(),
                    &c,
                    TransactionId::new(),
                );

                self.verifications.insert_sas(sas.clone());

                request.into()
            }
        };

        Ok((sas, request))
    }

    pub fn get_request(
        &self,
        user_id: &UserId,
        flow_id: impl AsRef<str>,
    ) -> Option<VerificationRequest> {
        self.requests
            .read()
            .get(user_id)?
            .get(flow_id.as_ref())
            .map(|cached| cached.request.clone())
    }

    pub fn get_requests(&self, user_id: &UserId) -> Vec<VerificationRequest> {
        self.requests
            .read()
            .get(user_id)
            .map(|requests| requests.values().map(|cached| cached.request.clone()).collect())
            .unwrap_or_default()
    }

    /// Add a new `VerificationRequest` object to the cache.
    /// If there are any existing requests with this user (and different
    /// flow_id), both the existing and new request will be cancelled.
    fn insert_request(&self, request: VerificationRequest) -> VerificationRequestInsertion {
        self.insert_request_with_delivery(request, false)
    }

    fn insert_incoming_to_device_request(
        &self,
        request: VerificationRequest,
    ) -> VerificationRequestInsertion {
        self.insert_request_with_delivery(request, true)
    }

    fn insert_request_with_delivery(
        &self,
        request: VerificationRequest,
        incoming_to_device: bool,
    ) -> VerificationRequestInsertion {
        #[cfg(test)]
        if let Some(barrier) = self.test_hooks.request_insert_before_write.read().clone() {
            barrier.wait();
        }

        let mut requests = self.requests.write();
        let user_requests = requests.entry(request.other_user().to_owned()).or_default();
        if let Some(existing) = user_requests.get(request.flow_id().as_str()) {
            debug!("Ignoring known verification request");
            return VerificationRequestInsertion::Existing {
                request: existing.request.clone(),
                incoming_to_device: existing.incoming_to_device,
            };
        }

        // Cancel all the old verifications requests as well as the new one we
        // have for this user if someone tries to have two verifications going
        // on at once.
        for old_verification in user_requests.values_mut().map(|cached| &mut cached.request) {
            if !old_verification.is_cancelled() {
                warn!(
                    "Received a new verification request whilst another request \
                    with the same user is ongoing. Cancelling both requests."
                );

                if let Some(r) = old_verification.cancel() {
                    self.verifications.add_request(r.into())
                }

                if let Some(r) = request.cancel() {
                    self.verifications.add_request(r.into())
                }
            }
        }

        // We still want to add the new verification request, in case users
        // want to inspect the verification object a matching
        // `m.key.verification.request` produced.
        user_requests.insert(
            request.flow_id().as_str().to_owned(),
            CachedVerificationRequest { request: request.clone(), incoming_to_device },
        );
        VerificationRequestInsertion::Inserted { request, incoming_to_device }
    }

    pub fn get_verification(&self, user_id: &UserId, flow_id: &str) -> Option<Verification> {
        self.verifications.get(user_id, flow_id)
    }

    pub fn get_sas(&self, user_id: &UserId, flow_id: &str) -> Option<Box<Sas>> {
        self.verifications.get_sas(user_id, flow_id)
    }

    fn is_timestamp_valid(timestamp: MilliSecondsSinceUnixEpoch) -> bool {
        // The event should be ignored if the event is older than 10 minutes
        let old_timestamp_threshold: UInt = uint!(600);
        // The event should be ignored if the event is 5 minutes or more into the
        // future.
        let timestamp_threshold: UInt = uint!(300);

        let timestamp = timestamp.as_secs();
        let now = SecondsSinceUnixEpoch::now().get();

        !(now.saturating_sub(timestamp) > old_timestamp_threshold
            || timestamp.saturating_sub(now) > timestamp_threshold)
    }

    fn queue_up_content(
        &self,
        recipient: &UserId,
        recipient_device: &DeviceId,
        content: OutgoingContent,
        request_id: Option<RequestInfo>,
    ) {
        self.verifications.queue_up_content(recipient, recipient_device, content, request_id)
    }

    pub fn mark_request_as_sent(&self, request_id: &TransactionId) {
        self.verifications.mark_request_as_sent(request_id);
    }

    pub fn outgoing_messages(&self) -> Vec<OutgoingRequest> {
        self.verifications.outgoing_requests()
    }

    pub fn garbage_collect(&self) -> Vec<Raw<AnyToDeviceEvent>> {
        let mut events = vec![];

        let mut owner = self.incoming_verification_request_owner.write();
        let owner_changed = owner.retain_pending(|pending| {
            pending.state.is_claimed() || Self::is_timestamp_valid(pending.event.content.timestamp)
        });
        drop(owner);
        if owner_changed {
            notify_watch(&self.incoming_verification_request_changed);
        }

        let mut requests: Vec<OutgoingVerificationRequest> = {
            let mut requests = self.requests.write();

            for user_verification in requests.values_mut() {
                user_verification.retain(|_, cached| {
                    !(cached.request.is_done() || cached.request.is_cancelled())
                });
            }
            requests.retain(|_, v| !v.is_empty());

            requests
                .values()
                .flatten()
                .filter_map(|(_, cached)| cached.request.cancel_if_timed_out())
                .collect()
        };

        requests.extend(self.verifications.garbage_collect());

        for request in requests {
            if let Ok(OutgoingContent::ToDevice(to_device)) = request.clone().try_into()
                && let AnyToDeviceEventContent::KeyVerificationCancel(content) = *to_device
            {
                let event = ToDeviceEvent::new(self.own_user_id().to_owned(), content);

                events.push(
                    Raw::new(&event)
                        .expect("Failed to serialize m.key_verification.cancel event")
                        .cast(),
                );
            }

            self.verifications.add_verification_request(request)
        }

        events
    }

    async fn mark_sas_as_done(
        &self,
        sas: &Sas,
        out_content: Option<OutgoingContent>,
    ) -> Result<(), CryptoStoreError> {
        match sas.mark_as_done().await? {
            VerificationResult::Ok => {
                if let Some(c) = out_content {
                    self.queue_up_content(sas.other_user_id(), sas.other_device_id(), c, None);
                }
            }
            VerificationResult::Cancel(c) => {
                if let Some(r) = sas.cancel_with_code(c) {
                    self.verifications.add_request(r.into());
                }
            }
            VerificationResult::SignatureUpload(r) => {
                self.verifications.add_request(r.into());

                if let Some(c) = out_content {
                    self.queue_up_content(sas.other_user_id(), sas.other_device_id(), c, None);
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_any_event(
        &self,
        event: impl Into<AnyEvent<'_>>,
    ) -> Result<(), CryptoStoreError> {
        self.receive_any_event_inner(event.into(), false).await.map(|_| ())
    }

    pub(crate) async fn receive_to_device_event(
        &self,
        event: &ToDeviceEvents,
    ) -> Result<VerificationEventResult, CryptoStoreError> {
        let result = self.receive_any_event_inner(AnyEvent::from(event), true).await?;
        if let ToDeviceEvents::KeyVerificationRequest(event) = event
            && matches!(
                &result,
                VerificationEventResult::RequestMaterialized(_) | VerificationEventResult::Handled
            )
        {
            self.remove_pending_to_device_request(&PendingToDeviceVerificationRequestKey::from(
                event,
            ));
        }
        Ok(result)
    }

    async fn prepare_incoming_verification_request(
        &self,
        event: &AnyEvent<'_>,
        flow_id: FlowId,
        content: &RequestContent<'_>,
        retain_unknown_sender: bool,
    ) -> Result<PreparedIncomingVerificationRequest, CryptoStoreError> {
        info!("Received a new verification request");

        let Some(timestamp) = event.timestamp() else {
            warn!("The key verification request didn't contain a valid timestamp");
            return Ok(PreparedIncomingVerificationRequest::Terminal(
                VerificationEventResult::Handled,
            ));
        };

        if !Self::is_timestamp_valid(timestamp) {
            info!("The received verification request was too old or too far into the future");
            return Ok(PreparedIncomingVerificationRequest::Terminal(
                VerificationEventResult::Handled,
            ));
        }

        let event_sent_from_us = event.sender() == self.store.account.user_id
            && (content.from_device() == self.store.account.device_id || event.is_room_event());
        if event_sent_from_us {
            trace!("The received verification request was sent by us, ignoring it");
            return Ok(PreparedIncomingVerificationRequest::Terminal(
                VerificationEventResult::Handled,
            ));
        }

        #[cfg(test)]
        let device_result =
            if self.fail_next_verification_request_device_lookup.swap(false, Ordering::SeqCst) {
                Err(CryptoStoreError::AccountUnset)
            } else {
                self.store.get_device(event.sender(), content.from_device()).await
            };
        #[cfg(not(test))]
        let device_result = self.store.get_device(event.sender(), content.from_device()).await;

        #[cfg(test)]
        self.pause_request_device_lookup_completed_for_test().await;

        let device_data = match device_result {
            Ok(Some(device_data)) => device_data,
            Ok(None) => {
                if let Some(queued) =
                    self.retain_unknown_to_device_request(event, retain_unknown_sender)
                {
                    return Ok(PreparedIncomingVerificationRequest::Terminal(queued));
                }
                warn!(
                    "Could not retrieve the device data for the incoming verification request, \
                     ignoring it"
                );
                return Ok(PreparedIncomingVerificationRequest::Terminal(
                    VerificationEventResult::Handled,
                ));
            }
            Err(error) => {
                if let Some(queued) =
                    self.retain_unknown_to_device_request(event, retain_unknown_sender)
                {
                    warn!(
                        "Could not read sender device data for an incoming verification request; \
                         retaining it for key-query recovery"
                    );
                    return Ok(PreparedIncomingVerificationRequest::Terminal(queued));
                }
                return Err(error);
            }
        };

        Ok(PreparedIncomingVerificationRequest::Ready(VerificationRequest::from_request(
            self.verifications.clone(),
            self.store.clone(),
            event.sender(),
            flow_id,
            content,
            device_data,
        )))
    }

    async fn receive_any_event_inner(
        &self,
        event: AnyEvent<'_>,
        retain_unknown_sender: bool,
    ) -> Result<VerificationEventResult, CryptoStoreError> {
        let incoming_to_device =
            matches!(&event, AnyEvent::ToDevice(ToDeviceEvents::KeyVerificationRequest(_)));
        let Ok(flow_id) = FlowId::try_from(&event) else {
            // This isn't a verification event, return early.
            return Ok(VerificationEventResult::Handled);
        };
        let flow_id_mismatch = || {
            warn!(
                "Received a verification event with a mismatched flow id, \
                 the verification object was created for a in-room \
                 verification but an event was received over to-device \
                 messaging or vice versa"
            );
        };

        let Some(content) = event.verification_content() else {
            return Ok(VerificationEventResult::Handled);
        };
        match &content {
            AnyVerificationContent::Request(r) => {
                return match self
                    .prepare_incoming_verification_request(
                        &event,
                        flow_id,
                        r,
                        retain_unknown_sender,
                    )
                    .await?
                {
                    PreparedIncomingVerificationRequest::Terminal(result) => Ok(result),
                    PreparedIncomingVerificationRequest::Ready(request) => {
                        let insertion = if incoming_to_device {
                            self.insert_incoming_to_device_request(request)
                        } else {
                            self.insert_request(request)
                        };
                        let (request, publishable) = insertion.into_request_and_provenance();
                        if incoming_to_device && publishable {
                            let key = PendingToDeviceVerificationRequestKey::new(
                                request.other_user(),
                                request.flow_id().as_str(),
                            );
                            self.publish_or_reject_incoming_verification_request(
                                key,
                                request.clone(),
                            );
                        }
                        Ok(VerificationEventResult::RequestMaterialized(request))
                    }
                };
            }
            AnyVerificationContent::Cancel(c) => {
                if let Some(verification) = self.get_request(event.sender(), flow_id.as_str()) {
                    verification.receive_cancel(event.sender(), c);
                }

                if let Some(verification) = self.get_verification(event.sender(), flow_id.as_str())
                {
                    match verification {
                        Verification::SasV1(sas) => {
                            // This won't produce an outgoing content
                            let _ = sas.receive_any_event(event.sender(), &content);
                        }
                        #[cfg(feature = "qrcode")]
                        Verification::QrV1(qr) => qr.receive_cancel(event.sender(), c),
                    }
                }
            }
            AnyVerificationContent::Ready(c) => {
                let Some(request) = self.get_request(event.sender(), flow_id.as_str()) else {
                    return Ok(VerificationEventResult::Handled);
                };

                if request.flow_id() == &flow_id {
                    if let Some(device_data) =
                        self.store.get_device(event.sender(), c.from_device()).await?
                    {
                        request.receive_ready(event.sender(), c, device_data);
                    } else {
                        warn!("Could not retrieve the data for the accepting device, ignoring it");
                    }
                } else {
                    flow_id_mismatch();
                }
            }
            AnyVerificationContent::Start(c) => {
                if let Some(request) = self.get_request(event.sender(), flow_id.as_str()) {
                    if request.flow_id() == &flow_id {
                        Box::pin(request.receive_start(event.sender(), c)).await?
                    } else {
                        flow_id_mismatch();
                    }
                } else if let FlowId::ToDevice(_) = flow_id {
                    // TODO remove this soon, this has been deprecated by
                    // MSC3122 https://github.com/matrix-org/matrix-doc/pull/3122
                    if let Some(device) =
                        self.store.get_device(event.sender(), c.from_device()).await?
                    {
                        let identities = self.store.get_identities(device).await?;

                        match Sas::from_start_event(flow_id, c, identities, None, false) {
                            Ok(sas) => {
                                self.verifications.insert_sas(sas);
                            }
                            Err(cancellation) => self.queue_up_content(
                                event.sender(),
                                c.from_device(),
                                cancellation,
                                None,
                            ),
                        }
                    }
                }
            }
            AnyVerificationContent::Accept(_) | AnyVerificationContent::Key(_) => {
                let Some(sas) = self.get_sas(event.sender(), flow_id.as_str()) else {
                    return Ok(VerificationEventResult::Handled);
                };

                if sas.flow_id() != &flow_id {
                    flow_id_mismatch();
                    return Ok(VerificationEventResult::Handled);
                }

                let Some((content, request_info)) = sas.receive_any_event(event.sender(), &content)
                else {
                    return Ok(VerificationEventResult::Handled);
                };

                self.queue_up_content(
                    sas.other_user_id(),
                    sas.other_device_id(),
                    content,
                    request_info,
                );
            }
            AnyVerificationContent::Mac(_) => {
                let Some(s) = self.get_sas(event.sender(), flow_id.as_str()) else {
                    return Ok(VerificationEventResult::Handled);
                };

                if s.flow_id() != &flow_id {
                    flow_id_mismatch();
                    return Ok(VerificationEventResult::Handled);
                }

                let content = s.receive_any_event(event.sender(), &content);

                if s.is_done() {
                    Box::pin(self.mark_sas_as_done(&s, content.map(|(c, _)| c))).await?;
                } else {
                    // Even if we are not done (yet), there might be content to
                    // send out, e.g. in the case where we are done with our
                    // side of the verification process, but the other side has
                    // not yet sent their "done".
                    let Some((content, request_id)) = content else {
                        return Ok(VerificationEventResult::Handled);
                    };

                    self.queue_up_content(
                        s.other_user_id(),
                        s.other_device_id(),
                        content,
                        request_id,
                    );
                }
            }
            AnyVerificationContent::Done(c) => {
                if let Some(verification) = self.get_request(event.sender(), flow_id.as_str()) {
                    verification.receive_done(event.sender(), c);
                }

                #[allow(clippy::single_match)]
                match self.get_verification(event.sender(), flow_id.as_str()) {
                    Some(Verification::SasV1(sas)) => {
                        let content = sas.receive_any_event(event.sender(), &content);

                        if sas.is_done() {
                            Box::pin(self.mark_sas_as_done(&sas, content.map(|(c, _)| c))).await?;
                        }
                    }
                    #[cfg(feature = "qrcode")]
                    Some(Verification::QrV1(qr)) => {
                        let (cancellation, request) = Box::pin(qr.receive_done(c)).await?;

                        if let Some(c) = cancellation {
                            self.verifications.add_request(c.into())
                        }

                        if let Some(s) = request {
                            self.verifications.add_request(s.into())
                        }
                    }
                    None => {}
                }
            }
        }

        Ok(VerificationEventResult::Handled)
    }

    fn retain_pending_to_device_request(
        &self,
        event: &ToDeviceKeyVerificationRequestEvent,
    ) -> bool {
        let key = PendingToDeviceVerificationRequestKey::from(event);
        let (query_needed, removed) = {
            let mut owner = self.incoming_verification_request_owner.write();
            let removed = owner.retain_pending(|pending| {
                pending.state.is_claimed()
                    || Self::is_timestamp_valid(pending.event.content.timestamp)
            });

            let query_needed = if owner.publication_position(&key).is_some() {
                false
            } else if let Some(pending) = owner.pending().find(|pending| {
                pending.event.sender == event.sender
                    && pending.event.content.transaction_id == event.content.transaction_id
            }) {
                pending.state == PendingToDeviceVerificationRequestState::NeedsQuery
            } else if owner.len() >= MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS {
                false
            } else {
                owner.entries.push_back(IncomingVerificationRequestEntry::Pending(
                    PendingToDeviceVerificationRequest {
                        event: event.clone(),
                        state: PendingToDeviceVerificationRequestState::NeedsQuery,
                        committed_update_generation: 0,
                    },
                ));
                true
            };
            (query_needed, removed)
        };
        if removed {
            notify_watch(&self.incoming_verification_request_changed);
        }
        query_needed
    }

    fn remove_pending_to_device_request(&self, key: &PendingToDeviceVerificationRequestKey) {
        let removed = self.incoming_verification_request_owner.write().retain_pending(|pending| {
            pending.event.sender != key.sender
                || pending.event.content.transaction_id != key.transaction_id
        });
        if removed {
            notify_watch(&self.incoming_verification_request_changed);
        }
    }

    fn publish_incoming_verification_request(
        &self,
        key: PendingToDeviceVerificationRequestKey,
        request: VerificationRequest,
    ) -> bool {
        let (admitted, changed) = {
            let mut owner = self.incoming_verification_request_owner.write();
            let mut changed = owner.retain_pending(|pending| {
                pending.state.is_claimed()
                    || Self::is_timestamp_valid(pending.event.content.timestamp)
            });
            let admitted = if owner.publication_position(&key).is_some() {
                true
            } else if let Some(position) = owner.pending_position(&key) {
                owner.entries[position] = IncomingVerificationRequestEntry::Publication(
                    IncomingVerificationRequestPublication {
                        key,
                        request,
                        state: IncomingVerificationRequestPublicationState::Unclaimed,
                    },
                );
                changed = true;
                true
            } else if owner.len() >= MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS {
                false
            } else {
                owner.entries.push_back(IncomingVerificationRequestEntry::Publication(
                    IncomingVerificationRequestPublication {
                        key,
                        request,
                        state: IncomingVerificationRequestPublicationState::Unclaimed,
                    },
                ));
                changed = true;
                true
            };
            (admitted, changed)
        };
        if changed {
            notify_watch(&self.incoming_verification_request_changed);
        }
        admitted
    }

    fn publish_or_reject_incoming_verification_request(
        &self,
        key: PendingToDeviceVerificationRequestKey,
        request: VerificationRequest,
    ) -> bool {
        if self.publish_incoming_verification_request(key, request.clone()) {
            return true;
        }

        // Capacity exhaustion is an explicit protocol-terminal rejection, not a silent product
        // drop. `UnexpectedMessage` is the existing generic protocol-level rejection code and
        // carries no local queue details or private identifiers to the peer.
        if let Some(cancel) = request.cancel_with_code(CancelCode::UnexpectedMessage) {
            self.verifications.add_verification_request(cancel);
        }
        false
    }

    fn retain_unknown_to_device_request(
        &self,
        event: &AnyEvent<'_>,
        retain_unknown_sender: bool,
    ) -> Option<VerificationEventResult> {
        if !retain_unknown_sender {
            return None;
        }
        let AnyEvent::ToDevice(ToDeviceEvents::KeyVerificationRequest(event)) = event else {
            return None;
        };
        let query_needed = self.retain_pending_to_device_request(event);
        Some(VerificationEventResult::UnknownSenderQueued {
            sender: event.sender.clone(),
            query_needed,
        })
    }

    pub(crate) fn mark_pending_to_device_key_query_scheduled(&self, user_id: &UserId) {
        for pending in self.incoming_verification_request_owner.write().pending_mut() {
            if pending.event.sender == user_id
                && pending.state == PendingToDeviceVerificationRequestState::NeedsQuery
            {
                pending.state = PendingToDeviceVerificationRequestState::QueryInFlight;
            }
        }
    }

    pub(crate) fn pending_to_device_key_query_retry_users(&self) -> HashSet<OwnedUserId> {
        self.incoming_verification_request_owner
            .read()
            .pending()
            .filter(|pending| pending.state == PendingToDeviceVerificationRequestState::NeedsQuery)
            .map(|pending| pending.event.sender.clone())
            .collect()
    }

    #[cfg(test)]
    pub(crate) async fn retry_pending_to_device_requests_for_users<'a>(
        &self,
        users: impl IntoIterator<Item = &'a UserId>,
    ) -> Result<(), CryptoStoreError> {
        let users: HashSet<OwnedUserId> = users.into_iter().map(ToOwned::to_owned).collect();
        let mut response_claim = self.claim_pending_to_device_key_query_response(&users);
        loop {
            self.retry_pending_to_device_requests_for_response(&users, response_claim.token())
                .await?;
            if !response_claim.finish_waiting_for_external_update() {
                return Ok(());
            }
        }
    }

    pub(crate) fn claim_pending_to_device_key_query_response(
        &self,
        users: &HashSet<OwnedUserId>,
    ) -> PendingToDeviceKeyQueryResponseClaim {
        let token = self
            .next_pending_to_device_key_query_response_claim_token
            .fetch_add(1, AtomicOrdering::Relaxed);
        let mut owner = self.incoming_verification_request_owner.write();
        for pending in owner.pending_mut() {
            if users.contains(&pending.event.sender) && !pending.state.is_claimed() {
                pending.state = PendingToDeviceVerificationRequestState::ResponseClaimed {
                    token,
                    observed_generation: pending.committed_update_generation,
                };
            }
        }
        drop(owner);
        PendingToDeviceKeyQueryResponseClaim {
            owner: self.incoming_verification_request_owner.clone(),
            token,
            active: true,
        }
    }

    pub(crate) fn record_pending_to_device_key_query_commit(
        &self,
        users: &HashSet<OwnedUserId>,
        response_token: u64,
    ) {
        let mut owner = self.incoming_verification_request_owner.write();
        for pending in owner.pending_mut().filter(|pending| users.contains(&pending.event.sender)) {
            pending.committed_update_generation =
                pending.committed_update_generation.wrapping_add(1);
            let committed_update_generation = pending.committed_update_generation;
            pending.state = match pending.state {
                PendingToDeviceVerificationRequestState::ResponseClaimed { token, .. }
                    if token == response_token =>
                {
                    PendingToDeviceVerificationRequestState::ResponseClaimed {
                        token,
                        observed_generation: committed_update_generation,
                    }
                }
                PendingToDeviceVerificationRequestState::ReplayClaimed {
                    response_token: owner_token,
                    replay_token,
                    ..
                } if owner_token == response_token => {
                    PendingToDeviceVerificationRequestState::ReplayClaimed {
                        response_token: owner_token,
                        replay_token,
                        observed_generation: committed_update_generation,
                    }
                }
                state if !state.is_claimed() => {
                    PendingToDeviceVerificationRequestState::ResponseClaimed {
                        token: response_token,
                        observed_generation: committed_update_generation,
                    }
                }
                state => state,
            };
        }
    }

    pub(crate) async fn retry_pending_to_device_requests_for_response(
        &self,
        users: &HashSet<OwnedUserId>,
        response_token: u64,
    ) -> Result<(), CryptoStoreError> {
        let (retry_keys, removed) = {
            let mut owner = self.incoming_verification_request_owner.write();
            let removed = owner.retain_pending(|pending| {
                pending.state.is_claimed()
                    || Self::is_timestamp_valid(pending.event.content.timestamp)
            });
            let retry_keys = owner
                .pending()
                .filter(|pending| {
                    users.contains(&pending.event.sender)
                        && matches!(
                            pending.state,
                            PendingToDeviceVerificationRequestState::ResponseClaimed {
                                token,
                                ..
                            } if token == response_token
                        )
                })
                .map(PendingToDeviceVerificationRequestKey::from)
                .collect::<Vec<_>>();
            (retry_keys, removed)
        };
        if removed {
            notify_watch(&self.incoming_verification_request_changed);
        }

        for key in retry_keys {
            let Some((mut claim, pending_event)) =
                self.claim_pending_to_device_request_for_replay(&key, response_token)
            else {
                continue;
            };

            #[cfg(test)]
            self.pause_replay_after_claim_for_test().await;

            #[cfg(test)]
            if self.should_fail_pending_replay_for_test() {
                claim.release_to_response_claim();
                return Err(CryptoStoreError::AccountUnset);
            }

            let event = ToDeviceEvents::KeyVerificationRequest(pending_event);
            let event = AnyEvent::from(&event);
            let Ok(flow_id) = FlowId::try_from(&event) else {
                claim.finish();
                continue;
            };
            let Some(AnyVerificationContent::Request(content)) = event.verification_content()
            else {
                claim.finish();
                continue;
            };
            match self.prepare_incoming_verification_request(&event, flow_id, &content, true).await
            {
                Ok(PreparedIncomingVerificationRequest::Ready(request)) => {
                    let (request, publishable) = self
                        .insert_incoming_to_device_request(request)
                        .into_request_and_provenance();
                    // The pending slot and the resulting publication are transitioned under the
                    // single owner lock, so recovery cannot strand a committed replay at capacity.
                    claim.publish(
                        request,
                        publishable,
                        &self.incoming_verification_request_changed,
                    );
                }
                Ok(PreparedIncomingVerificationRequest::Terminal(
                    VerificationEventResult::Handled,
                )) => {
                    claim.finish();
                }
                Ok(PreparedIncomingVerificationRequest::Terminal(
                    VerificationEventResult::UnknownSenderQueued { .. },
                )) => claim.release_to_response_claim(),
                Ok(PreparedIncomingVerificationRequest::Terminal(
                    VerificationEventResult::RequestMaterialized(_),
                )) => unreachable!("request preparation cannot materialize a request"),
                Err(error) => {
                    claim.release_to_response_claim();
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    fn next_pending_to_device_request_claim_token(&self) -> u64 {
        self.next_pending_to_device_request_claim_token.fetch_add(1, AtomicOrdering::Relaxed)
    }

    fn claim_pending_to_device_request_for_replay(
        &self,
        key: &PendingToDeviceVerificationRequestKey,
        response_token: u64,
    ) -> Option<(PendingToDeviceVerificationRequestClaim, ToDeviceKeyVerificationRequestEvent)>
    {
        let token = self.next_pending_to_device_request_claim_token();
        let mut owner = self.incoming_verification_request_owner.write();
        let pending = owner.pending_mut().find(|pending| {
            pending.event.sender == key.sender
                && pending.event.content.transaction_id == key.transaction_id
        })?;
        let PendingToDeviceVerificationRequestState::ResponseClaimed {
            token: owner_token,
            observed_generation,
        } = pending.state
        else {
            return None;
        };
        if owner_token != response_token {
            return None;
        }
        pending.state = PendingToDeviceVerificationRequestState::ReplayClaimed {
            response_token,
            replay_token: token,
            observed_generation,
        };
        let event = pending.event.clone();
        Some((
            PendingToDeviceVerificationRequestClaim {
                owner: self.incoming_verification_request_owner.clone(),
                publication_changed: self.incoming_verification_request_changed.clone(),
                key: key.clone(),
                token,
                response_token,
                kind: PendingToDeviceVerificationRequestClaimKind::Replay,
                active: true,
            },
            event,
        ))
    }

    #[cfg(test)]
    fn should_fail_pending_replay_for_test(&self) -> bool {
        let remaining = self.pending_replay_failure_after.load(Ordering::SeqCst);
        match remaining {
            ..=-1 => false,
            0 => {
                self.pending_replay_failure_after.store(-1, Ordering::SeqCst);
                true
            }
            _ => {
                self.pending_replay_failure_after.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_pending_replay_after_for_test(&self, successful_replays: usize) {
        self.pending_replay_failure_after.store(successful_replays as isize, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn clear_pending_replay_failure_for_test(&self) {
        self.pending_replay_failure_after.store(-1, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_verification_request_device_lookup_for_test(&self) {
        self.fail_next_verification_request_device_lookup.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_post_key_query_recovery_cache_acquisition_for_test(&self) {
        self.fail_next_post_key_query_recovery_cache_acquisition.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn should_fail_post_key_query_recovery_cache_acquisition_for_test(&self) -> bool {
        self.fail_next_post_key_query_recovery_cache_acquisition.swap(false, Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_replay_after_claim_pause_for_test(
        &self,
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) {
        *self.test_hooks.replay_after_claim.write() =
            Some(VerificationMachineTestPause { entered, release });
    }

    #[cfg(test)]
    async fn pause_replay_after_claim_for_test(&self) {
        let pause = self.test_hooks.replay_after_claim.write().take();
        if let Some(pause) = pause {
            pause.entered.wait().await;
            pause.release.wait().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn set_request_device_lookup_completed_pause_for_test(
        &self,
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) {
        *self.test_hooks.request_device_lookup_completed.write() =
            Some(VerificationMachineTestPause { entered, release });
    }

    #[cfg(test)]
    async fn pause_request_device_lookup_completed_for_test(&self) {
        let pause = self.test_hooks.request_device_lookup_completed.write().take();
        if let Some(pause) = pause {
            pause.entered.wait().await;
            pause.release.wait().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn set_publication_after_claim_pause_for_test(
        &self,
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) {
        *self.test_hooks.publication_after_claim.write() =
            Some(VerificationMachineTestPause { entered, release });
    }

    #[cfg(test)]
    async fn pause_publication_after_claim_for_test(&self) {
        let pause = self.test_hooks.publication_after_claim.write().take();
        if let Some(pause) = pause {
            pause.entered.wait().await;
            pause.release.wait().await;
        }
    }

    #[cfg(test)]
    fn set_request_insert_before_write_barrier_for_test(&self, barrier: Arc<std::sync::Barrier>) {
        *self.test_hooks.request_insert_before_write.write() = Some(barrier);
    }

    #[cfg(test)]
    pub(crate) fn pending_to_device_request_count(&self) -> usize {
        self.incoming_verification_request_owner.read().pending_count()
    }

    #[cfg(test)]
    pub(crate) fn incoming_verification_request_owner_count(&self) -> usize {
        self.incoming_verification_request_owner.read().len()
    }

    #[cfg(test)]
    pub(crate) fn has_pending_to_device_request(&self, user_id: &UserId, flow_id: &str) -> bool {
        self.incoming_verification_request_owner.read().pending().any(|pending| {
            pending.event.sender == user_id
                && pending.event.content.transaction_id.as_str() == flow_id
        })
    }

    #[cfg(test)]
    pub(crate) fn expire_pending_to_device_requests_for_test(&self) {
        let expired = MilliSecondsSinceUnixEpoch::from_system_time(std::time::UNIX_EPOCH)
            .expect("the Unix epoch is a valid Matrix timestamp");
        for pending in self.incoming_verification_request_owner.write().pending_mut() {
            pending.event.content.timestamp = expired;
        }
    }

    /**
     * Utility function to build the public identity (i.e., an
     * [`OwnUserIdentityData`]) corresponding to the private identity
     * stored in the `VerificationStore`.
     */
    #[cfg(test)]
    pub async fn get_own_user_identity_data(
        &self,
    ) -> Result<crate::OwnUserIdentityData, crate::SignatureError> {
        self.store.private_identity.lock().await.to_public_identity().await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, time::Duration};

    use futures_util::{FutureExt, StreamExt};
    use matrix_sdk_test::async_test;
    use ruma::{
        TransactionId,
        events::{AnyToDeviceEventContent, key::verification::cancel::CancelCode},
    };
    use tokio::sync::Mutex;

    use super::{
        AtomicBool, AtomicIsize, MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS,
        PendingToDeviceVerificationRequestKey, Sas, VerificationMachine,
        VerificationRequestInsertion,
    };
    use crate::{
        Account, VerificationRequest,
        olm::PrivateCrossSigningIdentity,
        store::{CryptoStoreWrapper, MemoryStore},
        verification::{
            FlowId, VerificationRequestState, VerificationStore,
            cache::VerificationCache,
            event_enums::{AcceptContent, KeyContent, MacContent, OutgoingContent},
            tests::{alice_device_id, alice_id, setup_stores, wrap_any_to_device_content},
        },
    };

    async fn verification_machine() -> (VerificationMachine, VerificationStore) {
        let (_account, store, _bob, bob_store) = setup_stores().await;
        let (incoming_verification_request_changed, _) = tokio::sync::watch::channel(0);

        let machine = VerificationMachine {
            store,
            verifications: VerificationCache::new(),
            requests: Default::default(),
            incoming_verification_request_owner: Default::default(),
            next_pending_to_device_request_claim_token: Default::default(),
            next_pending_to_device_key_query_response_claim_token: Default::default(),
            next_incoming_verification_request_subscriber_generation: Default::default(),
            next_incoming_verification_request_delivery_token: Default::default(),
            incoming_verification_request_changed,
            pending_replay_failure_after: Arc::new(AtomicIsize::new(-1)),
            fail_next_verification_request_device_lookup: Arc::new(AtomicBool::new(false)),
            fail_next_post_key_query_recovery_cache_acquisition: Arc::new(AtomicBool::new(false)),
            test_hooks: Default::default(),
        };

        (machine, bob_store)
    }

    #[test]
    fn incoming_verification_request_diagnostic_is_private_safe() {
        let source = include_str!("machine.rs");
        for (macro_name, message) in [
            ("info", "\"Received a new verification request\""),
            ("warn", "\"The key verification request didn't contain a valid timestamp\""),
            (
                "info",
                "\"The received verification request was too old or too far into the future\"",
            ),
            ("trace", "\"The received verification request was sent by us, ignoring it\""),
        ] {
            let message_position = source.find(message).expect("incoming request diagnostic");
            let invocation_start = source[..message_position]
                .rfind(&format!("{macro_name}!("))
                .expect("incoming request diagnostic invocation");
            let invocation = &source[invocation_start..message_position + message.len()];

            for forbidden in ["sender =", "from_device =", "?timestamp", "timestamp ="] {
                assert!(
                    !invocation.contains(forbidden),
                    "incoming request diagnostic exposed {forbidden}: {invocation}"
                );
            }
        }
    }

    #[test]
    fn known_verification_request_diagnostic_is_private_safe() {
        let source = include_str!("machine.rs");
        let message = "\"Ignoring known verification request\"";
        let message_position = source.find(message).expect("known request diagnostic");
        let invocation_start =
            source[..message_position].rfind("debug!(").expect("known request debug invocation");
        let invocation = &source[invocation_start..message_position + message.len()];

        assert!(
            !invocation.contains("flow_id"),
            "known request diagnostic exposed flow_id: {invocation}"
        );
    }

    #[test]
    fn verification_receive_diagnostics_are_private_safe() {
        let source = include_str!("machine.rs");
        let production = &source[..source.find("mod tests {").expect("verification tests module")];
        let receive_position = source
            .find("pub async fn receive_any_event")
            .expect("verification receive entry point");
        let instrument_start = source[..receive_position]
            .rfind("#[instrument")
            .expect("verification receive instrument attribute");
        let instrument = &source[instrument_start..receive_position];
        assert!(
            !instrument.contains("flow_id"),
            "verification receive span exposed flow_id: {instrument}"
        );
        assert!(
            !production.contains("Span::current().record(\"flow_id\"")
                && !production.contains("flow_id = flow_id.as_str()"),
            "verification receive diagnostics must not record flow IDs"
        );
    }

    async fn setup_verification_machine() -> (VerificationMachine, Sas) {
        let (machine, bob_store) = verification_machine().await;

        let alice_device =
            bob_store.get_device(alice_id(), alice_device_id()).await.unwrap().unwrap();

        let identities = bob_store.get_identities(alice_device).await.unwrap();
        let (bob_sas, start_content) =
            Sas::start(identities, TransactionId::new(), true, None, None);

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_sas.user_id(), start_content))
            .await
            .unwrap();

        (machine, bob_sas)
    }

    #[async_test]
    async fn test_create() {
        let alice = Account::with_device_id(alice_id(), alice_device_id());
        let identity = Arc::new(Mutex::new(PrivateCrossSigningIdentity::empty(alice_id())));
        let _ = VerificationMachine::new(
            alice.static_data,
            identity,
            Arc::new(CryptoStoreWrapper::new(alice_id(), alice_device_id(), MemoryStore::new())),
        );
    }

    #[async_test]
    async fn test_full_flow() {
        let (alice_machine, bob) = setup_verification_machine().await;

        let alice = alice_machine.get_sas(bob.user_id(), bob.flow_id().as_str()).unwrap();

        let request = alice.accept().unwrap();

        let content = OutgoingContent::try_from(request).unwrap();
        let content = AcceptContent::try_from(&content).unwrap().into();

        let (content, request_info) = bob.receive_any_event(alice.user_id(), &content).unwrap();

        let event = wrap_any_to_device_content(bob.user_id(), content);

        assert!(alice_machine.verifications.outgoing_requests().is_empty());
        alice_machine.receive_any_event(&event).await.unwrap();
        assert!(!alice_machine.verifications.outgoing_requests().is_empty());

        let request = alice_machine.verifications.outgoing_requests().first().cloned().unwrap();
        let txn_id = request.request_id().to_owned();
        let content = OutgoingContent::try_from(request).unwrap();
        let content = KeyContent::try_from(&content).unwrap().into();

        alice_machine.mark_request_as_sent(&txn_id);

        assert!(bob.receive_any_event(alice.user_id(), &content).is_none());

        assert!(alice.emoji().is_some());
        // Bob can only show the emoji if it marks the request carrying the
        // m.key.verification.key event as sent.
        assert!(bob.emoji().is_none());
        bob.mark_request_as_sent(&request_info.unwrap().request_id);
        assert!(bob.emoji().is_some());
        assert_eq!(alice.emoji(), bob.emoji());

        let mut requests = alice.confirm().await.unwrap().0;
        assert!(requests.len() == 1);
        let request = requests.pop().unwrap();
        let content = OutgoingContent::try_from(request).unwrap();
        let content = MacContent::try_from(&content).unwrap().into();
        bob.receive_any_event(alice.user_id(), &content);

        let mut requests = bob.confirm().await.unwrap().0;
        assert!(requests.len() == 1);
        let request = requests.pop().unwrap();
        let content = OutgoingContent::try_from(request).unwrap();
        let content = MacContent::try_from(&content).unwrap().into();
        alice.receive_any_event(bob.user_id(), &content);

        assert!(alice.is_done());
        assert!(bob.is_done());
    }

    #[cfg(not(target_os = "macos"))]
    #[expect(clippy::unchecked_time_subtraction)]
    #[async_test]
    async fn test_timing_out() {
        use std::time::Duration;

        use ruma::time::Instant;

        let (alice_machine, bob) = setup_verification_machine().await;
        let alice = alice_machine.get_sas(bob.user_id(), bob.flow_id().as_str()).unwrap();

        assert!(!alice.timed_out());
        assert!(alice_machine.verifications.outgoing_requests().is_empty());

        // This line panics on macOS, so we're disabled for now.
        alice.set_creation_time(Instant::now() - Duration::from_secs(60 * 15));
        assert!(alice.timed_out());
        assert!(alice_machine.verifications.outgoing_requests().is_empty());
        alice_machine.garbage_collect();
        assert!(!alice_machine.verifications.outgoing_requests().is_empty());
        alice_machine.garbage_collect();
        assert!(alice_machine.verifications.is_empty());
    }

    /// Test to ensure that we cancel both verifications if a second one gets
    /// started while another one is going on.
    #[async_test]
    async fn test_double_verification_cancellation() {
        let (machine, bob_store) = verification_machine().await;

        let alice_device =
            bob_store.get_device(alice_id(), alice_device_id()).await.unwrap().unwrap();
        let identities = bob_store.get_identities(alice_device).await.unwrap();

        // Start the first sas verification.
        let (bob_sas, start_content) =
            Sas::start(identities.clone(), TransactionId::new(), true, None, None);

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_sas.user_id(), start_content))
            .await
            .unwrap();

        let alice_sas = machine.get_sas(bob_sas.user_id(), bob_sas.flow_id().as_str()).unwrap();

        // We're not yet cancelled.
        assert!(!alice_sas.is_cancelled());

        let second_transaction_id = TransactionId::new();
        let (bob_sas, start_content) =
            Sas::start(identities, second_transaction_id.clone(), true, None, None);
        machine
            .receive_any_event(&wrap_any_to_device_content(bob_sas.user_id(), start_content))
            .await
            .unwrap();

        let second_sas = machine.get_sas(bob_sas.user_id(), bob_sas.flow_id().as_str()).unwrap();

        // Make sure we fetched the new one.
        assert_eq!(second_sas.flow_id().as_str(), second_transaction_id);

        // Make sure both of them are cancelled.
        assert!(alice_sas.is_cancelled());
        assert!(second_sas.is_cancelled());
    }

    /// Test to ensure that we cancel both verification requests if a second one
    /// gets started while another one is going on.
    #[async_test]
    async fn test_double_verification_request_cancellation() {
        let (machine, bob_store) = verification_machine().await;

        // Start the first verification request.
        let flow_id = FlowId::ToDevice("TEST_FLOW_ID".into());

        let bob_request = VerificationRequest::new(
            VerificationCache::new(),
            bob_store.clone(),
            flow_id.clone(),
            alice_id(),
            vec![],
            None,
        );

        let request = bob_request.request_to_device();
        let content: OutgoingContent = request.try_into().unwrap();

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_request.own_user_id(), content))
            .await
            .unwrap();

        let alice_request =
            machine.get_request(bob_request.own_user_id(), bob_request.flow_id().as_str()).unwrap();

        // We're not yet cancelled.
        assert!(!alice_request.is_cancelled());

        let second_transaction_id = TransactionId::new();
        let bob_request = VerificationRequest::new(
            VerificationCache::new(),
            bob_store,
            second_transaction_id.clone().into(),
            alice_id(),
            vec![],
            None,
        );

        let request = bob_request.request_to_device();
        let content: OutgoingContent = request.try_into().unwrap();

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_request.own_user_id(), content))
            .await
            .unwrap();

        let second_request =
            machine.get_request(bob_request.own_user_id(), bob_request.flow_id().as_str()).unwrap();

        // Make sure we fetched the new one.
        assert_eq!(second_request.flow_id().as_str(), second_transaction_id);

        // Make sure both of them are cancelled.
        assert!(alice_request.is_cancelled());
        assert!(second_request.is_cancelled());
    }

    /// Ensure that if a duplicate request is added (i.e. matching user and
    /// flow_id) the existing request is not cancelled and the new one is
    /// ignored
    #[async_test]
    async fn test_ignore_identical_verification_request() {
        let (machine, bob_store) = verification_machine().await;

        // Start the first verification request.
        let flow_id = FlowId::ToDevice("TEST_FLOW_ID".into());

        let bob_request = VerificationRequest::new(
            VerificationCache::new(),
            bob_store.clone(),
            flow_id.clone(),
            alice_id(),
            vec![],
            None,
        );

        let request = bob_request.request_to_device();
        let content: OutgoingContent = request.try_into().unwrap();

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_request.own_user_id(), content))
            .await
            .unwrap();

        let first_request =
            machine.get_request(bob_request.own_user_id(), bob_request.flow_id().as_str()).unwrap();

        // We're not yet cancelled.
        assert!(!first_request.is_cancelled());

        // Bob is adding a second request with the same flow_id as before
        let bob_request = VerificationRequest::new(
            VerificationCache::new(),
            bob_store,
            flow_id.clone(),
            alice_id(),
            vec![],
            None,
        );

        let request = bob_request.request_to_device();
        let content: OutgoingContent = request.try_into().unwrap();

        machine
            .receive_any_event(&wrap_any_to_device_content(bob_request.own_user_id(), content))
            .await
            .unwrap();

        let second_request =
            machine.get_request(bob_request.own_user_id(), bob_request.flow_id().as_str()).unwrap();

        // None of the requests are cancelled
        assert!(!first_request.is_cancelled());
        assert!(!second_request.is_cancelled());
    }

    #[async_test]
    async fn test_concurrent_identical_request_insertion_preserves_one_stable_handle() {
        let (machine, bob_store) = verification_machine().await;
        let flow_id = FlowId::ToDevice("CONCURRENT_IDENTICAL_FLOW".into());
        let first = VerificationRequest::new(
            VerificationCache::new(),
            bob_store.clone(),
            flow_id.clone(),
            alice_id(),
            vec![],
            None,
        );
        let second = VerificationRequest::new(
            VerificationCache::new(),
            bob_store,
            flow_id,
            alice_id(),
            vec![],
            None,
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        machine.set_request_insert_before_write_barrier_for_test(barrier);

        let (first, second) = std::thread::scope(|scope| {
            let first_machine = machine.clone();
            let first = scope.spawn(move || first_machine.insert_request(first));
            let second_machine = machine.clone();
            let second = scope.spawn(move || second_machine.insert_request(second));
            (first.join().unwrap(), second.join().unwrap())
        });
        let first_was_inserted = matches!(first, VerificationRequestInsertion::Inserted { .. });
        let second_was_inserted = matches!(second, VerificationRequestInsertion::Inserted { .. });
        assert_ne!(
            first_was_inserted, second_was_inserted,
            "the atomic insertion must report exactly one winning insertion"
        );
        let first = first.into_request();
        let second = second.into_request();

        assert!(!first.is_cancelled());
        assert!(!second.is_cancelled());
        let cached = machine
            .get_request(alice_id(), "CONCURRENT_IDENTICAL_FLOW")
            .expect("one request handle must be cached");
        assert!(!cached.is_cancelled());

        first.cancel();
        assert!(second.is_cancelled(), "both insertions must return the same shared handle");
        assert!(cached.is_cancelled(), "the cache must retain that same shared handle");
    }

    #[async_test]
    async fn test_same_flow_collision_does_not_upgrade_unrelated_cached_request_provenance() {
        let (machine, bob_store) = verification_machine().await;
        let flow_id = FlowId::ToDevice("SAME_FLOW_UNRELATED_PROVENANCE".into());
        let unrelated = VerificationRequest::new(
            VerificationCache::new(),
            bob_store.clone(),
            flow_id.clone(),
            alice_id(),
            vec![],
            None,
        );
        let incoming = VerificationRequest::new(
            VerificationCache::new(),
            bob_store,
            flow_id,
            alice_id(),
            vec![],
            None,
        );

        assert!(matches!(
            machine.insert_request(unrelated),
            VerificationRequestInsertion::Inserted { .. }
        ));
        assert!(matches!(
            machine.insert_incoming_to_device_request(incoming),
            VerificationRequestInsertion::Existing { .. }
        ));

        let cached = machine.requests.read();
        let cached = cached
            .get(alice_id())
            .and_then(|requests| requests.get("SAME_FLOW_UNRELATED_PROVENANCE"))
            .expect("the unrelated cache entry must stay present");
        assert!(
            !cached.incoming_to_device,
            "a same-flow collision must not relabel an unrelated cached handle as incoming"
        );
    }

    #[async_test]
    async fn test_known_request_cannot_overtake_earlier_pending_request() {
        let (machine, bob_store) = verification_machine().await;
        let request_for = |flow_id: &str| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(flow_id.to_owned().into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let earlier = request_for("EARLIER_PENDING");
        let content: OutgoingContent = earlier.request_to_device().try_into().unwrap();
        let event = wrap_any_to_device_content(alice_id(), content);
        let crate::types::events::ToDeviceEvents::KeyVerificationRequest(event) = event else {
            panic!("request helper must produce a to-device verification request");
        };
        assert!(machine.retain_pending_to_device_request(&event));

        let later = request_for("LATER_KNOWN");
        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                later.other_user(),
                later.flow_id().as_str(),
            ),
            later.clone(),
        ));
        let mut deliveries = machine.subscribe_to_incoming_verification_requests();
        assert!(
            deliveries.next().now_or_never().is_none(),
            "a later known request must remain behind an unresolved pending head"
        );

        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                earlier.other_user(),
                earlier.flow_id().as_str(),
            ),
            earlier.clone(),
        ));
        let first = deliveries.next().await.expect("the resolved head is delivered first");
        assert_eq!(first.flow_id(), earlier.flow_id());
        first.commit();
        let second = deliveries.next().await.expect("the known tail follows the resolved head");
        assert_eq!(second.flow_id(), later.flow_id());
        second.commit();
    }

    #[async_test]
    async fn test_terminal_pending_replay_wakes_later_publication_without_external_event() {
        let (machine, bob_store) = verification_machine().await;
        let request_for = |flow_id: &str| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(flow_id.to_owned().into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let earlier = request_for("TERMINAL_PENDING_HEAD");
        let content: OutgoingContent = earlier.request_to_device().try_into().unwrap();
        let event = wrap_any_to_device_content(alice_id(), content);
        let crate::types::events::ToDeviceEvents::KeyVerificationRequest(event) = event else {
            panic!("request helper must produce a to-device verification request");
        };
        let earlier_key = PendingToDeviceVerificationRequestKey::from(&event);
        assert!(machine.retain_pending_to_device_request(&event));
        let users = HashSet::from([alice_id().to_owned()]);
        let response_claim = machine.claim_pending_to_device_key_query_response(&users);
        let (mut replay_claim, _) = machine
            .claim_pending_to_device_request_for_replay(&earlier_key, response_claim.token())
            .expect("the pending head is claimed for terminal replay");

        let later = request_for("LATER_PUBLICATION_AFTER_TERMINAL");
        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                later.other_user(),
                later.flow_id().as_str(),
            ),
            later.clone(),
        ));
        let mut deliveries = machine.subscribe_to_incoming_verification_requests();
        let next_delivery = deliveries.next();
        tokio::pin!(next_delivery);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), next_delivery.as_mut()).await.is_err(),
            "the later publication must initially wait behind the pending head"
        );

        replay_claim.finish();

        let delivery = tokio::time::timeout(Duration::from_millis(100), next_delivery)
            .await
            .expect("terminal head removal must wake the waiting subscriber")
            .expect("the retained later publication is delivered");
        assert_eq!(delivery.flow_id(), later.flow_id());
        delivery.commit();
    }

    #[async_test]
    async fn test_direct_pending_removal_wakes_later_publication_without_external_event() {
        let (machine, bob_store) = verification_machine().await;
        let request_for = |flow_id: &str| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(flow_id.to_owned().into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let earlier = request_for("DIRECTLY_REMOVED_PENDING_HEAD");
        let content: OutgoingContent = earlier.request_to_device().try_into().unwrap();
        let event = wrap_any_to_device_content(alice_id(), content);
        let crate::types::events::ToDeviceEvents::KeyVerificationRequest(event) = event else {
            panic!("request helper must produce a to-device verification request");
        };
        let earlier_key = PendingToDeviceVerificationRequestKey::from(&event);
        assert!(machine.retain_pending_to_device_request(&event));

        let later = request_for("LATER_PUBLICATION_AFTER_DIRECT_REMOVAL");
        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                later.other_user(),
                later.flow_id().as_str(),
            ),
            later.clone(),
        ));
        let mut deliveries = machine.subscribe_to_incoming_verification_requests();
        let next_delivery = deliveries.next();
        tokio::pin!(next_delivery);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), next_delivery.as_mut()).await.is_err(),
            "the later publication must initially wait behind the pending head"
        );

        machine.remove_pending_to_device_request(&earlier_key);

        let delivery = tokio::time::timeout(Duration::from_millis(100), next_delivery)
            .await
            .expect("direct head removal must wake the waiting subscriber")
            .expect("the retained later publication is delivered");
        assert_eq!(delivery.flow_id(), later.flow_id());
        delivery.commit();
    }

    #[async_test]
    async fn test_response_expiry_cleanup_wakes_later_publication_without_external_event() {
        let (machine, bob_store) = verification_machine().await;
        let request_for = |flow_id: &str| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(flow_id.to_owned().into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let earlier = request_for("EXPIRED_PENDING_HEAD");
        let content: OutgoingContent = earlier.request_to_device().try_into().unwrap();
        let event = wrap_any_to_device_content(alice_id(), content);
        let crate::types::events::ToDeviceEvents::KeyVerificationRequest(event) = event else {
            panic!("request helper must produce a to-device verification request");
        };
        assert!(machine.retain_pending_to_device_request(&event));

        let later = request_for("LATER_PUBLICATION_AFTER_EXPIRY_CLEANUP");
        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                later.other_user(),
                later.flow_id().as_str(),
            ),
            later.clone(),
        ));
        machine.expire_pending_to_device_requests_for_test();
        let mut deliveries = machine.subscribe_to_incoming_verification_requests();
        let next_delivery = deliveries.next();
        tokio::pin!(next_delivery);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), next_delivery.as_mut()).await.is_err(),
            "the later publication must initially wait behind the expired pending head"
        );

        machine
            .retry_pending_to_device_requests_for_response(&HashSet::new(), 0)
            .await
            .expect("response cleanup succeeds");

        let delivery = tokio::time::timeout(Duration::from_millis(100), next_delivery)
            .await
            .expect("response expiry cleanup must wake the waiting subscriber")
            .expect("the retained later publication is delivered");
        assert_eq!(delivery.flow_id(), later.flow_id());
        delivery.commit();
    }

    #[async_test]
    async fn test_active_lease_counts_toward_bound_and_overflow_is_explicitly_rejected() {
        let (machine, bob_store) = verification_machine().await;
        let mut deliveries = machine.subscribe_to_incoming_verification_requests();
        let request_for = |index: usize| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(format!("BOUNDED_INCOMING_{index}").into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let mut active = None;
        let mut rejected = None;

        for index in 0..33 {
            let request = request_for(index);
            let key = PendingToDeviceVerificationRequestKey::new(
                request.other_user(),
                request.flow_id().as_str(),
            );
            let admitted =
                machine.publish_or_reject_incoming_verification_request(key, request.clone());
            if index < MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS {
                assert!(admitted);
            } else {
                assert!(!admitted, "the newest request is explicitly rejected at capacity");
                rejected = Some(request);
            }
            if index == 0 {
                active = Some(deliveries.next().await.expect("the first head must be claimable"));
            }
        }

        assert_eq!(machine.incoming_verification_request_owner_count(), 32);
        assert!(
            deliveries.next().now_or_never().is_none(),
            "the active head retains its bounded slot and blocks overtaking"
        );
        let rejected = rejected.expect("the overflow request is retained by the test");
        let VerificationRequestState::Cancelled(info) = rejected.state() else {
            panic!("capacity overload must make the request terminal");
        };
        assert!(info.cancelled_by_us());
        assert_eq!(info.cancel_code(), &CancelCode::UnexpectedMessage);
        let outgoing = machine.outgoing_messages();
        assert_eq!(outgoing.len(), 1, "capacity rejection must queue one protocol cancel");
        let OutgoingContent::ToDevice(content) = outgoing[0].clone().try_into().unwrap() else {
            panic!("a to-device verification request must reject over to-device");
        };
        let AnyToDeviceEventContent::KeyVerificationCancel(content) = *content else {
            panic!("capacity rejection must queue m.key.verification.cancel");
        };
        assert_eq!(content.code, CancelCode::UnexpectedMessage);

        drop(active.take());
        deliveries.next().await.expect("dropping an active lease releases the same head").commit();
        for _ in 1..MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS {
            deliveries.next().await.expect("the accepted FIFO tail remains deliverable").commit();
        }
        assert!(deliveries.next().now_or_never().is_none());

        let later = request_for(33);
        assert!(machine.publish_or_reject_incoming_verification_request(
            PendingToDeviceVerificationRequestKey::new(
                later.other_user(),
                later.flow_id().as_str(),
            ),
            later,
        ));
        deliveries
            .next()
            .await
            .expect("a new distinct flow is admitted after capacity frees")
            .commit();
    }

    #[async_test]
    async fn test_known_request_overflow_rejects_newest_and_preserves_pending_fifo() {
        let (machine, bob_store) = verification_machine().await;
        let request_for = |index: usize| {
            VerificationRequest::new(
                VerificationCache::new(),
                bob_store.clone(),
                FlowId::ToDevice(format!("PENDING_BEFORE_KNOWN_{index}").into()),
                alice_id(),
                vec![],
                None,
            )
        };
        let event_for = |index: usize| {
            let request = request_for(index);
            let content: OutgoingContent = request.request_to_device().try_into().unwrap();
            let event = wrap_any_to_device_content(request.own_user_id(), content);
            let crate::types::events::ToDeviceEvents::KeyVerificationRequest(event) = event else {
                panic!("request helper must produce a to-device verification request");
            };
            event
        };
        let expected_keys = (0..MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS)
            .map(|index| {
                let event = event_for(index);
                assert!(machine.retain_pending_to_device_request(&event));
                PendingToDeviceVerificationRequestKey::from(&event)
            })
            .collect::<Vec<_>>();

        let newcomer = request_for(MAX_PENDING_TO_DEVICE_VERIFICATION_REQUESTS);
        let newcomer_key = PendingToDeviceVerificationRequestKey::new(
            newcomer.other_user(),
            newcomer.flow_id().as_str(),
        );
        assert!(
            !machine
                .publish_or_reject_incoming_verification_request(newcomer_key, newcomer.clone(),),
            "a known materialized newcomer must be rejected when 32 obligations already exist"
        );

        let owner = machine.incoming_verification_request_owner.read();
        let actual_keys =
            owner.pending().map(PendingToDeviceVerificationRequestKey::from).collect::<Vec<_>>();
        assert_eq!(actual_keys, expected_keys, "known overflow must preserve the pending FIFO");
        assert_eq!(
            owner.pending_count(),
            owner.len(),
            "the rejected newcomer must not be published"
        );
        drop(owner);

        let VerificationRequestState::Cancelled(info) = newcomer.state() else {
            panic!("known overload must make the newcomer terminal");
        };
        assert!(info.cancelled_by_us());
        assert_eq!(info.cancel_code(), &CancelCode::UnexpectedMessage);
        assert_eq!(machine.outgoing_messages().len(), 1);
    }
}
