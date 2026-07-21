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

use std::{sync::Arc, time::Duration};

use futures_util::{FutureExt, StreamExt};
use matrix_sdk_test::async_test;
use ruma::{
    TransactionId, api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse,
    events::key::verification::VerificationMethod,
};
use serde_json::json;
use tokio::sync::{Barrier, oneshot};

use crate::{
    machine::{test_helpers::get_machine_pair_with_setup_sessions_test_helper, tests},
    store::types::{Changes, DeviceChanges},
    types::events::ToDeviceEvents,
    verification::{
        VerificationEventResult,
        tests::{outgoing_request_to_event, request_to_event},
    },
};

#[async_test]
async fn test_interactive_verification() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();

    assert!(!bob_device.is_verified());

    let (alice_sas, request) = bob_device.start_verification().await.unwrap();

    let event = request_to_event(alice.user_id(), &request.into());
    bob.handle_verification_event(&event).await;

    let bob_sas = bob
        .get_verification(alice.user_id(), alice_sas.flow_id().as_str())
        .unwrap()
        .sas_v1()
        .unwrap();

    assert!(alice_sas.emoji().is_none());
    assert!(bob_sas.emoji().is_none());

    let event = bob_sas.accept().map(|r| request_to_event(bob.user_id(), &r)).unwrap();

    alice.handle_verification_event(&event).await;

    let (event, request_id) = alice
        .inner
        .verification_machine
        .outgoing_messages()
        .first()
        .map(|r| (outgoing_request_to_event(alice.user_id(), r), r.request_id.to_owned()))
        .unwrap();
    alice.mark_request_as_sent(&request_id, &ToDeviceResponse::new()).await.unwrap();
    bob.handle_verification_event(&event).await;

    let (event, request_id) = bob
        .inner
        .verification_machine
        .outgoing_messages()
        .first()
        .map(|r| (outgoing_request_to_event(bob.user_id(), r), r.request_id.to_owned()))
        .unwrap();
    alice.handle_verification_event(&event).await;
    bob.mark_request_as_sent(&request_id, &ToDeviceResponse::new()).await.unwrap();

    assert!(alice_sas.emoji().is_some());
    assert!(bob_sas.emoji().is_some());

    assert_eq!(alice_sas.emoji(), bob_sas.emoji());
    assert_eq!(alice_sas.decimals(), bob_sas.decimals());

    let contents = bob_sas.confirm().await.unwrap().0;
    assert!(contents.len() == 1);
    let event = request_to_event(bob.user_id(), &contents[0]);
    alice.handle_verification_event(&event).await;

    assert!(!alice_sas.is_done());
    assert!(!bob_sas.is_done());

    let contents = alice_sas.confirm().await.unwrap().0;
    assert!(contents.len() == 1);
    let event = request_to_event(alice.user_id(), &contents[0]);

    assert!(alice_sas.is_done());
    assert!(bob_device.is_verified());

    let alice_device =
        bob.get_device(alice.user_id(), alice.device_id(), None).await.unwrap().unwrap();

    assert!(!alice_device.is_verified());
    bob.handle_verification_event(&event).await;
    assert!(bob_sas.is_done());
    assert!(alice_device.is_verified());
}

#[async_test]
async fn test_interactive_verification_started_from_request() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    // ----------------------------------------------------------------------------
    // On Alice's device:
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();

    assert!(!bob_device.is_verified());

    // Alice sends a verification request with her desired methods to Bob
    let (alice_ver_req, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);

    // ----------------------------------------------------------------------------
    // On Bobs's device:
    let event = request_to_event(alice.user_id(), &request);
    bob.handle_verification_event(&event).await;
    let flow_id = alice_ver_req.flow_id().as_str();

    let verification_request = bob.get_verification_request(alice.user_id(), flow_id).unwrap();

    // Bob accepts the request, sending a Ready request
    let accept_request =
        verification_request.accept_with_methods(vec![VerificationMethod::SasV1]).unwrap();
    // And also immediately sends a start request
    let (_, start_request_from_bob) = verification_request.start_sas().await.unwrap().unwrap();

    // ----------------------------------------------------------------------------
    // On Alice's device:

    // Alice receives the Ready
    let event = request_to_event(bob.user_id(), &accept_request);
    alice.handle_verification_event(&event).await;

    let verification_request = alice.get_verification_request(bob.user_id(), flow_id).unwrap();

    // And also immediately sends a start request
    let (alice_sas, start_request_from_alice) =
        verification_request.start_sas().await.unwrap().unwrap();

    // Now alice receives Bob's start:
    let event = request_to_event(bob.user_id(), &start_request_from_bob);
    alice.handle_verification_event(&event).await;

    // Since Alice's user id is lexicographically smaller than Bob's, Alice does not
    // do anything with the request, however.
    assert!(alice.user_id() < bob.user_id());

    // ----------------------------------------------------------------------------
    // On Bob's device:

    // Bob receives Alice's start:
    let event = request_to_event(alice.user_id(), &start_request_from_alice);
    bob.handle_verification_event(&event).await;

    let bob_sas = bob
        .get_verification(alice.user_id(), alice_sas.flow_id().as_str())
        .unwrap()
        .sas_v1()
        .unwrap();

    assert!(alice_sas.emoji().is_none());
    assert!(bob_sas.emoji().is_none());

    // ... and accepts it
    let event = bob_sas.accept().map(|r| request_to_event(bob.user_id(), &r)).unwrap();

    // ----------------------------------------------------------------------------
    // On Alice's device:

    // Alice receives the Accept request:
    alice.handle_verification_event(&event).await;

    // Alice sends a key
    let msgs = alice.inner.verification_machine.outgoing_messages();
    assert!(msgs.len() == 1);
    let msg = &msgs[0];
    let event = outgoing_request_to_event(alice.user_id(), msg);
    alice.inner.verification_machine.mark_request_as_sent(&msg.request_id);

    // ----------------------------------------------------------------------------
    // On Bob's device:

    // And bob receive's it:
    bob.handle_verification_event(&event).await;

    // Now bob sends a key
    let msgs = bob.inner.verification_machine.outgoing_messages();
    assert!(msgs.len() == 1);
    let msg = &msgs[0];
    let event = outgoing_request_to_event(bob.user_id(), msg);
    bob.inner.verification_machine.mark_request_as_sent(&msg.request_id);

    // ----------------------------------------------------------------------------
    // On Alice's device:

    // And alice receives it
    alice.handle_verification_event(&event).await;

    // As a result, both devices now can show emojis/decimals
    assert!(alice_sas.emoji().is_some());
    assert!(bob_sas.emoji().is_some());

    // ----------------------------------------------------------------------------
    // On Bob's device:

    assert_eq!(alice_sas.emoji(), bob_sas.emoji());
    assert_eq!(alice_sas.decimals(), bob_sas.decimals());

    // Bob first confirms that the emojis match and sends the MAC...
    let contents = bob_sas.confirm().await.unwrap().0;
    assert!(contents.len() == 1);
    let event = request_to_event(bob.user_id(), &contents[0]);

    // ----------------------------------------------------------------------------
    // On Alice's device:

    // ...which alice receives
    alice.handle_verification_event(&event).await;

    assert!(!alice_sas.is_done());
    assert!(!bob_sas.is_done());

    // Now alice confirms that the emojis match and sends...
    let contents = alice_sas.confirm().await.unwrap().0;
    assert!(contents.len() == 2);
    // ... her own MAC...
    let event_mac = request_to_event(alice.user_id(), &contents[0]);
    // ... and a Done message
    let event_done = request_to_event(alice.user_id(), &contents[1]);

    // ----------------------------------------------------------------------------
    // On Bob's device:

    // Bob receives the MAC message
    bob.handle_verification_event(&event_mac).await;

    // Bob verifies that the MAC is valid and also sends a "done" message.
    let msgs = bob.inner.verification_machine.outgoing_messages();
    eprintln!("{msgs:?}");
    assert!(msgs.len() == 1);
    let event = msgs.first().map(|r| outgoing_request_to_event(bob.user_id(), r)).unwrap();

    let alice_device =
        bob.get_device(alice.user_id(), alice.device_id(), None).await.unwrap().unwrap();

    assert!(!bob_sas.is_done());
    assert!(!alice_device.is_verified());
    // And Bob receives the Done message of alice.
    bob.handle_verification_event(&event_done).await;

    assert!(bob_sas.is_done());
    assert!(alice_device.is_verified());

    // ----------------------------------------------------------------------------
    // On Alice's device:

    assert!(!alice_sas.is_done());
    assert!(!bob_device.is_verified());
    // Alices receives the done message
    eprintln!("{event:?}");
    alice.handle_verification_event(&event).await;

    assert!(alice_sas.is_done());
    assert!(bob_device.is_verified());
}

#[async_test]
async fn test_unknown_sender_verification_request_is_recovered_after_key_query() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();

    bob.handle_verification_event(&event).await;
    bob.handle_verification_event(&event).await;
    assert!(
        bob.get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
            .is_none(),
        "an unknown sender must not create a verification request before its device keys arrive"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    assert_eq!(key_queries.len(), 1, "duplicate requests must coalesce into one key query");
    let (query_id, query) = key_queries.pop_first().unwrap();
    assert_eq!(query.device_keys.len(), 1);
    assert!(query.device_keys.contains_key(alice.user_id()));

    let missing_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {},
        },
        "failures": {},
    }));
    bob.receive_keys_query_response(&query_id, &missing_response).await.unwrap();
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "a response that still lacks the sender device must not publish a recovered request"
    );

    bob.handle_verification_event(&event).await;
    let subsequent_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    assert!(
        subsequent_queries.values().all(|query| !query.device_keys.contains_key(alice.user_id())),
        "a duplicate must not refresh or schedule another sender key query after a missing response"
    );
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "a duplicate of a still-pending request must not publish a notification"
    );

    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    bob.receive_keys_query_response(&TransactionId::new(), &response).await.unwrap();

    let recovered = bob
        .get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
        .expect("the pending request should be replayed after the sender device becomes known");
    assert!(matches!(
        recovered.state(),
        crate::verification::VerificationRequestState::Requested { .. }
    ));
    let notification = recovered_requests
        .next()
        .await
        .expect("successful materialization must publish the recovered request handle");
    assert_eq!(notification.flow_id(), outgoing_request.flow_id());
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);

    bob.handle_verification_event(&event).await;
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "an already-materialized duplicate must not publish a second notification"
    );
}

#[async_test]
async fn test_failed_key_query_response_claims_covered_pending_sender() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    bob.handle_verification_event(&event).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = key_queries.pop_first().expect("unknown sender schedules a key query");
    assert!(query.device_keys.contains_key(alice.user_id()));

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .verification_machine
        .set_replay_after_claim_pause_for_test(Arc::clone(&entered), Arc::clone(&release));
    let failed_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {},
        "failures": {
            alice.user_id().server_name(): {
                "errcode": "M_RESOURCE_LIMIT_EXCEEDED",
                "error": "synthetic key-query failure",
            }
        },
    }));
    let response_machine = bob.clone();
    let response_task = tokio::spawn(async move {
        response_machine.receive_keys_query_response(&query_id, &failed_response).await
    });

    tokio::time::timeout(Duration::from_millis(100), entered.wait())
        .await
        .expect("the failed response must claim its request-metadata users before replay");
    release.wait().await;
    response_task.await.expect("failed response task").expect("failure map is a valid response");
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
}

#[async_test]
async fn test_cancelled_key_query_response_after_store_commit_reschedules_pending_sender() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    bob.handle_verification_event(&event).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, _) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {},
        },
        "failures": {},
    }));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .identity_manager
        .set_post_key_query_commit_pause_for_test(Arc::clone(&entered), release);

    let response_machine = bob.clone();
    let response_task = tokio::spawn(async move {
        response_machine.receive_keys_query_response(&query_id, &response).await
    });
    entered.wait().await;
    response_task.abort();
    assert!(response_task.await.expect_err("response task is cancelled").is_cancelled());

    let retried = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    assert!(
        matches!(retried, VerificationEventResult::UnknownSenderQueued { query_needed: true, .. }),
        "cancelling after the durable key-query commit must release the scheduling obligation"
    );
}

#[async_test]
async fn test_cancelled_key_query_response_after_identity_processing_reuses_original_metadata() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    bob.handle_verification_event(&event).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {},
        },
        "failures": {},
    }));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .identity_manager
        .set_post_key_query_inner_processing_pause_for_test(Arc::clone(&entered), release);

    let response_machine = bob.clone();
    let response_query_id = query_id.clone();
    let response_task = tokio::spawn(async move {
        response_machine.receive_keys_query_response(&response_query_id, &response).await
    });
    entered.wait().await;
    response_task.abort();
    assert!(response_task.await.expect_err("response task is cancelled").is_cancelled());

    assert_eq!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id),
        query.device_keys.keys().cloned().collect(),
        "outer recovery cancellation must preserve the original request coverage"
    );

    let retry_id = bob
        .outgoing_requests()
        .await
        .expect("the outgoing retry scheduler remains usable")
        .into_iter()
        .find_map(|request| match request.request.as_ref() {
            crate::types::requests::AnyOutgoingRequest::KeysQuery(query)
                if query.device_keys.contains_key(alice.user_id()) =>
            {
                Some(request.request_id)
            }
            _ => None,
        })
        .expect("the cancelled response must remain retryable");
    assert_eq!(retry_id, query_id, "retry must reuse the original stable request ID");
}

#[async_test]
async fn test_cancelled_same_id_response_owner_hands_stable_metadata_to_waiter() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    bob.handle_verification_event(&request_to_event(alice.user_id(), &request)).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let response_json = json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    });

    let replay_entered = Arc::new(Barrier::new(2));
    let replay_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(
        Arc::clone(&replay_entered),
        Arc::clone(&replay_release),
    );
    let owner_machine = bob.clone();
    let owner_query_id = query_id.clone();
    let owner_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let owner = tokio::spawn(async move {
        owner_machine.receive_keys_query_response(&owner_query_id, &owner_response).await
    });
    replay_entered.wait().await;

    let waiter_entered = Arc::new(Barrier::new(2));
    let waiter_release = Arc::new(Barrier::new(2));
    bob.inner.identity_manager.set_pre_key_query_response_gate_pause_for_test(
        Arc::clone(&waiter_entered),
        Arc::clone(&waiter_release),
    );
    let duplicate_machine = bob.clone();
    let duplicate_query_id = query_id.clone();
    let duplicate_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let duplicate = tokio::spawn(async move {
        duplicate_machine
            .receive_keys_query_response(&duplicate_query_id, &duplicate_response)
            .await
    });
    waiter_entered.wait().await;
    waiter_release.wait().await;

    owner.abort();
    assert!(owner.await.expect_err("owner response is cancelled").is_cancelled());
    duplicate.await.expect("waiting duplicate task").expect("waiting duplicate succeeds");
    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "the successful same-ID waiter consumes the cancelled owner's stable metadata"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    assert!(query.device_keys.contains_key(alice.user_id()));
}

#[async_test]
async fn test_failed_same_id_response_owner_hands_stable_metadata_to_waiter() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    bob.handle_verification_event(&request_to_event(alice.user_id(), &request)).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let response_json = json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    });

    let replay_entered = Arc::new(Barrier::new(2));
    let replay_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(
        Arc::clone(&replay_entered),
        Arc::clone(&replay_release),
    );
    let owner_machine = bob.clone();
    let owner_query_id = query_id.clone();
    let owner_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let owner = tokio::spawn(async move {
        owner_machine.receive_keys_query_response(&owner_query_id, &owner_response).await
    });
    replay_entered.wait().await;

    let waiter_entered = Arc::new(Barrier::new(2));
    let waiter_release = Arc::new(Barrier::new(2));
    bob.inner.identity_manager.set_pre_key_query_response_gate_pause_for_test(
        Arc::clone(&waiter_entered),
        Arc::clone(&waiter_release),
    );
    let duplicate_machine = bob.clone();
    let duplicate_query_id = query_id.clone();
    let duplicate_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let duplicate = tokio::spawn(async move {
        duplicate_machine
            .receive_keys_query_response(&duplicate_query_id, &duplicate_response)
            .await
    });
    waiter_entered.wait().await;

    bob.inner.verification_machine.fail_pending_replay_after_for_test(0);
    replay_release.wait().await;
    owner.await.expect("owner response task").expect("applied owner response remains successful");

    let retry_id = bob
        .outgoing_requests()
        .await
        .expect("failed owner leaves the retry scheduler usable")
        .into_iter()
        .find_map(|request| match request.request.as_ref() {
            crate::types::requests::AnyOutgoingRequest::KeysQuery(query)
                if query.device_keys.contains_key(alice.user_id()) =>
            {
                Some(request.request_id)
            }
            _ => None,
        })
        .expect("failed owner keeps the original sender query retryable");
    assert_eq!(retry_id, query_id, "same-ID handoff must preserve the stable request ID");

    waiter_release.wait().await;
    duplicate.await.expect("waiting duplicate task").expect("waiting duplicate succeeds");
    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "the successful same-ID waiter consumes the failed owner's stable metadata"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    assert!(query.device_keys.contains_key(alice.user_id()));
}

#[async_test]
async fn test_cancelled_same_id_response_waiter_does_not_block_owner_cleanup() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    bob.handle_verification_event(&request_to_event(alice.user_id(), &request)).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, _) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let response_json = json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    });

    let replay_entered = Arc::new(Barrier::new(2));
    let replay_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(
        Arc::clone(&replay_entered),
        Arc::clone(&replay_release),
    );
    let owner_machine = bob.clone();
    let owner_query_id = query_id.clone();
    let owner_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let owner = tokio::spawn(async move {
        owner_machine.receive_keys_query_response(&owner_query_id, &owner_response).await
    });
    replay_entered.wait().await;

    let waiter_entered = Arc::new(Barrier::new(2));
    let waiter_release = Arc::new(Barrier::new(2));
    bob.inner.identity_manager.set_pre_key_query_response_gate_pause_for_test(
        Arc::clone(&waiter_entered),
        Arc::clone(&waiter_release),
    );
    let duplicate_machine = bob.clone();
    let duplicate_query_id = query_id.clone();
    let duplicate_response = matrix_sdk_test::ruma_response_from_json(&response_json);
    let duplicate = tokio::spawn(async move {
        duplicate_machine
            .receive_keys_query_response(&duplicate_query_id, &duplicate_response)
            .await
    });
    waiter_entered.wait().await;
    waiter_release.wait().await;
    tokio::task::yield_now().await;
    duplicate.abort();
    assert!(duplicate.await.expect_err("waiting duplicate is cancelled").is_cancelled());

    replay_release.wait().await;
    owner.await.expect("owner response task").expect("owner response succeeds");
    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "cancelling a same-ID waiter must not retain unreachable request metadata"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
}

#[async_test]
async fn test_successful_same_id_response_owner_leaves_failure_only_waiter_no_obligation() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    bob.handle_verification_event(&request_to_event(alice.user_id(), &request)).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, _) = key_queries.pop_first().expect("unknown sender schedules a key query");
    let success_json = json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    });
    let failure_only_json = json!({
        "device_keys": {},
        "failures": {
            "example.org": {
                "errcode": "M_RESOURCE_LIMIT_EXCEEDED",
                "error": "retry",
            },
        },
    });

    let replay_entered = Arc::new(Barrier::new(2));
    let replay_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(
        Arc::clone(&replay_entered),
        Arc::clone(&replay_release),
    );
    let owner_machine = bob.clone();
    let owner_query_id = query_id.clone();
    let owner_response = matrix_sdk_test::ruma_response_from_json(&success_json);
    let owner = tokio::spawn(async move {
        owner_machine.receive_keys_query_response(&owner_query_id, &owner_response).await
    });
    replay_entered.wait().await;

    let waiter_entered = Arc::new(Barrier::new(2));
    let waiter_release = Arc::new(Barrier::new(2));
    bob.inner.identity_manager.set_pre_key_query_response_gate_pause_for_test(
        Arc::clone(&waiter_entered),
        Arc::clone(&waiter_release),
    );
    let duplicate_machine = bob.clone();
    let duplicate_query_id = query_id.clone();
    let duplicate_response = matrix_sdk_test::ruma_response_from_json(&failure_only_json);
    let duplicate = tokio::spawn(async move {
        duplicate_machine
            .receive_keys_query_response(&duplicate_query_id, &duplicate_response)
            .await
    });
    waiter_entered.wait().await;

    replay_release.wait().await;
    owner.await.expect("owner response task").expect("owner response succeeds");
    waiter_release.wait().await;
    duplicate.await.expect("waiting duplicate task").expect("failure-only duplicate is applied");

    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "a failure-only waiter must not recreate metadata consumed by the owner"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    let requests = bob.outgoing_requests().await.expect("outgoing requests remain available");
    assert!(
        !requests.iter().any(|request| match request.request.as_ref() {
            crate::types::requests::AnyOutgoingRequest::KeysQuery(query) => {
                query.device_keys.contains_key(alice.user_id())
            }
            _ => false,
        }),
        "a failure-only waiter with no remaining obligation must not reschedule the clean user"
    );
}

#[async_test]
async fn test_failed_response_does_not_steal_newer_same_sender_response_claim() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, first_request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let (second_outgoing, second_request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let first_event = request_to_event(alice.user_id(), &first_request);
    let second_event = request_to_event(alice.user_id(), &second_request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&first_event).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (first_query_id, _) = key_queries.pop_first().expect("first sender key query");
    let missing_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {},
        },
        "failures": {},
    }));
    let first_commit_entered = Arc::new(Barrier::new(2));
    let first_commit_release = Arc::new(Barrier::new(2));
    bob.inner.identity_manager.set_post_key_query_commit_pause_for_test(
        Arc::clone(&first_commit_entered),
        Arc::clone(&first_commit_release),
    );
    let first_machine = bob.clone();
    let first_response = tokio::spawn(async move {
        first_machine.receive_keys_query_response(&first_query_id, &missing_response).await
    });
    first_commit_entered.wait().await;

    bob.handle_verification_event(&second_event).await;
    let second_replay_entered = Arc::new(Barrier::new(2));
    let second_replay_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(
        Arc::clone(&second_replay_entered),
        Arc::clone(&second_replay_release),
    );
    let second_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    let second_machine = bob.clone();
    let second_response = tokio::spawn(async move {
        second_machine.receive_keys_query_response(&TransactionId::new(), &second_response).await
    });
    second_replay_entered.wait().await;

    bob.inner.verification_machine.fail_pending_replay_after_for_test(0);
    first_commit_release.wait().await;
    first_response
        .await
        .expect("first response task")
        .expect("committed response remains successful after replay failure");
    second_replay_release.wait().await;
    second_response.await.expect("second response task").expect("second response succeeds");

    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "the newer publication must remain behind the earlier retryable pending request"
    );
    bob.inner.verification_machine.expire_pending_to_device_requests_for_test();
    bob.inner.verification_machine.garbage_collect();
    let recovered = tokio::time::timeout(Duration::from_millis(100), recovered_requests.next())
        .await
        .expect("expiring the earlier pending request must unblock the retained publication")
        .expect("second flow is published");
    assert_eq!(recovered.flow_id(), second_outgoing.flow_id());
}

#[async_test]
async fn test_overlapping_committed_response_is_replayed_after_older_stale_lookup() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;

    let mut key_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (older_query_id, _) = key_queries.pop_first().expect("older sender key query");
    let lookup_entered = Arc::new(Barrier::new(2));
    let lookup_release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_request_device_lookup_completed_pause_for_test(
        Arc::clone(&lookup_entered),
        Arc::clone(&lookup_release),
    );
    let missing_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {},
        },
        "failures": {},
    }));
    let older_machine = bob.clone();
    let older_response = tokio::spawn(async move {
        older_machine.receive_keys_query_response(&older_query_id, &missing_response).await
    });
    lookup_entered.wait().await;

    let newer_response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    bob.receive_keys_query_response(&TransactionId::new(), &newer_response)
        .await
        .expect("the overlapping newer response commits matching sender keys");

    lookup_release.wait().await;
    older_response.await.expect("older response task").expect("older response succeeds");

    let recovered = tokio::time::timeout(Duration::from_millis(100), recovered_requests.next())
        .await
        .expect("the committed overlapping response must be reevaluated after the stale lookup")
        .expect("the pending request is eventually published");
    assert_eq!(recovered.flow_id(), outgoing_request.flow_id());
    recovered.commit();
}

#[async_test]
async fn test_unknown_sender_scheduling_failure_remains_retryable() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);

    let first = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    assert!(matches!(
        first,
        VerificationEventResult::UnknownSenderQueued { query_needed: true, .. }
    ));

    // Do not acknowledge scheduling, exactly as if `mark_user_as_changed` failed.
    let retry = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    assert!(matches!(
        retry,
        VerificationEventResult::UnknownSenderQueued { query_needed: true, .. }
    ));

    bob.inner.verification_machine.mark_pending_to_device_key_query_scheduled(alice.user_id());
    let coalesced = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    assert!(matches!(
        coalesced,
        VerificationEventResult::UnknownSenderQueued { query_needed: false, .. }
    ));
}

#[async_test]
async fn test_initial_sender_device_store_failure_retains_request_and_schedules_query() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    bob.inner.verification_machine.fail_next_verification_request_device_lookup_for_test();

    bob.handle_verification_event(&event).await;

    assert_eq!(
        bob.inner.verification_machine.pending_to_device_request_count(),
        1,
        "a transient first device-store read failure must retain the original request"
    );
    let queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    assert!(
        queries.values().any(|query| query.device_keys.contains_key(alice.user_id())),
        "the retained request must use the ordinary coalesced sender key-query path"
    );
}

#[async_test]
async fn test_recovered_request_subscription_has_single_owner_replacement_semantics() {
    let (_alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let mut first = bob.subscribe_to_incoming_verification_requests();
    let _replacement = bob.subscribe_to_incoming_verification_requests();

    assert!(
        first.next().await.is_none(),
        "creating a new single-owner subscription must close the previous receiver"
    );
}

#[async_test]
async fn test_recovery_without_active_subscriber_still_materializes_and_clears_pending() {
    for subscribe_then_drop in [false, true] {
        let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
            tests::alice_id(),
            tests::user_id(),
            false,
        )
        .await;

        let alice_device =
            bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
        bob.store()
            .save_changes(Changes {
                devices: DeviceChanges {
                    deleted: vec![alice_device.clone()],
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();
        let bob_device =
            alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
        let (outgoing_request, request) =
            bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
        let event = request_to_event(alice.user_id(), &request);
        let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();

        if subscribe_then_drop {
            drop(bob.subscribe_to_incoming_verification_requests());
        }
        bob.store()
            .save_changes(Changes {
                devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
                ..Default::default()
            })
            .await
            .unwrap();

        bob.inner
            .verification_machine
            .retry_pending_to_device_requests_for_users([alice.user_id()])
            .await
            .expect("an absent or dropped subscriber must not fail key-query recovery");

        assert!(
            bob.get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
                .is_some()
        );
        assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    }
}

#[async_test]
async fn test_closed_recovery_subscriber_preserves_publication_for_later_owner() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let closed_owner = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    drop(closed_owner);

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();

    let mut later_owner = bob.subscribe_to_incoming_verification_requests();
    let recovered =
        later_owner.next().now_or_never().flatten().expect(
            "a later subscriber must receive the publication abandoned by the closed owner",
        );
    assert_eq!(recovered.flow_id(), outgoing_request.flow_id());
    assert!(
        later_owner.next().now_or_never().is_none(),
        "the retained publication must transfer exactly once"
    );
}

#[async_test]
async fn test_polled_recovery_without_application_commit_returns_to_later_owner() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut first_owner = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();

    let uncommitted = first_owner.next().await.expect("the first owner must acquire the delivery");
    assert_eq!(uncommitted.flow_id(), outgoing_request.flow_id());
    drop(uncommitted);
    drop(first_owner);

    let mut later_owner = bob.subscribe_to_incoming_verification_requests();
    let recovered = later_owner
        .next()
        .now_or_never()
        .flatten()
        .expect("dropping an uncommitted delivery must return it to the next owner");
    assert_eq!(recovered.flow_id(), outgoing_request.flow_id());
}

#[async_test]
async fn test_pending_replay_store_failure_retains_request_and_later_recovers() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.inner.verification_machine.fail_pending_replay_after_for_test(0);

    assert!(
        bob.inner
            .verification_machine
            .retry_pending_to_device_requests_for_users([alice.user_id()])
            .await
            .is_err(),
        "the injected get-device/store failure must propagate"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert!(recovered_requests.next().now_or_never().is_none());

    bob.inner.verification_machine.clear_pending_replay_failure_for_test();
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    assert_eq!(recovered_requests.next().await.unwrap().flow_id(), outgoing_request.flow_id());
}

#[async_test]
async fn test_normal_redelivery_materialization_uses_the_same_incoming_request_stream() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.handle_verification_event(&event).await;

    assert!(
        bob.get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
            .is_some()
    );
    assert_eq!(
        bob.inner.verification_machine.pending_to_device_request_count(),
        0,
        "normal raw-event materialization must consume its pending recovery slot"
    );
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    let delivery =
        recovered_requests.next().now_or_never().flatten().expect(
            "normal materialization must publish through the typed incoming-request stream",
        );
    assert_eq!(delivery.flow_id(), outgoing_request.flow_id());
    assert_eq!(
        format!("{delivery:?}"),
        "IncomingVerificationRequestDelivery { .. }",
        "delivery diagnostics must not expose request, account, device, identity-key, or owner data"
    );
    delivery.commit();
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "one materialization must publish one stable delivery"
    );
}

#[async_test]
async fn test_pending_replay_does_not_publish_a_preexisting_cached_request() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    // Materialize through the generic path so the same-flow cache entry exists while the
    // deferred slot remains pending. This models store/device churn without assigning recovery
    // publication ownership to that pending slot.
    bob.inner.verification_machine.receive_any_event(&event).await.unwrap();
    let normal_delivery = recovered_requests
        .next()
        .await
        .expect("normal materialization must use the typed delivery stream");
    normal_delivery.commit();
    let cached_before = bob
        .get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
        .expect("the generic delivery must populate the same-flow cache");

    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();

    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "an already-cached flow was not inserted by recovery and must not be republished"
    );
    let cached_after = bob
        .get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
        .expect("replay must leave the pre-existing stable handle cached");
    assert!(!cached_before.is_cancelled());
    assert!(!cached_after.is_cancelled());
    cached_before.cancel();
    assert!(
        cached_after.is_cancelled(),
        "replay must neither cancel nor replace the cached handle"
    );
}

#[async_test]
async fn test_concurrent_pending_replays_publish_exactly_once_and_share_the_cached_handle() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .verification_machine
        .set_replay_after_claim_pause_for_test(Arc::clone(&entered), Arc::clone(&release));
    let replay_machine = bob.inner.verification_machine.clone();
    let replay_user = alice.user_id().to_owned();
    let first = tokio::spawn(async move {
        replay_machine.retry_pending_to_device_requests_for_users([replay_user.as_ref()]).await
    });
    entered.wait().await;

    tokio::time::timeout(
        Duration::from_millis(100),
        bob.inner
            .verification_machine
            .retry_pending_to_device_requests_for_users([alice.user_id()]),
    )
    .await
    .expect("the losing concurrent response claim must return without waiting")
    .unwrap();
    release.wait().await;
    first.await.unwrap().unwrap();

    let notification = recovered_requests
        .next()
        .await
        .expect("one concurrent replay must publish the recovered request");
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "the losing replay must not publish a duplicate notification"
    );
    let cached = bob
        .get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
        .expect("the recovered request must be cached");
    assert!(!notification.is_cancelled());
    assert!(!cached.is_cancelled());
    notification.cancel();
    assert!(cached.is_cancelled(), "the notification and cache must share one stable handle");
}

#[async_test]
async fn test_raw_redelivery_steals_an_uncommitted_replay_without_duplicate_materialization() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .verification_machine
        .set_replay_after_claim_pause_for_test(entered.clone(), release.clone());
    let replay_machine = bob.inner.verification_machine.clone();
    let replay_user = alice.user_id().to_owned();
    let replay = tokio::spawn(async move {
        replay_machine.retry_pending_to_device_requests_for_users([replay_user.as_ref()]).await
    });
    entered.wait().await;
    let raw = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    let VerificationEventResult::RequestMaterialized(raw) = raw else {
        panic!("raw redelivery must own materialization before replay commit");
    };
    release.wait().await;
    replay.await.unwrap().unwrap();

    let delivery = recovered_requests
        .next()
        .now_or_never()
        .flatten()
        .expect("normal materialization must publish the one stable typed delivery");
    assert_eq!(delivery.flow_id(), outgoing_request.flow_id());
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "the replay whose pending claim was stolen must not publish a duplicate"
    );
    let cached = bob
        .get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
        .expect("raw delivery must cache the request");
    assert!(!raw.is_cancelled());
    assert!(!cached.is_cancelled());
    raw.cancel();
    assert!(cached.is_cancelled(), "raw delivery and cache must share one stable handle");
}

#[async_test]
async fn test_subscriber_replacement_during_publication_reroutes_to_the_current_owner() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut first_owner = bob.subscribe_to_incoming_verification_requests();
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    let uncommitted = first_owner.next().await.expect("the first owner must acquire the lease");
    let mut current_owner = bob.subscribe_to_incoming_verification_requests();
    drop(uncommitted);

    assert!(
        matches!(first_owner.next().now_or_never(), Some(None)),
        "the replaced owner must close after its uncommitted lease is dropped"
    );
    let recovered = current_owner
        .next()
        .await
        .expect("the current sole owner must receive the requeued recovered handle");
    recovered.commit();
}

#[async_test]
async fn test_incoming_request_claim_and_subscriber_replacement_are_linearized_together() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let mut event = request_to_event(alice.user_id(), &request);

    // Claim wins the owner lock first: replacement cannot revoke that active head lease,
    // even when it is created before `next()` returns it to the old subscriber.
    let first_owner = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner
        .verification_machine
        .set_publication_after_claim_pause_for_test(entered.clone(), release.clone());
    let first_poll = tokio::spawn(async move {
        let mut first_owner = first_owner;
        first_owner.next().await
    });
    entered.wait().await;
    let mut replacement = bob.subscribe_to_incoming_verification_requests();
    release.wait().await;
    let first_delivery = first_poll
        .await
        .unwrap()
        .expect("a claim linearized before replacement must retain the active head lease");
    assert!(replacement.next().now_or_never().is_none());
    first_delivery.commit();

    // Replacement wins the owner lock first: the stale generation cannot claim a later head.
    let ToDeviceEvents::KeyVerificationRequest(event) = &mut event else {
        panic!("request helper must return a verification request event");
    };
    event.content.transaction_id = TransactionId::new();
    bob.handle_verification_event(&ToDeviceEvents::KeyVerificationRequest(event.clone())).await;
    let mut stale = bob.subscribe_to_incoming_verification_requests();
    let mut current = bob.subscribe_to_incoming_verification_requests();
    assert!(matches!(stale.next().now_or_never(), Some(None)));
    current.next().await.expect("the current generation must own the unclaimed head").commit();
}

#[async_test]
async fn test_cancelled_recovery_handoff_releases_its_lease_for_retry() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let _ = bob.inner.verification_machine.receive_to_device_event(&event).await.unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    let mut cancelled_owner = bob.subscribe_to_incoming_verification_requests();
    let (claimed_tx, claimed_rx) = oneshot::channel();
    let cancelled_handoff = tokio::spawn(async move {
        let _delivery = cancelled_owner.next().await.expect("the handoff must acquire the lease");
        let _ = claimed_tx.send(());
        std::future::pending::<()>().await;
    });
    claimed_rx.await.expect("the cancelled handoff must first acquire the lease");
    cancelled_handoff.abort();
    assert!(cancelled_handoff.await.unwrap_err().is_cancelled());

    let mut retry_owner = bob.subscribe_to_incoming_verification_requests();
    let notification =
        retry_owner.next().await.expect("a later owner must receive after cancellation");
    assert_eq!(notification.flow_id(), outgoing_request.flow_id());
    notification.commit();
    assert!(
        retry_owner.next().now_or_never().is_none(),
        "the released recovery lease must still commit exactly once"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
}

#[async_test]
async fn test_pending_replay_mid_batch_error_retains_current_and_remaining_fifo_entries() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let ToDeviceEvents::KeyVerificationRequest(mut request_event) = event else {
        panic!("request helper must return a verification request event");
    };
    let mut flows = vec![request_event.content.transaction_id.clone()];
    let first_event = ToDeviceEvents::KeyVerificationRequest(request_event.clone());
    request_event.content.transaction_id = TransactionId::new();
    flows.push(request_event.content.transaction_id.clone());
    let second_event = ToDeviceEvents::KeyVerificationRequest(request_event.clone());
    request_event.content.transaction_id = TransactionId::new();
    flows.push(request_event.content.transaction_id.clone());
    let third_event = ToDeviceEvents::KeyVerificationRequest(request_event);

    for event in [&first_event, &second_event, &third_event] {
        let _ = bob.inner.verification_machine.receive_to_device_event(event).await.unwrap();
    }
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 3);

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.inner.verification_machine.fail_pending_replay_after_for_test(1);

    assert!(
        bob.inner
            .verification_machine
            .retry_pending_to_device_requests_for_users([alice.user_id()])
            .await
            .is_err()
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 2);
    assert!(
        !bob.inner
            .verification_machine
            .has_pending_to_device_request(alice.user_id(), flows[0].as_str())
    );
    assert!(
        bob.inner
            .verification_machine
            .has_pending_to_device_request(alice.user_id(), flows[1].as_str())
    );
    assert!(
        bob.inner
            .verification_machine
            .has_pending_to_device_request(alice.user_id(), flows[2].as_str())
    );

    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.inner.verification_machine.clear_pending_replay_failure_for_test();
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    let already_recovered = recovered_requests.next().await.unwrap();
    assert_eq!(
        already_recovered.flow_id().as_str(),
        flows[0].as_str(),
        "a publication queued before subscription must remain available"
    );
    already_recovered.commit();
    let failed = recovered_requests.next().await.unwrap();
    assert_eq!(
        failed.flow_id().as_str(),
        flows[1].as_str(),
        "the failed entry must retain its original FIFO slot"
    );
    failed.commit();
    let later = recovered_requests.next().await.unwrap();
    assert_eq!(
        later.flow_id().as_str(),
        flows[2].as_str(),
        "later entries must remain behind the failed entry"
    );
    later.commit();
}

#[async_test]
async fn test_applied_key_query_response_is_not_failed_by_pending_replay_and_reschedules_retry() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;

    let mut queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = queries.pop_first().expect("unknown sender must schedule a key query");
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    bob.inner.verification_machine.fail_pending_replay_after_for_test(0);

    bob.receive_keys_query_response(&query_id, &response)
        .await
        .expect("an applied key-query response must not be reclassified as failed by replay");
    assert!(
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().is_some(),
        "the key-query response must remain applied"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert_eq!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id),
        query.device_keys.keys().cloned().collect(),
        "replay failure must preserve the original request coverage"
    );
    let mut retry_queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (retry_id, retry_query) =
        retry_queries.pop_first().expect("transient replay failure must reschedule the sender");
    assert_eq!(retry_id, query_id, "replay failure must reuse the original request ID");
    assert!(retry_query.device_keys.contains_key(alice.user_id()));

    bob.inner.verification_machine.clear_pending_replay_failure_for_test();
    bob.receive_keys_query_response(&retry_id, &response).await.unwrap();
    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "successful outer recovery settlement must consume the request metadata"
    );
    let recovered = recovered_requests.next().await.expect("the rescheduled replay must recover");
    assert_eq!(recovered.flow_id(), outgoing_request.flow_id());
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
}

#[async_test]
async fn test_applied_key_query_survives_post_commit_cache_failure_and_retries_later() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;

    let mut queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = queries.pop_first().expect("unknown sender must schedule a key query");
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    bob.inner.verification_machine.fail_pending_replay_after_for_test(0);
    bob.inner.verification_machine.fail_next_post_key_query_recovery_cache_acquisition_for_test();

    let (device_changes, _) = bob
        .receive_keys_query_response(&query_id, &response)
        .await
        .expect("post-commit recovery failures must not fail an applied key-query response");
    assert_eq!(device_changes.new.len(), 1, "the original applied changes must be returned");
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert_eq!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id),
        query.device_keys.keys().cloned().collect(),
        "post-commit cache failure must preserve the original request coverage"
    );

    bob.inner.verification_machine.clear_pending_replay_failure_for_test();
    let retry = bob
        .outgoing_requests()
        .await
        .expect("the outgoing retry scheduler remains usable")
        .into_iter()
        .find_map(|request| match request.request.as_ref() {
            crate::types::requests::AnyOutgoingRequest::KeysQuery(query)
                if query.device_keys.contains_key(alice.user_id()) =>
            {
                Some(request.request_id)
            }
            _ => None,
        })
        .expect("the retry-needed pending request must schedule a later key query");
    assert_eq!(retry, query_id, "cache failure must reuse the original request ID");

    bob.receive_keys_query_response(&retry, &response).await.unwrap();
    assert!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id).is_empty(),
        "successful retry settlement must consume the request metadata"
    );
    let recovered = recovered_requests.next().await.expect("the later retry must recover");
    assert_eq!(recovered.flow_id(), outgoing_request.flow_id());
    recovered.commit();
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
}

#[async_test]
async fn test_cancelled_post_commit_key_query_replay_remains_schedulable() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    bob.handle_verification_event(&event).await;

    let mut queries = bob.inner.identity_manager.users_for_key_query().await.unwrap();
    let (query_id, query) = queries.pop_first().expect("unknown sender must schedule a key query");
    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    bob.inner.verification_machine.set_replay_after_claim_pause_for_test(entered.clone(), release);
    let response_machine = bob.clone();
    let response_query_id = query_id.clone();
    let response_task = tokio::spawn(async move {
        response_machine.receive_keys_query_response(&response_query_id, &response).await
    });
    entered.wait().await;
    response_task.abort();
    assert!(response_task.await.unwrap_err().is_cancelled());

    assert!(
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().is_some(),
        "the key-query changes must already be committed before the replay pause"
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    assert_eq!(
        bob.inner.identity_manager.users_for_key_query_request(&query_id),
        query.device_keys.keys().cloned().collect(),
        "post-commit cancellation must preserve the original request coverage"
    );
    assert!(
        bob.inner
            .verification_machine
            .pending_to_device_key_query_retry_users()
            .contains(alice.user_id()),
        "cancelling the post-commit replay must make the retained sender schedulable again"
    );
    let retry_id = bob
        .outgoing_requests()
        .await
        .expect("the retry scheduler remains usable")
        .into_iter()
        .find_map(|request| match request.request.as_ref() {
            crate::types::requests::AnyOutgoingRequest::KeysQuery(query)
                if query.device_keys.contains_key(alice.user_id()) =>
            {
                Some(request.request_id)
            }
            _ => None,
        })
        .expect("a later outgoing-request pass must produce the replacement key query");
    assert_eq!(retry_id, query_id, "cancellation must reuse the original request ID");
}

#[async_test]
async fn test_unknown_sender_verification_request_expires_before_key_query_replay() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    let alice_device_keys = alice_device.as_device_keys().to_owned();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (outgoing_request, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let event = request_to_event(alice.user_id(), &request);
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    bob.handle_verification_event(&event).await;
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 1);
    bob.inner.verification_machine.expire_pending_to_device_requests_for_test();

    let response = matrix_sdk_test::ruma_response_from_json(&json!({
        "device_keys": {
            alice.user_id(): {
                alice.device_id(): alice_device_keys,
            },
        },
        "failures": {},
    }));
    bob.receive_keys_query_response(&TransactionId::new(), &response).await.unwrap();

    assert!(
        bob.get_verification_request(alice.user_id(), outgoing_request.flow_id().as_str())
            .is_none()
    );
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    assert!(
        recovered_requests.next().now_or_never().is_none(),
        "an expired request must not publish a recovered-request notification"
    );
}

#[async_test]
async fn test_unknown_sender_verification_request_queue_is_fifo_bounded() {
    let (alice, bob) = get_machine_pair_with_setup_sessions_test_helper(
        tests::alice_id(),
        tests::user_id(),
        false,
    )
    .await;

    let alice_device =
        bob.store().get_device_data(alice.user_id(), alice.device_id()).await.unwrap().unwrap();
    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { deleted: vec![alice_device.clone()], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();

    let bob_device = alice.get_device(bob.user_id(), bob.device_id(), None).await.unwrap().unwrap();
    let (_, request) =
        bob_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
    let mut event = request_to_event(alice.user_id(), &request);
    let ToDeviceEvents::KeyVerificationRequest(event) = &mut event else {
        panic!("request helper must return a verification request event");
    };
    let oldest_flow = event.content.transaction_id.clone();
    let mut recovered_requests = bob.subscribe_to_incoming_verification_requests();
    let mut retained_flows = Vec::new();
    let mut rejected_newest_flow = None;

    for index in 0..33 {
        if index > 0 {
            event.content.transaction_id = TransactionId::new();
        }
        if index < 32 {
            retained_flows.push(event.content.transaction_id.clone());
        } else {
            rejected_newest_flow = Some(event.content.transaction_id.clone());
        }
        bob.handle_verification_event(&ToDeviceEvents::KeyVerificationRequest(event.clone())).await;
    }

    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 32);
    assert!(
        bob.inner
            .verification_machine
            .has_pending_to_device_request(alice.user_id(), oldest_flow.as_str())
    );
    let rejected_newest_flow = rejected_newest_flow.expect("the 33rd flow must be recorded");
    assert!(
        !bob.inner
            .verification_machine
            .has_pending_to_device_request(alice.user_id(), rejected_newest_flow.as_str()),
        "capacity must reject the newest unknown request without evicting the oldest obligation"
    );
    assert_eq!(bob.inner.identity_manager.users_for_key_query().await.unwrap().len(), 1);

    bob.store()
        .save_changes(Changes {
            devices: DeviceChanges { new: vec![alice_device], ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
    bob.inner
        .verification_machine
        .retry_pending_to_device_requests_for_users([alice.user_id()])
        .await
        .unwrap();
    assert_eq!(bob.inner.verification_machine.pending_to_device_request_count(), 0);
    for expected_flow in retained_flows {
        let recovered = recovered_requests
            .next()
            .await
            .expect("the bounded recovery channel must absorb the maximum pending FIFO batch");
        assert_eq!(recovered.flow_id().as_str(), expected_flow.as_str());
        recovered.commit();
    }
    assert!(recovered_requests.next().now_or_never().is_none());
}
