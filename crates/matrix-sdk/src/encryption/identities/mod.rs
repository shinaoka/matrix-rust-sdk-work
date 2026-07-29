// Copyright 2021 The Matrix.org Foundation C.I.C.
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

//! Cryptographic identities used in Matrix.
//!
//! There are two types of cryptographic identities in Matrix.
//!
//! 1. Devices, which are backed by [device keys], they represent each
//!    individual log in by an E2EE capable Matrix client. We represent devices
//!    using the [`Device`] struct.
//!
//! 2. User identities, which are backed by [cross signing keys]. The user
//!    identity represent a unique E2EE capable identity of any given user. This
//!    identity is generally created and uploaded to the server by the first
//!    E2EE capable client the user logs in with. We represent user identities
//!    using the [`UserIdentity`] struct.
//!
//! A [`Device`] or an [`UserIdentity`] can be used to inspect the public keys
//! of the device/identity, or it can be used to initiate a interactive
//! verification flow. They can also be manually marked as verified.
//!
//! # Examples
//!
//! Verifying a device is pretty straightforward:
//!
//! ```no_run
//! # use matrix_sdk::{Client, ruma::{device_id, user_id}};
//! # use url::Url;
//! # let alice = user_id!("@alice:example.org");
//! # let homeserver = Url::parse("http://example.com").unwrap();
//! # async {
//! # let client = Client::new(homeserver).await.unwrap();
//! let device =
//!     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
//!
//! if let Some(device) = device {
//!     // Let's request the device to be verified.
//!     let verification = device.request_verification().await?;
//!
//!     // Actually this is taking too long.
//!     verification.cancel().await?;
//!
//!     // Let's just mark it as verified.
//!     device.verify().await?;
//! }
//! # anyhow::Ok(()) };
//! ```
//!
//! Verifying a user identity works largely the same:
//!
//! ```no_run
//! # use matrix_sdk::{Client, ruma::user_id};
//! # use url::Url;
//! # let alice = user_id!("@alice:example.org");
//! # let homeserver = Url::parse("http://example.com").unwrap();
//! # async {
//! # let client = Client::new(homeserver).await.unwrap();
//! let user = client.encryption().get_user_identity(alice).await?;
//!
//! if let Some(user) = user {
//!     // Let's request the user to be verified.
//!     let verification = user.request_verification().await?;
//!
//!     // Actually this is taking too long.
//!     verification.cancel().await?;
//!
//!     // Let's just mark it as verified.
//!     user.verify().await?;
//! }
//! # anyhow::Ok(()) };
//! ```
//!
//! [cross signing keys]: https://spec.matrix.org/unstable/client-server-api/#cross-signing
//! [device keys]: https://spec.matrix.org/unstable/client-server-api/#device-keys

use std::collections::BTreeMap;

mod devices;
mod users;

pub use devices::{Device, DeviceUpdates, UserDevices};
pub use matrix_sdk_base::crypto::types::MasterPubkey;
use ruma::api::client::keys::upload_signatures;
pub use users::{IdentityUpdates, UserIdentity};

/// Error for the manual verification step, when we manually sign users or
/// devices.
#[derive(thiserror::Error, Debug)]
pub enum ManualVerifyError {
    /// Error that happens when we try to upload the user or device signature.
    #[error(transparent)]
    Http(#[from] crate::HttpError),
    /// Error that happens when we try to sign the user or device.
    #[error(transparent)]
    Signature(#[from] matrix_sdk_base::crypto::SignatureError),
    /// Error that happens when the homeserver accepts the signature upload
    /// request but rejects one or more contained signatures.
    #[error("signature upload response contained {failure_key_count} failures")]
    SignatureUploadFailures {
        /// Number of target users in the signature upload request.
        signed_target_count: usize,
        /// Number of signed keys in the signature upload request.
        signed_key_count: usize,
        /// Number of users with rejected signatures in the upload response.
        failure_user_count: usize,
        /// Number of rejected signatures in the upload response.
        failure_key_count: usize,
        /// Number of rejected signatures whose errcode is `M_INVALID_SIGNATURE`.
        invalid_signature_count: usize,
        /// Number of rejected signatures with a known non-`M_INVALID_SIGNATURE`
        /// errcode.
        other_failure_count: usize,
        /// Number of rejected signatures whose errcode could not be classified.
        unknown_failure_count: usize,
    },
}

/// Error when requesting a verification.
#[derive(thiserror::Error, Debug)]
pub enum RequestVerificationError {
    /// An ordinary error coming from the SDK, i.e. when we fail to send out a
    /// HTTP request or if there's an error with the storage layer.
    #[error(transparent)]
    Sdk(#[from] crate::Error),
    /// Verifying other users requires having a DM open with them, this error
    /// signals that we didn't have a DM and that we failed to create one.
    #[error("Couldn't create a DM with user {0} where the verification should take place")]
    RoomCreation(ruma::OwnedUserId),
}

fn signature_upload_request_summary(
    request: &upload_signatures::v3::Request,
) -> SignatureUploadRequestSummary {
    SignatureUploadRequestSummary {
        signed_target_count: request.signed_keys.len(),
        signed_key_count: request
            .signed_keys
            .values()
            .map(|signed_keys| signed_keys.iter().count())
            .sum(),
    }
}

fn signature_upload_failure_summary(
    response: &upload_signatures::v3::Response,
) -> SignatureUploadFailureSummary {
    nested_signature_upload_failure_summary(&response.failures, signature_upload_failure_kind)
}

fn signature_upload_error(
    request: SignatureUploadRequestSummary,
    failure: SignatureUploadFailureSummary,
) -> Option<ManualVerifyError> {
    if failure.failure_key_count == 0 {
        return None;
    }

    Some(ManualVerifyError::SignatureUploadFailures {
        signed_target_count: request.signed_target_count,
        signed_key_count: request.signed_key_count,
        failure_user_count: failure.failure_user_count,
        failure_key_count: failure.failure_key_count,
        invalid_signature_count: failure.invalid_signature_count,
        other_failure_count: failure.other_failure_count,
        unknown_failure_count: failure.unknown_failure_count,
    })
}

fn record_signature_upload_failure_details(
    context: &'static str,
    request: SignatureUploadRequestSummary,
    response: &upload_signatures::v3::Response,
) {
    let failure = signature_upload_failure_summary(response);
    if failure.failure_key_count == 0 {
        return;
    }
    for (errcode, count) in signature_upload_failure_errcode_counts(response) {
        eprintln!(
            "[koushi] sdk.signature_upload stage=failures context={} signed_target_count={} signed_key_count={} failure_user_count={} failure_key_count={} invalid_signature_count={} other_failure_count={} unknown_failure_count={} failure_errcode={} failure_errcode_count={}",
            context,
            request.signed_target_count,
            request.signed_key_count,
            failure.failure_user_count,
            failure.failure_key_count,
            failure.invalid_signature_count,
            failure.other_failure_count,
            failure.unknown_failure_count,
            errcode,
            count,
        );
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SignatureUploadRequestSummary {
    signed_target_count: usize,
    signed_key_count: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SignatureUploadFailureSummary {
    failure_user_count: usize,
    failure_key_count: usize,
    invalid_signature_count: usize,
    other_failure_count: usize,
    unknown_failure_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureUploadFailureKind {
    InvalidSignature,
    Other,
    Unknown,
}

fn nested_signature_upload_failure_summary<K1, K2, V>(
    failures: &BTreeMap<K1, BTreeMap<K2, V>>,
    classify: impl Fn(&V) -> SignatureUploadFailureKind,
) -> SignatureUploadFailureSummary {
    let mut summary = SignatureUploadFailureSummary {
        failure_user_count: failures.len(),
        failure_key_count: failures.values().map(|failures| failures.len()).sum(),
        ..SignatureUploadFailureSummary::default()
    };
    for failure in failures.values().flat_map(|failures| failures.values()) {
        match classify(failure) {
            SignatureUploadFailureKind::InvalidSignature => summary.invalid_signature_count += 1,
            SignatureUploadFailureKind::Other => summary.other_failure_count += 1,
            SignatureUploadFailureKind::Unknown => summary.unknown_failure_count += 1,
        }
    }
    summary
}

fn signature_upload_failure_kind(
    failure: &upload_signatures::v3::Failure,
) -> SignatureUploadFailureKind {
    let Ok(value) = serde_json::to_value(failure) else {
        return SignatureUploadFailureKind::Unknown;
    };
    match value.get("errcode").and_then(|errcode| errcode.as_str()) {
        Some("M_INVALID_SIGNATURE") => SignatureUploadFailureKind::InvalidSignature,
        Some(_) => SignatureUploadFailureKind::Other,
        None => SignatureUploadFailureKind::Unknown,
    }
}

fn signature_upload_failure_errcode_counts(
    response: &upload_signatures::v3::Response,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for failure in response.failures.values().flat_map(|failures| failures.values()) {
        let errcode = signature_upload_failure_errcode(failure);
        *counts.entry(errcode).or_insert(0) += 1;
    }
    counts
}

fn signature_upload_failure_errcode(failure: &upload_signatures::v3::Failure) -> String {
    let Ok(value) = serde_json::to_value(failure) else {
        return "SERDE_FAILED".to_owned();
    };
    value
        .get("errcode")
        .and_then(|errcode| errcode.as_str())
        .map(sanitize_signature_upload_errcode)
        .unwrap_or_else(|| "MISSING".to_owned())
}

fn sanitize_signature_upload_errcode(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        .take(80)
        .collect();
    if sanitized.is_empty() { "EMPTY".to_owned() } else { sanitized }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        SignatureUploadFailureKind, SignatureUploadFailureSummary,
        nested_signature_upload_failure_summary,
    };

    #[test]
    fn signature_upload_failures_are_reported() {
        let failures = BTreeMap::from([
            (
                "@alice:example.org",
                BTreeMap::from([("DEVICE", SignatureUploadFailureKind::InvalidSignature)]),
            ),
            (
                "@bob:example.org",
                BTreeMap::from([
                    ("DEVICE1", SignatureUploadFailureKind::Other),
                    ("DEVICE2", SignatureUploadFailureKind::Unknown),
                ]),
            ),
        ]);

        assert_eq!(
            nested_signature_upload_failure_summary(&failures, |failure| *failure),
            SignatureUploadFailureSummary {
                failure_user_count: 2,
                failure_key_count: 3,
                invalid_signature_count: 1,
                other_failure_count: 1,
                unknown_failure_count: 1,
            }
        );
    }
}
