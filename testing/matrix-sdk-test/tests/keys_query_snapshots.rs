//! Snapshot checks for the `/keys/query` fixtures in
//! [`matrix_sdk_test::test_json::keys_query_sets`].
//!
//! These live in an integration test rather than in the fixture functions so
//! that the library does not depend on `insta`. The insta macros expand to
//! `env!("CARGO_MANIFEST_DIR")`, which would tie every crate built on
//! `matrix-sdk-test` to the checkout path and defeat compiler caches.

use insta::{assert_json_snapshot, with_settings};
use matrix_sdk_test::{
    ruma_response_to_json,
    test_json::keys_query_sets::{KeyDistributionTestData, VerificationViolationTestData},
};

#[test]
fn key_distribution_me_keys_query_response() {
    with_settings!({sort_maps => true}, {
        assert_json_snapshot!(
            "KeyDistributionTestData__me_keys_query_response",
            ruma_response_to_json(KeyDistributionTestData::me_keys_query_response()),
        );
    });
}

#[test]
fn key_distribution_dan_keys_query_response() {
    with_settings!({sort_maps => true}, {
        assert_json_snapshot!(
            "KeyDistributionTestData__dan_keys_query_response",
            ruma_response_to_json(KeyDistributionTestData::dan_keys_query_response()),
        );
    });
}

#[test]
fn key_distribution_dan_keys_query_response_device_loggedout() {
    with_settings!({sort_maps => true}, {
        assert_json_snapshot!(
            "KeyDistributionTestData__dan_keys_query_response_device_loggedout",
            ruma_response_to_json(
                KeyDistributionTestData::dan_keys_query_response_device_loggedout()
            ),
        );
    });
}

#[test]
fn verification_violation_own_keys_query_response_1() {
    with_settings!({sort_maps => true}, {
        assert_json_snapshot!(
            "VerificationViolationTestData__own_keys_query_response_1",
            ruma_response_to_json(VerificationViolationTestData::own_keys_query_response_1()),
        );
    });
}
