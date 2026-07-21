use matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent;

// Keep this exhaustive: downstream crates could match every variant before the
// verification-delivery fix, so adding an SDK-internal dispatch marker here is
// a source-breaking public API change.
fn classify_original_variant(event: &ProcessedToDeviceEvent) -> &'static str {
    match event {
        ProcessedToDeviceEvent::Decrypted { .. } => "decrypted",
        ProcessedToDeviceEvent::UnableToDecrypt { .. } => "unable_to_decrypt",
        ProcessedToDeviceEvent::PlainText(_) => "plain_text",
        ProcessedToDeviceEvent::Invalid(_) => "invalid",
    }
}

#[test]
fn original_processed_to_device_event_variants_remain_exhaustive() {
    let classify: fn(&ProcessedToDeviceEvent) -> &'static str = classify_original_variant;
    let _ = classify;
}
