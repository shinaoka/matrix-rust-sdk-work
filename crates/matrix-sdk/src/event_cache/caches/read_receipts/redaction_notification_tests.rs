// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

use super::ReadReceiptsExt as _;
use matrix_sdk_base::read_receipts::ReadReceipts;
use matrix_sdk_test::event_factory::EventFactory;
use ruma::{
    event_id,
    push::{Action, HighlightTweakValue, Tweak},
    room_id, user_id,
};

#[test]
fn redaction_event_does_not_leave_a_notification_after_the_message_is_read() {
    let own = user_id!("@reader:example.invalid");
    let f = EventFactory::new()
        .room(room_id!("!room:example.invalid"))
        .sender(user_id!("@other:example.invalid"));
    let boundary_id = event_id!("$read:example.invalid");
    let boundary = f.text_msg("read message").event_id(boundary_id).into_event();
    let mut redaction = f
        .redaction(event_id!("$deleted:example.invalid"))
        .event_id(event_id!("$redaction:example.invalid"))
        .into_event();
    redaction.set_push_actions(vec![
        Action::Notify,
        Action::SetTweak(Tweak::Highlight(HighlightTweakValue::Yes)),
    ]);
    let mut later =
        f.text_msg("unread message").event_id(event_id!("$later:example.invalid")).into_event();
    later.set_push_actions(vec![Action::Notify]);
    for include_later in [false, true] {
        let mut events = vec![boundary.clone(), redaction.clone()];
        if include_later {
            events.push(later.clone());
        }
        let mut receipts = ReadReceipts::default();
        assert!(receipts.find_and_process_events(boundary_id, own, events.iter()));
        let expected = u64::from(include_later);
        assert_eq!(
            (receipts.num_unread, receipts.num_notifications, receipts.num_mentions),
            (expected, expected, 0)
        );
        // A receipt on the redaction itself is still a valid ordering boundary.
        assert!(receipts.find_and_process_events(
            event_id!("$redaction:example.invalid"),
            own,
            events.iter()
        ));
        assert_eq!(
            (receipts.num_unread, receipts.num_notifications, receipts.num_mentions),
            (expected, expected, 0)
        );
    }
}
