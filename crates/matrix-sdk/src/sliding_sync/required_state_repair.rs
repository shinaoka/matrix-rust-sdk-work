//! Bounded compatibility repair for selected canonical state omitted by sync.
//!
//! Runs inside the existing uncancellable response owner, with its position
//! guard held, before acquiring the global state-store lock. Never promotes
//! timeline state into current state; the server supplies a fresh full event.
use std::{collections::BTreeSet, time::Duration};

use futures_util::{StreamExt, stream};
use matrix_sdk_base::RequestedRequiredStates;
use ruma::{
    OwnedRoomId,
    api::client::{
        state::get_state_event_for_key::v3::{Request, StateEventFormat},
        sync::sync_events::v5,
    },
    events::{AnyStateEvent, AnySyncStateEvent, StateEvent, StateEventType},
    serde::Raw,
};

use crate::{Client, RoomState, config::RequestConfig};

const MAX_REPAIRS: usize = 8;
const CONCURRENCY: usize = 2;
const BUDGET: Duration = Duration::from_secs(2);
const MAX_EVENT_BYTES: usize = 256 * 1024;

struct Candidate {
    room: OwnedRoomId,
    kind: StateEventType,
}

fn has_pair<T>(event: &Raw<T>, kind: &StateEventType) -> bool {
    event.get_field::<StateEventType>("type").ok().flatten().as_ref() == Some(kind)
        && event.get_field::<String>("state_key").ok().flatten().as_deref() == Some("")
}

fn candidates(
    client: &Client,
    requested: &RequestedRequiredStates,
    explicit: &BTreeSet<OwnedRoomId>,
    response: &v5::Response,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (room, update) in &response.rooms {
        let own_membership = |event: &Raw<_>| {
            let value = event.deserialize_as_unchecked::<serde_json::Value>().ok()?;
            (value["type"] == "m.room.member"
                && value["state_key"].as_str() == client.user_id().map(|id| id.as_str()))
            .then(|| value["content"]["membership"].as_str().map(str::to_owned))
            .flatten()
        };
        let membership =
            update.required_state.iter().rev().find_map(own_membership).or_else(|| {
                update
                    .timeline
                    .iter()
                    .rev()
                    .find_map(|event| own_membership(event.cast_ref_unchecked()))
            });
        if membership.is_some_and(|membership| membership != "join")
            || !client.get_room(room).is_some_and(|room| room.state() == RoomState::Joined)
        {
            continue;
        }
        for kind in [StateEventType::RoomTopic, StateEventType::RoomPowerLevels] {
            let selected = requested.for_room(room).iter().any(|(selected, key)| {
                (selected == &kind || selected.to_string() == "*") && (key.is_empty() || key == "*")
            });
            if selected
                && !update.required_state.iter().any(|event| has_pair(event, &kind))
                && update.timeline.iter().any(|event| has_pair(event, &kind))
            {
                candidates.push(Candidate { room: room.clone(), kind });
                candidates.sort_by(|a, b| {
                    (!explicit.contains(&a.room), &a.room, &a.kind).cmp(&(
                        !explicit.contains(&b.room),
                        &b.room,
                        &b.kind,
                    ))
                });
                candidates.truncate(MAX_REPAIRS);
            }
        }
    }
    candidates
}

fn validated(raw: Raw<AnyStateEvent>, candidate: &Candidate) -> Option<Raw<AnySyncStateEvent>> {
    if raw.json().get().len() > MAX_EVENT_BYTES {
        return None;
    }
    let event = raw.deserialize().ok()?;
    if event.room_id() != candidate.room {
        return None;
    }
    let valid = matches!(
        (&candidate.kind, event),
        (StateEventType::RoomTopic, AnyStateEvent::RoomTopic(StateEvent::Original(_)))
            | (
                StateEventType::RoomPowerLevels,
                AnyStateEvent::RoomPowerLevels(StateEvent::Original(_))
            )
    );
    valid.then(|| raw.cast())
}

pub(super) async fn repair(
    client: &Client,
    requested: &RequestedRequiredStates,
    explicit: &BTreeSet<OwnedRoomId>,
    response: &mut v5::Response,
) {
    let candidates = candidates(client, requested, explicit, response);
    let deadline = tokio::time::Instant::now() + BUDGET;
    let mut repairs = stream::iter(candidates)
        .map(|candidate| async move {
            let mut request =
                Request::new(candidate.room.clone(), candidate.kind.clone(), String::new());
            request.format = StateEventFormat::Event;
            // Unlike SendRequest, send_inner never refreshes authentication or
            // repeats a GET on M_UNKNOWN_TOKEN. This repair has no auth
            // authority.
            let raw = client
                .send_inner(
                    request,
                    Some(RequestConfig::new().disable_retry().timeout(BUDGET)),
                    Default::default(),
                )
                .await
                .ok()
                .and_then(|response| validated(response.into_event(), &candidate));
            (candidate, raw)
        })
        .buffer_unordered(CONCURRENCY);
    while let Ok(Some((candidate, raw))) = tokio::time::timeout_at(deadline, repairs.next()).await {
        let Some(raw) = raw else {
            continue;
        };
        if client.get_room(&candidate.room).is_some_and(|room| room.state() == RoomState::Joined)
            && let Some(update) = response.rooms.get_mut(&candidate.room)
            && !update.required_state.iter().any(|event| has_pair(event, &candidate.kind))
        {
            update.required_state.push(raw);
        }
    }
}

#[cfg(test)]
mod tests;
