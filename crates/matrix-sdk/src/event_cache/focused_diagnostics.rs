// Copyright 2026 The Matrix.org Foundation C.I.C.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in, task-scoped timings for event-focused cache construction.
//! Observations contain no Matrix identifiers, content, or error text.

use std::{future::Future, sync::Arc, time::Instant};

/// A synchronous, nonblocking observer of focused-build stages.
pub type FocusedBuildObserver = Arc<dyn Fn(&'static str, &'static str, u64) + Send + Sync>;

tokio::task_local! {
    static OBSERVER: FocusedBuildObserver;
}

/// Observe only work polled inside this future (not unrelated or spawned
/// tasks).
pub async fn observe_focused_build<F: Future>(
    observer: FocusedBuildObserver,
    future: F,
) -> F::Output {
    OBSERVER.scope(observer, future).await
}

pub(crate) struct Stage {
    observer: Option<FocusedBuildObserver>,
    name: &'static str,
    started: Instant,
    outcome: &'static str,
}

impl Stage {
    pub(crate) fn new(name: &'static str) -> Self {
        let observer = OBSERVER.try_with(Arc::clone).ok();
        if let Some(observer) = &observer {
            observer(name, "started", 0);
        }
        Self { observer, name, started: Instant::now(), outcome: "cancelled" }
    }

    pub(crate) fn finish(mut self, success: bool) {
        self.outcome = if success { "succeeded" } else { "failed" };
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer(self.name, self.outcome, self.started.elapsed().as_millis() as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[tokio::test]
    async fn scoped_stages_report_success_failure_and_cancellation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let observer: FocusedBuildObserver = Arc::new(move |stage, outcome, _| {
            captured.lock().unwrap().push((stage, outcome));
        });
        observe_focused_build(observer, async {
            Stage::new("cache_lock").finish(true);
            Stage::new("context").finish(false);
            drop(Stage::new("initialization"));
        })
        .await;
        Stage::new("outside_scope").finish(true);
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ("cache_lock", "started"),
                ("cache_lock", "succeeded"),
                ("context", "started"),
                ("context", "failed"),
                ("initialization", "started"),
                ("initialization", "cancelled"),
            ]
        );
    }

    #[tokio::test]
    async fn dropping_pending_scope_records_cancellation_without_leaking_observer() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let observer: FocusedBuildObserver = Arc::new(move |stage, outcome, _| {
            captured.lock().unwrap().push((stage, outcome));
        });
        {
            let future = observe_focused_build(observer, async {
                let _stage = Stage::new("context");
                std::future::pending::<()>().await;
            });
            tokio::pin!(future);
            assert!(futures_util::poll!(future.as_mut()).is_pending());
            Stage::new("unrelated_task").finish(true);
        }
        assert_eq!(
            *events.lock().unwrap(),
            vec![("context", "started"), ("context", "cancelled"),]
        );
    }
}
