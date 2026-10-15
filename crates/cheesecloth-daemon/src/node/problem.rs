//! Failures of work that runs again and again, such as the acceptors check:
//! logged when they start or change and when they end, and shown in
//! `cheesecloth status` meanwhile, so that a lasting failure is seen but
//! doesn't fill the log.

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{info, warn};

/// The current failure of one piece of repeated work, if any. The one rule
/// for when a lasting failure is logged. `Problem` adds a lock and the
/// logging; code that keeps its failures behind its own lock, and logs them
/// with its own fields, uses this directly.
#[derive(Clone, Debug, Default)]
pub struct Failure {
    /// The failure's message without its causes (to notice a change), and
    /// with them (to show).
    current: Option<(String, String)>,
}

/// What `Failure::record` found, for the caller to log.
#[derive(Debug, PartialEq, Eq)]
pub enum Noted {
    /// The failure started, or its message changed.
    Started,
    /// The work succeeded after failing.
    Ended,
    /// Nothing new: still working, or the same failure.
    Same,
}

impl Failure {
    /// Records the outcome of one run. A failure is new when it starts, and
    /// when its message changes. Its causes are not compared: they often
    /// differ from one run to the next.
    pub fn record(&mut self, result: Result<()>) -> Noted {
        match result {
            Ok(()) => {
                if self.current.take().is_some() {
                    Noted::Ended
                } else {
                    Noted::Same
                }
            }
            Err(e) => {
                let summary = e.to_string();
                let full = format!("{e:#}");
                let new = self.current.as_ref().is_none_or(|(s, _)| *s != summary);
                self.current = Some((summary, full));
                if new { Noted::Started } else { Noted::Same }
            }
        }
    }

    /// The failure's message with its causes, while it lasts.
    pub fn message(&self) -> Option<&str> {
        self.current.as_ref().map(|(_, full)| full.as_str())
    }
}

/// The current failure of one repeated task, if any.
pub struct Problem {
    /// What the task does, for messages.
    what: &'static str,
    current: Mutex<Failure>,
}

impl Problem {
    pub fn new(what: &'static str) -> Self {
        Problem {
            what,
            current: Mutex::default(),
        }
    }

    /// Records the outcome of one run, logging it when it's new (see
    /// `Failure::record`).
    pub fn record(&self, result: Result<()>) {
        let mut current = self.current.lock();
        match current.record(result) {
            Noted::Started => {
                let full = current.message().expect("a failure was just recorded");
                warn!("{}: {full}", self.what);
            }
            Noted::Ended => info!("{}: working again", self.what),
            Noted::Same => {}
        }
    }

    /// The failure, as a status warning, while it lasts.
    pub fn warning(&self) -> Option<String> {
        let current = self.current.lock();
        current
            .message()
            .map(|full| format!("{}: {full}", self.what))
    }
}

#[cfg(test)]
mod tests;
