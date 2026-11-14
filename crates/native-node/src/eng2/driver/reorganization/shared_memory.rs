//! Retry only temporary byte contention before any canonical restoration.
use crate::p2p::{Budget, ByteUsage, Reservation, ReserveFailure};
use std::time::{Duration, Instant};

pub(super) const RETRY_INTERVAL: Duration = Duration::from_millis(250);
const WAIT_LIMIT: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Overflow,
    Unavailable,
    Deadline,
}
impl Failure {
    pub(super) fn alarm(self) -> &'static str {
        match self {
            Self::Overflow => "reorganization_shared_byte_budget_overflow",
            Self::Unavailable => "reorganization_shared_byte_budget_unavailable",
            Self::Deadline => "reorganization_shared_byte_budget_wait_expired",
        }
    }
}
struct Waiting {
    started: Instant,
    next: Instant,
}
struct Observation {
    largest_body: usize,
    requested: Option<usize>,
    usage: Option<ByteUsage>,
    outcome: &'static str,
    attempts: u32,
}
#[derive(Default)]
pub(super) struct MemoryAdmission {
    waiting: Option<Waiting>,
    last: Option<Observation>,
}
impl MemoryAdmission {
    pub(super) fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }
    pub(super) fn cancel_wait(&mut self) {
        self.waiting = None;
    }
    pub(super) fn ready_for_retry(&mut self, now: Instant) -> Result<bool, Failure> {
        if let Some(waiting) = &self.waiting {
            if now.duration_since(waiting.started) >= WAIT_LIMIT {
                if let Some(row) = &mut self.last {
                    row.outcome = "wait_expired";
                }
                return Err(Failure::Deadline);
            }
            return Ok(now >= waiting.next);
        }
        Ok(true)
    }
    pub(super) fn diagnostic(&self) -> Option<serde_json::Value> {
        self.last.as_ref().map(|row| serde_json::json!({
            "scope":"logical-shared-byte-admission",
            "waiting":self.is_waiting(),
            "largest_body_bytes":row.largest_body,
            "requested_bytes":row.requested,
            "maximum_bytes":row.usage.map(|usage| usage.maximum),
            "used_bytes_at_attempt":row.usage.map(|usage| usage.used),
            "available_bytes_at_attempt":row.usage.map(|usage| usage.maximum.saturating_sub(usage.used)),
            "outcome":row.outcome,
            "attempts":row.attempts,
            "retry_interval_ms":RETRY_INTERVAL.as_millis() as u64,
            "wait_limit_ms":WAIT_LIMIT.as_millis() as u64,
            "process_rss_measurement":false,
            "ownership_attribution_established":false
        }))
    }
    pub(super) fn try_acquire(
        &mut self,
        budget: &Budget,
        largest_body: usize,
        now: Instant,
    ) -> Result<Option<Reservation>, Failure> {
        let requested = largest_body
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(65536));
        if requested.is_none() {
            self.last = Some(Observation {
                largest_body,
                requested: None,
                usage: None,
                outcome: "overflow",
                attempts: 0,
            });
            return Err(Failure::Overflow);
        }
        if !self.ready_for_retry(now)? {
            return Ok(None);
        }
        let requested = requested.expect("checked replay charge");
        let attempts = self
            .last
            .as_ref()
            .map_or(1, |row| row.attempts.saturating_add(1));
        match budget.reserve_observed(requested) {
            Ok((reservation, usage)) => {
                self.waiting = None;
                self.last = Some(Observation {
                    largest_body,
                    requested: Some(requested),
                    usage: Some(usage),
                    outcome: "reserved",
                    attempts,
                });
                Ok(Some(reservation))
            }
            Err(ReserveFailure::Exhausted(usage)) => {
                let started = self.waiting.as_ref().map_or(now, |waiting| waiting.started);
                self.waiting = Some(Waiting {
                    started,
                    next: now + RETRY_INTERVAL,
                });
                self.last = Some(Observation {
                    largest_body,
                    requested: Some(requested),
                    usage: Some(usage),
                    outcome: "exhausted",
                    attempts,
                });
                Ok(None)
            }
            Err(failure) => {
                let failure = match failure {
                    ReserveFailure::Overflow => Failure::Overflow,
                    _ => Failure::Unavailable,
                };
                self.last = Some(Observation {
                    largest_body,
                    requested: Some(requested),
                    usage: None,
                    outcome: failure.alarm(),
                    attempts,
                });
                Err(failure)
            }
        }
    }
}

#[cfg(test)]
mod tests;
