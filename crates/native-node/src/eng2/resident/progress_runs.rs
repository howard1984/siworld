//! Bounded history of event-time qualified body-byte growth.
//!
//! The canonical owner publishes every eligibility transition. Download workers
//! may report progress against a published epoch, but cannot create an epoch.
use crate::wire::Hash;
use serde_json::{Value, json};
use siworld_core::pow::Work;
use std::{collections::VecDeque, sync::Mutex};

const MAX_RUNS: usize = 16;
const MAX_BYTES: usize = 4 * 1024;
const FRESH_NS: u64 = 5_000_000_000;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OwnerContext {
    pub state_epoch: u64,
    pub canonical_height: u64,
    pub canonical_id: Hash,
    pub canonical_work: Work,
    /// False during errors, recovery, or unavailable canonical state.
    pub eligible: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub id: Hash,
    pub sequence: u64,
    pub height: u64,
    pub work: Work,
    pub attempt_index: usize,
}

pub(crate) struct Token {
    owner: OwnerContext,
    candidate: Candidate,
}

struct Active {
    owner: OwnerContext,
    candidate: Candidate,
    id: u64,
    start: u64,
    last: u64,
    first_bytes: u64,
    last_bytes: u64,
}

struct Inner {
    owner: Option<OwnerContext>,
    owner_epoch: u64,
    boot: Option<String>,
    sequence: u64,
    next_id: u64,
    dropped: u64,
    retained_from: u64,
    active: Vec<Active>,
    records: VecDeque<Value>,
}

pub(crate) struct Recorder(Mutex<Inner>);

impl Default for Recorder {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            owner: None,
            owner_epoch: 0,
            boot: None,
            sequence: 0,
            next_id: 0,
            dropped: 0,
            retained_from: 1,
            active: Vec::new(),
            records: VecDeque::new(),
        }))
    }
}

impl Recorder {
    /// Called by the canonical owner, never by a download worker. Any change
    /// requires a strictly newer epoch; malformed publications fail closed.
    pub(crate) fn publish(&self, owner: OwnerContext) {
        let Ok(mut inner) = self.0.lock() else { return };
        if inner.owner.as_ref() == Some(&owner) {
            return;
        }
        inner.active.clear();
        if owner.state_epoch <= inner.owner_epoch {
            inner.owner = None;
        } else {
            inner.owner_epoch = owner.state_epoch;
            inner.owner = Some(owner);
        }
    }

    /// Read immediately before the progress callback. Only already verified
    /// header contexts may supply Candidate values.
    pub(crate) fn token(&self, candidate: Candidate) -> Option<Token> {
        let inner = self.0.lock().ok()?;
        let owner = inner.owner.as_ref()?;
        let lag = candidate.height.checked_sub(owner.canonical_height)?;
        if !owner.eligible || lag > 1 || candidate.work <= owner.canonical_work {
            return None;
        }
        Some(Token {
            owner: owner.clone(),
            candidate,
        })
    }

    /// Read the owner again after the callback. Neither repeated byte counts
    /// nor status reads extend an interval. Unsupported clocks produce no run.
    pub(crate) fn received(&self, token: Token, bytes: usize, total: usize) {
        let Some((now, boot)) = super::progress_clock::stamp() else {
            return;
        };
        self.received_at(token, bytes, total, now, boot);
    }

    fn received_at(&self, token: Token, bytes: usize, total: usize, now: u64, boot: String) {
        if bytes == 0 || bytes > total {
            return;
        }
        let Ok(mut inner) = self.0.lock() else { return };
        if inner.owner.as_ref() != Some(&token.owner) {
            return;
        }
        if inner.boot.as_ref().is_some_and(|old| old != &boot) {
            inner.active.clear();
            inner.records.clear();
            inner.dropped = inner.dropped.saturating_add(1);
            inner.retained_from = inner.sequence.saturating_add(1);
        }
        inner.boot = Some(boot);
        let key =
            |active: &Active| active.candidate == token.candidate && active.owner == token.owner;
        if let Some(index) = inner.active.iter().position(key) {
            let previous = &inner.active[index];
            if now < previous.last || now - previous.last > FRESH_NS {
                inner.active.remove(index);
            } else if bytes as u64 <= previous.last_bytes {
                return;
            } else {
                let Some(sequence) = inner.sequence.checked_add(1) else {
                    inner.active.clear();
                    inner.owner = None;
                    return;
                };
                inner.sequence = sequence;
                let active = &mut inner.active[index];
                active.last = now;
                active.last_bytes = bytes as u64;
                let id = active.id;
                let record = record(active, sequence);
                if let Some(position) = inner.records.iter().position(|value| value["id"] == id) {
                    inner.records.remove(position);
                }
                // Revision order is also eviction order. Updating an older
                // active run must not put a high revision before retained low
                // revisions and move the loss cursor past surviving records.
                inner.records.push_back(record);
                trim(&mut inner);
                return;
            }
        }
        // A single observation is retained only as a pending start. It cannot
        // establish duration until a second strict growth event arrives.
        if inner.active.len() >= 4 {
            return;
        }
        let Some(id) = inner.next_id.checked_add(1) else {
            inner.owner = None;
            return;
        };
        inner.next_id = id;
        inner.active.push(Active {
            owner: token.owner,
            candidate: token.candidate,
            id,
            start: now,
            last: now,
            first_bytes: bytes as u64,
            last_bytes: bytes as u64,
        });
    }

    pub(crate) fn end(&self, candidate_id: Hash, attempt_index: usize) {
        if let Ok(mut inner) = self.0.lock() {
            inner.active.retain(|active| {
                active.candidate.id != candidate_id
                    || active.candidate.attempt_index != attempt_index
            });
        }
    }

    pub(crate) fn snapshot(&self) -> Value {
        let Ok(inner) = self.0.lock() else {
            return Value::Null;
        };
        snapshot(&inner)
    }
}

fn record(active: &Active, sequence: u64) -> Value {
    json!({
        "sequence":sequence,"id":active.id,"state_epoch":active.owner.state_epoch,
        "candidate_id":crate::local::hex(&active.candidate.id),"candidate_sequence":active.candidate.sequence,
        "canonical_height":active.owner.canonical_height,"canonical_id":crate::local::hex(&active.owner.canonical_id),
        "canonical_work":active.owner.canonical_work.to_string(),
        "candidate_height":active.candidate.height,"candidate_work":active.candidate.work.to_string(),
        "lag_blocks":active.candidate.height-active.owner.canonical_height,"attempt_index":active.candidate.attempt_index,
        "start_ns":active.start.to_string(),"end_ns":active.last.to_string(),
        "first_bytes":active.first_bytes,"last_bytes":active.last_bytes,
    })
}

fn snapshot(inner: &Inner) -> Value {
    let Some(boot) = &inner.boot else {
        return Value::Null;
    };
    json!({"version":1,"clock":"linux_clock_monotonic","boot_id_sha256":boot,
        "sequence":inner.sequence,"retained_from_sequence":inner.retained_from,
        "dropped_records":inner.dropped,"runs":inner.records})
}

fn trim(inner: &mut Inner) {
    while inner.records.len() > MAX_RUNS
        || serde_json::to_vec(&snapshot(inner)).map_or(true, |bytes| bytes.len() > MAX_BYTES)
    {
        let Some(record) = inner.records.pop_front() else {
            break;
        };
        let removed_id = record["id"].as_u64().unwrap_or(0);
        inner.active.retain(|active| active.id != removed_id);
        inner.dropped = inner.dropped.saturating_add(1);
        inner.retained_from = inner
            .retained_from
            .max(record["sequence"].as_u64().unwrap_or(0).saturating_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(epoch: u64) -> OwnerContext {
        OwnerContext {
            state_epoch: epoch,
            canonical_height: 10,
            canonical_id: [1; 32],
            canonical_work: Work::zero(),
            eligible: true,
        }
    }
    fn candidate(attempt: usize) -> Candidate {
        Candidate {
            id: [2; 32],
            sequence: 7,
            height: 11,
            work: siworld_core::pow::block_work(&[255; 32]),
            attempt_index: attempt,
        }
    }
    fn event(recorder: &Recorder, attempt: usize, bytes: usize, now: u64) {
        recorder.received_at(
            recorder.token(candidate(attempt)).unwrap(),
            bytes,
            10_000,
            now,
            "11".repeat(32),
        );
    }
    #[test]
    fn runs_require_two_growth_events_and_never_extend_to_snapshot_time() {
        let recorder = Recorder::default();
        recorder.publish(owner(1));
        event(&recorder, 1, 10, 100);
        assert_eq!(recorder.snapshot()["runs"].as_array().unwrap().len(), 0);
        event(&recorder, 1, 10, 200);
        event(&recorder, 1, 20, 300);
        let value = recorder.snapshot();
        assert_eq!(value["runs"][0]["start_ns"], "100");
        assert_eq!(value["runs"][0]["end_ns"], "300");
        assert_eq!(value["sequence"], 1);
        assert_eq!(recorder.snapshot(), value);
        event(&recorder, 1, 30, 400);
        let next = recorder.snapshot();
        assert_eq!(next["runs"][0]["id"], value["runs"][0]["id"]);
        assert_eq!(next["runs"][0]["start_ns"], "100");
        assert_eq!(next["sequence"], 2);
    }
    #[test]
    fn epoch_races_errors_cancellation_and_stale_gaps_cannot_bridge_runs() {
        let recorder = Recorder::default();
        recorder.publish(owner(1));
        event(&recorder, 1, 10, 100);
        event(&recorder, 1, 20, 200);
        let stale = recorder.token(candidate(1)).unwrap();
        recorder.publish(owner(2));
        recorder.received_at(stale, 30, 10_000, 300, "11".repeat(32));
        event(&recorder, 1, 40, 400);
        event(&recorder, 1, 50, 500);
        recorder.end([2; 32], 1);
        event(&recorder, 1, 60, 600);
        event(&recorder, 1, 70, 700);
        event(&recorder, 1, 80, FRESH_NS + 701);
        event(&recorder, 1, 90, FRESH_NS + 800);
        let value = recorder.snapshot();
        let runs = value["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 4);
        assert_eq!(runs[0]["end_ns"], "200");
        assert_eq!(runs[1]["state_epoch"], 2);
        let mut error = owner(3);
        error.eligible = false;
        recorder.publish(error);
        assert!(recorder.token(candidate(1)).is_none());
        recorder.publish(owner(4));
        event(&recorder, 1, 100, FRESH_NS + 900);
        assert_eq!(recorder.snapshot()["runs"].as_array().unwrap().len(), 4);
    }
    #[test]
    fn retained_history_is_bounded_and_cursor_losses_are_explicit() {
        let recorder = Recorder::default();
        recorder.publish(owner(1));
        for attempt in 1..=30 {
            event(&recorder, attempt, 10, attempt as u64 * 100);
            event(&recorder, attempt, 20, attempt as u64 * 100 + 1);
            recorder.end([2; 32], attempt);
        }
        let value = recorder.snapshot();
        assert!(value["runs"].as_array().unwrap().len() <= MAX_RUNS);
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_BYTES);
        assert!(value["dropped_records"].as_u64().unwrap() > 0);
        assert!(value["retained_from_sequence"].as_u64().unwrap() > 1);
    }
    #[test]
    fn updating_an_old_active_run_preserves_revision_order_through_eviction() {
        let recorder = Recorder::default();
        recorder.publish(owner(1));
        event(&recorder, 1, 10, 100);
        event(&recorder, 1, 20, 200);
        for attempt in 2..=8 {
            event(&recorder, attempt, 10, attempt as u64 * 100);
            event(&recorder, attempt, 20, attempt as u64 * 100 + 1);
            recorder.end([2; 32], attempt);
        }
        event(&recorder, 1, 30, 2000);
        for attempt in 9..=30 {
            event(&recorder, attempt, 10, attempt as u64 * 100);
            event(&recorder, attempt, 20, attempt as u64 * 100 + 1);
            recorder.end([2; 32], attempt);
            let value = recorder.snapshot();
            let records = value["runs"].as_array().unwrap();
            let cursor = value["retained_from_sequence"].as_u64().unwrap();
            assert!(
                records
                    .iter()
                    .all(|run| run["sequence"].as_u64().unwrap() >= cursor)
            );
            assert!(
                records
                    .windows(2)
                    .all(|pair| pair[0]["sequence"].as_u64().unwrap()
                        < pair[1]["sequence"].as_u64().unwrap())
            );
        }
    }
    #[test]
    fn owner_epoch_and_header_work_are_required_at_event_time() {
        let recorder = Recorder::default();
        assert!(recorder.token(candidate(1)).is_none());
        recorder.publish(owner(1));
        let mut old = candidate(1);
        old.work = Work::zero();
        assert!(recorder.token(old).is_none());
        let mut far = candidate(1);
        far.height = 12;
        assert!(recorder.token(far).is_none());
        let mut changed = owner(1);
        changed.canonical_height = 11;
        recorder.publish(changed);
        assert!(recorder.token(candidate(1)).is_none());
    }
}
