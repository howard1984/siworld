//! Independent progress observer with cooperative cancellation of one producer round.

use crate::p2p::Cancellation;
use std::time::{Duration, Instant};

const POW_STALL_THRESHOLD: Duration = Duration::from_secs(300);

#[derive(Default)]
pub(super) struct Watchdog {
    expected_since: Option<Instant>,
    last_observed_progress: Option<Instant>,
    stalled: bool,
    episode: u64,
    active_round: Option<Cancellation>,
    observation: Option<(u64, u64)>,
    requested_episode: Option<u64>,
    restarts: u64,
}

impl Watchdog {
    pub(super) fn begin_round(&mut self) -> Cancellation {
        let round = Cancellation::default();
        self.active_round = Some(round.clone());
        round
    }

    pub(super) fn finish_round(&mut self) {
        self.active_round = None;
    }

    pub(super) fn poll(&mut self, now: Instant, expected: bool, last_pow: Option<Instant>) -> bool {
        let previous = self.observation.map(|(_, episode)| episode);
        self.observation = self.observe(now, expected, last_pow);
        if let Some((_, episode)) = self.observation
            && self.requested_episode != Some(episode)
            && let Some(round) = self.active_round.as_ref()
        {
            self.requested_episode = Some(episode);
            round.cancel();
        }
        self.observation
            .is_some_and(|(_, episode)| previous != Some(episode))
    }

    pub(super) fn stalled(&self) -> Option<(u64, u64)> {
        self.observation
    }

    pub(super) fn restart_waiting(&self) -> bool {
        self.active_round
            .as_ref()
            .is_some_and(Cancellation::is_cancelled)
    }

    pub(super) fn restarted(&mut self) {
        self.restarts = self.restarts.saturating_add(1);
    }

    pub(super) fn restarts(&self) -> u64 {
        self.restarts
    }

    fn observe(
        &mut self,
        now: Instant,
        expected: bool,
        last_pow: Option<Instant>,
    ) -> Option<(u64, u64)> {
        if !expected {
            self.expected_since = None;
            self.stalled = false;
            self.last_observed_progress = None;
            return None;
        }
        if last_pow != self.last_observed_progress {
            self.stalled = false;
            self.last_observed_progress = last_pow;
        }
        let expected_since = *self.expected_since.get_or_insert(now);
        let last_progress = last_pow.unwrap_or(expected_since).max(expected_since);
        let age = now.saturating_duration_since(last_progress);
        if age < POW_STALL_THRESHOLD {
            self.stalled = false;
            return None;
        }
        if !self.stalled {
            self.episode = self.episode.saturating_add(1);
            self.stalled = true;
        }
        Some((age.as_millis().try_into().unwrap_or(u64::MAX), self.episode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_round_is_cancelled_once_progress_rearms_and_pause_is_quiet() {
        let started = Instant::now();
        let at = |seconds| started + Duration::from_secs(seconds);
        let mut watch = Watchdog::default();
        let initial = watch.begin_round();
        watch.poll(at(0), true, None);
        watch.poll(at(299), true, None);
        assert!(!initial.is_cancelled());
        watch.poll(at(300), true, None);
        assert!(watch.restart_waiting());
        assert!(initial.is_cancelled());
        assert_eq!(watch.stalled(), Some((300_000, 1)));

        watch.finish_round();
        watch.restarted();
        let next = watch.begin_round();
        watch.poll(at(600), true, None);
        assert!(!next.is_cancelled());
        assert_eq!(watch.restarts(), 1);
        watch.poll(at(620), true, Some(at(620)));
        assert_eq!(watch.stalled(), None);
        watch.poll(at(920), false, Some(at(620)));
        assert!(!next.is_cancelled());
        watch.poll(at(921), true, Some(at(620)));
        watch.poll(at(1221), true, Some(at(620)));
        assert!(next.is_cancelled());
        assert_eq!(watch.stalled(), Some((300_000, 2)));
    }

    #[test]
    fn progress_between_sparse_observations_begins_a_different_episode() {
        let started = Instant::now();
        let at = |seconds| started + Duration::from_secs(seconds);
        let mut watch = Watchdog::default();
        assert_eq!(watch.observe(at(0), true, None), None);
        assert_eq!(watch.observe(at(300), true, None), Some((300_000, 1)));
        assert_eq!(
            watch.observe(at(620), true, Some(at(310))),
            Some((310_000, 2))
        );
    }

    #[test]
    fn boundary_dedupe_recovery_and_pause_follow_monotonic_progress_only() {
        let started = Instant::now();
        let at = |seconds| started + Duration::from_secs(seconds);
        let mut watch = Watchdog::default();
        assert_eq!(watch.observe(at(0), false, None), None);
        assert_eq!(watch.observe(at(10), true, None), None);
        assert_eq!(watch.observe(at(309), true, None), None);
        assert_eq!(watch.observe(at(310), true, None), Some((300_000, 1)));
        assert_eq!(watch.observe(at(400), true, None), Some((390_000, 1)));
        assert_eq!(watch.observe(at(401), true, Some(at(401))), None);
        assert_eq!(
            watch.observe(at(701), true, Some(at(401))),
            Some((300_000, 2))
        );
        assert_eq!(watch.observe(at(702), false, Some(at(401))), None);
        assert_eq!(watch.observe(at(1500), true, Some(at(401))), None);
        assert_eq!(
            watch.observe(at(1800), true, Some(at(401))),
            Some((300_000, 3))
        );
    }
}
