//! Immutable source-gated header plans and anchor lineage checks.
//!
//! These checks do not authenticate imported component contents or execute the
//! proof tail. Admission must still complete both in isolated storage.

use super::selection::{self, SelectionError, SourceObservation, VerifiedHeaders};
use crate::state::State;
use crate::wire::Hash;
use siworld_core::pow::Work;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub network: Hash,
    pub genesis: Hash,
    pub anchor_height: u64,
    pub anchor_id: Hash,
    pub tip_height: u64,
    pub tip_id: Hash,
    pub cumulative_work: Work,
    pub tail_work: Work,
    pub local_work_floor: Work,
}

pub struct AdmissionPlan {
    headers: VerifiedHeaders,
    pin: Pin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    Selection(SelectionError),
    AnchorMetadata,
    NetworkRules,
    Checkpoint,
    Availability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadChange {
    Unchanged,
    ExtendsPinned,
    HeavierFork,
    EqualWorkFork,
    KeepPinned,
}

impl AdmissionPlan {
    pub fn select(sources: &[SourceObservation<'_>], floor: Work) -> Result<Self, PlanError> {
        let headers = selection::select(sources, floor).map_err(PlanError::Selection)?;
        let anchor_height = headers.anchor_height();
        let pin = Pin {
            network: headers.rules().network,
            genesis: headers.rules().genesis,
            anchor_height,
            anchor_id: headers.id(anchor_height).map_err(PlanError::Selection)?,
            tip_height: headers.height(),
            tip_id: headers.id(headers.height()).map_err(PlanError::Selection)?,
            cumulative_work: headers.cumulative_work(),
            tail_work: headers.tail_work(),
            local_work_floor: floor,
        };
        Ok(Self {
            headers: headers.clone(),
            pin,
        })
    }
    /// Explicit signed-checkpoint mode only. Select the greatest-work complete
    /// verified header history among the supplied candidates without requiring
    /// automatic mode's three transport source groups. This preliminary plan
    /// grants no state admission: import must authenticate a current-roster
    /// certificate, reconstruct permanent state and execute the complete tail.
    pub fn select_signed(candidates: &[&VerifiedHeaders], floor: Work) -> Result<Self, PlanError> {
        use selection::SelectionError;
        let reject = PlanError::Selection;
        if floor.is_zero() {
            return Err(reject(SelectionError::WorkFloor));
        }
        if candidates.is_empty() || candidates.len() > 64 {
            return Err(reject(SelectionError::Sources));
        }
        let mut selected = candidates[0];
        let mut equal_competitor = false;
        for candidate in candidates {
            if candidate.rules() != selected.rules() {
                return Err(reject(SelectionError::Rules));
            }
            if candidate.cumulative_work() > selected.cumulative_work() {
                selected = candidate;
                equal_competitor = false;
            } else if candidate.cumulative_work() == selected.cumulative_work()
                && candidate.id(candidate.height()).map_err(reject)?
                    != selected.id(selected.height()).map_err(reject)?
            {
                equal_competitor = true;
            }
        }
        if equal_competitor {
            return Err(reject(SelectionError::EqualWork));
        }
        if selected.tail_work() < floor {
            return Err(reject(SelectionError::WorkFloor));
        }
        Ok(Self {
            headers: selected.clone(),
            pin: Pin {
                network: selected.rules().network,
                genesis: selected.rules().genesis,
                anchor_height: selected.anchor_height(),
                anchor_id: selected.id(selected.anchor_height()).map_err(reject)?,
                tip_height: selected.height(),
                tip_id: selected.id(selected.height()).map_err(reject)?,
                cumulative_work: selected.cumulative_work(),
                tail_work: selected.tail_work(),
                local_work_floor: floor,
            },
        })
    }
    pub fn headers(&self) -> &VerifiedHeaders {
        &self.headers
    }
    pub fn pin(&self) -> Pin {
        self.pin
    }
    /// Explicit signed-checkpoint mode only. The selected header history and
    /// the caller's work floor remain unchanged. Availability
    /// is a preliminary range declaration; the importer must read and verify
    /// every body before it can install any accepted state.
    pub fn at_checkpoint(
        &self,
        checkpoint: u64,
        first_full_body: u64,
        last_full_body: u64,
    ) -> Result<Self, PlanError> {
        let tail = self
            .pin
            .tip_height
            .checked_sub(checkpoint)
            .ok_or(PlanError::Checkpoint)?;
        if checkpoint == 0
            || !(super::runtime_export::CHECKPOINT_CONFIRMATIONS..=selection::TAIL_BLOCKS)
                .contains(&tail)
        {
            return Err(PlanError::Checkpoint);
        }
        if first_full_body > checkpoint + 1 || last_full_body < self.pin.tip_height {
            return Err(PlanError::Availability);
        }
        let mut pin = self.pin;
        pin.anchor_height = checkpoint;
        pin.anchor_id = self.headers.id(checkpoint).map_err(PlanError::Selection)?;
        pin.tail_work = pin.cumulative_work
            - self
                .headers
                .work_at(checkpoint)
                .map_err(PlanError::Selection)?;
        if pin.tail_work < pin.local_work_floor {
            return Err(PlanError::Selection(SelectionError::WorkFloor));
        }
        Ok(Self {
            headers: self.headers.clone(),
            pin,
        })
    }
    pub fn check_anchor_metadata(&self, state: &State) -> Result<(), PlanError> {
        let rules = self.headers.rules();
        let height = self.pin.anchor_height;
        if state.config.network != rules.network
            || state.config.genesis_timestamp != rules.genesis_timestamp
            || state.config.genesis_target != rules.genesis_target
            || state.config.target_interval != rules.target_interval
            || state.config.pow_iterations != rules.pow_iterations
            || state.height != height
            || state.tip != self.pin.anchor_id
            || state.cumulative_work
                != self.headers.work_at(height).map_err(PlanError::Selection)?
            || state.timestamps
                != self
                    .headers
                    .timestamp_window(height)
                    .map_err(PlanError::Selection)?
        {
            return Err(PlanError::AnchorMetadata);
        }
        let first = height.saturating_sub(crate::state::SNAPSHOT_WINDOW as u64 - 1);
        if state.snapshots.len() as u64 != height - first + 1 {
            return Err(PlanError::AnchorMetadata);
        }
        for (index, snapshot) in state.snapshots.iter().enumerate() {
            let height = first + index as u64;
            if snapshot.selector.height != height
                || snapshot.selector.block_id
                    != self.headers.id(height).map_err(PlanError::Selection)?
            {
                return Err(PlanError::AnchorMetadata);
            }
        }
        Ok(())
    }
    pub fn compare(&self, observed: &Self) -> Result<HeadChange, PlanError> {
        if self.headers.rules() != observed.headers.rules() {
            return Err(PlanError::NetworkRules);
        }
        if observed.pin.tip_height >= self.pin.tip_height
            && observed
                .headers
                .id(self.pin.tip_height)
                .map_err(PlanError::Selection)?
                == self.pin.tip_id
        {
            return Ok(if observed.pin.tip_height == self.pin.tip_height {
                HeadChange::Unchanged
            } else {
                HeadChange::ExtendsPinned
            });
        }
        if observed.pin.tip_height < self.pin.tip_height
            && self
                .headers
                .id(observed.pin.tip_height)
                .map_err(PlanError::Selection)?
                == observed.pin.tip_id
        {
            return Ok(HeadChange::KeepPinned);
        }
        Ok(
            match observed.pin.cumulative_work.cmp(&self.pin.cumulative_work) {
                std::cmp::Ordering::Greater => HeadChange::HeavierFork,
                std::cmp::Ordering::Equal => HeadChange::EqualWorkFork,
                std::cmp::Ordering::Less => HeadChange::KeepPinned,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::{header::Header, selection::HeaderRules};
    use super::*;
    use crate::state::{CanonicalSnapshot, Config};
    use native::codec::encode_digest;
    use std::net::IpAddr;

    fn chain(count: u64, tag: u8) -> VerifiedHeaders {
        let config = Config::development([71; 32], 0).unwrap();
        let rules = HeaderRules {
            network: config.network,
            genesis: config.genesis_id(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            pow_iterations: config.pow_iterations,
            max_headers: 1000,
        };
        let mut parent = rules.genesis;
        let mut headers = Vec::new();
        for height in 1..=count {
            let header = Header {
                network: rules.network,
                height,
                parent,
                timestamp: rules.genesis_timestamp + height * 300,
                target: [0xff; 32],
                execution_commitment: [tag; 32],
                body_commitment: [tag; 32],
                nonce: 0,
            };
            parent = header.id().unwrap();
            headers.push(header);
        }
        VerifiedHeaders::verify(rules, headers).unwrap()
    }
    fn sources(chain: &VerifiedHeaders) -> Vec<SourceObservation<'_>> {
        (1..=3)
            .map(|id| SourceObservation {
                authenticated_identity: [id; 32],
                transport_address: IpAddr::from([10, id, 0, 1]),
                chain,
            })
            .collect()
    }
    fn make_plan(count: u64, tag: u8) -> AdmissionPlan {
        AdmissionPlan::select(&sources(&chain(count, tag)), Work::one()).unwrap()
    }
    fn anchor(plan: &AdmissionPlan) -> State {
        let mut state = State::new(Config::development([71; 32], 0).unwrap()).unwrap();
        let root = encode_digest(&state.tree.root());
        let recent = state.tip_snapshot().recent_root;
        state.height = plan.pin.anchor_height;
        state.tip = plan.pin.anchor_id;
        state.cumulative_work = plan.headers.work_at(state.height).unwrap();
        state.timestamps = plan.headers.timestamp_window(state.height).unwrap();
        state.snapshots = (0..=state.height)
            .map(|height| CanonicalSnapshot {
                selector: crate::wire::Snapshot {
                    height,
                    block_id: plan.headers.id(height).unwrap(),
                },
                commitment_root: root,
                recent_root: recent,
            })
            .collect();
        state
    }

    #[test]
    fn plan_requires_source_gate_and_pins_exact_312_block_tail() {
        let headers = chain(313, 1);
        let sources = sources(&headers);
        assert!(matches!(
            AdmissionPlan::select(&sources[..2], Work::one()),
            Err(PlanError::Selection(SelectionError::Sources))
        ));
        assert!(matches!(
            AdmissionPlan::select(&sources, Work::zero()),
            Err(PlanError::Selection(SelectionError::WorkFloor))
        ));
        let plan = AdmissionPlan::select(&sources, Work::one()).unwrap();
        assert_eq!(plan.pin.anchor_height, 1);
        assert_eq!(plan.pin.tip_height, 313);
        assert_eq!(plan.pin.anchor_id, headers.id(1).unwrap());
        assert_eq!(plan.pin.tail_work, Work::from(312u64));
        assert_eq!(make_plan(312, 1).pin.anchor_height, 0);
    }

    #[test]
    fn imported_anchor_must_match_exact_work_times_and_every_snapshot_identity() {
        let plan = make_plan(345, 2);
        let state = anchor(&plan);
        assert_eq!(state.timestamps.len(), 11);
        assert_eq!(plan.check_anchor_metadata(&state), Ok(()));
        let mut changed = state.clone();
        changed.cumulative_work += Work::one();
        assert_eq!(
            plan.check_anchor_metadata(&changed),
            Err(PlanError::AnchorMetadata)
        );
        changed = state.clone();
        *changed.timestamps.back_mut().unwrap() -= 1;
        assert_eq!(
            plan.check_anchor_metadata(&changed),
            Err(PlanError::AnchorMetadata)
        );
        changed = state.clone();
        changed.snapshots[1].selector.block_id = [0; 32];
        assert_eq!(
            plan.check_anchor_metadata(&changed),
            Err(PlanError::AnchorMetadata)
        );
        changed = state;
        changed.tip = [0; 32];
        assert_eq!(
            plan.check_anchor_metadata(&changed),
            Err(PlanError::AnchorMetadata)
        );
        let short = make_plan(312, 2);
        assert_eq!(short.check_anchor_metadata(&anchor(&short)), Ok(()));
    }

    #[test]
    fn moving_head_never_relabels_a_snapshot_from_a_competing_fork() {
        let pinned = make_plan(313, 1);
        assert_eq!(
            pinned.compare(&make_plan(313, 1)),
            Ok(HeadChange::Unchanged)
        );
        assert_eq!(
            pinned.compare(&make_plan(314, 1)),
            Ok(HeadChange::ExtendsPinned)
        );
        assert_eq!(
            pinned.compare(&make_plan(315, 2)),
            Ok(HeadChange::HeavierFork)
        );
        assert_eq!(
            pinned.compare(&make_plan(313, 2)),
            Ok(HeadChange::EqualWorkFork)
        );
        assert_eq!(
            pinned.compare(&make_plan(312, 2)),
            Ok(HeadChange::KeepPinned)
        );
        assert_eq!(pinned.pin.tip_height, 313);
    }
}
