//! Sequential client dispatch policy. Transport/authentication is external.
//!
//! A schedule represents one live opening, never an approval cache. Only timeout
//! or unavailability permits trying the next slot. Both conservatively retain a
//! possibly-charged record. A credential failure is terminal. Timed-out or closed
//! requests cannot later accept a response through this scheduler.

use std::collections::BTreeSet;

use crate::message::{Domain, Operation};

pub const MAX_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientResult {
    Approved,
    WrongCredential,
    Timeout,
    Unavailable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Approved,
    WrongCredential,
    Rejected,
    NoEligibleSlots,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Ready,
    InFlight(Domain),
    Finished(Terminal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    InvalidPlan,
    AlreadyInFlight,
    Finished,
    UnexpectedResponse,
}

#[derive(Debug)]
pub struct Scheduler {
    targets: Vec<Domain>,
    cursor: usize,
    state: State,
    possibly_charged: Vec<Domain>,
}

impl Scheduler {
    /// Each target must be a distinct permanent slot for the same opening, with
    /// a distinct request identity. Endpoint incarnation is bound per target.
    pub fn new(targets: Vec<Domain>) -> Result<Self, SchedulerError> {
        let first = targets.first().ok_or(SchedulerError::InvalidPlan)?;
        if targets.len() > MAX_SLOTS || first.operation == Operation::Owner {
            return Err(SchedulerError::InvalidPlan);
        }
        let mut slots = BTreeSet::new();
        let mut requests = BTreeSet::new();
        for d in &targets {
            if d.suite != first.suite
                || d.network != first.network
                || d.safe != first.safe
                || d.generation != first.generation
                || d.operation != first.operation
                || !slots.insert(d.slot)
                || !requests.insert(d.request)
            {
                return Err(SchedulerError::InvalidPlan);
            }
        }
        Ok(Self {
            targets,
            cursor: 0,
            state: State::Ready,
            possibly_charged: Vec::new(),
        })
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn possibly_charged(&self) -> &[Domain] {
        &self.possibly_charged
    }

    pub fn begin_next(&mut self) -> Result<Domain, SchedulerError> {
        match self.state {
            State::InFlight(_) => return Err(SchedulerError::AlreadyInFlight),
            State::Finished(_) => return Err(SchedulerError::Finished),
            State::Ready => {}
        }
        let target = self.targets[self.cursor];
        self.cursor += 1;
        self.state = State::InFlight(target);
        Ok(target)
    }

    /// The caller must first authenticate and bind the response to the complete
    /// outstanding transcript. No credential bytes or result verification here.
    pub fn complete(&mut self, target: Domain, result: ClientResult) -> Result<(), SchedulerError> {
        if self.state != State::InFlight(target) {
            return Err(SchedulerError::UnexpectedResponse);
        }
        self.state = match result {
            ClientResult::Approved => State::Finished(Terminal::Approved),
            ClientResult::WrongCredential => State::Finished(Terminal::WrongCredential),
            ClientResult::Rejected => State::Finished(Terminal::Rejected),
            ClientResult::Timeout | ClientResult::Unavailable => {
                self.possibly_charged.push(target);
                if self.cursor == self.targets.len() {
                    State::Finished(Terminal::NoEligibleSlots)
                } else {
                    State::Ready
                }
            }
        };
        Ok(())
    }

    pub fn close(&mut self) {
        if let State::InFlight(target) = self.state {
            self.possibly_charged.push(target);
        }
        self.state = State::Finished(Terminal::Closed);
    }
}
