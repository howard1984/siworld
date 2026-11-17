//! Explicit fixed-peer relay limits on the existing authenticated body lanes.
use super::fixed_relay::{self, OfferContext, Permit, Policy};
use super::*;
use std::io;
struct Core {
    origin: Instant,
    policy: Mutex<Option<Policy>>,
    _charge: p2p::Reservation,
}
pub(super) struct Use {
    core: Arc<Core>,
    permit: Mutex<Option<Permit>>,
    deadline: p2p::Deadline,
}
impl Core {
    fn millis(&self, at: Instant) -> Result<u64, String> {
        u64::try_from(
            at.checked_duration_since(self.origin)
                .ok_or("fixed relay clock regressed")?
                .as_millis(),
        )
        .map_err(|_| "fixed relay clock exhausted".into())
    }
}
impl Use {
    fn apply(&self, bytes: u64, actual: bool) -> Result<(), String> {
        self.deadline.check().map_err(|_| "fixed relay expired")?;
        let permit = self
            .permit
            .lock()
            .map_err(|_| "fixed relay capability lock poisoned")?;
        let permit = permit.as_ref().ok_or("fixed relay capability closed")?;
        let now = self.core.millis(Instant::now())?;
        let mut policy = self
            .core
            .policy
            .lock()
            .map_err(|_| "fixed relay policy lock poisoned")?;
        let policy = policy.as_mut().ok_or("fixed relay unconfigured")?;
        if actual {
            policy.account_wire(permit, bytes, now)
        } else {
            policy.check_wire(permit, bytes, now)
        }
        .map_err(|_| "fixed relay wire allowance exhausted".into())
    }
    fn close(&self) -> Result<(), String> {
        let permit = self
            .permit
            .lock()
            .map_err(|_| "fixed relay capability lock poisoned")?
            .take();
        if let Some(permit) = permit {
            let now = self.core.millis(Instant::now())?;
            self.core
                .policy
                .lock()
                .map_err(|_| "fixed relay policy lock poisoned")?
                .as_mut()
                .ok_or("fixed relay unconfigured")?
                .close(permit, now)
                .map_err(|_| "fixed relay close rejected")?;
        }
        Ok(())
    }
}
impl p2p::WireFence for Use {
    fn check_wire(&self, bytes: u64) -> io::Result<()> {
        self.apply(bytes, false).map_err(io::Error::other)
    }
    fn account_wire(&self, bytes: u64) -> io::Result<()> {
        self.apply(bytes, true).map_err(io::Error::other)
    }
}
struct Saved {
    peer: Hash,
    session: u64,
    block: Hash,
    usage: Arc<Use>,
}
pub(super) struct Relay {
    core: Arc<Core>,
    local_role: p2p::Role,
    selected: std::collections::BTreeSet<Hash>,
    saved: Mutex<Vec<Saved>>,
}
impl Relay {
    pub(super) fn new(
        config: &config::Configuration,
        body: super::super::body::Policy,
        budget: &p2p::Budget,
    ) -> Result<Self, String> {
        let selected = config.fixed_relay_peers.clone();
        let pinned: Vec<_> = config
            .peers
            .iter()
            .map(|p| p.expected.fingerprint())
            .collect();
        let maximum = super::super::transport::propagation::maximum_wire(body.max_body_bytes)
            .map_err(|_| "fixed relay wire ceiling unavailable")?;
        let policy = if selected.is_empty() {
            None
        } else {
            Some(
                Policy::new(
                    &pinned,
                    &selected.iter().copied().collect::<Vec<_>>(),
                    fixed_relay::Limits {
                        maximum_body_bytes: body.max_body_bytes as u64,
                        maximum_credit_wire_bytes: maximum,
                        window_ms: 180_000,
                        offers_per_window: 32,
                        peer_offers_per_window: 4,
                        wire_per_window: maximum
                            .checked_mul(4)
                            .ok_or("fixed relay wire ceiling overflow")?,
                        peer_wire_per_window: maximum,
                    },
                    0,
                )
                .map_err(|_| "fixed relay selection rejected")?,
            )
        };
        let charge = budget
            .reserve(
                std::mem::size_of::<Self>()
                    + std::mem::size_of::<Core>()
                    + std::mem::size_of::<Policy>()
                    + 16 * 32
                    + 32 * (std::mem::size_of::<Saved>() + std::mem::size_of::<Use>()),
            )
            .map_err(|_| "fixed relay policy memory unavailable")?;
        Ok(Self {
            core: Arc::new(Core {
                origin: Instant::now(),
                policy: Mutex::new(policy),
                _charge: charge,
            }),
            local_role: config.role,
            selected,
            saved: Mutex::new(Vec::with_capacity(32)),
        })
    }
    pub(super) fn selected(&self, peer: Hash, role: p2p::Role) -> bool {
        self.selected.contains(&peer)
            && match self.local_role {
                p2p::Role::Miner => matches!(role, p2p::Role::Bootstrap | p2p::Role::Validator),
                p2p::Role::Bootstrap | p2p::Role::Validator => role == p2p::Role::Miner,
                _ => false,
            }
    }
    pub(super) fn sender(&self) -> bool {
        self.local_role == p2p::Role::Miner
    }
    pub(super) fn open(
        &self,
        peer: Hash,
        session: u64,
        request: u64,
        header: &super::super::header::Header,
        body_bytes: usize,
        deadline: &p2p::Deadline,
    ) -> Result<Arc<Use>, String> {
        let now = self.core.millis(Instant::now())?;
        let expiry = self.core.millis(deadline.expires_at())?;
        let block = header
            .id()
            .map_err(|_| "fixed relay header identity rejected")?;
        let maximum = super::super::transport::propagation::maximum_wire(body_bytes)
            .map_err(|_| "fixed relay wire ceiling unavailable")?;
        let mut state = self
            .core
            .policy
            .lock()
            .map_err(|_| "fixed relay policy lock poisoned")?;
        let policy = state.as_mut().ok_or("fixed relay unconfigured")?;
        let ticket = policy
            .open_offer(
                OfferContext {
                    peer,
                    session,
                    block,
                    height: header.height,
                    request,
                    body_bytes: body_bytes as u64,
                    original_expires_ms: expiry,
                },
                now,
            )
            .map_err(|_| "fixed relay offer deferred")?;
        let permit = policy
            .credit(ticket, session, maximum, now)
            .map_err(|_| "fixed relay credit deferred")?;
        Ok(Arc::new(Use {
            core: self.core.clone(),
            permit: Mutex::new(Some(permit)),
            deadline: deadline.clone(),
        }))
    }
    /// The first inbound offer/query was bounded by Session before dispatch.
    /// Account it once when the exact fixed-peer capability becomes known.
    pub(super) fn account(&self, usage: &Use, bytes: u64) -> Result<(), String> {
        usage.apply(bytes, true)
    }
    pub(super) fn close(&self, usage: Arc<Use>) -> Result<(), String> {
        usage.close()
    }
    pub(super) fn save(
        &self,
        peer: Hash,
        session: u64,
        block: Hash,
        _deadline: p2p::Deadline,
        usage: Arc<Use>,
    ) -> Result<(), String> {
        let mut saved = self
            .saved
            .lock()
            .map_err(|_| "fixed relay permit lock poisoned")?;
        saved.retain(|entry| entry.usage.deadline.check().is_ok());
        if saved.len() >= 32
            || saved
                .iter()
                .any(|entry| entry.peer == peer && entry.session == session && entry.block == block)
        {
            return Err("fixed relay permit capacity exhausted".into());
        }
        saved.push(Saved {
            peer,
            session,
            block,
            usage,
        });
        Ok(())
    }
    pub(super) fn take(
        &self,
        peer: Hash,
        session: u64,
        block: Hash,
    ) -> Result<Option<Arc<Use>>, String> {
        let mut saved = self
            .saved
            .lock()
            .map_err(|_| "fixed relay permit lock poisoned")?;
        Ok(saved
            .iter()
            .position(|entry| {
                entry.peer == peer && entry.session == session && entry.block == block
            })
            .map(|index| saved.remove(index).usage))
    }
}
