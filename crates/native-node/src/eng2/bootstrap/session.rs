//! Outbound cold-client rounds with the universal phase order. No quarantine
//! progress is represented as accepted chain state or pending transactions.
use crate::{
    eng2::{
        body::Body,
        checkpoint_exchange::{self, OwnedIncoming},
        genesis::{FeeMode, Genesis},
        header::Header,
        network::{self, BootstrapPull, Error, Limits, Owner, Round, Sequence},
        transaction_exchange,
        transport::Peer,
    },
    p2p,
    wire::Hash,
};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

struct ColdOwner {
    genesis: Hash,
}
impl Owner for ColdOwner {
    fn head(&self) -> Result<(u64, Hash), String> {
        Ok((0, self.genesis))
    }
    fn header(&self, _: u64) -> Result<Option<Header>, String> {
        Ok(None)
    }
    fn block_size(&self, _: u64) -> Result<Option<usize>, String> {
        Ok(None)
    }
    fn block(&self, _: u64) -> Result<(Header, Body), String> {
        Err("unadmitted bootstrap client has no accepted proof bodies".into())
    }
    fn accept(&mut self, _: &Header, _: &Body) -> Result<(), String> {
        Err("unadmitted bootstrap client cannot accept blocks".into())
    }
}
impl transaction_exchange::Owner for ColdOwner {
    fn transaction_ids(&self) -> Vec<Hash> {
        Vec::new()
    }
    // A cold client requests no pending packets while it has no accepted state.
    fn has_transaction(&self, _: &Hash) -> bool {
        true
    }
    fn transaction_packet(&self, _: &Hash) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn submit_transaction(
        &mut self,
        _: Hash,
        _: Hash,
        _: &[u8],
        _: &p2p::Deadline,
    ) -> Result<Hash, String> {
        Err("unadmitted bootstrap client cannot accept pending transactions".into())
    }
}

pub struct Completed<T> {
    pub round: Round,
    pub acquired: T,
    /// Decoded, bounded observations only. Retain the reservations while
    /// staging them; these packets create no signing or state authority.
    pub checkpoints: Vec<OwnedIncoming>,
}

pub struct ColdSession {
    owner: Arc<Mutex<ColdOwner>>,
    sequence: Sequence,
    network: Hash,
    genesis: Hash,
}
impl ColdSession {
    pub fn admitted_head(&self) -> (u64, Hash) {
        (0, self.genesis)
    }
    pub fn new(genesis: &Genesis) -> Result<Self, String> {
        if genesis.fee_mode() != FeeMode::LegacyMiner {
            return Err("cold signed bootstrap requires the reviewed legacy genesis mode".into());
        }
        Ok(Self {
            owner: Arc::new(Mutex::new(ColdOwner {
                genesis: genesis.id(),
            })),
            sequence: Sequence::default(),
            network: genesis.config().network,
            genesis: genesis.id(),
        })
    }
    /// Perform finite acquisition, announce only genesis/height zero, finish
    /// reverse pull, consume nonsigning checkpoint packets and complete the
    /// transaction phase. Discard the peer on every error; no phase is skipped.
    pub fn round<S: Read + Write, T>(
        &mut self,
        peer: &mut Peer<S>,
        limits: Limits,
        acquire: impl FnOnce(&mut BootstrapPull<'_, S>) -> Result<T, Error>,
    ) -> Result<Completed<T>, Error> {
        if peer.genesis_id() != self.genesis {
            return Err(Error::Protocol);
        }
        let (round, acquired) =
            network::initiate_bootstrap(peer, &self.owner, &mut self.sequence, limits, acquire)?;
        let checkpoints = checkpoint_exchange::initiate(peer, &[], self.network)?;
        transaction_exchange::initiate(peer, &self.owner)?;
        Ok(Completed {
            round,
            acquired,
            checkpoints,
        })
    }
}
