//! Single mutable owner for versioned durable admission and local production.
//! Socket reads, actual proving and nonce search run outside this owner.

use super::{
    body::Body,
    execution::{CommittedBlock, Engine},
    header::Header,
    producer::{self, PreparedBlock, ProvedBlock, Work},
    snapshot::ImportLimits,
    store::Store,
};
use crate::{
    admission::{Mempool, PeerId},
    pool::{Padding, Pool},
    producer::{MiningSettings, PreparedPadding, prepare_padding_witness},
    proofs::NativeVerifier,
    wire::Hash,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub network: Hash,
    pub genesis: Hash,
    pub height: u64,
    pub id: Hash,
    pub work: siworld_core::pow::Work,
}

/// Native verification is synchronous, so this is a commit deadline rather
/// than CPU preemption. Late verification never inserts into the pending pool.
struct TimedAdmission<'a, V> {
    verifier: &'a V,
    deadline: &'a crate::p2p::Deadline,
}
impl<V: crate::admission::AdmissionVerifier> crate::admission::AdmissionVerifier
    for TimedAdmission<'_, V>
{
    fn verify(
        &self,
        public: &native::codec::PublicTransaction,
        context: &native::codec::ProofContext,
        fee: &native::multi_asset::Digest,
        root: &native::multi_asset::Digest,
        proof: &[u8],
    ) -> Result<(), crate::admission::VerificationError> {
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)?;
        self.verifier.verify(public, context, fee, root, proof)?;
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)
    }
    fn check_commit(&self) -> Result<(), crate::admission::VerificationError> {
        self.verifier.check_commit()?;
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)
    }
}
fn transaction_identity(packet: &[u8], network: &Hash) -> Result<(Hash, usize), String> {
    let prefix: [u8; 4] = packet
        .get(..4)
        .ok_or("pending transaction framing rejected")?
        .try_into()
        .expect("checked prefix");
    let length = u32::from_le_bytes(prefix) as usize;
    if length > crate::wire::MAX_ENVELOPE_BYTES
        || packet.len() != 4 + length + crate::wire::SIDECAR_BYTES
    {
        return Err("pending transaction framing rejected".into());
    }
    let id = crate::wire::borrowed_envelope(&packet[4..4 + length], network)
        .map_err(|_| "pending transaction envelope rejected")?
        .0
        .statement_id(network);
    Ok((id, length))
}

pub struct Driver {
    store: Store,
    verifier: NativeVerifier,
    padding: Pool,
    pending: Mempool,
    imports: ImportLimits,
    last_archive_error: Option<String>,
}
impl Driver {
    /// The caller explicitly creates or resumes the store and loads only the
    /// verification keys. This constructor never creates identity credentials.
    pub fn new(
        store: Store,
        verifier: NativeVerifier,
        imports: ImportLimits,
    ) -> Result<Self, String> {
        store.ensure_exportable()?;
        Ok(Self {
            padding: Pool::new(store.engine().state().network()),
            pending: Mempool::with_limits(
                store.engine().state().network(),
                crate::admission::Limits {
                    bytes: crate::pool::MAX_BYTES,
                    entries: 128,
                    peer_bytes: 8 * 1024 * 1024,
                    peer_entries: 16,
                    peers: 128,
                },
            )
            .map_err(|_| "pending admission limits rejected")?,
            store,
            verifier,
            imports,
            last_archive_error: None,
        })
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn engine(&self) -> &Engine {
        self.store.engine()
    }
    pub fn head(&self) -> Result<Head, String> {
        self.store.ensure_exportable()?;
        let engine = self.store.engine();
        Ok(Head {
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            height: engine.state().height(),
            id: engine.state().tip(),
            work: engine.state().chain().cumulative_work,
        })
    }
    pub fn header(&self, height: u64) -> Result<Header, String> {
        self.store.header(height)
    }
    pub fn block_size(&self, height: u64) -> Result<usize, String> {
        self.store.block_size(height)
    }
    pub fn block(&self, height: u64) -> Result<(Header, Body), String> {
        self.store.block(height)
    }

    /// Return only after the exact native block is durably committed. Archive
    /// failures are independently observable and do not undo accepted history.
    pub fn accept(&mut self, header: &Header, body: &Body) -> Result<CommittedBlock, String> {
        let committed = self.store.append(header, body, &self.verifier)?;
        // The pool is created for this immutable network, so pruning cannot
        // fail its context check after a successful append.
        self.pending
            .prune(self.store.engine().state().chain())
            .expect("owner pending network is immutable");
        self.padding
            .prune(self.store.engine().state().chain())
            .expect("owner padding network is immutable");
        if committed.height().is_multiple_of(72) {
            self.last_archive_error = self.store.archive_checkpoint_anchor(self.imports).err();
        }
        Ok(committed)
    }
    pub fn last_archive_error(&self) -> Option<&str> {
        self.last_archive_error.as_deref()
    }
    /// Pending wallet work is independently verified and retained until its
    /// inputs become canonical. No fee sidecar is exported in public status.
    pub fn ready_positions(&self) -> usize {
        self.padding.len().saturating_add(self.pending.len())
    }
    pub fn transaction_ids(&self) -> Vec<Hash> {
        self.pending.ids()
    }
    pub fn has_transaction(&self, id: &Hash) -> bool {
        self.pending.contains(id)
    }
    pub fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        match (self.pending.transaction(id), self.pending.sidecar(id)) {
            (Some(transaction), Some(sidecar)) => crate::runtime::encode_gossip(
                transaction,
                sidecar,
                &self.store.engine().state().network(),
            )
            .map(Some),
            (None, None) => Ok(None),
            _ => Err("pending transaction sidecar unavailable".into()),
        }
    }
    pub fn submit_transaction(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
    ) -> Result<Hash, String> {
        self.submit_transaction_before(
            peer,
            expected,
            packet,
            &crate::p2p::Deadline::new(std::time::Duration::from_secs(10)),
        )
    }
    fn submit_transaction_before(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        deadline
            .check()
            .map_err(|_| "pending transaction deadline elapsed")?;
        self.store.ensure_exportable()?;
        let network = self.store.engine().state().network();
        let (id, length) = transaction_identity(packet, &network)?;
        let envelope = &packet[4..4 + length];
        if id != expected {
            return Err("pending transaction identity differs".into());
        }
        if self.pending.contains(&id) {
            let existing = zeroize::Zeroizing::new(
                self.transaction_packet(&id)?
                    .ok_or("pending packet unavailable")?,
            );
            deadline
                .check()
                .map_err(|_| "pending transaction deadline elapsed")?;
            return if existing.as_slice() == packet {
                Ok(id)
            } else {
                Err("pending retry differs from admitted packet".into())
            };
        }
        self.pending
            .submit_encoded(
                self.store.engine().state().chain(),
                PeerId(peer),
                envelope,
                Some(&packet[4 + length..]),
                &TimedAdmission {
                    verifier: &self.verifier,
                    deadline,
                },
            )
            .map_err(|_| "pending transaction admission rejected".into())
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(crate) fn submit_local_transaction(
        &mut self,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        deadline
            .check()
            .map_err(|_| "pending transaction deadline elapsed")?;
        let network = self.store.engine().state().network();
        let (id, _) = transaction_identity(packet, &network)?;
        let peer = blake3::derive_key(
            "siworld eng2 owner local submission v1",
            &self.store.engine().genesis().id(),
        );
        self.submit_transaction_before(peer, id, packet, deadline)
    }
    pub fn padding_count(&self) -> usize {
        self.padding.len()
    }
    pub fn padding_bytes(&self) -> usize {
        self.padding.bytes()
    }

    /// A single bounded producer worker calls this, proves outside its owner
    /// lock, then returns the completed padding for independent admission.
    pub fn prepare_padding(&mut self) -> Result<Option<PreparedPadding>, String> {
        self.store.ensure_exportable()?;
        self.padding.prune(self.store.engine().state().chain())?;
        if !self.padding.can_grow() {
            return Ok(None);
        }
        prepare_padding_witness(self.store.engine().state().chain()).map(Some)
    }
    pub fn insert_padding(&mut self, padding: Padding) -> Result<(), String> {
        self.store.ensure_exportable()?;
        self.padding
            .insert(self.store.engine().state().chain(), padding, &self.verifier)
    }
    pub fn prepare_block(
        &mut self,
        count: usize,
        timestamp: u64,
        settings: &MiningSettings,
    ) -> Result<PreparedBlock, String> {
        self.prepare_block_with_operations(count, timestamp, settings, None, Vec::new())
    }
    pub fn prepare_block_with_operations(
        &mut self,
        count: usize,
        timestamp: u64,
        settings: &MiningSettings,
        operations: Option<crate::eng2_operations::PendingOperations>,
        issuances: Vec<crate::issuance::IssuanceRecord>,
    ) -> Result<PreparedBlock, String> {
        self.store.ensure_exportable()?;
        if !(crate::wire::MIN_SLOTS..=crate::wire::MAX_SLOTS).contains(&count)
            || !count.is_multiple_of(crate::wire::GROUP)
        {
            return Err("production position count rejected".into());
        }
        let state = self.store.engine().state().chain();
        self.padding.prune(state)?;
        let mut positions = self
            .pending
            .select(state, count)
            .map_err(|_| "pending transaction selection rejected")?;
        positions.extend(self.padding.take_for_fill(state, count - positions.len())?);
        producer::prepare(
            self.store.engine(),
            positions,
            timestamp,
            settings,
            operations,
            issuances,
        )
    }
    pub fn prepare_work(&self, proved: ProvedBlock) -> Result<Work, String> {
        self.store.ensure_exportable()?;
        proved.prepare_work(self.store.engine(), &self.verifier)
    }
}

impl super::network::Owner for Driver {
    fn head(&self) -> Result<(u64, Hash), String> {
        let head = Driver::head(self)?;
        Ok((head.height, head.id))
    }
    fn header(&self, height: u64) -> Result<Option<Header>, String> {
        let head = Driver::head(self)?;
        if height == 0 || height > head.height {
            return Ok(None);
        }
        Driver::header(self, height).map(Some)
    }
    fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
        let head = Driver::head(self)?;
        if height == 0 || height > head.height {
            return Ok(None);
        }
        Driver::block_size(self, height).map(Some)
    }
    fn block(&self, height: u64) -> Result<(Header, Body), String> {
        Driver::block(self, height)
    }
    fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String> {
        Driver::accept(self, header, body).map(|_| ())
    }
}

#[cfg(all(unix, feature = "eng2-runtime"))]
impl super::transaction_exchange::Owner for Driver {
    fn transaction_ids(&self) -> Vec<Hash> {
        Driver::transaction_ids(self)
    }
    fn has_transaction(&self, id: &Hash) -> bool {
        Driver::has_transaction(self, id)
    }
    fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        Driver::transaction_packet(self, id)
    }
    fn submit_transaction(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        self.submit_transaction_before(peer, expected, packet, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn late_verification_or_final_commit_never_inserts_pending_work() {
        use crate::admission::{AdmissionVerifier, VerificationError};
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        struct Late {
            clock: Arc<AtomicU64>,
            after_verify: bool,
        }
        impl AdmissionVerifier for Late {
            fn verify(
                &self,
                _: &native::codec::PublicTransaction,
                _: &native::codec::ProofContext,
                _: &native::multi_asset::Digest,
                _: &native::multi_asset::Digest,
                _: &[u8],
            ) -> Result<(), VerificationError> {
                if self.after_verify {
                    self.clock.store(20_000, Ordering::Relaxed);
                }
                Ok(())
            }
            fn check_commit(&self) -> Result<(), VerificationError> {
                if !self.after_verify {
                    self.clock.store(20_000, Ordering::Relaxed);
                }
                Ok(())
            }
        }
        let state = super::super::snapshot::tests::bootstrap().chain;
        let mut transaction = crate::fixtures::candidate(&state, 2_500_000)
            .transactions
            .remove(0);
        transaction.record.fee_commit = native::codec::encode_digest(
            &native::multi_asset::Hasher::new()
                .fee_commit(0, &[native::multi_asset::F::default(); 8]),
        );
        let id = transaction.record.statement_id(&state.config.network);
        let sidecar = crate::wire::Sidecar {
            transaction_id: id,
            fee: 0,
            blind: [0; 8],
        }
        .encode()
        .unwrap();
        let envelope = transaction.encode_envelope(&state.config.network).unwrap();
        for after_verify in [true, false] {
            let clock = Arc::new(AtomicU64::new(0));
            let deadline =
                crate::p2p::Deadline::test_clock(std::time::Duration::from_secs(10), clock.clone());
            let late = Late {
                clock: clock.clone(),
                after_verify,
            };
            let mut pool = Mempool::new(state.config.network);
            assert!(
                pool.submit_encoded(
                    &state,
                    PeerId([7; 32]),
                    &envelope,
                    Some(&sidecar),
                    &TimedAdmission {
                        verifier: &late,
                        deadline: &deadline
                    }
                )
                .is_err()
            );
            assert_eq!(clock.load(Ordering::Relaxed), 20_000);
            assert!(pool.is_empty());
            assert_eq!(pool.bytes(), 0);
            assert_eq!(pool.peer_count(), 0);
        }
    }
    #[test]
    fn resident_owner_rejects_synthetic_native_proofs_without_publication() {
        let initial = super::super::snapshot::tests::bootstrap();
        let genesis = super::super::genesis::Genesis::seal(
            initial.chain.config.clone(),
            initial.governance.clone(),
            super::super::genesis::FeeMode::LegacyMiner,
        )
        .unwrap();
        let imports = ImportLimits {
            chain: super::super::state_components::Limits {
                max_leaves: 10_000,
                max_nullifiers: 10_000,
                max_component_bytes: 16 * 1024 * 1024,
            },
            max_snapshot_bytes: 32 * 1024 * 1024,
        };
        let directory = std::env::temp_dir().join(format!("eng2-driver-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("chain.redb");
        let store = Store::create(&path, genesis, imports.chain).unwrap();
        let mut owner = Driver::new(store, NativeVerifier::new().unwrap(), imports).unwrap();
        let head = owner.head().unwrap();
        assert_eq!(head.height, 0);
        assert!(
            super::super::network::Owner::header(&owner, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            super::super::network::Owner::block_size(&owner, 1)
                .unwrap()
                .is_none()
        );
        let mut pending = crate::fixtures::candidate(owner.engine().state().chain(), 2_500_000)
            .transactions
            .remove(0);
        pending.record.fee_commit = native::codec::encode_digest(
            &native::multi_asset::Hasher::new()
                .fee_commit(0, &[native::multi_asset::F::default(); 8]),
        );
        let pending_id = pending.record.statement_id(&head.network);
        let packet = crate::runtime::encode_gossip(
            &pending,
            &crate::wire::Sidecar {
                transaction_id: pending_id,
                fee: 0,
                blind: [0; 8],
            },
            &head.network,
        )
        .unwrap();
        assert!(
            owner
                .submit_transaction([7; 32], [8; 32], &packet)
                .unwrap_err()
                .contains("identity differs")
        );
        assert!(
            owner
                .submit_transaction([7; 32], pending_id, &packet)
                .is_err()
        );
        assert!(owner.transaction_ids().is_empty());
        assert_eq!(owner.head().unwrap(), head);
        // Seed only this retry-policy test through an explicit mock verifier.
        // The real Driver admission above rejected the same synthetic proof.
        struct Accepted;
        impl crate::admission::AdmissionVerifier for Accepted {
            fn verify(
                &self,
                _: &native::codec::PublicTransaction,
                _: &native::codec::ProofContext,
                _: &native::multi_asset::Digest,
                _: &native::multi_asset::Digest,
                _: &[u8],
            ) -> Result<(), crate::admission::VerificationError> {
                Ok(())
            }
        }
        let envelope_length = u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize;
        owner
            .pending
            .submit_encoded(
                owner.store.engine().state().chain(),
                PeerId([7; 32]),
                &packet[4..4 + envelope_length],
                Some(&packet[4 + envelope_length..]),
                &Accepted,
            )
            .unwrap();
        assert_eq!(
            owner
                .submit_transaction([7; 32], pending_id, &packet)
                .unwrap(),
            pending_id
        );
        let mut different = packet.clone();
        different[4 + envelope_length - 1] ^= 1;
        assert!(
            owner
                .submit_transaction([7; 32], pending_id, &different)
                .unwrap_err()
                .contains("retry differs")
        );
        assert_eq!(owner.transaction_ids(), vec![pending_id]);
        assert_eq!(owner.head().unwrap(), head);
        owner.pending.remove(&pending_id);
        let old = crate::fixtures::candidate(owner.engine().state().chain(), 2_500_000);
        let body = Body {
            network: old.network,
            height: old.height,
            profile: owner.engine().body_policy().profile,
            transactions: old.transactions,
            reward_mode: old.reward_mode,
            rewards: old.rewards,
            fee_output: super::super::execution::legacy_fee_output(),
            fund_claims: Vec::new(),
            governance: Vec::new(),
            issuances: Vec::new(),
            settlement_proof: vec![1],
        };
        let header = Header {
            network: body.network,
            height: body.height,
            parent: head.id,
            timestamp: old.timestamp,
            target: old.target,
            execution_commitment: [3; 32],
            body_commitment: body.commitment(owner.engine().body_policy()).unwrap(),
            nonce: 0,
        };
        assert!(owner.accept(&header, &body).is_err());
        assert_eq!(owner.head().unwrap(), head);
        assert_eq!(owner.padding_count(), 0);
        assert!(owner.last_archive_error().is_none());
        assert!(owner.block(1).is_err());
        drop(owner);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
