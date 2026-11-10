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

pub struct Driver {
    store: Store,
    verifier: NativeVerifier,
    padding: Pool,
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
        let positions = self
            .padding
            .take(self.store.engine().state().chain(), count)?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
