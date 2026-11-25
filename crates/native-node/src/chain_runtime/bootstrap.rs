//! Read-only signed bootstrap offers from an actual durable service store.
//! Transfer hashes identify bytes; only the signed importer grants admission.
use super::{
    certificate::{AuthorizationWitness, Certificate},
    checkpoint_wire::{Incoming, MAX_CHECKPOINT_PACKET_BYTES, MAX_GOVERNANCE_BYTES},
    genesis::Genesis,
    runtime_export::{CHECKPOINT_CONFIRMATIONS, CertifiedCheckpoint},
    snapshot::ImportLimits,
    store::Store,
};
use crate::{p2p, wire::Hash};
use siworld_core::pow::Work;

const MAGIC: &[u8; 8] = b"SW2BOOT1";
const FIXED: usize = 8 + 4 * 32 + 8 + 32 + 64 + 8 + 32 + 4;
pub const MAX_MANIFEST_BYTES: usize = FIXED + MAX_CHECKPOINT_PACKET_BYTES + 32;
/// One artifact slice fits one ordinary bounded control response.
pub const MAX_CHUNK_BYTES: usize = p2p::MAX_CONTROL_BYTES - 160;
const _: () = assert!(MAX_MANIFEST_BYTES < p2p::MAX_CONTROL_BYTES - 1);
pub mod cache;
pub mod client;
pub(crate) mod leases;
pub use leases::BodyPins;
#[cfg(feature = "eng2-runtime")]
pub mod session;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub length: u64,
    pub digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    Snapshot,
    Receipt { height: u64, id: Hash },
}
pub struct Chunk {
    pub descriptor: Descriptor,
    pub bytes: Vec<u8>,
}
/// Decoded framing remains untrusted, including work, signers and state claims.
#[derive(Clone)]
pub struct Manifest {
    pub network: Hash,
    pub genesis: Hash,
    pub rules: Hash,
    pub profile: Hash,
    pub tip_height: u64,
    pub tip_id: Hash,
    pub cumulative_work: Work,
    pub snapshot: Descriptor,
    pub certificate: Certificate,
    pub witness: AuthorizationWitness,
    bundle: Hash,
}
impl Manifest {
    pub fn bundle(&self) -> Hash {
        self.bundle
    }
    pub fn checkpoint_height(&self) -> u64 {
        self.certificate.statement.checkpoint_height
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bytes = self.prefix()?;
        if *blake3::hash(&bytes).as_bytes() != self.bundle {
            return Err("bootstrap manifest binding changed".into());
        }
        bytes.extend_from_slice(&self.bundle);
        Ok(bytes)
    }
    fn prefix(&self) -> Result<Vec<u8>, String> {
        if self.witness.governance.len() > MAX_GOVERNANCE_BYTES {
            return Err("bootstrap manifest witness exceeds control bound".into());
        }
        let packet = Incoming::Certified {
            certificate: Box::new(self.certificate.clone()),
            witness: self.witness.clone(),
        }
        .encode(MAX_GOVERNANCE_BYTES)?;
        let mut bytes = Vec::with_capacity(FIXED + packet.len());
        bytes.extend_from_slice(MAGIC);
        for value in [self.network, self.genesis, self.rules, self.profile] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.tip_height.to_le_bytes());
        bytes.extend_from_slice(&self.tip_id);
        bytes.extend_from_slice(&self.cumulative_work.to_big_endian());
        bytes.extend_from_slice(&self.snapshot.length.to_le_bytes());
        bytes.extend_from_slice(&self.snapshot.digest);
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&packet);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis, limits: ImportLimits) -> Result<Self, String> {
        if bytes.len() < FIXED + 32 || bytes.len() > MAX_MANIFEST_BYTES || &bytes[..8] != MAGIC {
            return Err("bootstrap manifest version or length rejected".into());
        }
        let packet_length =
            u32::from_le_bytes(bytes[FIXED - 4..FIXED].try_into().expect("fixed width")) as usize;
        if packet_length.checked_add(FIXED + 32) != Some(bytes.len()) {
            return Err("bootstrap manifest packet length differs".into());
        }
        let binding = |offset| <Hash>::try_from(&bytes[offset..offset + 32]).expect("fixed width");
        let network = binding(8);
        if network != genesis.config().network
            || binding(40) != genesis.id()
            || binding(72) != genesis.rules_commitment()
            || binding(104) != crate::proofs::protocol_profile_fingerprint()
        {
            return Err("bootstrap manifest immutable context differs".into());
        }
        let Incoming::Certified {
            certificate,
            witness,
        } = Incoming::decode(
            &bytes[FIXED..FIXED + packet_length],
            network,
            limits.chain.max_component_bytes,
        )?
        else {
            return Err("bootstrap manifest requires a certificate packet".into());
        };
        let tip_height = u64::from_le_bytes(bytes[136..144].try_into().expect("fixed width"));
        let snapshot = Descriptor {
            length: u64::from_le_bytes(bytes[240..248].try_into().expect("fixed width")),
            digest: binding(248),
        };
        let statement = &certificate.statement;
        let tail = tip_height
            .checked_sub(statement.checkpoint_height)
            .ok_or("bootstrap anchor exceeds tip")?;
        if !(CHECKPOINT_CONFIRMATIONS..=super::selection::TAIL_BLOCKS).contains(&tail)
            || tip_height > 1_000_000
            || statement.authorization_height > tip_height
            || !super::runtime_export::confirmed_checkpoint(
                statement.checkpoint_height,
                statement.authorization_height,
            )
            || snapshot.length == 0
            || snapshot.length > limits.max_snapshot_bytes as u64
        {
            return Err("bootstrap manifest availability or size bound rejected".into());
        }
        let bundle = binding(bytes.len() - 32);
        if blake3::hash(&bytes[..bytes.len() - 32]).as_bytes() != &bundle {
            return Err("bootstrap manifest transfer binding differs".into());
        }
        Ok(Self {
            network,
            genesis: genesis.id(),
            rules: genesis.rules_commitment(),
            profile: binding(104),
            tip_height,
            tip_id: binding(144),
            cumulative_work: Work::from_big_endian(&bytes[176..240]),
            snapshot,
            certificate: *certificate,
            witness,
            bundle,
        })
    }
}

/// One bounded immutable offer, explicitly enabled only by the service owner.
/// No constructor accepts arbitrary snapshot bytes or an unsigned proposal.
pub struct Provider {
    manifest: Manifest,
    encoded: Vec<u8>,
    snapshot: Vec<u8>,
    _reservation: p2p::Reservation,
}
impl Provider {
    pub fn capture(
        store: &Store,
        certified: &CertifiedCheckpoint,
        limits: ImportLimits,
        budget: &p2p::Budget,
    ) -> Result<Self, String> {
        certified.check_current(store)?;
        let engine = store.engine();
        let state = engine.state();
        let certificate = certified.certificate();
        let anchor = certificate.statement.checkpoint_height;
        let tail = state
            .height()
            .checked_sub(anchor)
            .ok_or("bootstrap anchor exceeds durable head")?;
        if !(CHECKPOINT_CONFIRMATIONS..=super::selection::TAIL_BLOCKS).contains(&tail)
            || certified.snapshot_bytes().is_empty()
            || certified.snapshot_bytes().len() > limits.max_snapshot_bytes
            || certified.witness().governance.len() > MAX_GOVERNANCE_BYTES
        {
            return Err("bootstrap checkpoint is outside bounded availability".into());
        }
        // Serving requires already materialized accepted receipts. This read
        // never backfills proof data or performs native replay under the owner.
        for height in 1..=anchor {
            if store.permanent_receipt_descriptor(height)?.is_none() {
                return Err("bootstrap permanent receipt prefix is not materialized".into());
            }
        }
        for height in anchor + 1..=state.height() {
            let length = store.block_size(height)?;
            let charge = length
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(65536))
                .ok_or("bootstrap body availability memory overflow")?;
            let _body_charge = budget
                .reserve(charge)
                .map_err(|_| "bootstrap body availability memory unavailable")?;
            if store.body_availability(height)?
                != (super::store::BodyAvailability::Full {
                    encoded_body_bytes: length,
                })
            {
                return Err("bootstrap full native tail is unavailable".into());
            }
        }
        let charge = certified
            .snapshot_bytes()
            .len()
            .checked_add(MAX_MANIFEST_BYTES * 4)
            .ok_or("bootstrap provider memory bound overflow")?;
        let reservation = budget
            .reserve(charge)
            .map_err(|_| "bootstrap provider memory unavailable")?;
        let mut manifest = Manifest {
            network: state.network(),
            genesis: engine.genesis().id(),
            rules: engine.genesis().rules_commitment(),
            profile: crate::proofs::protocol_profile_fingerprint(),
            tip_height: state.height(),
            tip_id: state.tip(),
            cumulative_work: state.chain().cumulative_work,
            snapshot: Descriptor {
                length: certified.snapshot_bytes().len() as u64,
                digest: *blake3::hash(certified.snapshot_bytes()).as_bytes(),
            },
            certificate: certificate.clone(),
            witness: certified.witness().clone(),
            bundle: [0; 32],
        };
        manifest.bundle = *blake3::hash(&manifest.prefix()?).as_bytes();
        let encoded = manifest.encode()?;
        // Decode exactly the public offer before making the capability visible.
        Manifest::decode(&encoded, engine.genesis(), limits)?;
        Ok(Self {
            manifest,
            encoded,
            snapshot: certified.snapshot_bytes().to_vec(),
            _reservation: reservation,
        })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn check_current(&self, store: &Store) -> Result<(), String> {
        store.ensure_exportable()?;
        let state = store.engine().state();
        self.check_bindings(
            store.engine().genesis().id(),
            state.height(),
            state.governance().active_roster().digest(state.network()),
            |height| {
                store
                    .header(height)?
                    .id()
                    .map_err(|_| "bootstrap canonical header encoding invalid".into())
            },
        )
    }
    fn check_bindings(
        &self,
        genesis: Hash,
        height: u64,
        roster_digest: Hash,
        mut header_id: impl FnMut(u64) -> Result<Hash, String>,
    ) -> Result<(), String> {
        let statement = &self.manifest.certificate.statement;
        if genesis != self.manifest.genesis
            || height < self.manifest.tip_height
            || roster_digest != statement.roster_digest
            || header_id(self.manifest.tip_height)? != self.manifest.tip_id
            || header_id(statement.checkpoint_height)? != statement.checkpoint_block
            || header_id(statement.authorization_height)? != statement.authorization_block
        {
            return Err("bootstrap offer no longer matches current accepted history".into());
        }
        Ok(())
    }
    pub fn chunk(
        &self,
        store: &Store,
        bundle: Hash,
        object: Object,
        offset: u64,
        maximum: usize,
    ) -> Result<Option<Chunk>, String> {
        if bundle != self.manifest.bundle || maximum == 0 || maximum > MAX_CHUNK_BYTES {
            return Ok(None);
        }
        self.check_current(store)?;
        match object {
            Object::Snapshot => {
                let offset =
                    usize::try_from(offset).map_err(|_| "bootstrap offset exceeds range")?;
                if offset >= self.snapshot.len() {
                    return Ok(None);
                }
                let end = offset.saturating_add(maximum).min(self.snapshot.len());
                Ok(Some(Chunk {
                    descriptor: self.manifest.snapshot,
                    bytes: self.snapshot[offset..end].to_vec(),
                }))
            }
            Object::Receipt { height, id } => {
                if height == 0
                    || height > self.manifest.checkpoint_height()
                    || store
                        .header(height)?
                        .id()
                        .map_err(|_| "bootstrap receipt header invalid")?
                        != id
                {
                    return Ok(None);
                }
                store.permanent_receipt_chunk(height, offset, maximum)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
