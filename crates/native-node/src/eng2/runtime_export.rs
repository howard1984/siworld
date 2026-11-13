//! Public exports and checkpoint candidates derived only from a durable eng2 store.
//! This module neither initializes keys nor creates a listener or service loop.
use super::{
    certificate::{AuthorizationWitness, Certificate, Statement, Vote},
    commitment::{self, Component, ComponentId},
    header::Header,
    snapshot::{ImportLimits, SnapshotState},
    state_components::Binding,
    store::Store,
};
use crate::{
    eng2_governance::{ActiveRoster, GovernanceState},
    eng2_operations::projection::{ProjectionHead, issuance_fee_projection},
    wire::Hash,
};
#[cfg(unix)]
use libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey;
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
use serde_json::{Value, json};

pub mod archive_work;
#[cfg(unix)]
mod preparation;
#[cfg(test)]
use super::commitment::Descriptor;

pub const CHECKPOINT_INTERVAL: u64 = 12;
pub const LEGACY_CHECKPOINT_INTERVAL: u64 = 72;
pub const CHECKPOINT_CONFIRMATIONS: u64 = 24;
/// Nominal cadence at the five-minute target; publication follows block height.
pub const PUBLICATION_INTERVAL_SECONDS: u64 = 60 * 60;
pub const STALE_SECONDS: u64 = 18 * 60 * 60;
pub const MAX_PROJECTION_BYTES: usize = 131072;
#[cfg(unix)]
mod files;
#[cfg(unix)]
pub use files::{PublicExport, WalletPolicy, WalletProgress, WalletPublisher};
#[cfg(unix)]
pub mod host;
#[cfg(unix)]
mod retained;

/// The newest eligible actual archive height; no height is synthesized.
pub fn eligible_checkpoint(head: u64) -> Option<u64> {
    let height =
        head.checked_sub(CHECKPOINT_CONFIRMATIONS)? / CHECKPOINT_INTERVAL * CHECKPOINT_INTERVAL;
    (height > 0).then_some(height)
}

/// Check confirmation depth independently of the publisher's local cadence.
/// Signature, authorized roster and selected-chain checks remain separate gates.
pub fn confirmed_checkpoint(height: u64, authorization: u64) -> bool {
    height > 0
        && authorization
            .checked_sub(height)
            .is_some_and(|depth| depth >= CHECKPOINT_CONFIRMATIONS)
}

pub(super) fn pending_obsolete(height: u64, published: Option<u64>, head: u64) -> bool {
    published.is_some_and(|latest| height <= latest)
        || eligible_checkpoint(head).is_some_and(|eligible| height < eligible)
}

/// An independently matched anchor and authenticated current signer context.
/// There is no public constructor from arbitrary bytes or claimed descriptors.
pub struct PreparedCheckpoint {
    network: Hash,
    genesis: Hash,
    rules: Hash,
    anchor: Header,
    authorization: Header,
    roster: ActiveRoster,
    statement: Statement,
    witness: AuthorizationWitness,
    snapshot: Vec<u8>,
    _snapshot_reservation: Option<crate::p2p::Reservation>,
}
pub struct CertifiedCheckpoint {
    prepared: PreparedCheckpoint,
    certificate: Certificate,
    published: u64,
}
impl PreparedCheckpoint {
    /// Read only the actual durable boundary archived by the resident driver.
    pub fn prepare_from_archive(
        store: &Store,
        limits: ImportLimits,
    ) -> Result<Option<Self>, String> {
        store.ensure_exportable()?;
        let Some(height) = eligible_checkpoint(store.engine().state().height()) else {
            return Ok(None);
        };
        Self::prepare(store, &store.checkpoint_anchor(height, limits)?, limits)
    }
    /// Restore an exact unsigned public candidate after a restart. Both its
    /// historical state and authorization witness are checked against the local
    /// executed chain; input bytes cannot create an unchecked signing capability.
    pub fn restore(
        store: &Store,
        statement: Statement,
        witness: AuthorizationWitness,
        snapshot: Vec<u8>,
        limits: ImportLimits,
    ) -> Result<Self, String> {
        let value = Self::restore_prefix(store, statement, witness, snapshot, limits)?;
        value.check_current(store)?;
        Ok(value)
    }
    fn restore_prefix(
        store: &Store,
        statement: Statement,
        witness: AuthorizationWitness,
        snapshot: Vec<u8>,
        limits: ImportLimits,
    ) -> Result<Self, String> {
        if statement.authorization_height > store.engine().state().height() {
            return Err("saved checkpoint authorization is above the canonical prefix".into());
        }
        let anchor = saved_anchor(store, &statement, &snapshot, limits)?;
        let authorization = store.header(statement.authorization_height)?;
        exact_saved_header(
            &authorization,
            statement.network,
            statement.authorization_height,
            statement.authorization_block,
        )?;
        let roster = saved_roster(&statement, &witness, &authorization, limits)?;
        let value = Self {
            network: statement.network,
            genesis: store.engine().genesis().id(),
            rules: store.engine().genesis().rules_commitment(),
            anchor,
            authorization,
            roster,
            statement,
            witness,
            snapshot,
            _snapshot_reservation: None,
        };
        value.check_prefix(store)?;
        Ok(value)
    }

    /// A peer supplies no historical ledger. Reconstruct the snapshot from this
    /// node's own actual archive before comparing its complete signed context.
    pub fn from_proposal(
        store: &Store,
        statement: Statement,
        witness: AuthorizationWitness,
        limits: ImportLimits,
    ) -> Result<Self, String> {
        store.ensure_exportable()?;
        let header = store.header(statement.checkpoint_height)?;
        let archived = store.checkpoint_anchor(statement.checkpoint_height, limits)?;
        let engine = store.engine();
        let components = archived.canonical_components(
            Binding {
                genesis: engine.genesis().id(),
                rules_commitment: engine.genesis().rules_commitment(),
                parent: header.parent,
            },
            limits.chain,
        )?;
        Self::restore(
            store,
            statement,
            witness,
            super::snapshot::encode_components(&components, limits)?,
            limits,
        )
    }
    /// `anchor` must be the complete actual historical state returned by the
    /// durable archive, never a recent-root selector or current ledger relabel.
    pub fn prepare(
        store: &Store,
        anchor: &SnapshotState,
        limits: ImportLimits,
    ) -> Result<Option<Self>, String> {
        store.ensure_exportable()?;
        let state = store.engine().state();
        let Some(height) = eligible_checkpoint(state.height()) else {
            return Ok(None);
        };
        if anchor.height() != height || anchor.network() != state.network() {
            return Err("checkpoint anchor differs from the eligible archived height".into());
        }
        let engine = store.engine();
        let genesis = engine.genesis().id();
        let rules = engine.genesis().rules_commitment();
        let anchor_header = store.header(height)?;
        let authorization = store.header(state.height())?;
        let binding = Binding {
            genesis,
            rules_commitment: rules,
            parent: anchor_header.parent,
        };
        if anchor.tip()
            != anchor_header
                .id()
                .map_err(|_| "invalid checkpoint anchor header")?
            || anchor.execution_commitment(binding, limits.chain)?
                != anchor_header.execution_commitment
            || anchor.chain().cumulative_work > state.chain().cumulative_work
        {
            return Err(
                "checkpoint anchor state differs from its executed canonical header".into(),
            );
        }
        let components = anchor.canonical_components(binding, limits.chain)?;
        let snapshot = super::snapshot::encode_components(&components, limits)?;
        let current_binding = Binding {
            genesis,
            rules_commitment: rules,
            parent: authorization.parent,
        };
        let witness = state.checkpoint_witness(current_binding, limits.chain)?;
        if commitment::aggregate_descriptors(
            state.network(),
            state.height(),
            authorization.parent,
            &witness.descriptors,
        )
        .map_err(|_| "invalid checkpoint authorization descriptors")?
            != authorization.execution_commitment
        {
            return Err("checkpoint authorization differs from the executed current header".into());
        }
        let roster = state.governance().active_roster().clone();
        let statement = Statement {
            network: state.network(),
            checkpoint_height: height,
            checkpoint_block: anchor.tip(),
            authorization_height: state.height(),
            authorization_block: state.tip(),
            roster_sequence: roster.epoch_sequence,
            roster_digest: roster.digest(state.network()),
        };
        statement
            .encode()
            .map_err(|_| "invalid prepared checkpoint statement")?;
        witness
            .encode(limits.chain.max_component_bytes)
            .map_err(|_| "invalid prepared checkpoint witness")?;
        let prepared = Self {
            network: state.network(),
            genesis,
            rules,
            anchor: anchor_header,
            authorization,
            roster,
            statement,
            witness,
            snapshot,
            _snapshot_reservation: None,
        };
        prepared.check_current(store)?;
        Ok(Some(prepared))
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn witness(&self) -> &AuthorizationWitness {
        &self.witness
    }
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.snapshot
    }
    pub fn check_current(&self, store: &Store) -> Result<(), String> {
        self.check_prefix(store)?;
        if store
            .engine()
            .state()
            .governance()
            .active_roster()
            .digest(self.network)
            != self.roster.digest(self.network)
        {
            return Err("checkpoint signer epoch is no longer current".into());
        }
        Ok(())
    }
    fn check_prefix(&self, store: &Store) -> Result<(), String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let state = engine.state();
        if state.network() != self.network
            || engine.genesis().id() != self.genesis
            || engine.genesis().rules_commitment() != self.rules
            || state.height() < self.authorization.height
            || store.header(self.anchor.height)? != self.anchor
            || store.header(self.authorization.height)? != self.authorization
        {
            return Err(
                "prepared checkpoint no longer matches the canonical current signer context".into(),
            );
        }
        Ok(())
    }
    pub fn verify_vote(&self, vote: &Vote) -> Result<(), String> {
        verify_saved_vote(&self.roster, &self.statement, vote)
    }
    /// The durable PublicExport journal must be used before transmitting a vote.
    #[cfg(unix)]
    fn sign(
        &self,
        store: &Store,
        slot: u8,
        key: &MLDSA65SigningKey,
        randomness: [u8; 32],
    ) -> Result<Vote, String> {
        self.check_current(store)?;
        let signature = ml_dsa_65::sign(
            key,
            &self
                .statement
                .encode()
                .map_err(|_| "invalid checkpoint statement")?,
            Statement::signing_context(),
            randomness,
        )
        .map_err(|_| "checkpoint signing failed")?;
        let vote = Vote {
            slot,
            signature: *signature.as_ref(),
        };
        self.verify_vote(&vote)?;
        Ok(vote)
    }
    pub fn certify(
        self,
        store: &Store,
        votes: [Vote; 2],
        published: u64,
    ) -> Result<CertifiedCheckpoint, String> {
        self.check_current(store)?;
        let certificate = Certificate {
            statement: self.statement.clone(),
            votes,
        };
        certificate
            .check_signatures(self.roster.keys())
            .map_err(|_| "checkpoint requires two distinct authorized signatures")?;
        if published > (1u64 << 53) - 1 {
            return Err("checkpoint publication time exceeds projection bounds".into());
        }
        Ok(CertifiedCheckpoint {
            prepared: self,
            certificate,
            published,
        })
    }
}
impl CertifiedCheckpoint {
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
    pub fn witness(&self) -> &AuthorizationWitness {
        &self.prepared.witness
    }
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.prepared.snapshot
    }
    pub fn check_current(&self, store: &Store) -> Result<(), String> {
        self.prepared.check_current(store)
    }
}
/// Shared checks for durable current and retained obsolete records. This
/// returns an anchor header, never a signing or publication capability.
fn saved_anchor(
    store: &Store,
    statement: &Statement,
    snapshot: &[u8],
    limits: ImportLimits,
) -> Result<Header, String> {
    store.ensure_exportable()?;
    let state = store.engine().state();
    if statement.network != state.network()
        || !confirmed_checkpoint(statement.checkpoint_height, statement.authorization_height)
        || statement.checkpoint_height > state.height()
        || snapshot.len() > limits.max_snapshot_bytes
    {
        return Err("saved checkpoint has an invalid network, anchor or byte bound".into());
    }
    statement
        .encode()
        .map_err(|_| "invalid saved checkpoint statement")?;
    let anchor = store.header(statement.checkpoint_height)?;
    exact_saved_header(
        &anchor,
        statement.network,
        statement.checkpoint_height,
        statement.checkpoint_block,
    )?;
    let archived = store.checkpoint_anchor(statement.checkpoint_height, limits)?;
    let components = archived.canonical_components(
        Binding {
            genesis: store.engine().genesis().id(),
            rules_commitment: store.engine().genesis().rules_commitment(),
            parent: anchor.parent,
        },
        limits.chain,
    )?;
    if super::snapshot::encode_components(&components, limits)? != snapshot {
        return Err("saved checkpoint snapshot differs from durable historical state".into());
    }
    Ok(anchor)
}
fn exact_saved_header(header: &Header, network: Hash, height: u64, id: Hash) -> Result<(), String> {
    let bytes = header
        .encode()
        .map_err(|_| "saved checkpoint header framing invalid")?;
    let decoded = Header::decode(&bytes, &network)
        .map_err(|_| "saved checkpoint header network or framing invalid")?;
    if decoded != *header
        || header.height != height
        || header
            .id()
            .map_err(|_| "saved checkpoint header identity invalid")?
            != id
    {
        return Err("saved checkpoint header differs from its exact identity".into());
    }
    Ok(())
}
fn verify_saved_vote(
    roster: &ActiveRoster,
    statement: &Statement,
    vote: &Vote,
) -> Result<(), String> {
    let key = roster
        .keys()
        .get(usize::from(vote.slot))
        .ok_or("checkpoint vote slot is outside the fixed roster")?;
    ml_dsa_65::verify(
        &MLDSA65VerificationKey::new(*key),
        &statement
            .encode()
            .map_err(|_| "invalid checkpoint statement")?,
        Statement::signing_context(),
        &MLDSA65Signature::new(vote.signature),
    )
    .map_err(|_| "checkpoint vote does not authenticate the local candidate".into())
}
fn saved_roster(
    statement: &Statement,
    witness: &AuthorizationWitness,
    authorization: &Header,
    limits: ImportLimits,
) -> Result<ActiveRoster, String> {
    witness
        .encode(limits.chain.max_component_bytes)
        .map_err(|_| "invalid saved authorization witness")?;
    let governance_descriptor = Component::from_local_encoding(
        ComponentId::Governance,
        &witness.governance,
        limits.chain.max_component_bytes,
    )
    .map_err(|_| "checkpoint governance witness exceeds bounds")?
    .descriptor();
    if witness.descriptors[7] != governance_descriptor
        || commitment::aggregate_descriptors(
            statement.network,
            authorization.height,
            authorization.parent,
            &witness.descriptors,
        )
        .map_err(|_| "invalid checkpoint authorization descriptors")?
            != authorization.execution_commitment
    {
        return Err("saved checkpoint witness differs from its authorization header".into());
    }
    let governance = GovernanceState::decode_component(&witness.governance, statement.network)?;
    let roster = governance.active_roster().clone();
    if governance.height() != authorization.height
        || roster.activated_height > authorization.height
        || roster.epoch_sequence != statement.roster_sequence
        || roster.digest(statement.network) != statement.roster_digest
    {
        return Err("saved checkpoint witness does not authorize its signer epoch".into());
    }
    Ok(roster)
}
#[cfg(test)]
fn execution_descriptors(
    state: &SnapshotState,
    raw: &[Vec<u8>; 11],
    limits: ImportLimits,
) -> Result<[Descriptor; 11], String> {
    // Permanent tree/nullifier encodings are reconstruction data. Their execution
    // descriptors use the exact compact encoders called by the shared engine.
    let tree = super::state_components::tree_execution_encoding(&state.chain().tree);
    let nullifiers = state.nullifiers.execution_encoding();
    commitment::COMPONENTS
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            let bytes = match id {
                ComponentId::CommitmentTree => tree.as_slice(),
                ComponentId::Nullifiers => nullifiers.as_slice(),
                _ => raw[index].as_slice(),
            };
            Component::from_local_encoding(id, bytes, limits.chain.max_component_bytes)
                .map(|c| c.descriptor())
                .map_err(|_| "checkpoint component exceeds byte bound".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "checkpoint component cardinality differs".into())
}

/// One explicit read of the actual durable head. There is no fee aggregation,
/// slot classification, address lookup or historical native-proof execution.
pub fn public_projection(
    store: &Store,
    published: u64,
    checkpoint: Option<&CertifiedCheckpoint>,
) -> Result<Value, String> {
    store.ensure_exportable()?;
    let engine = store.engine();
    let state = engine.state();
    if state.height() > 1_000_000 || published > (1u64 << 53) - 1 {
        return Err("public projection exceeds engineering bounds".into());
    }
    let blocks = (state.height().saturating_sub(100).max(1)..=state.height())
        .map(|height| public_block(store, height))
        .collect::<Result<Vec<_>, _>>()?;
    projection_with_blocks(store, published, checkpoint, blocks)
}
fn public_block(store: &Store, height: u64) -> Result<Value, String> {
    let header = store.header(height)?;
    let (slots, reward_mode) = if let Some(bytes) = store.permanent_receipt(height)? {
        public_receipt_fields(
            store.engine().genesis(),
            &header,
            store.block_size(height)?,
            &bytes,
        )?
    } else {
        let (_, body) = store.block(height)?;
        (body.transactions.len(), body.reward_mode)
    };
    Ok(
        json!({"height":height,"hash":crate::local::hex(&header.id().map_err(|_| "invalid public header")?),
        "parent_hash":crate::local::hex(&header.parent),"timestamp":header.timestamp,"target":crate::local::hex(&header.target),
        "slots_including_padding":slots,"reward_mode":reward_mode.name(),
        "work":siworld_core::pow::block_work(&header.target).to_string()}),
    )
}
fn public_receipt_fields(
    genesis: &super::genesis::Genesis,
    header: &Header,
    body_bytes: usize,
    bytes: &[u8],
) -> Result<(usize, crate::wire::RewardMode), String> {
    use super::wallet_history::codec::{Context, ReceiptBlock};
    let context = Context::from_genesis(&genesis.encode()?, genesis.id())?;
    let encoded = header
        .encode()
        .map_err(|_| "invalid public receipt header")?;
    let receipt = ReceiptBlock::decode(&context, &encoded, bytes)?;
    if receipt.body_bytes() != body_bytes {
        return Err("public receipt body length differs from accepted index".into());
    }
    Ok((receipt.transactions().len(), receipt.reward_mode()))
}
fn projection_with_blocks(
    store: &Store,
    published: u64,
    checkpoint: Option<&CertifiedCheckpoint>,
    blocks: Vec<Value>,
) -> Result<Value, String> {
    store.ensure_exportable()?;
    let engine = store.engine();
    let state = engine.state();
    if state.height() > 1_000_000 || published > (1u64 << 53) - 1 {
        return Err("public projection exceeds engineering bounds".into());
    }
    let head = ProjectionHead {
        network: state.network(),
        genesis: engine.genesis().id(),
        height: state.height(),
        tip: state.tip(),
    };
    let economics = state.economics();
    let schedule = economics
        .locked_schedule()
        .iter()
        .take(64)
        .map(|(height, amount)| json!({"height":height,"atoms":amount.to_string()}))
        .collect::<Vec<_>>();
    let members = engine
        .genesis()
        .config()
        .fund_allocation
        .as_ref()
        .ok_or("missing immutable fund allocation")?
        .basis_points()
        .len();
    let funds = (0..members).map(|index| {let balance = state.fund().balance(index as u8)?;
        Ok(json!({"index":index,"entitled_atoms":balance.entitlement.to_string(),"released_atoms":balance.unlocked().map_err(|_| "invalid public fund release balance")?.to_string(),"spent_atoms":balance.spent.to_string()}))
    }).collect::<Result<Vec<_>,String>>()?;
    let checkpoint = if let Some(certified) = checkpoint {
        certified.prepared.check_prefix(store)?;
        let item = &certified.certificate.statement;
        Some(
            json!({"height":item.checkpoint_height,"hash":crate::local::hex(&item.checkpoint_block),
            "issued_unix_seconds":certified.published,
            "roster":crate::local::hex(&item.roster_digest),"signer_indices":certified.certificate.votes.iter().map(|v|v.slot).collect::<Vec<_>>()}),
        )
    } else {
        None
    };
    let value = json!({"version":2,"network":crate::local::hex(&head.network),"genesis":crate::local::hex(&head.genesis),
        "height":head.height,"tip":crate::local::hex(&head.tip),"published_unix_seconds":published,"blocks":blocks,
        "economics":{"issued_atoms":economics.issued().to_string(),"burned_atoms":economics.burned().to_string(),
            "holder_pool_atoms":economics.pool().to_string(),"locked_reward_atoms":economics.locked_total().to_string(),
            "unlock_schedule":schedule,"unlock_schedule_complete":economics.locked_schedule().len()<=64,"funds":funds,"circulating_estimate_atoms":null},
        "checkpoint":checkpoint,"governance":{"current_signers":null,"fee_address":null,"fund_addresses":null,"changes":null,
            "issuance_fee":issuance_fee_projection(engine,head)?}});
    if serde_json::to_vec(&value)
        .map_err(|_| "public projection encoding failed")?
        .len()
        > MAX_PROJECTION_BYTES
    {
        return Err("public projection exceeds byte bound".into());
    }
    store.ensure_exportable()?;
    Ok(value)
}

#[cfg(test)]
mod tests;
