//! Explicit signed-checkpoint admission, separate from automatic synchronization.
//! Verification writes no files and exposes no accepted Store or signing handle.

use super::{
    admission::AdmissionPlan,
    body::Body,
    certificate::{AuthorizationWitness, Certificate, CurrentOutcome},
    execution::Engine,
    genesis::{FeeMode, Genesis},
    header::Header,
    runtime_export::{CHECKPOINT_CONFIRMATIONS, CHECKPOINT_INTERVAL},
    snapshot::{ImportLimits, ImportedAnchor},
    wallet_history::codec::{Context, MAX_RECEIPT_BYTES, ReceiptBlock},
};
use crate::{proofs::NativeVerifier, wire::Hash};
use native::{
    codec::{PublicTransaction, decode_digest, encode_digest},
    multi_asset::{Hasher, RecentRoots},
};
use std::collections::BTreeSet;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub struct Policy {
    pub state: ImportLimits,
    pub max_headers: usize,
    pub max_verification_bytes: u64,
}

/// An owner-selected bounded byte source, not an authenticated chain selector.
/// The AdmissionPlan independently validates complete headers and the explicit
/// work floor; the importer requires a current signed certificate. Implementors
/// must honor each read cap. Installation rereads every verified source row.
pub trait Source {
    fn receipt(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String>;
    fn body(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String>;
}

pub struct Input<'a> {
    pub genesis: &'a [u8],
    pub pinned_genesis: Hash,
    pub plan: &'a AdmissionPlan,
    pub certificate: &'a [u8],
    pub witness: &'a [u8],
    pub snapshot: &'a [u8],
}

#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(super) struct Row {
    pub digest: Hash,
    pub length: usize,
    pub body_length: usize,
}

/// Constructible only after signed snapshot reconstruction, permanent-history
/// comparison, complete actual native tail execution and current-roster checks.
/// This capability still does not mean installation or network readiness.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub struct VerifiedImport {
    pub(super) engine: Engine,
    pub(super) headers: Vec<Header>,
    pub(super) anchor: u64,
    pub(super) receipts: Vec<Row>,
    pub(super) bodies: Vec<Row>,
    pub(super) certificate: Vec<u8>,
    pub(super) witness: Vec<u8>,
    pub(super) snapshot: Vec<u8>,
    verification_bytes: u64,
}
/// Directory durability follows atomic canonical admission. An I/O failure at
/// that boundary is reported separately; it must never invite an overwrite or
/// silently assert startup readiness.
pub enum Installation {
    Durable(Box<super::store::Store>),
    DurabilityUnconfirmed,
}
impl VerifiedImport {
    pub fn height(&self) -> u64 {
        self.engine.state().height()
    }
    pub fn tip(&self) -> Hash {
        self.engine.state().tip()
    }
    pub fn checkpoint_height(&self) -> u64 {
        self.anchor
    }
    /// Logical input bytes validated once, excluding header acquisition,
    /// installation rereads and transport overhead. This is not network volume.
    pub fn verification_bytes(&self) -> u64 {
        self.verification_bytes
    }
}

fn check_cancel(canceled: &impl Fn() -> bool) -> Result<(), String> {
    if canceled() {
        Err("explicit checkpoint import canceled before admission".into())
    } else {
        Ok(())
    }
}
fn charge(total: &mut u64, bytes: usize, maximum: u64) -> Result<(), String> {
    *total = total
        .checked_add(bytes as u64)
        .filter(|total| *total <= maximum)
        .ok_or("checkpoint import verification byte budget exceeded")?;
    Ok(())
}

fn replay_governance(
    state: &mut crate::eng2_governance::GovernanceState,
    height: u64,
    records: &[Vec<u8>],
) -> Result<(), String> {
    let actions = records
        .iter()
        .map(|record| crate::eng2_governance::SignedAction::decode(record))
        .collect::<Result<Vec<_>, _>>()?;
    state.apply_block(height, &actions)?;
    Ok(())
}

fn check_governance_lineage(
    actual: &crate::eng2_governance::GovernanceState,
    expected: &[u8],
) -> Result<(), String> {
    if actual.canonical_component_bytes()? != expected {
        return Err("checkpoint governance does not descend from pinned genesis".into());
    }
    Ok(())
}

fn preflight(
    input: &Input<'_>,
    policy: Policy,
) -> Result<(Genesis, Certificate, AuthorizationWitness), String> {
    if input.pinned_genesis == [0; 32]
        || policy.max_headers == 0
        || policy.max_verification_bytes == 0
        || input.genesis.len() > 1024 * 1024
        || input.snapshot.len() > policy.state.max_snapshot_bytes
    {
        return Err("checkpoint import input or policy bound rejected".into());
    }
    let genesis = Genesis::decode(input.genesis)?;
    if genesis.id() != input.pinned_genesis || genesis.fee_mode() != FeeMode::LegacyMiner {
        return Err("checkpoint import differs from pinned genesis or fee mode".into());
    }
    let pin = input.plan.pin();
    let rules = input.plan.headers().rules();
    let config = genesis.config();
    let tail = pin
        .tip_height
        .checked_sub(pin.anchor_height)
        .ok_or("checkpoint above selected head")?;
    if pin.genesis != genesis.id()
        || rules.genesis != genesis.id()
        || rules.network != config.network
        || rules.genesis_timestamp != config.genesis_timestamp
        || rules.genesis_target != config.genesis_target
        || rules.target_interval != config.target_interval
        || rules.pow_iterations != config.pow_iterations
        || pin.tip_height > policy.max_headers as u64
        || pin.anchor_height == 0
        || !pin.anchor_height.is_multiple_of(CHECKPOINT_INTERVAL)
        || !(CHECKPOINT_CONFIRMATIONS..=super::selection::TAIL_BLOCKS).contains(&tail)
    {
        return Err("signed checkpoint plan, complete rules or retained tail rejected".into());
    }
    let certificate = Certificate::decode(input.certificate, config.network)
        .map_err(|_| "checkpoint certificate framing rejected")?;
    let statement = &certificate.statement;
    if statement.checkpoint_height != pin.anchor_height
        || statement.checkpoint_block != pin.anchor_id
        || statement.authorization_height < pin.anchor_height + CHECKPOINT_CONFIRMATIONS
        || statement.authorization_height > pin.tip_height
        || super::runtime_export::eligible_checkpoint(statement.authorization_height)
            != Some(pin.anchor_height)
    {
        return Err("checkpoint certificate is outside selected confirmed ancestry".into());
    }
    let witness =
        AuthorizationWitness::decode(input.witness, policy.state.chain.max_component_bytes)
            .map_err(|_| "checkpoint authorization witness framing rejected")?;
    let included = witness
        .verify_binding(
            statement,
            input.plan.headers(),
            policy.state.chain.max_component_bytes,
        )
        .map_err(|_| "checkpoint signer witness is outside selected header history")?;
    let governance = crate::eng2_governance::GovernanceState::decode_component(
        included.bytes(),
        included.network(),
    )?;
    let roster = governance.active_roster();
    if governance.height() != statement.authorization_height
        || roster.activated_height > statement.authorization_height
        || roster.epoch_sequence != statement.roster_sequence
        || roster.digest(config.network) != statement.roster_digest
    {
        return Err("checkpoint authorization roster binding rejected".into());
    }
    // Cryptographic validity is provisional. Prefix governance is replayed
    // from pinned genesis before the witness can establish signer authority.
    certificate
        .check_signatures(roster.keys())
        .map_err(|_| "checkpoint requires two distinct authorized signatures")?;
    Ok((genesis, certificate, witness))
}

/// Validate untrusted bytes without touching any destination. A canceled or
/// rejected call cannot create a database, restart seal, key or service status.
pub fn verify(
    input: Input<'_>,
    source: &mut impl Source,
    policy: Policy,
    canceled: impl Fn() -> bool,
) -> Result<VerifiedImport, String> {
    check_cancel(&canceled)?;
    let (genesis, certificate, witness) = preflight(&input, policy)?;
    let mut verification_bytes = 0;
    for bytes in [
        input.genesis,
        input.certificate,
        input.witness,
        input.snapshot,
    ] {
        charge(
            &mut verification_bytes,
            bytes.len(),
            policy.max_verification_bytes,
        )?;
    }
    let bootstrap = genesis.initial_state()?;
    let anchor = ImportedAnchor::reconstruct(
        input.plan,
        &bootstrap,
        genesis.rules_commitment(),
        input.snapshot,
        policy.state,
    )?;
    let context = Context::from_genesis(input.genesis, input.pinned_genesis)?;
    let expected = anchor.state().chain();
    let mut tree = crate::state::CommitmentTree::new();
    let mut spends = BTreeSet::new();
    let mut leaves = 0;
    let mut registry = crate::issuance::AssetRegistry::default();
    let mut governance = genesis.initial_governance().clone();
    let hasher = Hasher::new();
    let mut roots = RecentRoots::new();
    roots.insert(&hasher, 0, &tree.root(), genesis.fee_mode().base_fee(0)?);
    if let Some(snapshot) = expected.snapshots.iter().find(|s| s.selector.height == 0)
        && (snapshot.commitment_root != encode_digest(&tree.root())
            || snapshot.recent_root != encode_digest(&roots.tree(&hasher).root()))
    {
        return Err("permanent receipt genesis roots differ from checkpoint snapshots".into());
    }
    let pin = input.plan.pin();
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(pin.tip_height as usize)
        .map_err(|_| "import header allocation failed")?;
    for height in 1..=pin.tip_height {
        headers.push(
            input
                .plan
                .headers()
                .header(height)
                .ok_or("selected import header missing")?
                .clone(),
        );
    }
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(pin.anchor_height as usize)
        .map_err(|_| "import receipt index allocation failed")?;
    for height in 1..=pin.anchor_height {
        check_cancel(&canceled)?;
        let bytes = source.receipt(height, MAX_RECEIPT_BYTES)?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err("import receipt exceeds byte cap".into());
        }
        charge(
            &mut verification_bytes,
            bytes.len(),
            policy.max_verification_bytes,
        )?;
        let header = &headers[height as usize - 1];
        let encoded = header
            .encode()
            .map_err(|_| "selected receipt header rejected")?;
        let receipt = ReceiptBlock::decode(&context, &encoded, &bytes)?;
        replay_governance(&mut governance, height, receipt.governance_records())?;
        for output in receipt.outputs()? {
            let leaf = decode_digest(&output).map_err(|_| "import receipt commitment rejected")?;
            if expected.leaves.get(leaves) != Some(&leaf) || leaves >= policy.state.chain.max_leaves
            {
                return Err("permanent receipt leaves differ from checkpoint snapshot".into());
            }
            tree.append(leaf)?;
            leaves += 1;
        }
        for transaction in receipt.transactions() {
            let public = PublicTransaction::decode(&transaction.body)
                .map_err(|_| "import receipt transaction fields rejected")?;
            for nf in public.nf {
                if !spends.insert(encode_digest(&nf))
                    || spends.len() > policy.state.chain.max_nullifiers
                {
                    return Err("duplicate or oversized permanent receipt nullifier set".into());
                }
            }
        }
        for issuance in receipt.issuances() {
            registry.apply(issuance, height)?;
        }
        roots.insert(
            &hasher,
            height,
            &tree.root(),
            genesis.fee_mode().base_fee(height)?,
        );
        if let Some(snapshot) = expected
            .snapshots
            .iter()
            .find(|snapshot| snapshot.selector.height == height)
            && (snapshot.commitment_root != encode_digest(&tree.root())
                || snapshot.recent_root != encode_digest(&roots.tree(&hasher).root()))
        {
            return Err("permanent receipt roots differ from checkpoint snapshots".into());
        }
        receipts.push(Row {
            digest: *blake3::hash(&bytes).as_bytes(),
            length: bytes.len(),
            body_length: receipt.body_bytes(),
        });
    }
    let mut actual_registry = Vec::new();
    registry.visit_encoding(&mut |part| actual_registry.extend_from_slice(part));
    let mut expected_registry = Vec::new();
    expected
        .assets
        .visit_encoding(&mut |part| expected_registry.extend_from_slice(part));
    if leaves != expected.leaves.len()
        || spends != expected.spent
        || tree.root() != expected.tree.root()
        || actual_registry != expected_registry
    {
        return Err("permanent receipt history does not reconstruct checkpoint chain data".into());
    }
    check_governance_lineage(
        &governance,
        &anchor.state().governance().canonical_component_bytes()?,
    )?;
    let mut engine = Engine::from_imported_anchor(genesis, anchor, policy.state.chain)?;
    let verifier = NativeVerifier::new()?;
    let mut bodies = Vec::new();
    for height in pin.anchor_height + 1..=pin.tip_height {
        check_cancel(&canceled)?;
        let bytes = source.body(height, engine.body_policy().max_body_bytes)?;
        charge(
            &mut verification_bytes,
            bytes.len(),
            policy.max_verification_bytes,
        )?;
        let body = Body::decode(&bytes, pin.network, height, engine.body_policy())?;
        let header = &headers[height as usize - 1];
        engine.apply(header, &body, &verifier)?;
        if height == certificate.statement.authorization_height {
            check_governance_lineage(engine.state().governance(), &witness.governance)?;
        }
        check_cancel(&canceled)?;
        bodies.push(Row {
            digest: *blake3::hash(&bytes).as_bytes(),
            length: bytes.len(),
            body_length: bytes.len(),
        });
    }
    if engine.state().height() != pin.tip_height
        || engine.state().tip() != pin.tip_id
        || engine.state().chain().cumulative_work != pin.cumulative_work
        || certificate
            .evaluate_current(
                &witness,
                input.plan,
                engine.state().governance(),
                policy.state.chain.max_component_bytes,
            )
            .map_err(|_| "executed current checkpoint roster evaluation failed")?
            != CurrentOutcome::Consistent
    {
        return Err(
            "checkpoint is stale, conflicting or outside the executed current roster".into(),
        );
    }
    check_cancel(&canceled)?;
    Ok(VerifiedImport {
        engine,
        headers,
        anchor: pin.anchor_height,
        receipts,
        bodies,
        certificate: input.certificate.to_vec(),
        witness: input.witness.to_vec(),
        snapshot: input.snapshot.to_vec(),
        verification_bytes,
    })
}
