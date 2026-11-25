//! Raw state reconstruction authenticated by a source-selected complete header.
//!
//! An imported anchor is not an admitted live node: its complete proof tail and
//! current optional certificate policy must still run in isolated storage.

use super::{
    admission::{AdmissionPlan, Pin},
    commitment::{COMPONENTS, SnapshotTip},
    state_components::{
        self, Binding, ChainComponents, ExecutionComponents, Limits, VersionedLedgers,
    },
};
use crate::{
    eng2_economics::EconomicState,
    eng2_fund::FundLedger,
    eng2_governance::GovernanceState,
    state::{Config, State},
    wire::Hash,
};

#[derive(Clone, Copy)]
pub struct ImportLimits {
    pub chain: Limits,
    pub max_snapshot_bytes: usize,
}

/// Actual reconstructed components. V1 economics inside the chain carrier is
/// unused; the versioned economic and fund ledgers are the authoritative state.
#[cfg_attr(test, derive(Clone))]
pub struct SnapshotState {
    pub(crate) fee_mode: super::genesis::FeeMode,
    pub(crate) chain: State,
    pub(crate) economics: EconomicState,
    pub(crate) fund: FundLedger,
    pub(crate) governance: GovernanceState,
    pub(crate) nullifiers: super::nullifiers::NullifierSet,
}
impl SnapshotState {
    /// Reconstruct a locally archived state already bound to a durably accepted
    /// complete header. This is not an incoming peer admission entry point.
    pub(super) fn from_committed_components(
        genesis: &super::genesis::Genesis,
        header: &super::header::Header,
        bytes: &[u8],
        limits: ImportLimits,
    ) -> Result<Self, String> {
        if header.network != genesis.config().network || header.height == 0 {
            return Err("archived state header context differs".into());
        }
        let raw = decode_components(bytes, limits)?;
        let binding = Binding {
            genesis: genesis.id(),
            rules_commitment: genesis.rules_commitment(),
            parent: header.parent,
        };
        let chain = ChainComponents::reconstruct_for_fee_mode(
            genesis.config().clone(),
            binding,
            header.id().map_err(|_| "invalid archived header")?,
            [raw[0], raw[1], raw[2], raw[3], raw[10]],
            limits.chain,
            genesis.fee_mode(),
        )?;
        let economics = EconomicState::from_components(
            header.network,
            header.height,
            [raw[4], raw[8], raw[9]],
        )?;
        let fund = FundLedger::decode_component(
            raw[5],
            header.network,
            genesis
                .config()
                .fund_allocation
                .as_ref()
                .ok_or("missing archived fund allocation")?,
        )?;
        let governance = GovernanceState::decode_component(raw[7], header.network)?;
        if governance.canonical_fee_destination_bytes()? != raw[6] {
            return Err("archived fee destination differs from actual governance".into());
        }
        let result = Self {
            fee_mode: genesis.fee_mode(),
            nullifiers: super::nullifiers::NullifierSet::rebuild(&chain.spent)?,
            chain,
            economics,
            fund,
            governance,
        };
        result.check_context()?;
        if result.height() != header.height
            || result
                .canonical_components(binding, limits.chain)?
                .each_ref()
                .map(Vec::as_slice)
                != raw
            || result.execution_commitment(binding, limits.chain)? != header.execution_commitment
        {
            return Err("archived state differs from actual complete execution commitment".into());
        }
        Ok(result)
    }
    /// Initialize only from local immutable bootstrap configuration.
    pub fn genesis(
        config: Config,
        genesis: Hash,
        governance: GovernanceState,
    ) -> Result<Self, String> {
        Self::genesis_for_fee_mode(
            config,
            genesis,
            governance,
            super::genesis::FeeMode::ConfidentialDestination,
        )
    }
    pub(crate) fn genesis_for_fee_mode(
        config: Config,
        genesis: Hash,
        governance: GovernanceState,
        fee_mode: super::genesis::FeeMode,
    ) -> Result<Self, String> {
        let fund = FundLedger::new(
            config.network,
            config
                .fund_allocation
                .clone()
                .ok_or("versioned fund allocation is required")?,
        )?;
        let economics = EconomicState::new(config.network)?;
        if governance.height() != 0 {
            return Err("bootstrap governance is not at genesis".into());
        }
        let result = Self {
            fee_mode,
            chain: state_components::genesis_chain_for_fee_mode(config, genesis, fee_mode)?,
            economics,
            fund,
            governance,
            nullifiers: super::nullifiers::NullifierSet::new(),
        };
        result.check_context()?;
        Ok(result)
    }
    pub fn height(&self) -> u64 {
        self.chain.height
    }
    pub fn network(&self) -> Hash {
        self.chain.config.network
    }
    pub fn tip(&self) -> Hash {
        self.chain.tip
    }
    /// Read-only canonical chain data for native wallet paths and padding.
    /// The enclosing versioned engine owns economic and fund transitions.
    pub fn chain(&self) -> &State {
        &self.chain
    }
    pub fn economics(&self) -> &EconomicState {
        &self.economics
    }
    pub fn fund(&self) -> &FundLedger {
        &self.fund
    }
    pub fn governance(&self) -> &GovernanceState {
        &self.governance
    }
    pub fn fee_mode(&self) -> super::genesis::FeeMode {
        self.fee_mode
    }
    pub(crate) fn check_context(&self) -> Result<(), String> {
        let network = self.network();
        let height = self.height();
        let count = self
            .chain
            .config
            .fund_allocation
            .as_ref()
            .ok_or("missing fund allocation")?
            .basis_points()
            .len();
        VersionedLedgers {
            economics: &self.economics,
            fund: &self.fund,
            governance: &self.governance,
        }
        .check_context(network, height, count)
    }
    pub fn canonical_components(
        &self,
        binding: Binding,
        limits: Limits,
    ) -> Result<[Vec<u8>; 11], String> {
        self.check_context()?;
        let chain = ChainComponents::recompute_for_fee_mode(
            &self.chain,
            binding,
            SnapshotTip::Materialized(self.tip()),
            limits,
            self.fee_mode,
        )?;
        let [context, tree, nullifiers, roots, assets] =
            chain.canonical_bytes().map(<[u8]>::to_vec);
        let [pool, counters, locked] = self.economics.component_bytes()?;
        let bytes = [
            context,
            tree,
            nullifiers,
            roots,
            pool,
            self.fund.canonical_component_bytes()?,
            self.governance.canonical_fee_destination_bytes()?,
            self.governance.canonical_component_bytes()?,
            counters,
            locked,
            assets,
        ];
        if bytes
            .iter()
            .any(|part| part.len() > limits.max_component_bytes)
        {
            return Err("snapshot component exceeds local byte bound".into());
        }
        Ok(bytes)
    }
    pub fn execution_commitment(&self, binding: Binding, limits: Limits) -> Result<Hash, String> {
        self.check_context()?;
        let chain = ExecutionComponents::from_local_state_for_fee_mode(
            &self.chain,
            &self.nullifiers,
            binding,
            SnapshotTip::Materialized(self.tip()),
            limits,
            self.fee_mode,
        )?;
        let members = self
            .chain
            .config
            .fund_allocation
            .as_ref()
            .ok_or("missing fund allocation")?
            .basis_points()
            .len();
        chain.assemble(
            VersionedLedgers {
                economics: &self.economics,
                fund: &self.fund,
                governance: &self.governance,
            }
            .components(self.network(), self.height(), members, limits)?,
        )
    }
}

pub struct ImportedAnchor {
    state: SnapshotState,
    pin: Pin,
    binding: Binding,
}
impl ImportedAnchor {
    pub(super) fn into_state(self) -> SnapshotState {
        self.state
    }
    pub fn state(&self) -> &SnapshotState {
        &self.state
    }
    pub fn pin(&self) -> Pin {
        self.pin
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    pub fn reconstruct(
        plan: &AdmissionPlan,
        bootstrap: &SnapshotState,
        rules_commitment: Hash,
        bytes: &[u8],
        limits: ImportLimits,
    ) -> Result<Self, String> {
        let pin = plan.pin();
        bootstrap.check_context()?;
        if bootstrap.height() != 0
            || bootstrap.tip() != pin.genesis
            || bootstrap.network() != pin.network
            || rules_commitment == [0; 32]
        {
            return Err("snapshot import differs from local bootstrap".into());
        }
        let raw = decode_components(bytes, limits)?;
        let parent = if pin.anchor_height == 0 {
            [0; 32]
        } else {
            plan.headers()
                .id(pin.anchor_height - 1)
                .map_err(|_| "anchor parent is unavailable")?
        };
        let binding = Binding {
            genesis: pin.genesis,
            rules_commitment,
            parent,
        };
        let chain = ChainComponents::reconstruct_for_fee_mode(
            bootstrap.chain.config.clone(),
            binding,
            pin.anchor_id,
            [raw[0], raw[1], raw[2], raw[3], raw[10]],
            limits.chain,
            bootstrap.fee_mode,
        )?;
        plan.check_anchor_metadata(&chain)
            .map_err(|_| "reconstructed anchor lineage differs")?;
        let economics = EconomicState::from_components(
            pin.network,
            pin.anchor_height,
            [raw[4], raw[8], raw[9]],
        )?;
        let fund = FundLedger::decode_component(
            raw[5],
            pin.network,
            bootstrap
                .chain
                .config
                .fund_allocation
                .as_ref()
                .ok_or("missing immutable fund allocation")?,
        )?;
        let governance = GovernanceState::decode_component(raw[7], pin.network)?;
        if governance.canonical_fee_destination_bytes()? != raw[6] {
            return Err("fee destination differs from actual governance state".into());
        }
        let state = SnapshotState {
            fee_mode: bootstrap.fee_mode,
            nullifiers: super::nullifiers::NullifierSet::rebuild(&chain.spent)?,
            chain,
            economics,
            fund,
            governance,
        };
        state.check_context()?;
        let canonical = state.canonical_components(binding, limits.chain)?;
        if canonical.each_ref().map(Vec::as_slice) != raw {
            return Err("reconstructed snapshot components are not canonical".into());
        }
        let reconstructed = state.execution_commitment(binding, limits.chain)?;
        let expected = if pin.anchor_height == 0 {
            bootstrap.execution_commitment(binding, limits.chain)?
        } else {
            plan.headers()
                .header(pin.anchor_height)
                .ok_or("selected anchor header is unavailable")?
                .execution_commitment
        };
        if reconstructed != expected {
            return Err("reconstructed state differs from selected header commitment".into());
        }
        Ok(Self {
            state,
            pin,
            binding,
        })
    }
}

#[cfg(test)]
fn aggregate(
    network: Hash,
    height: u64,
    parent: Hash,
    bytes: &[Vec<u8>; 11],
    limit: usize,
) -> Result<Hash, String> {
    let components = COMPONENTS
        .into_iter()
        .zip(bytes)
        .map(|(id, bytes)| {
            super::commitment::Component::from_local_encoding(id, bytes, limit)
                .map_err(|_| "snapshot component byte bound exceeded".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    super::commitment::aggregate(network, height, parent, &components)
        .map_err(|_| "invalid snapshot aggregate".into())
}

/// Raw ordered bytes only: component descriptors and cached seals are excluded.
pub fn encode_components(bytes: &[Vec<u8>; 11], limits: ImportLimits) -> Result<Vec<u8>, String> {
    let mut length = 8usize;
    for part in bytes {
        if part.len() > limits.chain.max_component_bytes {
            return Err("snapshot component exceeds byte bound".into());
        }
        length = length
            .checked_add(10)
            .and_then(|n| n.checked_add(part.len()))
            .ok_or("snapshot length overflow")?;
    }
    if length > limits.max_snapshot_bytes {
        return Err("snapshot total exceeds byte bound".into());
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| "snapshot allocation bound")?;
    result.extend_from_slice(b"SW2S\x01\x00\x0b\x00");
    for (id, bytes) in COMPONENTS.into_iter().zip(bytes) {
        result.extend_from_slice(&(id as u16).to_le_bytes());
        result.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        result.extend_from_slice(bytes);
    }
    Ok(result)
}

fn decode_components(bytes: &[u8], limits: ImportLimits) -> Result<[&[u8]; 11], String> {
    if bytes.len() > limits.max_snapshot_bytes || bytes.get(..8) != Some(b"SW2S\x01\x00\x0b\x00") {
        return Err("invalid snapshot version, component count or total bound".into());
    }
    let mut position = 8usize;
    let mut result = [&[][..]; 11];
    for (part, id) in result.iter_mut().zip(COMPONENTS) {
        let prefix = position.checked_add(10).ok_or("snapshot offset overflow")?;
        let header = bytes
            .get(position..prefix)
            .ok_or("truncated snapshot component header")?;
        if u16::from_le_bytes(header[..2].try_into().expect("fixed component ID")) != id as u16 {
            return Err("snapshot component order or identifier differs".into());
        }
        let length = usize::try_from(u64::from_le_bytes(
            header[2..].try_into().expect("fixed component length"),
        ))
        .map_err(|_| "snapshot component length conversion")?;
        if length > limits.chain.max_component_bytes {
            return Err("snapshot component exceeds byte bound".into());
        }
        let end = prefix
            .checked_add(length)
            .ok_or("snapshot component length overflow")?;
        *part = bytes
            .get(prefix..end)
            .ok_or("truncated snapshot component body")?;
        position = end;
    }
    if position != bytes.len() {
        return Err("snapshot has trailing bytes".into());
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{
        header::Header,
        selection::{HeaderRules, SourceObservation, VerifiedHeaders},
    };
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65;
    use native::codec::encode_digest;
    use p3_field::PrimeCharacteristicRing;
    use siworld_core::pow::Work;

    pub(crate) fn limits() -> ImportLimits {
        ImportLimits {
            chain: Limits {
                max_leaves: 100,
                max_nullifiers: 100,
                max_component_bytes: 16 * 1024 * 1024,
            },
            max_snapshot_bytes: 32 * 1024 * 1024,
        }
    }
    pub(crate) fn bootstrap() -> SnapshotState {
        let config = Config::development([1; 32], 0).unwrap();
        let address = |seed| {
            crate::wallet::WalletKeys::from_seed(
                config.network,
                zeroize::Zeroizing::new([seed; 32]),
                0,
            )
            .unwrap()
            .address()
        };
        let key = |seed| {
            *ml_dsa_65::generate_key_pair([seed; 32])
                .verification_key
                .as_ref()
        };
        let governance = GovernanceState::new(
            config.network,
            key(1),
            key(2),
            [3, 4, 5].map(key),
            address(30),
            vec![address(31), address(32)],
        )
        .unwrap();
        SnapshotState::genesis(config.clone(), config.genesis_id(), governance).unwrap()
    }
    pub(crate) fn binding(state: &SnapshotState, parent: Hash) -> Binding {
        Binding {
            genesis: state.chain.config.genesis_id(),
            rules_commitment: [9; 32],
            parent,
        }
    }
    pub(crate) fn plan(
        bootstrap: &SnapshotState,
        anchor_commitment: Hash,
        count: u64,
    ) -> AdmissionPlan {
        let config = &bootstrap.chain.config;
        let rules = HeaderRules {
            network: config.network,
            genesis: bootstrap.tip(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            pow_iterations: config.pow_iterations,
            max_headers: 1000,
        };
        let mut headers = Vec::new();
        let mut parent = rules.genesis;
        for height in 1..=count {
            let header = Header {
                network: rules.network,
                height,
                parent,
                timestamp: rules.genesis_timestamp + height * 300,
                target: [0xff; 32],
                execution_commitment: if height == 1 {
                    anchor_commitment
                } else {
                    [8; 32]
                },
                body_commitment: [6; 32],
                nonce: 0,
            };
            parent = header.id().unwrap();
            headers.push(header);
        }
        let verified = VerifiedHeaders::verify(rules, headers).unwrap();
        let sources: Vec<_> = (1..=3)
            .map(|id| SourceObservation {
                authenticated_identity: [id; 32],
                transport_address: std::net::IpAddr::from([10, id, 0, 1]),
                chain: &verified,
            })
            .collect();
        AdmissionPlan::select(&sources, Work::one()).unwrap()
    }
    pub(crate) fn populated(bootstrap: &SnapshotState) -> SnapshotState {
        let mut state = bootstrap.clone();
        state.governance.apply_block(1, &[]).unwrap();
        let funds = state.chain.config.fund_allocation.as_ref().unwrap();
        state.economics = state
            .economics
            .prepare(1, siworld_core::v1_economics::RewardMode::Voyager, funds)
            .unwrap()
            .0;
        state
            .fund
            .advance(1, siworld_core::v1_economics::subsidy(1).unwrap())
            .unwrap();
        state.chain.height = 1;
        state.chain.tip = [3; 32];
        state.chain.cumulative_work = Work::one();
        state
            .chain
            .timestamps
            .push_back(state.chain.config.genesis_timestamp + 300);
        let root = encode_digest(&state.chain.tree.root());
        let mut roots = native::multi_asset::RecentRoots::new();
        let hasher = native::multi_asset::Hasher::new();
        roots.insert(
            &hasher,
            0,
            &state.chain.tree.root(),
            crate::eng2_economics::fee_base(0).unwrap(),
        );
        roots.insert(
            &hasher,
            1,
            &state.chain.tree.root(),
            crate::eng2_economics::fee_base(1).unwrap(),
        );
        state
            .chain
            .snapshots
            .push_back(crate::state::CanonicalSnapshot {
                selector: crate::wire::Snapshot {
                    height: 1,
                    block_id: state.tip(),
                },
                commitment_root: root,
                recent_root: encode_digest(&roots.tree(&hasher).root()),
            });
        state
    }
    #[test]
    fn reconstructs_all_eleven_actual_components_against_the_selected_anchor_header() {
        let bootstrap = bootstrap();
        let mut state = populated(&bootstrap);
        let binding = binding(&bootstrap, bootstrap.tip());
        let commitment = state.execution_commitment(binding, limits().chain).unwrap();
        let plan = plan(&bootstrap, commitment, 313);
        state.chain.tip = plan.pin().anchor_id;
        state.chain.snapshots.back_mut().unwrap().selector.block_id = state.tip();
        let bytes = state.canonical_components(binding, limits().chain).unwrap();
        let raw = encode_components(&bytes, limits()).unwrap();
        let imported = ImportedAnchor::reconstruct(
            &plan,
            &bootstrap,
            binding.rules_commitment,
            &raw,
            limits(),
        )
        .unwrap();
        assert_eq!(imported.pin(), plan.pin());
        assert_eq!(imported.state().height(), 1);
        assert_eq!(
            imported
                .state()
                .execution_commitment(binding, limits().chain)
                .unwrap(),
            commitment
        );
        assert_eq!(imported.state().fund(), state.fund());
        assert_eq!(imported.state().economics(), state.economics());
        assert_eq!(imported.state().governance(), state.governance());
    }
    #[test]
    fn canonical_but_changed_component_contents_cannot_replace_the_committed_state() {
        let bootstrap = bootstrap();
        let state = populated(&bootstrap);
        let binding = binding(&bootstrap, bootstrap.tip());
        let bytes = state.canonical_components(binding, limits().chain).unwrap();
        let plan = plan(
            &bootstrap,
            state.execution_commitment(binding, limits().chain).unwrap(),
            313,
        );
        let mut changed = bytes.clone();
        changed[2] = {
            let mut bytes = 1u64.to_le_bytes().to_vec();
            bytes.extend_from_slice(&encode_digest(&[native::multi_asset::F::ZERO; 12]));
            bytes
        };
        assert!(
            ImportedAnchor::reconstruct(
                &plan,
                &bootstrap,
                binding.rules_commitment,
                &encode_components(&changed, limits()).unwrap(),
                limits()
            )
            .is_err()
        );
        for component in [4, 5, 6, 7, 8, 9, 10] {
            changed = bytes.clone();
            let last = changed[component].len() - 1;
            changed[component][last] ^= 1;
            assert!(
                ImportedAnchor::reconstruct(
                    &plan,
                    &bootstrap,
                    binding.rules_commitment,
                    &encode_components(&changed, limits()).unwrap(),
                    limits()
                )
                .is_err(),
                "component {component}"
            );
        }
    }
    #[test]
    fn genesis_anchor_must_equal_the_entire_locally_pinned_bootstrap_state() {
        let bootstrap = bootstrap();
        let plan = plan(&bootstrap, [8; 32], 1);
        let binding = binding(&bootstrap, [0; 32]);
        let bytes = bootstrap
            .canonical_components(binding, limits().chain)
            .unwrap();
        let raw = encode_components(&bytes, limits()).unwrap();
        assert!(
            ImportedAnchor::reconstruct(
                &plan,
                &bootstrap,
                binding.rules_commitment,
                &raw,
                limits()
            )
            .is_ok()
        );
        let mut changed = bytes;
        changed[7][50] ^= 1;
        assert!(
            ImportedAnchor::reconstruct(
                &plan,
                &bootstrap,
                binding.rules_commitment,
                &encode_components(&changed, limits()).unwrap(),
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_raw_framing_rejects_unknown_order_length_overflow_and_trailing_data() {
        let bootstrap = bootstrap();
        let bytes = bootstrap
            .canonical_components(binding(&bootstrap, [0; 32]), limits().chain)
            .unwrap();
        let raw = encode_components(&bytes, limits()).unwrap();
        assert_eq!(
            decode_components(&raw, limits()).unwrap(),
            bytes.each_ref().map(Vec::as_slice)
        );
        for offset in [0, 4, 6, 8, 10] {
            let mut changed = raw.clone();
            changed[offset] ^= 1;
            assert!(decode_components(&changed, limits()).is_err());
        }
        for length in [0, 7, 8, 17, raw.len() - 1] {
            assert!(decode_components(&raw[..length], limits()).is_err());
        }
        let mut changed = raw.clone();
        changed[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_components(&changed, limits()).is_err());
        changed = raw.clone();
        changed.push(0);
        assert!(decode_components(&changed, limits()).is_err());
        let smaller = ImportLimits {
            max_snapshot_bytes: raw.len() - 1,
            ..limits()
        };
        assert!(decode_components(&raw, smaller).is_err());
        assert!(encode_components(&bytes, smaller).is_err());
    }

    #[test]
    fn even_a_matching_header_cannot_override_cross_component_entitlement_or_height_invariants() {
        let bootstrap = bootstrap();
        let state = populated(&bootstrap);
        let binding = binding(&bootstrap, bootstrap.tip());
        let original = state.canonical_components(binding, limits().chain).unwrap();
        // These economic components are individually canonical at height one,
        // but deliberately omit the actual fund credit at the same height.
        let mut zero = EconomicState::new(state.network())
            .unwrap()
            .component_bytes()
            .unwrap();
        for part in &mut zero {
            part[38..46].copy_from_slice(&1u64.to_le_bytes());
        }
        assert!(
            EconomicState::from_components(state.network(), 1, zero.each_ref().map(Vec::as_slice))
                .is_ok()
        );
        let mut changed = original.clone();
        for (index, part) in [4, 8, 9].into_iter().zip(zero) {
            changed[index] = part;
        }
        let commitment = aggregate(
            state.network(),
            1,
            binding.parent,
            &changed,
            limits().chain.max_component_bytes,
        )
        .unwrap();
        let selected = plan(&bootstrap, commitment, 313);
        assert!(
            ImportedAnchor::reconstruct(
                &selected,
                &bootstrap,
                binding.rules_commitment,
                &encode_components(&changed, limits()).unwrap(),
                limits()
            )
            .is_err()
        );
        // An internally valid governance state at another height is also invalid.
        let mut future = state.governance.clone();
        future.apply_block(2, &[]).unwrap();
        changed = original;
        changed[7] = future.canonical_component_bytes().unwrap();
        let commitment = aggregate(
            state.network(),
            1,
            binding.parent,
            &changed,
            limits().chain.max_component_bytes,
        )
        .unwrap();
        let selected = plan(&bootstrap, commitment, 313);
        assert!(
            ImportedAnchor::reconstruct(
                &selected,
                &bootstrap,
                binding.rules_commitment,
                &encode_components(&changed, limits()).unwrap(),
                limits()
            )
            .is_err()
        );
    }
}
