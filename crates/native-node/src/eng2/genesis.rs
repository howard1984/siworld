//! Immutable internal engineering genesis and explicit fee rules.

use crate::{eng2_governance::GovernanceState, state::Config, wire::Hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FeeMode {
    LegacyMiner = 0,
    ConfidentialDestination = 1,
}
impl FeeMode {
    pub fn base_fee(self, height: u64) -> Result<u64, String> {
        let fee = siworld_core::v1_economics::fee_base(height.max(1))
            .map_err(|error| error.to_string())?;
        Ok(match self {
            Self::LegacyMiner => fee,
            Self::ConfidentialDestination => fee / 10,
        })
    }
}
pub struct Genesis {
    config: Config,
    governance: GovernanceState,
    mode: FeeMode,
    id: Hash,
    rules: Hash,
}
impl Genesis {
    pub fn seal(
        config: Config,
        governance: GovernanceState,
        mode: FeeMode,
    ) -> Result<Self, String> {
        config.validate()?;
        if mode != FeeMode::LegacyMiner {
            return Err(
                "confidential destination profile is not qualified for internal activation".into(),
            );
        }
        let members = config
            .fund_allocation
            .as_ref()
            .ok_or("internal genesis requires fund allocation")?
            .basis_points()
            .len();
        if governance.network() != config.network
            || governance.height() != 0
            || governance.sequence() != 0
            || governance.active_fund_destination(members as u8).is_ok()
            || (0..members).any(|member| governance.active_fund_destination(member as u8).is_err())
        {
            return Err("internal genesis governance context or membership differs".into());
        }
        let governance_bytes = governance.canonical_component_bytes()?;
        let mut hash = blake3::Hasher::new_derive_key("siworld eng2 internal immutable rules v1");
        hash.update(&[mode as u8]);
        hash.update(&config.encode_rules());
        hash.update(&crate::proofs::protocol_profile_fingerprint());
        hash.update(&(governance_bytes.len() as u64).to_le_bytes());
        hash.update(&governance_bytes);
        hash.update(b"native-header:2;execution-components:2;fund:direct24-month8766x48;governance:4032-roster24;issuance-fee:public-governed-destination-v1");
        let rules = *hash.finalize().as_bytes();
        let id = blake3::derive_key("siworld eng2 internal genesis v1", &rules);
        Ok(Self {
            config,
            governance,
            mode,
            id,
            rules,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn rules_commitment(&self) -> Hash {
        self.rules
    }
    /// Domain-separated authenticated peer identity for these exact rules.
    pub fn peer_binding(&self) -> crate::p2p::Binding {
        let mut hash = blake3::Hasher::new_derive_key("siworld eng2 peer verifier manifest v1");
        hash.update(&self.rules_commitment());
        hash.update(&crate::proofs::protocol_profile_fingerprint());
        hash.update(&[self.fee_mode() as u8]);
        crate::p2p::Binding {
            network: self.config().network,
            genesis: self.id(),
            verifier: *hash.finalize().as_bytes(),
        }
    }
    pub fn fee_mode(&self) -> FeeMode {
        self.mode
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn initial_governance(&self) -> &GovernanceState {
        &self.governance
    }
    pub fn initial_state(&self) -> Result<super::snapshot::SnapshotState, String> {
        super::snapshot::SnapshotState::genesis_for_fee_mode(
            self.config.clone(),
            self.id,
            self.governance.clone(),
            self.mode,
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let governance = self.governance.canonical_component_bytes()?;
        let length =
            u32::try_from(governance.len()).map_err(|_| "initial governance length overflow")?;
        let mut bytes = b"SWE2GEN1".to_vec();
        bytes.push(self.mode as u8);
        bytes.extend_from_slice(&crate::proofs::protocol_profile_fingerprint());
        bytes.extend_from_slice(&self.config.encode_rules());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&governance);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let prefix = 8 + 1 + 32 + crate::state::CONFIG_RULE_BYTES + 4;
        if bytes.len() < prefix
            || bytes.len() > prefix + 131_072
            || &bytes[..8] != b"SWE2GEN1"
            || bytes[8] != FeeMode::LegacyMiner as u8
            || bytes[9..41] != crate::proofs::protocol_profile_fingerprint()
        {
            return Err("unsupported internal genesis encoding, fee mode or proof profile".into());
        }
        let config_end = 41 + crate::state::CONFIG_RULE_BYTES;
        let config = Config::decode_rules(&bytes[41..config_end])?;
        let length = u32::from_le_bytes(
            bytes[config_end..prefix]
                .try_into()
                .expect("fixed initial governance length"),
        ) as usize;
        if length != bytes.len() - prefix {
            return Err("internal genesis governance length differs".into());
        }
        let governance = GovernanceState::decode_component(&bytes[prefix..], config.network)?;
        let genesis = Self::seal(config, governance, FeeMode::LegacyMiner)?;
        if genesis.encode()? != bytes {
            return Err("noncanonical internal genesis encoding".into());
        }
        Ok(genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_internal_genesis_binds_native_rules_and_governance_and_refuses_candidate_fallback()
    {
        let parent = crate::eng2::snapshot::tests::bootstrap();
        let config = parent.chain.config.clone();
        let original = Genesis::seal(
            config.clone(),
            parent.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        let repeated = Genesis::seal(
            config.clone(),
            parent.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        assert_eq!(original.id(), repeated.id());
        assert_eq!(original.rules_commitment(), repeated.rules_commitment());
        assert_ne!(original.id(), config.genesis_id());
        assert_eq!(original.fee_mode(), FeeMode::LegacyMiner);
        assert!(
            Genesis::seal(
                config.clone(),
                parent.governance.clone(),
                FeeMode::ConfidentialDestination
            )
            .is_err()
        );
        let mut other = config;
        other.network[0] ^= 1;
        assert!(Genesis::seal(other, parent.governance.clone(), FeeMode::LegacyMiner).is_err());
        assert_eq!(
            FeeMode::LegacyMiner.base_fee(0).unwrap(),
            crate::state::base_fee(0)
        );
        assert_eq!(
            FeeMode::LegacyMiner.base_fee(1).unwrap() / 10,
            FeeMode::ConfidentialDestination.base_fee(1).unwrap()
        );
    }
    #[test]
    fn sealed_legacy_genesis_uses_the_same_actual_fee_root_in_compact_and_full_state() {
        use crate::eng2::commitment::SnapshotTip;
        use crate::eng2::state_components::{Binding, ChainComponents, Limits, VersionedLedgers};
        let original = crate::eng2::snapshot::tests::bootstrap();
        let genesis = Genesis::seal(
            original.chain.config.clone(),
            original.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        let state = genesis.initial_state().unwrap();
        assert_eq!(state.fee_mode(), FeeMode::LegacyMiner);
        assert_eq!(state.tip(), genesis.id());
        let root = native::codec::encode_digest(
            &state
                .chain
                .recent_roots()
                .unwrap()
                .tree(&native::multi_asset::Hasher::new())
                .root(),
        );
        assert_eq!(state.chain.tip_snapshot().recent_root, root);
        let binding = Binding {
            genesis: genesis.id(),
            rules_commitment: genesis.rules_commitment(),
            parent: [0; 32],
        };
        let limits = Limits {
            max_leaves: 1000,
            max_nullifiers: 1000,
            max_component_bytes: 16 * 1024 * 1024,
        };
        let chain = ChainComponents::recompute_for_fee_mode(
            &state.chain,
            binding,
            SnapshotTip::Materialized(state.tip()),
            limits,
            FeeMode::LegacyMiner,
        )
        .unwrap();
        let external = VersionedLedgers {
            economics: state.economics(),
            fund: state.fund(),
            governance: state.governance(),
        }
        .components(state.network(), 0, 2, limits)
        .unwrap();
        assert_eq!(
            chain.assemble(external).unwrap(),
            state.execution_commitment(binding, limits).unwrap()
        );
        assert!(
            ChainComponents::recompute(
                &state.chain,
                binding,
                SnapshotTip::Materialized(state.tip()),
                limits
            )
            .is_err()
        );
        assert!(state.canonical_components(binding, limits).is_ok());
    }
    #[test]
    fn sealed_genesis_encoding_rejects_mode_profile_and_trailing_substitution() {
        let parent = crate::eng2::snapshot::tests::bootstrap();
        let genesis = Genesis::seal(
            parent.chain.config.clone(),
            parent.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        let bytes = genesis.encode().unwrap();
        assert_eq!(Genesis::decode(&bytes).unwrap().id(), genesis.id());
        assert_eq!(
            Genesis::decode(&bytes).unwrap().rules_commitment(),
            genesis.rules_commitment()
        );
        for offset in [8, 9] {
            let mut damaged = bytes.clone();
            damaged[offset] ^= 1;
            assert!(Genesis::decode(&damaged).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Genesis::decode(&trailing).is_err());
        assert!(Genesis::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
