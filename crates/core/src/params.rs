//! Shared encoding widths and retained-network protocol constants.
//! Native V1 monetary and vesting rules are defined in `v1_economics`.

/// 1 SIP = 10^8 atom.
pub const ATOMS_PER_SIP: u64 = 100_000_000;

/// Minimum SIP held by every non-zero package (0.0001 SIP).
pub const MIN_PACKAGE_DEPOSIT: u64 = 10_000;

/// One epoch (two weeks at 60-second blocks).
pub const EPOCH_BLOCKS: u64 = 20_160;

pub const INITIAL_REWARD: u64 = 678_904_903;
/// Each epoch multiplies by this value and shifts right by 32, approximately 0.85^(1/26).
pub const DECAY_Q32: u64 = 4_268_204_354;
pub const TAIL_REWARD: u64 = 30_000_000;

/// Standard tier = reward(e) / FEE_BASE_DIVISOR (rounded down).
pub const FEE_BASE_DIVISOR: u64 = 1_000;
/// Priority tier = standard tier × FEE_PRIORITY_MULT.
pub const FEE_PRIORITY_MULT: u64 = 4;

/// Maturity period of the miner package and of development-fund credits.
pub const COINBASE_MATURITY: u64 = 100;

/// Development-fund payouts a block body may carry.
pub const MAX_PAYOUTS_PER_BLOCK: usize = 8;
/// One protocol day, in seconds of target block time.
pub const DAY_SECONDS: u64 = 86_400;
/// A development-fund lock deposit is released linearly over this much
/// protocol time: 1,825 days.
pub const DEV_LOCK_SECONDS: u64 = 1_825 * DAY_SECONDS;

/// ML-DSA-65 (FIPS 204) verifying-key and signature lengths: the signature
/// scheme of development-fund payouts and pre-confirmation batches.
pub const VERIFYING_KEY_LEN: usize = 1_952;
pub const SIGNATURE_LEN: usize = 3_309;

/// Every slot has exactly 2 inputs and 2 outputs.
pub const SLOT_INPUTS: usize = 2;
pub const SLOT_OUTPUTS: usize = 2;

/// ASERT half-life in seconds: the target doubles or halves for every half-life
/// of drift between actual and scheduled time since genesis (midstate's value).
pub const ASERT_HALF_LIFE: i64 = 4 * 60 * 60;
/// A block's timestamp must exceed the median of this many previous timestamps.
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;
/// Relay policy, not validity: a block whose timestamp is further than this
/// ahead of the local clock is held until it is within range.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 15 * 60;
/// Deepest reorganization a node follows: once its tip has reached height T,
/// the main-chain block at T − MAX_REORG_DEPTH is final, and a block whose
/// branch leaves the main chain below it is invalid.
pub const MAX_REORG_DEPTH: u64 = 100;

pub const CONTAINER_SIZE_INIT: u32 = 32;
pub const CONTAINER_SIZE_STEPS: [u32; 4] = [16, 32, 64, 128];

/// The two development-fund accounts' ML-DSA-65 verifying keys, fixed at
/// genesis. Each key authorizes payouts from its corresponding account.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevFundKeys {
    pub direct: [u8; VERIFYING_KEY_LEN],
    pub lock: [u8; VERIFYING_KEY_LEN],
}

impl DevFundKeys {
    /// The key of `account`.
    pub fn key(&self, account: crate::types::DevAccount) -> &[u8; VERIFYING_KEY_LEN] {
        match account {
            crate::types::DevAccount::Direct => &self.direct,
            crate::types::DevAccount::Lock => &self.lock,
        }
    }
}

impl core::fmt::Debug for DevFundKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DevFundKeys(..)")
    }
}

/// Which proof system a network's blocks carry. Nodes of one network must
/// agree, so it is a chain parameter and part of the genesis id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofSystemKind {
    /// The mock of `siworld-circuits`: checks the relation natively and binds
    /// the statement with a hash. Not sound; devnet and tests only.
    Mock,
    /// Plonky3 STARK leaf proofs and recursive aggregation (`siworld-prover`).
    Plonky3,
}

impl ProofSystemKind {
    /// The byte the genesis id hashes.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Mock => 0,
            Self::Plonky3 => 1,
        }
    }
}

/// Parameters that vary by network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// The proof system of the network's blocks.
    pub proofs: ProofSystemKind,
    /// Names the chain in everything signed off chain for it (development-fund
    /// payouts), so that a signature for one network is not valid on another
    /// that happens to share a key. The chain configuration fixes this identifier.
    pub chain_id: crate::types::Digest,
    /// Fixed slots per block in this container format. Must be a power of two.
    pub container_size: u32,
    /// Commitment-tree depth; the default chain profile uses depth 40.
    pub commitment_tree_depth: u8,
    /// Recent-roots window W, a power of two: the number of blocks whose
    /// commitment-tree roots 𝒜 keeps.
    pub anchor_window: u32,
    /// Sequential BLAKE3 hashes per nonce.
    pub pow_iterations: u64,
    /// Target block time in seconds; ASERT's schedule.
    pub target_block_time: u64,
    /// PoW target of block 1 and ASERT's reference, big-endian.
    pub genesis_target: [u8; 32],
    /// Genesis timestamp, ASERT's anchor. Fixed at launch.
    ///
    /// [`ChainParams::mainnet`] leaves it at 0, a placeholder: ASERT measures
    /// every block against it, so a chain launched with 0 is decades behind
    /// schedule and its target is the ceiling from block 2 (no work at all).
    /// A network configuration must supply its genesis timestamp.
    pub genesis_timestamp: u64,
    /// The development-fund accounts' verifying keys. `None` means the fund
    /// cannot pay out: every payout is invalid.
    pub dev_fund_keys: Option<DevFundKeys>,
}

/// midstate's launch target, calibrated for about 60 s at 1,000,000 iterations.
const MAINNET_GENESIS_TARGET: [u8; 32] = {
    let mut t = [0xff; 32];
    t[0] = 0x00;
    t[1] = 0x11;
    t
};

impl ChainParams {
    pub fn mainnet() -> Self {
        Self {
            proofs: ProofSystemKind::Plonky3,
            // Placeholder until launch; see the field's documentation.
            chain_id: crate::types::Digest::ZERO,
            container_size: CONTAINER_SIZE_INIT,
            commitment_tree_depth: 40,
            anchor_window: 4096,
            pow_iterations: 1_000_000,
            target_block_time: 60,
            genesis_target: MAINNET_GENESIS_TARGET,
            // Placeholders until launch; see the fields' documentation.
            genesis_timestamp: 0,
            dev_fund_keys: None,
        }
    }

    /// Single-machine development network: small capacity, one-second blocks and
    /// cheap work (about 16 nonces of 100 hashes each) for fast blocks and tests.
    pub fn devnet() -> Self {
        let mut genesis_target = [0xff; 32];
        genesis_target[0] = 0x0f;
        Self {
            proofs: ProofSystemKind::Mock,
            chain_id: crate::types::Digest([0xd1; 32]),
            container_size: 4,
            pow_iterations: 100,
            target_block_time: 1,
            genesis_target,
            ..Self::mainnet()
        }
    }
}
