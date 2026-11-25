//! Native reference implementation of a slot-relation subset (Poseidon2 / KoalaBear,
//! width 24) and witness generation.
//!
//! Native witness oracle for the experimental W24 AIR and aggregation port.
//! This is a separate application encoding, not the current node codec or SP1 guest.
//!
//! Relation subset (corresponding to `crates/circuits/src/relation.rs::check_slot`):
//! - input i: owner = H_owner(nk), cm = H_note(owner, v, unlock, ρ, rseed),
//!   cm leads to anchor in a depth-40 tree (skipped for dummy inputs, which have v = 0),
//!   nf = H_nf(nk, ρ);
//! - output j: ρⱼ = H_rho_j(nf₀, nf₁), cmⱼ = H_note(owner, v, unlock, ρⱼ, rseed);
//! - nf₀ ≠ nf₁;
//! - each output value is 0 or at least MIN_PACKAGE_DEPOSIT;
//! - value conservation v₀ + v₁ = o₀ + o₁ + fee (u64, in 16-bit limbs);
//! - fee tier: 0 when all inputs are dummies, otherwise the standard or priority tier;
//!   fee_commit = H_fee(fee, blind).
//!
//! Accumulator mode (`AccWitness`) follows docs/00-decisions: the anchor is proven to be in
//! the recent-roots accumulator 𝒜, whose entry also supplies the base fee of the tier check,
//! and the slot maps to a set element E that binds the ciphertext digest d_ct. Only this mode
//! knows the anchor height, so only it checks unlock_height ≤ anchor height for real inputs.
//!
//! Not covered: ciphertext correctness.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
pub use p3_koala_bear::KoalaBear as F;
use p3_koala_bear::{Poseidon2KoalaBear, default_koalabear_poseidon2_24};
use p3_symmetric::Permutation;

pub const WIDTH: usize = 24;
pub const RATE: usize = 12;
pub const DIGEST: usize = 12;
pub const TREE_DEPTH: usize = 40;
pub const LIMBS: usize = 4;
/// Eight independent canonical field elements: approximately 248 bits of entropy.
pub const FEE_BLIND_LEN: usize = 8;
pub const LIMB_BITS: usize = 16;

pub type Digest = [F; DIGEST];
pub type Block = [F; RATE];

/// Domain tags (the registry in docs/00-decisions). The first sponge input carries the tag and
/// the number of absorbed blocks in the first two capacity elements; each tag has a fixed
/// input length, so no padding rule is needed.
pub const TAG_OWNER: u32 = 1;
pub const TAG_NOTE: u32 = 2;
pub const TAG_NF: u32 = 3;
/// The ρ of output j uses TAG_RHO + j.
pub const TAG_RHO: u32 = 4;
/// Benchmark-only: the chained-mode fee commitment. Retired in the registry.
pub const TAG_FEE: u32 = 6;
/// Benchmark-only, retired in the registry. Slot chain: s' = H(s ‖ slot public values). The aggregation statement carries only the
/// first and last states, so its width is constant.
pub const TAG_CHAIN: u32 = 7;
/// Order-independent accumulator: each slot maps to a set element E of SET_LEN field elements
/// (six sponge squeezes), and the aggregation statement carries the field sum over all slots.
pub const TAG_SET: u32 = 8;
pub const SET_LEN: usize = 6 * DIGEST;
/// Blocks E absorbs before squeezing: nf₀, nf₁, cm₀, cm₁ and two zero-padded blocks of d_ct.
pub const SET_ABSORB: usize = 6;
/// Internal accumulator nodes publish only sponge(TAG_ACC_NODE, full node statement); the
/// parent takes the full statement as a private input and recomputes the digest.
pub const TAG_ACC_NODE: u32 = 9;
/// Recent-roots accumulator entry: sponge(TAG_ANCHOR, [r_h] [h limbs ‖ base_fee limbs]).
pub const TAG_ANCHOR: u32 = 10;
/// ρ of a block's miner package: sponge(TAG_MINER_RHO, [height limbs ‖ 0 × 8]).
pub const TAG_MINER_RHO: u32 = 11;
/// 𝒜 is a Merkle tree of depth ANCHOR_DEPTH over a ring of the last ANCHOR_RING blocks.
pub const ANCHOR_DEPTH: usize = 12;
pub const ANCHOR_RING: usize = 1 << ANCHOR_DEPTH;
/// The ciphertext digest d_ct (32 bytes, BLAKE3 in the protocol) enters E as 16 little-endian
/// 16-bit limbs, zero-padded to two rate-twelve blocks. This encoding is experimental.
pub const DCT_BYTES: usize = 32;
pub const DCT_LEN: usize = DCT_BYTES / 2;
/// The miner package unlocks at height + COINBASE_MATURITY.
pub const COINBASE_MATURITY: u64 = 100;
/// The root decomposes the block height and the miner package unlock height into HEIGHT_BITS bits, so both
/// must stay below 2^HEIGHT_BITS (a prototype bound; every such value is a canonical field element).
pub const HEIGHT_BITS: usize = 30;

/// The two fee tiers of epoch 0 (atoms): reward(0) / 1000 and four times that,
/// taken from crates/core/src/params.rs.
pub const FEE_BASE: u64 = 678_904;
pub const FEE_PRIORITY: u64 = FEE_BASE * 4;
/// The miner's 90% share of the epoch-0 block reward (atoms), from crates/core/src/issuance.rs.
pub const MINER_SHARE: u64 = 611_014_413;
/// Smallest nonzero output value (atoms), from crates/core/src/params.rs.
pub const MIN_PACKAGE_DEPOSIT: u64 = 10_000;

/// Public inputs: nf₀, nf₁, cm₀, cm₁, anchor, fee_commit, 12 field elements each.
pub const NUM_PUBLIC: usize = 6 * DIGEST;

/// Canonical zero padding for short numeric blocks in the experimental W24 encoding.
pub fn padded_block(xs: &[F]) -> Block {
    assert!(xs.len() <= RATE);
    let mut b = [F::ZERO; RATE];
    b[..xs.len()].copy_from_slice(xs);
    b
}

pub struct Hasher {
    perm: Poseidon2KoalaBear<WIDTH>,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            perm: default_koalabear_poseidon2_24(),
        }
    }

    pub fn permute(&self, state: [F; WIDTH]) -> [F; WIDTH] {
        self.perm.permute(state)
    }

    /// Permutation input for the first block of a sponge absorbing `len` blocks:
    /// [block, tag, len, 0 × 14].
    pub fn first_input(tag: u32, len: usize, block: &Block) -> [F; WIDTH] {
        let mut s = [F::ZERO; WIDTH];
        s[..RATE].copy_from_slice(block);
        s[RATE] = F::from_u32(tag);
        s[RATE + 1] = F::from_usize(len);
        s
    }

    /// Overwrite-mode sponge: each block overwrites the rate; the capacity carries over
    /// from the previous permutation output. Returns the input of every permutation
    /// (for witness generation) and the final digest.
    pub fn sponge_trace(&self, tag: u32, blocks: &[Block]) -> (Vec<[F; WIDTH]>, Digest) {
        let mut inputs = Vec::with_capacity(blocks.len());
        let mut state = [F::ZERO; WIDTH];
        for (k, b) in blocks.iter().enumerate() {
            let input = if k == 0 {
                Self::first_input(tag, blocks.len(), b)
            } else {
                let mut s = state;
                s[..RATE].copy_from_slice(b);
                s
            };
            inputs.push(input);
            state = self.permute(input);
        }
        (inputs, digest_of(&state))
    }

    pub fn sponge(&self, tag: u32, blocks: &[Block]) -> Digest {
        self.sponge_trace(tag, blocks).1
    }

    /// Merkle 2-to-1 compression: truncated permutation perm(l ‖ r)[0..16].
    pub fn compress_input(left: &Digest, right: &Digest) -> [F; WIDTH] {
        let mut s = [F::ZERO; WIDTH];
        s[..DIGEST].copy_from_slice(left);
        s[DIGEST..].copy_from_slice(right);
        s
    }

    pub fn compress(&self, left: &Digest, right: &Digest) -> Digest {
        digest_of(&self.permute(Self::compress_input(left, right)))
    }

    pub fn owner(&self, nk: &Digest) -> Digest {
        self.sponge(TAG_OWNER, &[*nk])
    }

    pub fn note_cm(&self, note: &Note) -> Digest {
        self.sponge(TAG_NOTE, &note.blocks())
    }

    pub fn nullifier(&self, nk: &Digest, rho: &Digest) -> Digest {
        self.sponge(TAG_NF, &[*nk, *rho])
    }

    pub fn output_rho(&self, nf0: &Digest, nf1: &Digest, j: usize) -> Digest {
        self.sponge(TAG_RHO + j as u32, &[*nf0, *nf1])
    }

    pub fn fee_commit(&self, fee: u64, blind: &[F; FEE_BLIND_LEN]) -> Digest {
        self.sponge(TAG_FEE, &[fee_block(fee, blind)])
    }

    /// 𝒜 entry of block h: sponge(TAG_ANCHOR, [r_h] [h limbs ‖ base_fee limbs]).
    pub fn anchor_entry(&self, root: &Digest, height: u64, base_fee: u64) -> Digest {
        self.sponge(TAG_ANCHOR, &[*root, anchor_block(height, base_fee)])
    }

    /// ρ of the miner package of block `height`.
    pub fn miner_rho(&self, height: u64) -> Digest {
        let l = limbs(height);
        self.sponge(TAG_MINER_RHO, &[padded_block(&l)])
    }

    /// Commitment of the miner package of block `height`: an ordinary note carrying the fee
    /// total plus the miner's share of the block reward.
    pub fn miner_note_cm(&self, value: u64, height: u64, owner: &Digest, rseed: &Digest) -> Digest {
        self.note_cm(&Note {
            owner: *owner,
            value,
            unlock_height: height + COINBASE_MATURITY,
            rho: self.miner_rho(height),
            rseed: *rseed,
        })
    }

    /// From leaf to root; `path[k] = (sibling, whether the current node is a right child)`.
    pub fn merkle_root(&self, leaf: &Digest, path: &[(Digest, bool)]) -> Digest {
        let mut cur = *leaf;
        for (sib, is_right) in path {
            cur = if *is_right {
                self.compress(sib, &cur)
            } else {
                self.compress(&cur, sib)
            };
        }
        cur
    }
}

pub fn digest_of(state: &[F; WIDTH]) -> Digest {
    core::array::from_fn(|i| state[i])
}

/// u64 → four 16-bit limbs (least significant first).
pub fn limbs(v: u64) -> [F; LIMBS] {
    core::array::from_fn(|k| F::from_u32(((v >> (LIMB_BITS * k)) & 0xffff) as u32))
}

pub fn limbs_u32(v: u64) -> [u32; LIMBS] {
    core::array::from_fn(|k| ((v >> (LIMB_BITS * k)) & 0xffff) as u32)
}

/// Second block of an 𝒜 entry: [h limbs ‖ base_fee limbs].
pub fn anchor_block(height: u64, base_fee: u64) -> Block {
    let (h, b) = (limbs(height), limbs(base_fee));
    padded_block(&[h[0], h[1], h[2], h[3], b[0], b[1], b[2], b[3]])
}

/// Decodes a field element from its canonical u32 encoding. Since 2p < 2^32, every element x has
/// a second encoding x + p that `F::from_u32` maps to the same element, so a decoder that reduced
/// instead of rejecting would give one nullifier two on-chain spellings (docs/13-set-hash-review).
pub fn felt_from_canonical(x: u32) -> Option<F> {
    (x < F::ORDER_U32).then(|| F::from_u32(x))
}

/// d_ct bytes → 16 little-endian 16-bit limbs.
pub fn pack_dct(d_ct: &[u8; DCT_BYTES]) -> [F; DCT_LEN] {
    core::array::from_fn(|k| F::from_u32(u32::from(d_ct[2 * k]) | u32::from(d_ct[2 * k + 1]) << 8))
}

pub fn fee_block(fee: u64, blind: &[F; FEE_BLIND_LEN]) -> Block {
    let mut block = [F::ZERO; RATE];
    block[..LIMBS].copy_from_slice(&limbs(fee));
    block[LIMBS..].copy_from_slice(blind);
    block
}

#[derive(Clone, Debug)]
pub struct Note {
    pub owner: Digest,
    pub value: u64,
    pub unlock_height: u64,
    pub rho: Digest,
    pub rseed: Digest,
}

impl Note {
    /// Four blocks: [owner] [value limbs ‖ unlock limbs] [ρ] [rseed].
    pub fn blocks(&self) -> [Block; 4] {
        let v = limbs(self.value);
        let u = limbs(self.unlock_height);
        [
            self.owner,
            padded_block(&[v[0], v[1], v[2], v[3], u[0], u[1], u[2], u[3]]),
            self.rho,
            self.rseed,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct InputWitness {
    pub nk: Digest,
    pub rho: Digest,
    pub rseed: Digest,
    pub value: u64,
    pub unlock_height: u64,
    /// Dummy input: Merkle membership is not checked and the value must be 0; a
    /// pseudorandom nf is still computed.
    pub dummy: bool,
    /// Length TREE_DEPTH. Dummy inputs also carry an (arbitrary) path so the row layout is fixed.
    pub path: Vec<(Digest, bool)>,
}

#[derive(Clone, Debug)]
pub struct OutputWitness {
    pub owner: Digest,
    pub value: u64,
    pub unlock_height: u64,
    pub rseed: Digest,
}

#[derive(Clone, Debug)]
pub struct SlotWitness {
    pub anchor: Digest,
    pub inputs: [InputWitness; 2],
    pub outputs: [OutputWitness; 2],
    pub fee: u64,
    pub fee_blind: [F; FEE_BLIND_LEN],
    pub fee_is_priority: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub nf: [Digest; 2],
    pub cm_out: [Digest; 2],
    pub anchor: Digest,
    pub fee_commit: Digest,
}

impl PublicInputs {
    /// Advances the chain state by one step:
    /// s' = sponge(TAG_CHAIN, [s, nf₀, nf₁, cm₀, cm₁, anchor, fee_commit]).
    pub fn chain_step(&self, h: &Hasher, s: &Digest) -> Digest {
        let v = self.to_vec();
        let mut blocks = vec![*s];
        blocks.extend(
            v.chunks(RATE)
                .map(|c| <Block>::try_from(c).expect("RATE elements")),
        );
        h.sponge(TAG_CHAIN, &blocks)
    }

    /// Set element of the slot: E = sponge(TAG_SET, [nf₀, nf₁, cm₀, cm₁, d_ct]) squeezed six
    /// times (zero blocks after the first squeeze), SET_LEN elements in total. Neither the anchor
    /// nor the fee enters E: the anchor is proven against 𝒜, and the leaf statement carries the fee.
    pub fn set_element(&self, h: &Hasher, d_ct: &[F; DCT_LEN]) -> [F; SET_LEN] {
        let mut s = h.permute(Hasher::first_input(TAG_SET, SET_ABSORB, &self.nf[0]));

        for b in [&self.nf[1], &self.cm_out[0], &self.cm_out[1]] {
            s[..RATE].copy_from_slice(b);
            s = h.permute(s);
        }
        // The 16 ciphertext limbs occupy two rate-12 blocks. Bind the tail.
        for chunk in d_ct.chunks(RATE) {
            s[..RATE].copy_from_slice(&padded_block(chunk));
            s = h.permute(s);
        }
        let mut out = [F::ZERO; SET_LEN];
        out[..DIGEST].copy_from_slice(&s[..DIGEST]);
        for k in 1..SET_LEN / DIGEST {
            s[..RATE].fill(F::ZERO);
            s = h.permute(s);
            out[k * DIGEST..(k + 1) * DIGEST].copy_from_slice(&s[..DIGEST]);
        }
        out
    }

    pub fn to_vec(&self) -> Vec<F> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        for d in [
            &self.nf[0],
            &self.nf[1],
            &self.cm_out[0],
            &self.cm_out[1],
            &self.anchor,
            &self.fee_commit,
        ] {
            v.extend_from_slice(d);
        }
        v
    }

    pub fn to_u32s(&self) -> Vec<u32> {
        self.to_vec().iter().map(|x| x.as_canonical_u32()).collect()
    }
}

impl InputWitness {
    pub fn owner(&self, h: &Hasher) -> Digest {
        h.owner(&self.nk)
    }

    pub fn note(&self, h: &Hasher) -> Note {
        Note {
            owner: self.owner(h),
            value: self.value,
            unlock_height: self.unlock_height,
            rho: self.rho,
            rseed: self.rseed,
        }
    }
}

impl SlotWitness {
    pub fn output_note(&self, h: &Hasher, nf: &[Digest; 2], j: usize) -> Note {
        let o = &self.outputs[j];
        Note {
            owner: o.owner,
            value: o.value,
            unlock_height: o.unlock_height,
            rho: h.output_rho(&nf[0], &nf[1], j),
            rseed: o.rseed,
        }
    }

    pub fn public_inputs(&self, h: &Hasher) -> PublicInputs {
        let nf = [
            h.nullifier(&self.inputs[0].nk, &self.inputs[0].rho),
            h.nullifier(&self.inputs[1].nk, &self.inputs[1].rho),
        ];
        let cm_out = [
            h.note_cm(&self.output_note(h, &nf, 0)),
            h.note_cm(&self.output_note(h, &nf, 1)),
        ];
        PublicInputs {
            nf,
            cm_out,
            anchor: self.anchor,
            fee_commit: h.fee_commit(self.fee, &self.fee_blind),
        }
    }

    /// Native relation check: the constraints of the AIR and the SP1 guest must be equivalent to it.
    pub fn check(&self, h: &Hasher) -> Result<PublicInputs, &'static str> {
        self.check_with_base_fee(h, FEE_BASE)
    }

    /// `check` with the standard tier taken from `base_fee` (the priority tier is four times it).
    pub fn check_with_base_fee(
        &self,
        h: &Hasher,
        base_fee: u64,
    ) -> Result<PublicInputs, &'static str> {
        for inp in &self.inputs {
            if inp.path.len() != TREE_DEPTH {
                return Err("path length");
            }
            if inp.dummy {
                if inp.value != 0 {
                    return Err("dummy input with value");
                }
            } else if h.merkle_root(&h.note_cm(&inp.note(h)), &inp.path) != self.anchor {
                return Err("merkle root");
            }
        }
        let pi = self.public_inputs(h);
        if pi.nf[0] == pi.nf[1] {
            return Err("duplicate nullifier");
        }
        if self
            .outputs
            .iter()
            .any(|o| o.value != 0 && o.value < MIN_PACKAGE_DEPOSIT)
        {
            return Err("below minimum deposit");
        }
        let all_dummy = self.inputs.iter().all(|i| i.dummy);
        let tier = if self.fee_is_priority {
            4 * base_fee
        } else {
            base_fee
        };
        if self.fee != if all_dummy { 0 } else { tier } {
            return Err("fee tier");
        }
        let vin = u128::from(self.inputs[0].value) + u128::from(self.inputs[1].value);
        let vout = u128::from(self.outputs[0].value)
            + u128::from(self.outputs[1].value)
            + u128::from(self.fee);
        if vin != vout {
            return Err("value conservation");
        }
        Ok(pi)
    }
}

/// Recent-roots accumulator 𝒜: position h mod ANCHOR_RING holds anchor_entry(r_h, h,
/// base_fee(h)). Unused positions hold the zero digest, which is not an entry.
pub struct RecentRoots {
    leaves: Vec<Digest>,
}

impl Default for RecentRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl RecentRoots {
    pub fn new() -> Self {
        Self {
            leaves: vec![[F::ZERO; DIGEST]; ANCHOR_RING],
        }
    }

    pub fn insert(&mut self, h: &Hasher, height: u64, root: &Digest, base_fee: u64) {
        self.leaves[height as usize % ANCHOR_RING] = h.anchor_entry(root, height, base_fee);
    }

    /// All tree levels, leaves first.
    pub fn tree(&self, h: &Hasher) -> AnchorTree {
        let mut levels = vec![self.leaves.clone()];
        while levels.last().expect("non-empty").len() > 1 {
            let next = levels
                .last()
                .expect("non-empty")
                .chunks(2)
                .map(|p| h.compress(&p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        AnchorTree { levels }
    }
}

pub struct AnchorTree {
    levels: Vec<Vec<Digest>>,
}

impl AnchorTree {
    pub fn root(&self) -> Digest {
        self.levels[ANCHOR_DEPTH][0]
    }

    /// Membership path of block `height`, in `Hasher::merkle_root` order.
    pub fn path(&self, height: u64) -> Vec<(Digest, bool)> {
        let mut pos = height as usize % ANCHOR_RING;
        let mut path = Vec::with_capacity(ANCHOR_DEPTH);
        for level in &self.levels[..ANCHOR_DEPTH] {
            path.push((level[pos ^ 1], pos & 1 == 1));
            pos >>= 1;
        }
        path
    }
}

/// Accumulator-mode slot witness: the slot, its ciphertext digest, its 𝒜 entry data, and the
/// entry's membership path (used by the level-1 merge node, not by the leaf).
#[derive(Clone, Debug)]
pub struct AccWitness {
    pub slot: SlotWitness,
    pub d_ct: [u8; DCT_BYTES],
    /// Height h of the anchor block; `slot.anchor` is r_h.
    pub anchor_height: u64,
    pub base_fee: u64,
    /// Length ANCHOR_DEPTH.
    pub anchor_path: Vec<(Digest, bool)>,
}

/// What an accumulator leaf exposes: E, the fee, and the 𝒜 root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccLeaf {
    pub set: [F; SET_LEN],
    pub fee: u64,
    pub anchors_root: Digest,
}

impl AccWitness {
    /// The 𝒜 entry the leaf exposes; the level-1 merge node checks its membership.
    pub fn anchor_entry(&self, h: &Hasher) -> Digest {
        h.anchor_entry(&self.slot.anchor, self.anchor_height, self.base_fee)
    }

    pub fn anchors_root(&self, h: &Hasher) -> Digest {
        h.merkle_root(&self.anchor_entry(h), &self.anchor_path)
    }

    pub fn set_element(&self, h: &Hasher) -> [F; SET_LEN] {
        self.slot
            .public_inputs(h)
            .set_element(h, &pack_dct(&self.d_ct))
    }

    /// Native check against the 𝒜 root the block uses.
    pub fn check(&self, h: &Hasher, anchors_root: &Digest) -> Result<AccLeaf, &'static str> {
        if self.anchor_path.len() != ANCHOR_DEPTH {
            return Err("anchor path length");
        }
        if self.anchors_root(h) != *anchors_root {
            return Err("anchor not in accumulator");
        }
        if self
            .slot
            .inputs
            .iter()
            .any(|i| !i.dummy && i.unlock_height > self.anchor_height)
        {
            return Err("unlock height");
        }
        let pi = self.slot.check_with_base_fee(h, self.base_fee)?;
        Ok(AccLeaf {
            set: pi.set_element(h, &pack_dct(&self.d_ct)),
            fee: self.slot.fee,
            anchors_root: *anchors_root,
        })
    }
}

/// Accumulator witnesses for one block: slot i anchors at height `first_height + i` with the
/// given base fee, all entries in one 𝒜. Returns the witnesses and the 𝒜 root.
pub fn acc_witnesses(
    slots: Vec<SlotWitness>,
    first_height: u64,
    base_fee: u64,
    seed: u64,
) -> (Vec<AccWitness>, Digest) {
    assert!(slots.len() <= ANCHOR_RING);
    let h = Hasher::new();
    let mut ring = RecentRoots::new();
    for (i, s) in slots.iter().enumerate() {
        ring.insert(&h, first_height + i as u64, &s.anchor, base_fee);
    }
    let tree = ring.tree(&h);
    let mut rng = Rng::new(seed);
    let ws = slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            let anchor_height = first_height + i as u64;
            let mut d_ct = [0u8; DCT_BYTES];
            for c in d_ct.chunks_mut(8) {
                c.copy_from_slice(&rng.next_u64().to_le_bytes());
            }
            AccWitness {
                slot,
                d_ct,
                anchor_height,
                base_fee,
                anchor_path: tree.path(anchor_height),
            }
        })
        .collect();
    (ws, tree.root())
}

/// Sets the input unlock heights and rebuilds the level-0 siblings and the anchor to match.
/// The second input's path is only rebuilt when it is real (a dummy carries a random path).
pub fn with_unlock_heights(mut w: SlotWitness, unlock: [u64; 2]) -> SlotWitness {
    let h = Hasher::new();
    for (inp, u) in w.inputs.iter_mut().zip(unlock) {
        inp.unlock_height = u;
    }
    let cm0 = h.note_cm(&w.inputs[0].note(&h));
    let cm1 = h.note_cm(&w.inputs[1].note(&h));
    w.inputs[0].path[0].0 = cm1;
    if !w.inputs[1].dummy {
        w.inputs[1].path[0].0 = cm0;
    }
    w.anchor = h.merkle_root(&cm0, &w.inputs[0].path);
    w
}

/// Moves a slot to another base fee: its fee follows the tier and output 1 absorbs the change.
pub fn with_base_fee(mut w: SlotWitness, base_fee: u64) -> SlotWitness {
    let all_dummy = w.inputs.iter().all(|i| i.dummy);
    let fee = match (all_dummy, w.fee_is_priority) {
        (true, _) => 0,
        (false, false) => base_fee,
        (false, true) => 4 * base_fee,
    };
    w.outputs[1].value = w.outputs[1].value + w.fee - fee;
    w.fee = fee;
    w
}

/// u32 word-stream encoding of the witness (read by the SP1 guest). Field elements are stored
/// in canonical form; a u64 is split into (low, high).
impl SlotWitness {
    pub fn to_words(&self) -> Vec<u32> {
        let mut w = Vec::new();
        let d = |w: &mut Vec<u32>, x: &[F]| w.extend(x.iter().map(|e| e.as_canonical_u32()));
        let u = |w: &mut Vec<u32>, x: u64| w.extend([x as u32, (x >> 32) as u32]);
        d(&mut w, &self.anchor);
        for i in &self.inputs {
            d(&mut w, &i.nk);
            d(&mut w, &i.rho);
            d(&mut w, &i.rseed);
            u(&mut w, i.value);
            u(&mut w, i.unlock_height);
            w.push(u32::from(i.dummy));
            w.push(i.path.len() as u32);
            for (sib, right) in &i.path {
                d(&mut w, sib);
                w.push(u32::from(*right));
            }
        }
        for o in &self.outputs {
            d(&mut w, &o.owner);
            u(&mut w, o.value);
            u(&mut w, o.unlock_height);
            d(&mut w, &o.rseed);
        }
        u(&mut w, self.fee);
        d(&mut w, &self.fee_blind);
        w.push(u32::from(self.fee_is_priority));
        w
    }

    /// Decodes; returns None on any non-canonical field element, any boolean other than 0/1,
    /// or any length mismatch.
    pub fn from_words(words: &[u32]) -> Option<Self> {
        let mut r = Reader { w: words, pos: 0 };
        let anchor = r.digest()?;
        let input = |r: &mut Reader| -> Option<InputWitness> {
            let nk = r.digest()?;
            let rho = r.digest()?;
            let rseed = r.digest()?;
            let value = r.u64()?;
            let unlock_height = r.u64()?;
            let dummy = r.bool()?;
            let n = r.next()? as usize;
            if n != TREE_DEPTH {
                return None;
            }
            let mut path = Vec::with_capacity(n);
            for _ in 0..n {
                path.push((r.digest()?, r.bool()?));
            }
            Some(InputWitness {
                nk,
                rho,
                rseed,
                value,
                unlock_height,
                dummy,
                path,
            })
        };
        let inputs = [input(&mut r)?, input(&mut r)?];
        let output = |r: &mut Reader| -> Option<OutputWitness> {
            Some(OutputWitness {
                owner: r.digest()?,
                value: r.u64()?,
                unlock_height: r.u64()?,
                rseed: r.digest()?,
            })
        };
        let outputs = [output(&mut r)?, output(&mut r)?];
        let fee = r.u64()?;
        let mut fee_blind = [F::ZERO; FEE_BLIND_LEN];
        for element in &mut fee_blind {
            *element = r.felt()?;
        }
        let fee_is_priority = r.bool()?;
        (r.pos == words.len()).then_some(Self {
            anchor,
            inputs,
            outputs,
            fee,
            fee_blind,
            fee_is_priority,
        })
    }
}

struct Reader<'a> {
    w: &'a [u32],
    pos: usize,
}

impl Reader<'_> {
    fn next(&mut self) -> Option<u32> {
        let x = *self.w.get(self.pos)?;
        self.pos += 1;
        Some(x)
    }
    fn felt(&mut self) -> Option<F> {
        felt_from_canonical(self.next()?)
    }
    fn digest(&mut self) -> Option<Digest> {
        let mut d = [F::ZERO; DIGEST];
        for e in &mut d {
            *e = self.felt()?;
        }
        Some(d)
    }
    fn u64(&mut self) -> Option<u64> {
        let lo = self.next()?;
        let hi = self.next()?;
        Some(u64::from(lo) | (u64::from(hi) << 32))
    }
    fn bool(&mut self) -> Option<bool> {
        match self.next()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

/// Deterministic pseudorandom source (splitmix64), used only to generate benchmark witnesses.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn felt(&mut self) -> F {
        F::from_u64(self.next_u64())
    }

    pub fn digest(&mut self) -> Digest {
        core::array::from_fn(|_| self.felt())
    }
}

/// Generates a valid slot: two real inputs in the same depth-40 tree (siblings at level 0),
/// or, with `dummy_second`, a dummy second input.
pub fn sample_slot(seed: u64, dummy_second: bool) -> SlotWitness {
    let h = Hasher::new();
    let mut rng = Rng::new(seed);
    let v0 = 5_000_000 + (rng.next_u64() % 1_000_000);
    let v1 = if dummy_second {
        0
    } else {
        3_000_000 + (rng.next_u64() % 1_000_000)
    };
    let mut in0 = InputWitness {
        nk: rng.digest(),
        rho: rng.digest(),
        rseed: rng.digest(),
        value: v0,
        unlock_height: 100,
        dummy: false,
        path: Vec::new(),
    };
    let mut in1 = InputWitness {
        nk: rng.digest(),
        rho: rng.digest(),
        rseed: rng.digest(),
        value: v1,
        unlock_height: 120,
        dummy: dummy_second,
        path: Vec::new(),
    };
    let cm0 = h.note_cm(&in0.note(&h));
    let cm1 = h.note_cm(&in1.note(&h));
    let upper: Vec<(Digest, bool)> = (1..TREE_DEPTH)
        .map(|_| (rng.digest(), rng.next_u64() & 1 == 1))
        .collect();
    in0.path.push((cm1, false));
    in0.path.extend_from_slice(&upper);
    if dummy_second {
        in1.path = (0..TREE_DEPTH)
            .map(|_| (rng.digest(), rng.next_u64() & 1 == 1))
            .collect();
    } else {
        in1.path.push((cm0, true));
        in1.path.extend_from_slice(&upper);
    }
    let anchor = h.merkle_root(&cm0, &in0.path);
    let fee = FEE_BASE;
    let o0 = (v0 + v1 - fee) / 3;
    let o1 = v0 + v1 - fee - o0;
    let outputs = [
        OutputWitness {
            owner: rng.digest(),
            value: o0,
            unlock_height: 0,
            rseed: rng.digest(),
        },
        OutputWitness {
            owner: rng.digest(),
            value: o1,
            unlock_height: 0,
            rseed: rng.digest(),
        },
    ];
    SlotWitness {
        anchor,
        inputs: [in0, in1],
        outputs,
        fee,
        fee_blind: core::array::from_fn(|_| rng.felt()),
        fee_is_priority: false,
    }
}

/// Empty package: both inputs dummy, zero value and zero fee (what a miner fills unused slots
/// with).
pub fn sample_empty_slot(seed: u64) -> SlotWitness {
    let mut w = sample_slot(seed, true);
    w.inputs[0].dummy = true;
    w.inputs[0].value = 0;
    for o in &mut w.outputs {
        o.value = 0;
    }
    w.fee = 0;
    w
}

/// `sample_slot` paying the priority tier.
pub fn sample_priority_slot(seed: u64) -> SlotWitness {
    let mut w = sample_slot(seed, false);
    w.fee_is_priority = true;
    w.fee = FEE_PRIORITY;
    w.outputs[1].value -= FEE_PRIORITY - FEE_BASE;
    w
}

#[cfg(test)]
mod tests {
    #[test]
    fn fee_blinding_uses_all_eight_independent_elements() {
        use p3_field::PrimeCharacteristicRing;
        assert_eq!(super::FEE_BLIND_LEN, 8);
        let hasher = super::Hasher::new();
        let blind = [super::F::ONE; super::FEE_BLIND_LEN];
        let expected = hasher.fee_commit(super::FEE_BASE, &blind);
        for k in 0..super::FEE_BLIND_LEN {
            let mut changed = blind;
            changed[k] += super::F::ONE;
            assert_ne!(hasher.fee_commit(super::FEE_BASE, &changed), expected);
        }
        let witness = super::sample_slot(994, false);
        assert_eq!(
            super::SlotWitness::from_words(&witness.to_words())
                .unwrap()
                .fee_blind,
            witness.fee_blind
        );
    }
    use super::*;

    #[test]
    fn witness_words_roundtrip_and_reject_noncanonical() {
        let h = Hasher::new();
        for dummy in [false, true] {
            let w = sample_slot(9, dummy);
            let words = w.to_words();
            let back = SlotWitness::from_words(&words).expect("decodable");
            assert_eq!(back.check(&h), w.check(&h));
            let mut bad = words.clone();
            bad[0] = F::ORDER_U32;
            assert!(SlotWitness::from_words(&bad).is_none());
            let mut bad = words.clone();
            bad.push(0);
            assert!(SlotWitness::from_words(&bad).is_none());
        }
    }

    #[test]
    fn sample_slots_satisfy_relation() {
        let h = Hasher::new();
        for seed in 0..4 {
            sample_slot(seed, false).check(&h).unwrap();
            sample_slot(seed, true).check(&h).unwrap();
            sample_empty_slot(seed).check(&h).unwrap();
            sample_priority_slot(seed).check(&h).unwrap();
        }
    }

    #[test]
    fn set_elements_are_deterministic_and_distinct() {
        let h = Hasher::new();
        let a = sample_slot(1, false).public_inputs(&h);
        let b = sample_slot(2, false).public_inputs(&h);
        let d = pack_dct(&[7; DCT_BYTES]);
        assert_eq!(SET_LEN, 72);
        assert_eq!(a.set_element(&h, &d), a.set_element(&h, &d));
        assert_ne!(a.set_element(&h, &d), b.set_element(&h, &d));
        // Every squeeze contributes distinct elements.
        let e = a.set_element(&h, &d);
        for k in 1..SET_LEN / DIGEST {
            assert_ne!(e[..DIGEST], e[k * DIGEST..(k + 1) * DIGEST]);
        }
        // Neither the fee commitment nor the anchor enters E; every d_ct limb does.
        let mut c = a.clone();
        c.fee_commit[0] += F::ONE;
        c.anchor[7] += F::ONE;
        assert_eq!(c.set_element(&h, &d), e);
        for k in 0..DCT_LEN {
            let mut d2 = d;
            d2[k] += F::ONE;
            assert_ne!(a.set_element(&h, &d2), e, "d_ct limb {k}");
        }
        for k in 0..2 {
            let mut c = a.clone();
            c.nf[k][0] += F::ONE;
            assert_ne!(c.set_element(&h, &d), e);
            let mut c = a.clone();
            c.cm_out[k][0] += F::ONE;
            assert_ne!(c.set_element(&h, &d), e);
        }
    }

    #[test]
    fn dct_packing_is_injective_little_endian() {
        let mut b = [0u8; DCT_BYTES];
        b[0] = 0x34;
        b[1] = 0x12;
        b[31] = 0xff;
        let d = pack_dct(&b);
        assert_eq!(d[0], F::from_u32(0x1234));
        assert_eq!(d[DCT_LEN - 1], F::from_u32(0xff00));
        let mut b2 = b;
        b2[1] = 0x13;
        assert_ne!(pack_dct(&b2), d);
    }

    #[test]
    fn anchor_accumulator_membership() {
        let h = Hasher::new();
        let slots: Vec<_> = (0..4).map(|s| sample_slot(s, s % 2 == 1)).collect();
        // Heights wrap around the ring: position 4095 and then 0, 1, 2.
        let first = 3 * ANCHOR_RING as u64 - 1;
        let (ws, root) = acc_witnesses(slots, first, FEE_BASE, 1);
        for w in &ws {
            assert_eq!(w.anchor_path.len(), ANCHOR_DEPTH);
            assert_eq!(h.merkle_root(&w.anchor_entry(&h), &w.anchor_path), root);
            let leaf = w.check(&h, &root).expect("valid accumulator witness");
            assert_eq!(leaf.fee, FEE_BASE);
            assert_eq!(leaf.set, w.set_element(&h));
        }
        assert_eq!(ws[1].anchor_height as usize % ANCHOR_RING, 0);

        let mut bad = ws[0].clone();
        bad.anchor_height += 1;
        assert_eq!(bad.check(&h, &root), Err("anchor not in accumulator"));
        let mut bad = ws[0].clone();
        bad.base_fee += 1;
        assert_eq!(bad.check(&h, &root), Err("anchor not in accumulator"));
        let mut bad = ws[0].clone();
        bad.anchor_path[ANCHOR_DEPTH - 1].0[0] += F::ONE;
        assert_eq!(bad.check(&h, &root), Err("anchor not in accumulator"));
        // Another slot's anchor root with this slot's membership path.
        let mut bad = ws[0].clone();
        bad.slot.anchor = ws[1].slot.anchor;
        assert_eq!(bad.check(&h, &root), Err("anchor not in accumulator"));
    }

    #[test]
    fn fee_tiers_follow_the_accumulator_base_fee() {
        let h = Hasher::new();
        let base = 500_001;
        let slots = vec![
            with_base_fee(sample_slot(1, false), base),
            with_base_fee(sample_priority_slot(2), base),
            with_base_fee(sample_empty_slot(3), base),
        ];
        let (ws, root) = acc_witnesses(slots, 200, base, 2);
        let fees: Vec<u64> = ws.iter().map(|w| w.check(&h, &root).unwrap().fee).collect();
        assert_eq!(fees, [base, 4 * base, 0]);
        // The epoch-0 constant is no longer accepted when the entry says otherwise.
        let (ws, root) = acc_witnesses(vec![sample_slot(1, false)], 200, base, 2);
        assert_eq!(ws[0].check(&h, &root), Err("fee tier"));
    }

    #[test]
    fn miner_note_commitment_is_a_note() {
        let h = Hasher::new();
        let (owner, rseed) = (Rng::new(1).digest(), Rng::new(2).digest());
        let cm = h.miner_note_cm(1234, 77, &owner, &rseed);
        let note = Note {
            owner,
            value: 1234,
            unlock_height: 177,
            rho: h.miner_rho(77),
            rseed,
        };
        assert_eq!(cm, h.note_cm(&note));
        assert_ne!(h.miner_rho(77), h.miner_rho(78));
        assert_ne!(cm, h.miner_note_cm(1235, 77, &owner, &rseed));
        assert_ne!(cm, h.miner_note_cm(1234, 78, &owner, &rseed));
    }

    #[test]
    fn broken_slots_are_rejected() {
        let h = Hasher::new();
        let mut w = sample_slot(1, false);
        w.outputs[0].value += 1;
        assert_eq!(w.check(&h), Err("value conservation"));

        let mut w = sample_slot(1, false);
        w.anchor[0] += F::ONE;
        assert_eq!(w.check(&h), Err("merkle root"));

        let mut w = sample_slot(1, false);
        w.fee = 1;
        assert_eq!(w.check(&h), Err("fee tier"));

        let mut w = sample_slot(1, true);
        w.inputs[1].value = 7;
        assert_eq!(w.check(&h), Err("dummy input with value"));

        let mut w = sample_slot(1, false);
        w.inputs[1].nk = w.inputs[0].nk;
        w.inputs[1].rho = w.inputs[0].rho;
        w.inputs[1].dummy = true;
        w.inputs[1].value = 0;
        w.outputs[1].value -= sample_slot(1, false).inputs[1].value;
        assert_eq!(w.check(&h), Err("duplicate nullifier"));

        // An output is 0 or at least MIN_PACKAGE_DEPOSIT; output 1 absorbs the difference.
        for (o0, ok) in [
            (1, false),
            (MIN_PACKAGE_DEPOSIT - 1, false),
            (MIN_PACKAGE_DEPOSIT, true),
            (0, true),
        ] {
            let mut w = sample_slot(1, false);
            w.outputs[1].value = w.outputs[1].value + w.outputs[0].value - o0;
            w.outputs[0].value = o0;
            let r = w.check(&h).map(|_| ());
            assert_eq!(
                r,
                if ok {
                    Ok(())
                } else {
                    Err("below minimum deposit")
                },
                "{o0}"
            );
        }
    }

    /// A real input unlocks at the latest at the anchor height; a dummy input's unlock height is
    /// not checked.
    #[test]
    fn unlock_height_is_checked_against_the_anchor_height() {
        let h = Hasher::new();
        let at = |w: SlotWitness, height: u64| {
            let (ws, root) = acc_witnesses(vec![w], height, FEE_BASE, 3);
            ws[0].check(&h, &root).map(|_| ())
        };
        let w = sample_slot(1, false);
        assert_eq!(at(w.clone(), 120), Ok(()));
        assert_eq!(at(w.clone(), 119), Err("unlock height"));
        for (unlock, ok) in [
            ([500, 500], true),
            ([501, 0], false),
            ([0, 501], false),
            ([500 + (1 << 16), 0], false),
            ([u64::MAX, 0], false),
        ] {
            let w = with_unlock_heights(sample_slot(1, false), unlock);
            w.check(&h).expect("the slot itself is valid");
            let r = at(w, 500);
            assert_eq!(
                r,
                if ok { Ok(()) } else { Err("unlock height") },
                "{unlock:?}"
            );
        }
        let w = with_unlock_heights(sample_slot(1, true), [500, u64::MAX]);
        assert_eq!(at(w, 500), Ok(()), "dummy input");
    }

    /// Non-canonical encodings alias: the same nullifier would have two byte spellings, the
    /// proof (and E) would accept both, and a byte-keyed nullifier set would admit a double spend.
    #[test]
    fn noncanonical_encodings_alias_and_are_rejected() {
        let p = F::ORDER_U32;
        // 2p < 2^32, so every element has a second encoding.
        for x in [0, 1, p / 2, p - 1] {
            assert_eq!(F::from_u32(x), F::from_u32(x + p), "alias of {x}");
            assert_eq!(felt_from_canonical(x), Some(F::from_u32(x)));
            assert_eq!(felt_from_canonical(x + p), None);
        }
        assert_eq!(felt_from_canonical(p - 1), Some(F::NEG_ONE));
        assert_eq!(felt_from_canonical(p), None);
    }

    /// Why each leaf position may count once and the tree shape is fixed: with multiplicities
    /// taken mod p, SET_LEN + 1 set elements always have a nontrivial dependency, which Gaussian
    /// elimination finds instantly. A tree that let a prover re-merge a subtree an arbitrary number
    /// of times (or let the count wrap) would turn it into a forged ΣE. The coefficients needed
    /// are full-size field elements, far above any multiplicity N ≤ 128 allows.
    #[test]
    fn unbounded_multiplicities_break_the_sum() {
        use p3_field::Field;
        let h = Hasher::new();
        let cols: Vec<[F; SET_LEN]> = (0..SET_LEN as u64 + 1)
            .map(|i| {
                let mut d = [0u8; DCT_BYTES];
                d[..8].copy_from_slice(&i.to_le_bytes());
                sample_slot(100 + i, false)
                    .public_inputs(&h)
                    .set_element(&h, &pack_dct(&d))
            })
            .collect();
        let n = cols.len();
        // Row-reduce the SET_LEN × n matrix whose columns are the set elements.
        let mut m: Vec<Vec<F>> = (0..SET_LEN)
            .map(|r| cols.iter().map(|c| c[r]).collect())
            .collect();
        let mut pivots = Vec::new();
        let mut row = 0;
        for col in 0..n {
            let Some(pr) = (row..SET_LEN).find(|&r| m[r][col] != F::ZERO) else {
                continue;
            };
            m.swap(row, pr);
            let inv = m[row][col].inverse();
            for v in &mut m[row] {
                *v *= inv;
            }
            for r in 0..SET_LEN {
                if r != row && m[r][col] != F::ZERO {
                    let f = m[r][col];
                    let pivot_row = m[row].clone();
                    for (v, p) in m[r].iter_mut().zip(pivot_row) {
                        *v -= p * f;
                    }
                }
            }
            pivots.push(col);
            row += 1;
            if row == SET_LEN {
                break;
            }
        }
        let free = (0..n).find(|c| !pivots.contains(c)).expect("n > rank");
        let mut coeff = vec![F::ZERO; n];
        coeff[free] = F::ONE;
        for (r, &pc) in pivots.iter().enumerate() {
            coeff[pc] = -m[r][free];
        }
        for e in 0..SET_LEN {
            let s = cols
                .iter()
                .zip(&coeff)
                .fold(F::ZERO, |a, (c, &k)| a + c[e] * k);
            assert_eq!(s, F::ZERO, "dependency holds in coordinate {e}");
        }
        // Read the coefficients as signed multiplicities: they are nowhere near small.
        let p = F::ORDER_U32;
        let max = coeff
            .iter()
            .map(|k| {
                let x = k.as_canonical_u32();
                x.min(p - x)
            })
            .max()
            .unwrap();
        assert!(max > 1 << 20, "max |multiplicity| {max}");
    }
}
