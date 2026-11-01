//! Private seed-recoverable wallet primitives for native engineering chains.
//!
//! These primitives accept a supplied 32-byte seed. The wallet_vault module
//! adds mnemonic entropy backup and encrypted seed custody. User interfaces,
//! durable payment integration and relay transport require separate acceptance.
//! Rescans authenticate ciphertext and reconstruct commitments after independent
//! canonical replay. Wallet keys, receipts and payment bundles have no Debug or
//! serialization implementation. Their private contents must never be sent to
//! public telemetry, including through lower-level note or sidecar types.
use crate::audit::{AuditReport, replay_chain};
use crate::proofs::NativeProver;
use crate::state::{BlockVerifier, Config, State, base_fee};
use crate::wallet_crypto::RecoverableViewKey;
use crate::wire::{Block, DigestBytes, Hash, PublicRecord, Sidecar, Transaction};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::encryption::{
    EncryptionContext, PaymentAddress, PaymentCiphertext, PaymentEncryptionOpening,
    SenderChangeSecret, decrypt_change_at, encrypt_change_at, encrypt_payment_with_opening,
};
use native::multi_asset::{
    AccWitness, AssetId, Digest, F, Hasher, InputWitness, Note, OutputWitness, SIP_ASSET_ID,
    SlotWitness, TREE_DEPTH,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// Independent domains separate spend, ML-KEM and sender-change key material.
/// The network ID and little-endian account index are included in each domain.
pub struct WalletKeys {
    network: Hash,
    nullifier_key: Zeroizing<DigestBytes>,
    recipient: RecoverableViewKey,
    change: SenderChangeSecret,
    automatic_selection_key: Zeroizing<[u8; 32]>,
}
impl WalletKeys {
    /// Consume the seed buffer; the caller must erase any preexisting source
    /// copies. Native field and dependency-internal copies are not covered by
    /// byte-buffer erasure. No seed is persisted by this API.
    pub fn from_seed(
        network: Hash,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
    ) -> Result<Self, String> {
        if network == [0; 32] {
            return Err("wallet requires a nonzero engineering network ID".into());
        }
        let derive = |domain: &'static str| {
            let mut hash = blake3::Hasher::new_derive_key(domain);
            hash.update(seed.as_ref());
            hash.update(&network);
            hash.update(&account.to_le_bytes());
            hash.finalize_xof()
        };
        let mut spend_reader = derive("siworld native wallet spend key v1");
        let nullifier_key = fields(&mut |bytes| {
            spend_reader.fill(bytes);
            Ok(())
        })?;
        let mut kem_seed = Zeroizing::new([0; 64]);
        derive("siworld native wallet ML-KEM view key v1").fill(kem_seed.as_mut());
        let recipient =
            RecoverableViewKey::from_seed(Hasher::new().owner(&nullifier_key), kem_seed)
                .map_err(|_| "wallet view-key derivation failed")?;
        let mut change_seed = Zeroizing::new([0; 32]);
        derive("siworld native wallet sender change key v1").fill(change_seed.as_mut());
        let mut automatic_selection_key = Zeroizing::new([0; 32]);
        derive("siworld native wallet automatic note scheduling v1")
            .fill(automatic_selection_key.as_mut());
        Ok(Self {
            network,
            automatic_selection_key,
            nullifier_key: Zeroizing::new(encode_digest(&nullifier_key)),
            recipient,
            change: SenderChangeSecret::new(*change_seed),
        })
    }
    pub fn address(&self) -> PaymentAddress {
        self.recipient.address()
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    fn spend_key(&self) -> Digest {
        decode_digest(&self.nullifier_key).expect("canonical wallet key encoding")
    }
    /// Recheck the completed 2-in/3-out public fields before proof/broadcast.
    /// This checks encryption consistency, not inclusion or proof validity.
    pub fn check_before_broadcast(
        &self,
        public: &PublicTransaction,
        notes: &[Note; 3],
        recipient: &PaymentAddress,
        opening: &PaymentEncryptionOpening,
    ) -> Result<(), String> {
        let h = Hasher::new();
        if public.cm != notes.each_ref().map(|note| h.note_cm(note)) {
            return Err("wallet output commitment mismatch".into());
        }
        let ec = EncryptionContext::new(self.network);
        let payment = opening
            .verify_payment(recipient, &public.cm[0], &public.payment, &ec)
            .map_err(|_| "wallet payment self-check failed")?;
        if !same_note(&payment, &notes[0]) {
            return Err("wallet payment plaintext mismatch".into());
        }
        for (index, note) in notes.iter().enumerate().skip(1) {
            if note.owner != self.address().owner() {
                return Err("wallet change owner mismatch".into());
            }
            let change = decrypt_change_at(
                &self.change,
                note.owner,
                &public.cm[index],
                &public.change[index - 1],
                &ec,
                index as u8,
            )
            .map_err(|_| "wallet change self-check failed")?;
            if !same_note(&change, note) {
                return Err("wallet change plaintext mismatch".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeTier {
    Standard,
    Priority,
}

/// Private authenticated receipt. No field is a public monitoring statistic.
pub struct OwnedNote {
    pub commitment: DigestBytes,
    pub nullifier: DigestBytes,
    pub height: u64,
    pub block_id: Hash,
    /// Local output-category position, not a receipt identity. Transactions
    /// repeat positions across slots; persistent records must use commitments
    /// or a complete tagged origin instead of a block/position pair.
    pub output_index: u8,
    pub spent: bool,
    // Canonical timestamp when this note first becomes consensus-spendable.
    // This remains private and is reconstructed from canonical history.
    eligible_timestamp: Option<u64>,
    note: Note,
}
impl OwnedNote {
    pub fn note(&self) -> &Note {
        &self.note
    }
}
impl Drop for OwnedNote {
    fn drop(&mut self) {
        self.nullifier.zeroize();
        self.note.asset_id.0.zeroize();
        self.note.owner.fill(F::ZERO);
        self.note.value.zeroize();
        self.note.unlock_height.zeroize();
        self.note.rho.fill(F::ZERO);
        self.note.rseed.fill(F::ZERO);
        self.eligible_timestamp.zeroize();
    }
}

/// Private wallet-display data. Dates estimate target-time progress only;
/// consensus spendability is determined exclusively by accepted block height.
pub struct LockedTranche {
    pub asset: AssetId,
    pub amount: u128,
    pub unlock_height: u64,
    pub estimated_timestamp: Option<u64>,
}
pub struct BalanceDetails {
    pub available: BTreeMap<AssetId, u128>,
    pub locked: BTreeMap<AssetId, u128>,
    pub tranches: Vec<LockedTranche>,
    pub next_unlock_height: Option<u64>,
}

pub const AUTO_DELAY_MIN_SECONDS: u64 = 6 * 60 * 60;
pub const AUTO_DELAY_MAX_SECONDS: u64 = 3 * 24 * 60 * 60;

pub struct Wallet {
    keys: WalletKeys,
    head: Option<(u64, Hash, Hash)>,
    receipts: Vec<OwnedNote>,
}
impl Wallet {
    pub fn from_seed(
        network: Hash,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
    ) -> Result<Self, String> {
        Ok(Self {
            keys: WalletKeys::from_seed(network, seed, account)?,
            head: None,
            receipts: Vec::new(),
        })
    }
    pub fn address(&self) -> PaymentAddress {
        self.keys.address()
    }
    pub fn head(&self) -> Option<(u64, Hash, Hash)> {
        self.head
    }
    pub fn receipts(&self) -> &[OwnedNote] {
        &self.receipts
    }
    /// Replace private receipts atomically after independently replaying the
    /// complete canonical chain. The caller authenticates/selects that chain;
    /// this does not authenticate checkpoints or choose the greatest-work fork.
    /// A replacement replay removes orphan outputs and restores orphan spends.
    pub fn reconcile(
        &mut self,
        config: Config,
        blocks: &[Block],
        verifier: &impl BlockVerifier,
    ) -> Result<AuditReport, String> {
        if config.network != self.keys.network {
            return Err("wallet network differs from canonical replay".into());
        }
        let (state, report) = replay_chain(config, blocks, verifier)?;
        let mut receipts = Vec::new();
        let ec = EncryptionContext::new(self.keys.network);
        for block in blocks {
            let block_id = block.id()?;
            for tx in &block.transactions {
                let public = PublicTransaction::decode(&tx.record.body)
                    .map_err(|_| "wallet replay contains invalid public fields")?;
                if let Ok(note) =
                    self.keys
                        .recipient
                        .decrypt_payment(&public.cm[0], &public.payment, &ec)
                {
                    receipts.push(self.receipt(note, public.cm[0], block.height, block_id, 0));
                }
                for index in 1..3 {
                    if let Ok(note) = decrypt_change_at(
                        &self.keys.change,
                        self.keys.address().owner(),
                        &public.cm[index],
                        &public.change[index - 1],
                        &ec,
                        index as u8,
                    ) {
                        receipts.push(self.receipt(
                            note,
                            public.cm[index],
                            block.height,
                            block_id,
                            index as u8,
                        ));
                    }
                }
            }
            for (index, reward) in block.rewards.iter().enumerate() {
                let commitment = decode_digest(&reward.commitment)
                    .map_err(|_| "wallet replay contains invalid reward commitment")?;
                if let Ok(note) = self.keys.recipient.decrypt_payment(
                    &commitment,
                    &decode_payment(&reward.ciphertext),
                    &ec,
                ) {
                    receipts.push(self.receipt(
                        note,
                        commitment,
                        block.height,
                        block_id,
                        3 + index as u8,
                    ));
                }
            }
            for (issuance_index, issuance) in block.issuances.iter().enumerate() {
                for (note_index, ciphertext) in issuance.ciphertexts.iter().enumerate() {
                    let commitment = issuance.signed.declaration.note_commitments[note_index];
                    let bytes = ciphertext
                        .as_slice()
                        .try_into()
                        .map_err(|_| "wallet issuance ciphertext width")?;
                    if let Ok(note) = self.keys.recipient.decrypt_payment(
                        &commitment,
                        &decode_payment(bytes),
                        &ec,
                    ) {
                        let output_index = u8::try_from(
                            8 + crate::wire::MAX_FUND_SPENDS
                                + issuance_index * crate::issuance::INITIAL_NOTES
                                + note_index,
                        )
                        .map_err(|_| "issuance receipt index exceeds wallet width")?;
                        receipts.push(self.receipt(
                            note,
                            commitment,
                            block.height,
                            block_id,
                            output_index,
                        ));
                    }
                }
            }
            for (index, spend) in block.fund_spends.iter().enumerate() {
                let commitment = decode_digest(&spend.commitment)
                    .map_err(|_| "wallet replay contains invalid fund commitment")?;
                if let Ok(note) = self.keys.recipient.decrypt_payment(
                    &commitment,
                    &decode_payment(&spend.ciphertext),
                    &ec,
                ) {
                    let output_index = u8::try_from(8 + index)
                        .map_err(|_| "fund receipt index exceeds wallet width")?;
                    receipts.push(self.receipt(
                        note,
                        commitment,
                        block.height,
                        block_id,
                        output_index,
                    ));
                }
            }
        }
        // Keep timestamps only for relevant unlock heights, rather than a
        // second full permanent copy of canonical block headers.
        let mut eligibility = receipts
            .iter()
            .map(|r| (r.height.max(r.note.unlock_height), None))
            .collect::<BTreeMap<u64, Option<u64>>>();
        for block in blocks {
            if let Some(timestamp) = eligibility.get_mut(&block.height) {
                *timestamp = Some(block.timestamp);
            }
        }
        for receipt in &mut receipts {
            receipt.spent = state.spent.contains(&receipt.nullifier);
            receipt.eligible_timestamp = eligibility
                .get(&receipt.height.max(receipt.note.unlock_height))
                .copied()
                .flatten();
        }
        self.head = Some((state.height, state.tip, state.fingerprint()));
        self.receipts = receipts;
        Ok(report)
    }
    fn receipt(
        &self,
        note: Note,
        commitment: Digest,
        height: u64,
        block_id: Hash,
        output_index: u8,
    ) -> OwnedNote {
        OwnedNote {
            commitment: encode_digest(&commitment),
            nullifier: encode_digest(&Hasher::new().nullifier(&self.keys.spend_key(), &note.rho)),
            height,
            block_id,
            output_index,
            spent: false,
            eligible_timestamp: None,
            note,
        }
    }
    /// Return private mature unspent balances, separately for each asset.
    pub fn balances(&self, spend_height: u64) -> Result<BTreeMap<AssetId, u128>, String> {
        let mut balances = BTreeMap::<AssetId, u128>::new();
        for receipt in &self.receipts {
            if !receipt.spent
                && receipt.note.unlock_height <= spend_height
                && receipt.note.value > 0
            {
                let balance = balances.entry(receipt.note.asset_id).or_default();
                *balance = balance
                    .checked_add(u128::from(receipt.note.value))
                    .ok_or("wallet balance overflow")?;
            }
        }
        Ok(balances)
    }
    fn require_state(&self, state: &State) -> Result<(), String> {
        if self.keys.network != state.config.network
            || self.head != Some((state.height, state.tip, state.fingerprint()))
        {
            return Err("wallet must reconcile the exact accepted state before spending".into());
        }
        Ok(())
    }
    /// Authenticated private balances and lock batches at the exact replayed
    /// head. Do not export these values as node metrics or public statistics.
    pub fn balance_details(&self, state: &State) -> Result<BalanceDetails, String> {
        self.require_state(state)?;
        let available = self.balances(state.height)?;
        let mut locked = BTreeMap::<AssetId, u128>::new();
        let mut batches = BTreeMap::<(u64, AssetId), u128>::new();
        for receipt in &self.receipts {
            if receipt.spent
                || receipt.note.value == 0
                || receipt.note.unlock_height <= state.height
            {
                continue;
            }
            let value = u128::from(receipt.note.value);
            let total = locked.entry(receipt.note.asset_id).or_default();
            *total = total
                .checked_add(value)
                .ok_or("wallet locked balance overflow")?;
            let batch = batches
                .entry((receipt.note.unlock_height, receipt.note.asset_id))
                .or_default();
            *batch = batch
                .checked_add(value)
                .ok_or("wallet lock batch overflow")?;
        }
        let next_unlock_height = batches.keys().next().map(|(height, _)| *height);
        let tranches = batches
            .into_iter()
            .map(|((unlock_height, asset), amount)| LockedTranche {
                asset,
                amount,
                unlock_height,
                estimated_timestamp: unlock_height
                    .checked_sub(state.height)
                    .and_then(|blocks| blocks.checked_mul(state.config.target_interval))
                    .and_then(|seconds| state.timestamp().checked_add(seconds)),
            })
            .collect();
        Ok(BalanceDetails {
            available,
            locked,
            tranches,
            next_unlock_height,
        })
    }
    /// Private wallet scheduling time, reconstructed after seed recovery.
    /// Locked inputs use this boundary for transfer preparation; automatic
    /// consolidation also applies it to ordinary notes. Unreached unlocks and
    /// spent/zero notes return None. Local time never changes consensus validity.
    pub fn automatic_ready_timestamp(
        &self,
        commitment: &DigestBytes,
    ) -> Result<Option<u64>, String> {
        let receipt = self
            .receipts
            .iter()
            .find(|r| &r.commitment == commitment)
            .ok_or("automatic selection requires an authenticated owned note")?;
        self.ready_timestamp(receipt)
    }
    fn ready_timestamp(&self, receipt: &OwnedNote) -> Result<Option<u64>, String> {
        if receipt.spent || receipt.note.value == 0 {
            return Ok(None);
        }
        let Some(eligible) = receipt.eligible_timestamp else {
            return Ok(None);
        };
        let mut hash = blake3::Hasher::new_keyed(&self.keys.automatic_selection_key);
        hash.update(&receipt.commitment);
        let mut reader = hash.finalize_xof();
        let span = AUTO_DELAY_MAX_SECONDS - AUTO_DELAY_MIN_SECONDS + 1;
        let ceiling = u64::MAX - u64::MAX % span;
        let sampled = loop {
            let mut bytes = [0; 8];
            reader.fill(&mut bytes);
            let value = u64::from_le_bytes(bytes);
            if value < ceiling {
                break value % span;
            }
        };
        eligible
            .checked_add(AUTO_DELAY_MIN_SECONDS + sampled)
            .map(Some)
            .ok_or_else(|| "wallet automation timestamp overflow".into())
    }
    /// Opt-in preparation only: the caller must privately reserve selected
    /// inputs and protect the payment opening before proof or submission.
    /// Retains at most two candidates. Token consolidation would also require
    /// a SIP fee input, so two token notes cannot use this two-input operation.
    pub fn prepare_small_sip_consolidation(
        &self,
        state: &State,
        max_note_value: u64,
        tier: FeeTier,
        now: u64,
    ) -> Result<Option<PreparedTransfer>, String> {
        self.require_state(state)?;
        if max_note_value == 0 {
            return Err("small-note threshold must be positive".into());
        }
        let mut candidates: [Option<&OwnedNote>; 2] = [None, None];
        for receipt in &self.receipts {
            if receipt.spent
                || receipt.note.asset_id != SIP_ASSET_ID
                || receipt.note.value == 0
                || receipt.note.value > max_note_value
                || receipt.note.unlock_height > state.height
                || state.spent.contains(&receipt.nullifier)
                || self
                    .ready_timestamp(receipt)?
                    .is_none_or(|ready| now < ready)
            {
                continue;
            }
            let key = (receipt.note.value, receipt.commitment);
            if candidates[0].is_none_or(|first| key < (first.note.value, first.commitment)) {
                candidates[1] = candidates[0];
                candidates[0] = Some(receipt);
            } else if candidates[1]
                .is_none_or(|second| key < (second.note.value, second.commitment))
            {
                candidates[1] = Some(receipt);
            }
        }
        let [Some(first), Some(second)] = candidates else {
            return Ok(None);
        };
        let total = first
            .note
            .value
            .checked_add(second.note.value)
            .ok_or("consolidation amount overflow")?;
        let fee = base_fee(state.height)
            .checked_mul(if tier == FeeTier::Priority { 4 } else { 1 })
            .ok_or("consolidation fee overflow")?;
        let Some(amount) = total.checked_sub(fee).filter(|amount| *amount > 0) else {
            return Ok(None);
        };
        self.prepare_transfer(
            state,
            [Some(first.commitment), Some(second.commitment)],
            &self.address(),
            SIP_ASSET_ID,
            amount,
            tier,
            now,
        )
        .map(Some)
    }
    /// Construct a private transfer witness with one recipient and up to two
    /// asset-specific change outputs. `None` supplies a fresh zero-value input.
    /// SIP alone pays the selected canonical-snapshot standard/priority fee.
    /// Every nonzero-unlock input waits for its private post-maturity delay.
    /// `now` is local wallet policy and must never enter consensus validation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_transfer(
        &self,
        state: &State,
        selected: [Option<DigestBytes>; 2],
        recipient: &PaymentAddress,
        asset: AssetId,
        amount: u64,
        tier: FeeTier,
        now: u64,
    ) -> Result<PreparedTransfer, String> {
        self.prepare_transfer_with_randomness(
            state, selected, recipient, asset, amount, tier, now, None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_transfer_with_randomness(
        &self,
        state: &State,
        selected: [Option<DigestBytes>; 2],
        recipient: &PaymentAddress,
        asset: AssetId,
        amount: u64,
        tier: FeeTier,
        now: u64,
        payment_randomness: Option<Digest>,
    ) -> Result<PreparedTransfer, String> {
        self.require_state(state)?;
        if amount == 0 || selected == [None, None] {
            return Err("wallet transfer requires a nonzero payment and an owned input".into());
        }
        if selected[0].is_some() && selected[0] == selected[1] {
            return Err("wallet input selected twice".into());
        }
        let h = Hasher::new();
        let mut totals = BTreeMap::<AssetId, u128>::new();
        let mut make_input = |selected: Option<DigestBytes>| -> Result<InputWitness, String> {
            let Some(commitment) = selected else {
                return Ok(InputWitness {
                    asset_id: SIP_ASSET_ID,
                    nk: random_fields()?,
                    rho: random_fields()?,
                    rseed: random_fields()?,
                    value: 0,
                    unlock_height: 0,
                    dummy: true,
                    path: vec![([F::ZERO; 12], false); TREE_DEPTH],
                });
            };
            let receipt = self
                .receipts
                .iter()
                .find(|r| r.commitment == commitment)
                .ok_or("wallet input is not an authenticated owned note")?;
            if receipt.spent
                || receipt.note.value == 0
                || receipt.note.unlock_height > state.height
                || state.spent.contains(&receipt.nullifier)
            {
                return Err("wallet input is spent, zero-valued, or immature".into());
            }
            if receipt.note.unlock_height != 0 {
                let ready = self
                    .ready_timestamp(receipt)?
                    .ok_or("wallet locked input has no canonical eligibility timestamp")?;
                if now < ready {
                    return Err("wallet locked input privacy delay has not elapsed".into());
                }
            }
            let index = state
                .leaves
                .iter()
                .position(|value| encode_digest(value) == commitment)
                .ok_or("wallet input missing from canonical commitment tree")?;
            let total = totals.entry(receipt.note.asset_id).or_default();
            *total = total
                .checked_add(u128::from(receipt.note.value))
                .ok_or("wallet input sum overflow")?;
            Ok(InputWitness {
                asset_id: receipt.note.asset_id,
                nk: self.keys.spend_key(),
                rho: receipt.note.rho,
                rseed: receipt.note.rseed,
                value: receipt.note.value,
                unlock_height: receipt.note.unlock_height,
                dummy: false,
                path: state.tree.path(&state.leaves, index)?,
            })
        };
        let inputs = [make_input(selected[0])?, make_input(selected[1])?];
        let snapshot = state.tip_snapshot();
        let fee = base_fee(snapshot.selector.height)
            .checked_mul(if tier == FeeTier::Priority { 4 } else { 1 })
            .ok_or("wallet fee overflow")?;
        debit(&mut totals, asset, amount)?;
        debit(&mut totals, SIP_ASSET_ID, fee)?;
        let mut change = totals
            .into_iter()
            .filter(|(_, amount)| *amount > 0)
            .collect::<Vec<_>>();
        if change.len() > 2 {
            return Err("wallet transfer exceeds two change assets".into());
        }
        while change.len() < 2 {
            change.push((SIP_ASSET_ID, 0));
        }
        let mut witness = AccWitness {
            slot: SlotWitness {
                anchor: decode_digest(&snapshot.commitment_root)
                    .map_err(|_| "invalid canonical anchor")?,
                inputs,
                outputs: [
                    OutputWitness {
                        asset_id: asset,
                        owner: recipient.owner(),
                        value: amount,
                        unlock_height: 0,
                        rseed: match payment_randomness {
                            Some(randomness) => randomness,
                            None => random_fields()?,
                        },
                    },
                    OutputWitness {
                        asset_id: change[0].0,
                        owner: self.keys.address().owner(),
                        value: change[0]
                            .1
                            .try_into()
                            .map_err(|_| "wallet change exceeds amount width")?,
                        unlock_height: 0,
                        rseed: random_fields()?,
                    },
                    OutputWitness {
                        asset_id: change[1].0,
                        owner: self.keys.address().owner(),
                        value: change[1]
                            .1
                            .try_into()
                            .map_err(|_| "wallet change exceeds amount width")?,
                        unlock_height: 0,
                        rseed: random_fields()?,
                    },
                ],
                fee,
                fee_blind: random_fields()?,
                fee_is_priority: tier == FeeTier::Priority,
            },
            d_ct: [0; 32],
            anchor_height: snapshot.selector.height,
            base_fee: base_fee(snapshot.selector.height),
            anchor_path: state
                .recent_roots()?
                .tree(&h)
                .path(snapshot.selector.height),
        };
        let fields = witness.slot.public_inputs(&h);
        let notes = core::array::from_fn(|index| witness.slot.output_note(&h, &fields.nf, index));
        let ec = EncryptionContext::new(state.config.network);
        let (payment, opening) = encrypt_payment_with_opening(recipient, &notes[0], &ec)
            .map_err(|_| "wallet payment encryption failed")?;
        let public = PublicTransaction {
            nf: fields.nf,
            cm: fields.cm_out,
            payment,
            change: [
                encrypt_change_at(&self.keys.change, &notes[1], &ec, 1)
                    .map_err(|_| "wallet first change encryption failed")?,
                encrypt_change_at(&self.keys.change, &notes[2], &ec, 2)
                    .map_err(|_| "wallet second change encryption failed")?,
            ],
        };
        self.keys
            .check_before_broadcast(&public, &notes, recipient, &opening)?;
        let context = ProofContext::for_snapshot(
            state.config.network,
            snapshot.selector.height,
            snapshot.selector.block_id,
        );
        witness = public
            .bind_witness(&witness, &context)
            .map_err(|_| "wallet statement binding failed")?;
        witness
            .check_at_snapshot(
                &h,
                &decode_digest(&snapshot.recent_root)
                    .map_err(|_| "invalid canonical recent root")?,
                snapshot.selector.height,
            )
            .map_err(str::to_owned)?;
        let record = PublicRecord::new(
            snapshot.selector,
            public.encode(),
            encode_digest(&fields.fee_commit),
        )?;
        let sidecar = Sidecar {
            transaction_id: record.statement_id(&state.config.network),
            fee,
            blind: witness.slot.fee_blind.map(|field| field.as_canonical_u32()),
        };
        sidecar.check_opening(&record, &state.config.network)?;
        Ok(PreparedTransfer {
            witness: PrivateWitness(witness),
            public,
            record,
            sidecar,
            context,
            opening,
        })
    }
}

fn debit(totals: &mut BTreeMap<AssetId, u128>, asset: AssetId, value: u64) -> Result<(), String> {
    let total = totals
        .get_mut(&asset)
        .ok_or("wallet has no selected input for the required asset")?;
    *total = total
        .checked_sub(u128::from(value))
        .ok_or("wallet has insufficient selected asset value")?;
    Ok(())
}
fn fields<const N: usize>(
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<[F; N], String> {
    let mut fields = [F::ZERO; N];
    let mut count = 0;
    let mut entropy = Zeroizing::new([0; 64]);
    while count < N {
        fill(entropy.as_mut())?;
        for word in entropy.as_chunks::<4>().0 {
            let value = u32::from_le_bytes(*word);
            if value < F::ORDER_U32 {
                fields[count] = F::from_u32(value);
                count += 1;
                if count == N {
                    break;
                }
            }
        }
    }
    Ok(fields)
}
fn random_fields<const N: usize>() -> Result<[F; N], String> {
    fields(&mut |bytes| getrandom::fill(bytes).map_err(|_| "wallet OS entropy unavailable".into()))
}
fn same_note(left: &Note, right: &Note) -> bool {
    left.asset_id == right.asset_id
        && left.owner == right.owner
        && left.value == right.value
        && left.unlock_height == right.unlock_height
        && left.rho == right.rho
        && left.rseed == right.rseed
}
fn decode_payment(bytes: &[u8; 1313]) -> PaymentCiphertext {
    PaymentCiphertext {
        kem_ciphertext: bytes[..1088].try_into().expect("fixed reward KEM width"),
        body: bytes[1088..1296]
            .try_into()
            .expect("fixed reward plaintext width"),
        tag: bytes[1296..1312]
            .try_into()
            .expect("fixed reward tag width"),
        view_tag: bytes[1312],
    }
}
#[cfg(test)]
fn encode_payment(payment: &PaymentCiphertext) -> [u8; 1313] {
    let mut out = [0; 1313];
    out[..1088].copy_from_slice(&payment.kem_ciphertext);
    out[1088..1296].copy_from_slice(&payment.body);
    out[1296..1312].copy_from_slice(&payment.tag);
    out[1312] = payment.view_tag;
    out
}

/// Private witness and opening, prepared but not yet stored or broadcast.
/// The payment opening must be durably protected before the transaction is sent.
struct PrivateWitness(AccWitness);
impl Drop for PrivateWitness {
    fn drop(&mut self) {
        for input in &mut self.0.slot.inputs {
            input.asset_id.0.zeroize();
            input.nk.fill(F::ZERO);
            input.rho.fill(F::ZERO);
            input.rseed.fill(F::ZERO);
            input.value.zeroize();
            input.unlock_height.zeroize();
        }
        for output in &mut self.0.slot.outputs {
            output.asset_id.0.zeroize();
            output.owner.fill(F::ZERO);
            output.value.zeroize();
            output.unlock_height.zeroize();
            output.rseed.fill(F::ZERO);
        }
        self.0.slot.fee_blind.fill(F::ZERO);
        self.0.slot.fee.zeroize();
    }
}

#[must_use = "Persist the payment opening securely before sending a proven transaction"]
pub struct PreparedTransfer {
    witness: PrivateWitness,
    public: PublicTransaction,
    record: PublicRecord,
    sidecar: Sidecar,
    context: ProofContext,
    opening: PaymentEncryptionOpening,
}
impl PreparedTransfer {
    pub fn witness(&self) -> &AccWitness {
        &self.witness.0
    }
    pub fn public(&self) -> &PublicTransaction {
        &self.public
    }
    pub fn record(&self) -> &PublicRecord {
        &self.record
    }
    pub fn sidecar(&self) -> &Sidecar {
        &self.sidecar
    }
    pub fn payment_opening(&self) -> &PaymentEncryptionOpening {
        &self.opening
    }
    /// Generate and independently verify the native proof using the resident
    /// prover. This does not persist the opening or broadcast the transaction.
    pub fn prove(self, prover: &NativeProver) -> Result<WalletPayment, String> {
        let proof = prover.transaction(&self.witness.0, &self.public, &self.context)?;
        Ok(WalletPayment {
            transaction: Transaction {
                record: self.record,
                proof,
            },
            sidecar: self.sidecar,
            opening: self.opening,
        })
    }
}

/// Payment bundle for protected local storage and encrypted relay admission.
/// The opening is a per-payment disclosure, never a master-key proof.
#[must_use = "Store the payment opening before encrypted relay admission"]
pub struct WalletPayment {
    pub transaction: Transaction,
    pub sidecar: Sidecar,
    opening: PaymentEncryptionOpening,
}
impl WalletPayment {
    pub fn payment_opening(&self) -> &PaymentEncryptionOpening {
        &self.opening
    }
}

pub mod issuance;

#[cfg(test)]
mod tests;
