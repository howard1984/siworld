//! Header/compact-authenticated wallet state; transaction validity trusts full nodes.
use crate::state::SNAPSHOT_WINDOW;
use crate::wallet::FeeTier;
use crate::{
    compact::CompactBlock,
    proofs::NativeVerifier,
    state::{CanonicalSnapshot, Config, State, base_fee},
    wallet::{PreparedTransfer, Wallet},
    wire::{DigestBytes, Snapshot},
};
use native::{
    FriParams,
    codec::{ProofContext, PublicTransaction, decode_digest, encode_digest},
    multi_asset::{AssetId, Hasher, RecentRoots, SIP_ASSET_ID},
    multi_asset_transaction::TransactionProver,
};
use serde_json::json;
use siworld_core::pow;
use zeroize::Zeroizing;

pub struct LightWallet {
    pub state: State,
    pub wallet: Wallet,
    prover: Option<TransactionProver>,
    prepared: Option<PreparedTransfer>,
    paths: crate::paths::OwnedPaths,
}
impl LightWallet {
    pub fn new(config: Config, seed: Zeroizing<[u8; 32]>, account: u32) -> Result<Self, String> {
        let mut wallet = Wallet::from_seed(config.network, seed, account)?;
        let state = State::new(config)?;
        wallet.scan_light_data(&state, &[], &[], false)?;
        Ok(Self {
            state,
            wallet,
            prover: None,
            prepared: None,
            paths: crate::paths::OwnedPaths::new(),
        })
    }
    pub fn fork(&self, seed: Zeroizing<[u8; 32]>, account: u32) -> Result<Self, String> {
        let mut fork = Self::new(self.state.config.clone(), seed, account)?;
        fork.wallet.copy_light_receipts(&self.wallet)?;
        fork.state = self.state.clone();
        fork.paths = self.paths.clone();
        Ok(fork)
    }
    /// Adopt a tree built from authenticated history without scanning older ciphertext.
    pub fn adopt_history(
        &mut self,
        history: &crate::history::CommitmentHistory,
    ) -> Result<(), String> {
        if self.state.height != 0
            || !self.wallet.receipts().is_empty()
            || self.state.config != history.state.config
        {
            return Err("Historical tree requires a fresh wallet on the same network.".into());
        }
        let state = history.scanner_state()?;
        let paths = crate::paths::OwnedPaths::from_tree_cache(
            state.tree.count,
            &state.tree.cache_frontier(),
            encode_digest(&state.tree.root()),
        )?;
        self.wallet.scan_light_data(&state, &[], &[], false)?;
        self.state = state;
        self.paths = paths;
        Ok(())
    }
    pub fn retain_prover(&mut self, previous: &mut Self) {
        self.prover = previous.prover.take();
    }
    pub fn append(&mut self, compact: &CompactBlock) -> Result<(), String> {
        let b = &compact.block;
        let mut trial = self.state.clone();
        if b.network != trial.config.network
            || b.height != trial.height.checked_add(1).ok_or("Height overflow.")?
            || b.parent != trial.tip
            || b.timestamp <= trial.median_time_past()
        {
            return Err("Light header chain continuity failed.".into());
        }
        let expected = trial.next_target();
        if b.target != expected
            || !pow::meets_target(
                &pow::pow_hash(&compact.seed, b.nonce, trial.config.pow_iterations),
                &b.target,
            )
        {
            return Err("Light header work or target failed.".into());
        }
        trial.cumulative_work = trial
            .cumulative_work
            .checked_add(pow::block_work(&b.target))
            .ok_or("Work overflow.")?;
        let staged = self
            .wallet
            .scan_light_receipts(std::slice::from_ref(b), &[compact.id])?;
        let owned_nullifiers = self
            .wallet
            .receipts()
            .iter()
            .chain(staged.iter())
            .map(|r| r.nullifier)
            .collect::<std::collections::BTreeSet<_>>();
        let owned_outputs = staged
            .iter()
            .filter(|r| r.note().value > 0)
            .map(|r| r.commitment)
            .collect::<std::collections::BTreeSet<_>>();
        let mut seen_nullifiers = std::collections::BTreeSet::new();
        let mut paths = self.paths.clone();
        let mut outputs = Vec::new();
        for tx in &b.transactions {
            trial.snapshot(tx.record.snapshot)?;
            let p = PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "Invalid compact public fields.")?;
            for nf in p.nf {
                let bytes = encode_digest(&nf);
                if !seen_nullifiers.insert(bytes) {
                    return Err("Duplicate compact nullifier.".into());
                }
                if owned_nullifiers.contains(&bytes) && !trial.spent.insert(bytes) {
                    return Err("Owned nullifier was already spent.".into());
                }
            }
            outputs.extend(p.cm);
        }
        for issuance in &b.issuances {
            outputs.extend(issuance.signed.declaration.note_commitments.iter().copied());
            trial.assets.apply(issuance, b.height)?;
        }
        for reward in &b.rewards {
            outputs.push(decode_digest(&reward.commitment).map_err(|_| "Invalid compact reward.")?);
        }
        for spend in &b.fund_spends {
            outputs.push(
                decode_digest(&spend.commitment).map_err(|_| "Invalid compact fund output.")?,
            );
        }
        for receipt in self.wallet.receipts() {
            if trial.spent.contains(&receipt.nullifier) {
                paths.remove(&receipt.commitment);
            }
        }
        let mut seen_outputs = std::collections::BTreeSet::new();
        for cm in outputs {
            let bytes = encode_digest(&cm);
            if !seen_outputs.insert(bytes) {
                return Err("Duplicate compact commitment.".into());
            }
            let retain = owned_outputs.contains(&bytes);
            if retain && !trial.commitments.insert(bytes) {
                return Err("Owned commitment was reused.".into());
            }
            trial.tree.append(cm)?;
            paths.append(cm, retain)?;
        }
        if paths.root() != trial.tree.root() || paths.count() != trial.tree.count {
            return Err("Incremental local commitment root differs.".into());
        }
        let mut roots = RecentRoots::new();
        let h = Hasher::new();
        for s in &trial.snapshots {
            if b.height - s.selector.height < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &h,
                    s.selector.height,
                    &decode_digest(&s.commitment_root).map_err(|_| "Invalid local root.")?,
                    base_fee(s.selector.height),
                );
            }
        }
        roots.insert(&h, b.height, &trial.tree.root(), base_fee(b.height));
        trial.snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height: b.height,
                block_id: compact.id,
            },
            commitment_root: encode_digest(&trial.tree.root()),
            recent_root: encode_digest(&roots.tree(&h).root()),
        });
        while trial.snapshots.len() > SNAPSHOT_WINDOW {
            trial.snapshots.pop_front();
        }
        trial.height = b.height;
        trial.tip = compact.id;
        trial.timestamps.push_back(b.timestamp);
        while trial.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
            trial.timestamps.pop_front();
        }
        self.wallet
            .commit_light_receipts(&trial, staged, std::slice::from_ref(b), true);
        self.state = trial;
        self.paths = paths;
        Ok(())
    }
    pub fn balance_json(&self) -> Result<String, String> {
        let b = self.wallet.balance_details(&self.state)?;
        let mut pending = std::collections::BTreeMap::<AssetId, u128>::new();
        let mut batches = std::collections::BTreeMap::<(u64, AssetId, bool), u128>::new();
        for receipt in self.wallet.receipts() {
            let note = receipt.note();
            if receipt.spent || note.value == 0 || note.unlock_height <= self.state.height {
                continue;
            }
            // Only the first miner reward note uses coinbase maturity. Other
            // timelocks remain scheduled locks even when their dates coincide.
            let maturing = receipt.output_index == 3
                && receipt
                    .height
                    .checked_add(self.state.config.economics.maturity)
                    == Some(note.unlock_height);
            if maturing {
                let total = pending.entry(note.asset_id).or_default();
                *total = total
                    .checked_add(u128::from(note.value))
                    .ok_or("Maturing balance overflow.")?;
            }
            let total = batches
                .entry((note.unlock_height, note.asset_id, maturing))
                .or_default();
            *total = total
                .checked_add(u128::from(note.value))
                .ok_or("Unlock batch overflow.")?;
        }
        let mut assets = std::collections::BTreeSet::<&AssetId>::new();
        assets.extend(b.available.keys());
        assets.extend(b.locked.keys());
        let rows = assets
            .into_iter()
            .map(|asset| {
                let locked = b.locked.get(asset).copied().unwrap_or(0);
                let maturing = pending.get(asset).copied().unwrap_or(0);
                let scheduled = locked
                    .checked_sub(maturing)
                    .ok_or("Maturing balance exceeds total locks.")?;
                Ok(json!({"asset":crate::local::hex(&asset.0),
                "available_atoms":b.available.get(asset).copied().unwrap_or(0).to_string(),
                "locked_atoms":locked.to_string(), "pending_maturity_atoms":maturing.to_string(),
                "time_locked_atoms":scheduled.to_string()}))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tranches = batches
            .into_iter()
            .map(|((height, asset, maturing), amount)| {
                let estimated = height
                    .checked_sub(self.state.height)
                    .and_then(|blocks| blocks.checked_mul(self.state.config.target_interval))
                    .and_then(|seconds| self.state.timestamp().checked_add(seconds));
                json!({"asset":crate::local::hex(&asset.0), "amount_atoms":amount.to_string(),
                "unlock_height":height,"estimated_timestamp":estimated,
                "kind":if maturing {"maturing"} else {"locked"}})
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"trust":"header-and-compact-authenticated-full-node-consensus",
            "height":self.state.height,"tip":crate::local::hex(&self.state.tip),
            "rows":rows, "locked_tranches":tranches})
            .to_string(),
        )
    }
    pub fn prepare(
        &mut self,
        recipient: &native::encryption::PaymentAddress,
        amount: u64,
        priority: bool,
        reserved: &[DigestBytes],
    ) -> Result<String, String> {
        if self.prepared.is_some() {
            return Err("A payment is already prepared.".into());
        }
        let fee = base_fee(self.state.height)
            .checked_mul(if priority { 4 } else { 1 })
            .ok_or("Fee overflow.")?;
        let target = amount.checked_add(fee).ok_or("Amount overflow.")?;
        let mut candidates = self
            .wallet
            .receipts()
            .iter()
            .filter(|r| {
                !r.spent
                    && r.note().asset_id == SIP_ASSET_ID
                    && r.note().unlock_height <= self.state.height
                    && r.note().value > 0
                    && !reserved.contains(&r.commitment)
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|r| (std::cmp::Reverse(r.note().value), r.commitment));
        let mut selected = [None, None];
        let mut sum = 0u128;
        for (i, r) in candidates.into_iter().take(2).enumerate() {
            selected[i] = Some(r.commitment);
            sum += u128::from(r.note().value);
            if sum >= u128::from(target) {
                break;
            }
        }
        if sum < u128::from(target) {
            return Err("Insufficient mature unreserved SIP within two inputs.".into());
        }
        let p = self.wallet.prepare_light_transfer(
            &self.state,
            selected,
            recipient,
            AssetId(SIP_ASSET_ID.0),
            amount,
            if priority {
                FeeTier::Priority
            } else {
                FeeTier::Standard
            },
            self.state.timestamp(),
            &self.paths.all_paths(),
        )?;
        let record=json!({"phase":"prepared","statement_id":crate::local::hex(&p.record().statement_id(&self.state.config.network)),"inputs":selected.iter().flatten().map(|v|crate::local::hex(v)).collect::<Vec<_>>(),"payment_opening":crate::local::hex(p.payment_opening().expose_encapsulation_coins()),"public":crate::local::hex(&p.public().encode()),"amount_atoms":amount.to_string(),"fee_atoms":fee.to_string(),"input_atoms":sum.to_string()}).to_string();
        self.prepared = Some(p);
        Ok(record)
    }
    pub fn prove(&mut self) -> Result<(Vec<u8>, [u8; 78]), String> {
        let p = self
            .prepared
            .as_ref()
            .ok_or("No durably reserved payment is prepared.")?;
        let prover = self.prover.get_or_insert_with(|| {
            TransactionProver::new(FriParams {
                log_blowup: 7,
                num_queries: 41,
                query_pow_bits: 20,
                commit_pow_bits: 0,
                batch_pow_bits: 20,
                max_log_arity: 1,
            })
        });
        let (proof, _) = prover.prove_at_snapshot(p.witness(), p.record().snapshot.height);
        let bytes = postcard::to_allocvec(&proof).map_err(|_| "Cannot encode browser proof.")?;
        if bytes.len() > crate::wire::MAX_TX_PROOF {
            return Err("Browser proof exceeds native cap.".into());
        }
        let context = ProofContext::for_snapshot(
            self.state.config.network,
            p.record().snapshot.height,
            p.record().snapshot.block_id,
        );
        let w = p.witness();
        let h = Hasher::new();
        let fee = h.fee_commit(w.slot.fee, &w.slot.fee_blind);
        NativeVerifier::new()?.verify_transaction(
            p.public(),
            &context,
            &fee,
            &w.anchors_root(&h),
            &bytes,
        )?;
        let tx = crate::wire::Transaction {
            record: p.record().clone(),
            proof: bytes,
        };
        Ok((
            tx.encode_envelope(&self.state.config.network)?,
            p.sidecar().encode()?,
        ))
    }
    pub fn clear_prepared(&mut self) {
        self.prepared = None;
    }
}
