//! Offline payment construction over the verified engineering-v2 receipt prefix.
//!
//! These APIs do not authorize submission or change the read-only website gate.
use super::*;
use crate::{
    proofs::NativeVerifier,
    wallet::FeeTier,
    wire::{MAX_ENVELOPE_BYTES, SIDECAR_BYTES, Sidecar, Transaction},
};
use native::{
    FriParams,
    codec::ProofContext,
    encryption::PaymentAddress,
    multi_asset::{AssetId, SIP_ASSET_ID},
    multi_asset_transaction::TransactionProver,
};

/// The protocol snapshot lifetime is independent of proof-storage retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentAnchor {
    pub network: Hash,
    pub snapshot: Snapshot,
}
impl PaymentAnchor {
    pub fn check_lifetime(&self, expected: Hash, height: u64) -> Result<(), String> {
        if self.network != expected {
            return Err("eng2 payment network differs".into());
        }
        if height
            .checked_sub(self.snapshot.height)
            .is_none_or(|age| age >= SNAPSHOT_WINDOW as u64)
        {
            return Err("eng2 payment anchor expired or is in the future".into());
        }
        Ok(())
    }
}

impl Eng2LightState {
    pub fn check_payment_anchor(
        &self,
        expected: Hash,
        snapshot: Snapshot,
    ) -> Result<&CanonicalSnapshot, String> {
        PaymentAnchor {
            network: self.context.config().network,
            snapshot,
        }
        .check_lifetime(expected, self.height())?;
        self.state.snapshot(snapshot)
    }

    /// The exact verified tip is required because private paths track that tip.
    /// Return private reservation data only to the encrypted worker journal.
    pub fn prepare_sip(
        &mut self,
        expected: Hash,
        anchor: Snapshot,
        recipient: &PaymentAddress,
        amount: u64,
        priority: bool,
        reserved: &[DigestBytes],
    ) -> Result<String, String> {
        self.check_payment_anchor(expected, anchor)?;
        if anchor != self.tip_snapshot().selector || self.height() == 0 {
            return Err("eng2 payment requires the complete verified receipt tip".into());
        }
        if self.prepared.is_some() || reserved.len() > 128 {
            return Err("eng2 prepared payment or reservation bound rejected".into());
        }
        let fee = base_fee(self.height())
            .checked_mul(if priority { 4 } else { 1 })
            .ok_or("eng2 payment fee overflow")?;
        let target = amount
            .checked_add(fee)
            .ok_or("eng2 payment amount overflow")?;
        let mut candidates = self
            .wallet
            .receipts()
            .iter()
            .filter(|row| {
                !row.spent
                    && row.note().asset_id == SIP_ASSET_ID
                    && row.note().unlock_height <= self.height()
                    && row.note().value > 0
                    && !reserved.contains(&row.commitment)
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|row| (std::cmp::Reverse(row.note().value), row.commitment));
        let mut selected = [None, None];
        let mut total = 0u128;
        for (index, row) in candidates.into_iter().take(2).enumerate() {
            selected[index] = Some(row.commitment);
            total += u128::from(row.note().value);
            if total >= u128::from(target) {
                break;
            }
        }
        if total < u128::from(target) {
            return Err("insufficient mature unreserved SIP within two eng2 inputs".into());
        }
        let payment = self.wallet.prepare_light_transfer(
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
        let record = json!({
            "version":2,"phase":"reserved","network":crate::local::hex(&expected),
            "genesis":crate::local::hex(&self.context.genesis()),
            "rules":crate::local::hex(&self.context.rules()),
            "profile":crate::local::hex(&self.context.profile()),"fee_mode":self.context.fee_mode(),
            "anchor_height":anchor.height,"anchor_tip":crate::local::hex(&anchor.block_id),
            "expires_at_height":anchor.height.checked_add(SNAPSHOT_WINDOW as u64).ok_or("eng2 anchor height overflow")?,
            "commitment_root":crate::local::hex(&self.tip_snapshot().commitment_root),
            "recent_root":crate::local::hex(&self.tip_snapshot().recent_root),
            "statement_id":crate::local::hex(&payment.record().statement_id(&expected)),
            "inputs":selected.iter().flatten().map(|value|crate::local::hex(value)).collect::<Vec<_>>(),
            "payment_opening":crate::local::hex(payment.payment_opening().expose_encapsulation_coins()),
            "public":crate::local::hex(&payment.public().encode()),
            "amount_atoms":amount.to_string(),"fee_atoms":fee.to_string(),"input_atoms":total.to_string()
        }).to_string();
        self.prepared = Some(payment);
        Ok(record)
    }

    /// Generate a frozen native proof and verify it independently before return.
    /// The returned framing is envelope || sidecar, without a relay length prefix.
    pub fn prove_sip(&mut self) -> Result<Vec<u8>, String> {
        let payment = self.prepared.as_ref().ok_or("no reserved eng2 payment")?;
        self.check_payment_anchor(self.context.config().network, payment.record().snapshot)?;
        for nf in payment.public().nf {
            if self.state.spent.contains(&encode_digest(&nf)) {
                return Err("eng2 payment input was spent after preparation".into());
            }
        }
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
        let (proof, _) =
            prover.prove_at_snapshot(payment.witness(), payment.record().snapshot.height);
        let transaction = Transaction {
            record: payment.record().clone(),
            proof: postcard::to_allocvec(&proof).map_err(|_| "eng2 proof encoding failed")?,
        };
        let mut packet = transaction.encode_envelope(&self.context.config().network)?;
        packet.extend_from_slice(&payment.sidecar().encode()?);
        self.check_payment_packet(self.context.config().network, &packet)?;
        Ok(packet)
    }

    /// Verify the exact network, retained eng2 snapshot, opening and native proof.
    /// This is not full-node admission: global non-owned spends are not available.
    pub fn check_payment_packet(&self, expected: Hash, packet: &[u8]) -> Result<String, String> {
        if expected != self.context.config().network
            || !(crate::wire::TX_PREFIX_BYTES + SIDECAR_BYTES..=MAX_ENVELOPE_BYTES + SIDECAR_BYTES)
                .contains(&packet.len())
        {
            return Err("eng2 payment packet context or size rejected".into());
        }
        let split = packet.len() - SIDECAR_BYTES;
        let tx = Transaction::decode_envelope(&packet[..split], &expected)?;
        let snapshot = self.check_payment_anchor(expected, tx.record.snapshot)?;
        let sidecar = Sidecar::decode(&packet[split..])?;
        sidecar.check_opening(&tx.record, &expected)?;
        let public = PublicTransaction::decode(&tx.record.body)
            .map_err(|_| "eng2 payment public values rejected")?;
        for nf in public.nf {
            if self.state.spent.contains(&encode_digest(&nf)) {
                return Err("eng2 payment owned input is already spent".into());
            }
        }
        NativeVerifier::new()?.verify_transaction(
            &public,
            &ProofContext::for_snapshot(
                expected,
                tx.record.snapshot.height,
                tx.record.snapshot.block_id,
            ),
            &decode_digest(&tx.record.fee_commit).map_err(|_| "eng2 payment fee rejected")?,
            &decode_digest(&snapshot.recent_root)
                .map_err(|_| "eng2 payment anchor root rejected")?,
            &tx.proof,
        )?;
        Ok(json!({"statement_id":crate::local::hex(&tx.record.statement_id(&expected)),
            "anchor_height":tx.record.snapshot.height,"anchor_tip":crate::local::hex(&tx.record.snapshot.block_id),
            "proof_verified":true,"send_supported":false}).to_string())
    }

    pub fn clear_eng2_prepared(&mut self) {
        self.prepared = None;
    }

    /// Preserve only the warm prover across an authenticated candidate adoption.
    /// A private witness must be rebuilt and reserved against the adopted prefix.
    pub fn retain_eng2_prover(&mut self, previous: &mut Self) {
        self.prover = previous.prover.take();
    }

    pub fn payment_inclusion_valid(&self, height: u64, id: Hash) -> bool {
        self.header(height).and_then(|header| header.id().ok()) == Some(id)
    }

    /// Authenticate inclusion against an already committed header; receipt bytes
    /// alone cannot create a new canonical head or establish full-node validity.
    pub fn payment_receipt(
        &self,
        height: u64,
        bytes: &[u8],
        statement: Hash,
    ) -> Result<String, String> {
        let header = self
            .header(height)
            .ok_or("eng2 payment receipt header is not committed")?;
        let raw = header
            .encode()
            .map_err(|_| "eng2 receipt header rejected")?;
        let receipt = ReceiptBlock::decode(&self.context, &raw, bytes)?;
        if !receipt
            .transactions()
            .iter()
            .any(|record| record.statement_id(&self.context.config().network) == statement)
        {
            return Err("eng2 payment statement absent from authenticated receipt".into());
        }
        Ok(json!({"statement_id":crate::local::hex(&statement),"height":height,
            "block_id":crate::local::hex(&header.id().map_err(|_| "eng2 receipt header identity rejected")?),
            "receipt_authenticated":true,"full_node_consensus_verified":false}).to_string())
    }
}
