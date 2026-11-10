use super::*;
use crate::fixtures::{TestVerifier, candidate};
use crate::state::{BlockVerifier, Config, State};
use crate::wire::Block;
use libcrux_ml_dsa::ml_dsa_65;
use native::codec::{ProofContext, PublicTransaction};
use native::multi_asset::{Digest, F};
use native::settlement::RewardPlan;
use p3_field::PrimeCharacteristicRing;

struct IssuanceVerifier;
impl BlockVerifier for IssuanceVerifier {
    fn transaction(
        &self,
        p: &PublicTransaction,
        c: &ProofContext,
        f: &Digest,
        r: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        TestVerifier.transaction(p, c, f, r, proof)
    }
    fn settlement(
        &self,
        f: &[Digest],
        p: &RewardPlan,
        n: Hash,
        l: Hash,
        r: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        TestVerifier.settlement(f, p, n, l, r, proof)
    }
    fn issuance(&self, r: &IssuanceRecord) -> Result<(), String> {
        if r.proof == [1] {
            Ok(())
        } else {
            Err("test issuance proof rejected".into())
        }
    }
}
fn config() -> Config {
    let mut c = Config::development([9; 32], 0).unwrap();
    c.issuance = Some(IssuanceConfig {
        fee_owner: encode_digest(&[F::from_u32(333); 12]),
        max_metadata_bytes: 256,
        max_per_block: 2,
    });
    c
}
fn sample(config: &Config) -> IssuanceRecord {
    let (mut signed, witness, _) = native::issuance::sample_issuance(INITIAL_NOTES);
    signed.declaration.issuance_fee_atoms = TESTNET_ISSUANCE_FEE_ATOMS;
    let pair = ml_dsa_65::generate_key_pair([7; 32]);
    signed.signature = Some(
        *ml_dsa_65::sign(
            &pair.signing_key,
            &signed.declaration.canonical_bytes(),
            b"siworld asset issuance v1",
            [8; 32],
        )
        .unwrap()
        .as_ref(),
    );
    let mut record = IssuanceRecord {
        signed,
        ciphertexts: witness.ciphertexts,
        proof: vec![1],
        fee_commitment: [0; 48],
        fee_rho: encode_digest(&[F::from_u32(444); 12]),
    };
    record.fee_commitment = encode_digest(
        &Hasher::new().note_cm(&record.fee_note(config.issuance.as_ref().unwrap()).unwrap()),
    );
    record
}
fn issued_block(state: &State, record: IssuanceRecord, seed: u32) -> Block {
    let mut b = candidate(state, seed);
    b.transactions[0].record.body[96..144].copy_from_slice(&record.fee_commitment);
    b.transactions
        .sort_by_key(|tx| tx.record.statement_id(&b.network));
    b.issuances.push(record);
    b
}
#[test]
fn issuance_fee_requires_same_block_sip_output_and_exact_declaration_binding() {
    let c = config();
    let r = sample(&c);
    r.validate(&c).unwrap();
    let bytes = r.encode().unwrap();
    assert_eq!(IssuanceRecord::decode(&bytes).unwrap(), r);
    assert!(IssuanceRecord::decode(&bytes[..bytes.len() - 1]).is_err());
    let state = State::new(c).unwrap();
    let b = issued_block(&state, r.clone(), 1000);
    let mut next = state.clone();
    next.apply(&b, &IssuanceVerifier).unwrap();
    assert_eq!(next.assets.len(), 1);
    assert_eq!(
        next.assets
            .get(&r.signed.declaration.asset_id.0)
            .unwrap()
            .public_supply,
        r.signed.declaration.public_supply
    );
    for mutation in 0..5 {
        let mut bad = b.clone();
        match mutation {
            0 => bad.issuances[0].fee_rho[0] ^= 1,
            1 => bad.issuances[0].signed.signature.as_mut().unwrap()[0] ^= 1,
            2 => bad.issuances[0].proof = vec![2],
            3 => bad.issuances[0].ciphertexts[0][0] ^= 1,
            _ => {
                bad.transactions
                    .iter_mut()
                    .find(|tx| tx.record.body[96..144] == r.fee_commitment)
                    .unwrap()
                    .record
                    .body[96..144]
                    .copy_from_slice(&encode_digest(&[F::from_u32(555); 12]));
                bad.transactions
                    .sort_by_key(|tx| tx.record.statement_id(&bad.network));
            }
        }
        let mut trial = state.clone();
        let before = trial.fingerprint();
        assert!(
            trial.apply(&bad, &IssuanceVerifier).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(trial.fingerprint(), before);
        assert!(trial.assets.is_empty());
    }
}
#[test]
fn absent_fee_destination_and_reused_registration_are_rejected_atomically() {
    let c = config();
    let r = sample(&c);
    let mut absent = c.clone();
    absent.issuance = None;
    assert!(r.validate(&absent).is_err());
    let mut state = State::new(c).unwrap();
    state
        .apply(&issued_block(&state, r.clone(), 1000), &IssuanceVerifier)
        .unwrap();
    let before = state.fingerprint();
    assert!(
        state
            .apply(&issued_block(&state, r, 10000), &IssuanceVerifier)
            .is_err()
    );
    assert_eq!(state.fingerprint(), before);
}

fn resign(record: &mut IssuanceRecord) {
    let pair = ml_dsa_65::generate_key_pair([7; 32]);
    record.signed.signature = Some(
        *ml_dsa_65::sign(
            &pair.signing_key,
            &record.signed.declaration.canonical_bytes(),
            b"siworld asset issuance v1",
            [8; 32],
        )
        .unwrap()
        .as_ref(),
    );
}
#[test]
fn changed_declaration_or_rho_cannot_reuse_an_issuance_fee_output() {
    let c = config();
    let record = sample(&c);
    for mutation in 0..5 {
        let mut bad = record.clone();
        match mutation {
            0 => bad.signed.declaration.metadata.name.push('x'),
            1 => {
                bad.signed.declaration.sequence += 1;
                bad.signed.declaration.asset_id = native::issuance::derive_asset_id(
                    &c.network,
                    &bad.signed.declaration.issuer_key,
                    bad.signed.declaration.sequence,
                );
            }
            2 => bad.fee_rho = encode_digest(&[F::from_u32(777); 12]),
            3 => bad.signed.declaration.public_supply += 1,
            _ => bad.signed.declaration.version = 2,
        }
        resign(&mut bad);
        assert!(bad.validate(&c).is_err(), "mutation {mutation}");
    }
    let mut registry = AssetRegistry::default();
    registry.apply(&record, 1).unwrap();
    let mut reused_fee = record.clone();
    reused_fee.signed.declaration.sequence += 1;
    reused_fee.signed.declaration.asset_id = native::issuance::derive_asset_id(
        &c.network,
        &reused_fee.signed.declaration.issuer_key,
        reused_fee.signed.declaration.sequence,
    );
    assert!(registry.apply(&reused_fee, 2).is_err());
}
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-native-issuance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("chain.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn registry_recovers_after_restart_and_rolls_back_with_a_heavier_branch() {
    use crate::chain::{BranchOutcome, CandidatePolicy};
    use crate::store::Store;
    let c = config();
    let record = sample(&c);
    let asset = record.signed.declaration.asset_id.0;
    let dir = Directory::new();
    let mut store = Store::open(dir.db(), c.clone(), &IssuanceVerifier).unwrap();
    let block = issued_block(store.state(), record, 1000);
    let orphan = block.id().unwrap();
    store.append(&block, &IssuanceVerifier).unwrap();
    let accepted = store.state().fingerprint();
    assert!(store.state().assets.get(&asset).is_some());
    drop(store);
    let mut reopened = Store::open_existing(dir.db(), c.clone(), &IssuanceVerifier).unwrap();
    assert_eq!(reopened.state().fingerprint(), accepted);
    assert!(reopened.state().assets.get(&asset).is_some());
    let mut alternative = State::new(c.clone()).unwrap();
    let first = candidate(&alternative, 100_000);
    alternative.apply(&first, &IssuanceVerifier).unwrap();
    let mut second = candidate(&alternative, 200_000);
    // A late issuance rejection must not detach the accepted registry or block.
    second.issuances.push(sample(&c));
    let before = reopened.state().fingerprint();
    assert!(
        reopened
            .consider_branch(
                0,
                &[first.clone(), second],
                CandidatePolicy::default(),
                &IssuanceVerifier
            )
            .is_err()
    );
    assert_eq!(reopened.state().fingerprint(), before);
    assert!(reopened.state().assets.get(&asset).is_some());
    let second = candidate(&alternative, 200_000);
    assert!(matches!(
        reopened
            .consider_branch(
                0,
                &[first, second],
                CandidatePolicy::default(),
                &IssuanceVerifier
            )
            .unwrap(),
        BranchOutcome::Adopted {
            detached: 1,
            attached: 2,
            ..
        }
    ));
    assert!(reopened.state().assets.is_empty());
    assert_eq!(
        reopened.detached_block(&orphan).unwrap().id().unwrap(),
        orphan
    );
    let rolled_back = reopened.state().fingerprint();
    drop(reopened);
    let recovered = Store::open_existing(dir.db(), c, &IssuanceVerifier).unwrap();
    assert_eq!(recovered.state().fingerprint(), rolled_back);
    assert!(recovered.state().assets.is_empty());
}
#[test]
fn bounded_rpc_requires_admitted_fee_output_and_retries_idempotently() {
    use crate::runtime::Node;
    use crate::store::Store;
    use crate::wire::Sidecar;
    let c = config();
    let record = sample(&c);
    let dir = Directory::new();
    let mut node = Node::new(
        Store::open(dir.db(), c.clone(), &IssuanceVerifier).unwrap(),
        IssuanceVerifier,
    );
    let bytes = record.encode().unwrap();
    assert!(node.submit_issuance(&bytes).is_err());
    assert_eq!(node.pending_issuance_count(), 0);
    let mut fee_tx = candidate(node.state(), 500_000).transactions.remove(0);
    fee_tx.record.body[96..144].copy_from_slice(&record.fee_commitment);
    let fee = crate::state::base_fee(fee_tx.record.snapshot.height);
    let blind = [F::from_u32(22); 8];
    fee_tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(fee, &blind));
    let sidecar = Sidecar {
        transaction_id: fee_tx.record.statement_id(&c.network),
        fee,
        blind: [22; 8],
    };
    node.submit_local(
        &fee_tx.encode_envelope(&c.network).unwrap(),
        Some(&sidecar.encode().unwrap()),
    )
    .unwrap();
    let request = serde_json::to_vec(
        &serde_json::json!({"method":"submitissuance", "record":crate::local::hex(&bytes)}),
    )
    .unwrap();
    let response: serde_json::Value =
        serde_json::from_slice(&node.dispatch_issuance_rpc(&request).unwrap()).unwrap();
    assert_eq!(response["accepted"], true);
    assert_eq!(
        response["declaration"],
        crate::local::hex(&record.signed.declaration.binding())
    );
    assert_eq!(
        node.submit_issuance(&bytes).unwrap(),
        record.signed.declaration.binding()
    );
    assert_eq!(node.pending_issuance_count(), 1);
    let mut changed = record.clone();
    changed.proof = vec![2];
    assert!(node.submit_issuance(&changed.encode().unwrap()).is_err());
    assert!(
        node.dispatch_issuance_rpc(br#"{"method":"submitissuance","record":"ff","extra":0}"#)
            .is_err()
    );
    assert!(
        node.dispatch_issuance_rpc(&vec![b' '; 2 * MAX_RECORD_BYTES + 129])
            .is_err()
    );
    let mut included = candidate(node.state(), 600_000);
    included.transactions[0] = fee_tx;
    included
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&c.network));
    included.issuances.push(record);
    node.import_branch(0, &[included], crate::chain::CandidatePolicy::default())
        .unwrap();
    assert_eq!(node.pending_issuance_count(), 0);
    assert_eq!(node.state().assets.len(), 1);
}

#[test]
fn canonical_fee_payment_survives_separate_inclusion_and_fund_spending() {
    let mut c = config();
    let fund_nk = [F::from_u32(333); 12];
    c.issuance.as_mut().unwrap().fee_owner = encode_digest(&Hasher::new().owner(&fund_nk));
    let record = sample(&c);
    let fee_nullifier = encode_digest(&Hasher::new().nullifier(
        &fund_nk,
        &record.fee_note(c.issuance.as_ref().unwrap()).unwrap().rho,
    ));
    let mut state = State::new(c.clone()).unwrap();
    let mut payment = issued_block(&state, record.clone(), 700_000);
    payment.issuances.clear();
    state.apply(&payment, &IssuanceVerifier).unwrap();
    assert!(state.assets.is_empty());
    assert!(state.commitments.contains(&record.fee_commitment));
    // A spent fund note remains a valid historical receipt. This synthetic
    // transition test supplies its true owner-derived nullifier; native proof
    // verification is exercised separately by the ignored complete-block test.
    let mut spend = candidate(&state, 800_000);
    spend.transactions[0].record.body[..48].copy_from_slice(&fee_nullifier);
    spend
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&c.network));
    state.apply(&spend, &IssuanceVerifier).unwrap();
    assert!(state.spent.contains(&fee_nullifier));
    let mut mint = candidate(&state, 900_000);
    mint.issuances.push(record.clone());
    state.apply(&mint, &IssuanceVerifier).unwrap();
    assert_eq!(state.assets.len(), 1);
    let before = state.fingerprint();
    let mut duplicate = candidate(&state, 1_000_000);
    duplicate.issuances.push(record.clone());
    assert!(state.apply(&duplicate, &IssuanceVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
    // Reconstructing a branch without the payment removes its eligibility.
    let mut alternative = State::new(c).unwrap();
    let block = candidate(&alternative, 1_100_000);
    alternative.apply(&block, &IssuanceVerifier).unwrap();
    let mut unpaid = candidate(&alternative, 1_200_000);
    unpaid.issuances.push(record);
    let before = alternative.fingerprint();
    assert!(alternative.apply(&unpaid, &IssuanceVerifier).is_err());
    assert_eq!(alternative.fingerprint(), before);
    assert!(alternative.assets.is_empty());
}

#[test]
fn rpc_reorg_prunes_a_receipt_whose_canonical_payment_was_removed() {
    use crate::chain::CandidatePolicy;
    use crate::runtime::Node;
    use crate::store::Store;
    let c = config();
    let record = sample(&c);
    let dir = Directory::new();
    let mut node = Node::new(
        Store::open(dir.db(), c.clone(), &IssuanceVerifier).unwrap(),
        IssuanceVerifier,
    );
    let mut payment = issued_block(node.state(), record.clone(), 1_300_000);
    payment.issuances.clear();
    node.import_branch(0, &[payment], CandidatePolicy::default())
        .unwrap();
    node.submit_issuance(&record.encode().unwrap()).unwrap();
    assert_eq!(node.pending_issuance_count(), 1);
    let mut alternative = State::new(c).unwrap();
    let first = candidate(&alternative, 1_400_000);
    alternative.apply(&first, &IssuanceVerifier).unwrap();
    let second = candidate(&alternative, 1_500_000);
    node.import_branch(0, &[first, second], CandidatePolicy::default())
        .unwrap();
    assert_eq!(node.pending_issuance_count(), 0);
    assert!(!node.state().commitments.contains(&record.fee_commitment));
    assert!(node.submit_issuance(&record.encode().unwrap()).is_err());
}

#[test]
fn governed_issuance_freezes_exact_public_amount_and_payment_owner() {
    use native::encryption::RecipientViewKey;
    let config = config();
    let recipient = RecipientViewKey::generate([F::from_u32(919); 12]).unwrap();
    let address = recipient.address();
    let amount = 7 * 100_000_000;
    let policy = ActiveIssuancePolicy::new(&address, amount).unwrap();
    let mut record = sample(&config);
    record.signed.declaration.issuance_fee_atoms = amount;
    resign(&mut record);
    record.fee_commitment =
        encode_digest(&Hasher::new().note_cm(&record.public_fee_note(&policy).unwrap()));
    record.validate_with_policy(&config, &policy).unwrap();
    assert!(record.validate(&config).is_err());
    let recovered = record.public_fee_note(&policy).unwrap();
    assert_eq!(recovered.owner, address.owner());
    assert_eq!(recovered.asset_id, native::multi_asset::SIP_ASSET_ID);
    assert_eq!(recovered.value, amount);
    assert_eq!(recovered.unlock_height, 0);
    assert_eq!(
        encode_digest(&Hasher::new().note_cm(&recovered)),
        record.fee_commitment
    );
    let wrong_amount = ActiveIssuancePolicy::new(&address, amount + 1).unwrap();
    assert!(record.validate_with_policy(&config, &wrong_amount).is_err());
    let wrong_recipient = RecipientViewKey::generate([F::from_u32(920); 12]).unwrap();
    let wrong_address = wrong_recipient.address();
    let wrong_owner = ActiveIssuancePolicy::new(&wrong_address, amount).unwrap();
    assert!(record.validate_with_policy(&config, &wrong_owner).is_err());
    for index in 0..5 {
        let mut bad = record.clone();
        match index {
            0 => bad.fee_rho[0] ^= 1,
            1 => bad.signed.signature.as_mut().unwrap()[0] ^= 1,
            2 => bad.ciphertexts[0][0] ^= 1,
            3 => bad.fee_commitment[0] ^= 1,
            _ => bad.signed.declaration.issuance_fee_atoms += 1,
        }
        assert!(
            bad.validate_with_policy(&config, &policy).is_err(),
            "case {index}"
        );
    }
    let mut wrong_network = config.clone();
    wrong_network.network[0] ^= 1;
    assert!(
        record
            .validate_with_policy(&wrong_network, &policy)
            .is_err()
    );
}

#[test]
fn governed_issuance_accepts_only_the_genesis_amount_bounds() {
    use native::encryption::RecipientViewKey;
    let recipient = RecipientViewKey::generate([F::from_u32(921); 12]).unwrap();
    let address = recipient.address();
    for amount in [0, 99_999_999, 1_000_000_000_001, u64::MAX] {
        assert!(ActiveIssuancePolicy::new(&address, amount).is_err());
    }
    for amount in [100_000_000, TESTNET_ISSUANCE_FEE_ATOMS, 1_000_000_000_000] {
        assert_eq!(
            ActiveIssuancePolicy::new(&address, amount)
                .unwrap()
                .fee_atoms(),
            amount
        );
    }
}

#[test]
fn governed_public_receipt_recovery_does_not_claim_kem_ciphertext_binding() {
    use native::encryption::RecipientViewKey;
    let config = config();
    let owner = [F::from_u32(922); 12];
    let first = RecipientViewKey::generate(owner).unwrap().address();
    let second = RecipientViewKey::generate(owner).unwrap().address();
    assert_ne!(first, second);
    let policy = ActiveIssuancePolicy::new(&first, TESTNET_ISSUANCE_FEE_ATOMS).unwrap();
    let alternate = ActiveIssuancePolicy::new(&second, TESTNET_ISSUANCE_FEE_ATOMS).unwrap();
    let mut record = sample(&config);
    record.fee_commitment =
        encode_digest(&Hasher::new().note_cm(&record.public_fee_note(&policy).unwrap()));
    record.validate_with_policy(&config, &policy).unwrap();
    record.validate_with_policy(&config, &alternate).unwrap();
    assert_eq!(policy.destination(), &first);
    let note = record.public_fee_note(&alternate).unwrap();
    assert_eq!(note.owner, owner);
    assert_eq!(
        encode_digest(&Hasher::new().note_cm(&note)),
        record.fee_commitment
    );
}

#[test]
fn governed_issuance_preflight_requires_the_paid_output_and_keeps_parent_unchanged() {
    use crate::chain_transition::{Actions, Context, PreparedActions};
    use native::encryption::RecipientViewKey;
    let config = config();
    let recipient = RecipientViewKey::generate([F::from_u32(923); 12]).unwrap();
    let address = recipient.address();
    let policy = ActiveIssuancePolicy::new(&address, 8 * 100_000_000).unwrap();
    let mut record = sample(&config);
    record.signed.declaration.issuance_fee_atoms = policy.fee_atoms();
    resign(&mut record);
    record.fee_commitment =
        encode_digest(&Hasher::new().note_cm(&record.public_fee_note(&policy).unwrap()));
    let state = State::new(config).unwrap();
    let block = issued_block(&state, record.clone(), 1000);
    let before = state.fingerprint();
    let prepare = |block: &Block| {
        PreparedActions::prepare_with_issuance_policy(
            &state,
            Context {
                network: block.network,
                height: block.height,
                parent: block.parent,
                timestamp: block.timestamp,
                target: block.target,
            },
            Actions {
                transactions: &block.transactions,
                issuances: &block.issuances,
                rewards: &block.rewards,
            },
            Some(&policy),
        )
        .is_ok()
    };
    assert!(prepare(&block));
    assert_eq!(state.fingerprint(), before);
    let mut unpaid = block.clone();
    unpaid
        .transactions
        .iter_mut()
        .find(|tx| tx.record.body[96..144] == record.fee_commitment)
        .unwrap()
        .record
        .body[96..144]
        .copy_from_slice(&encode_digest(&[F::from_u32(924); 12]));
    unpaid
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&unpaid.network));
    assert!(!prepare(&unpaid));
    assert_eq!(state.fingerprint(), before);
    let mut outdated = block;
    outdated.issuances[0].signed.declaration.issuance_fee_atoms = TESTNET_ISSUANCE_FEE_ATOMS;
    resign(&mut outdated.issuances[0]);
    assert!(!prepare(&outdated));
    assert_eq!(state.fingerprint(), before);
    assert!(state.assets.is_empty());
}
