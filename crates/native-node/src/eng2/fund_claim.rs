//! Versioned public fund claims. Encapsulation coins disclose only this public note.
//!
//! This format must not be used for confidential fees or wallet payments.
//! Authorization does not establish available entitlement: the sole fund ledger
//! must still debit the released amount and counter before an output is published.

use crate::{eng2_governance::GovernanceState, fund_spend::FundSpend, state::Config, wire::Hash};
use native::encryption::{EncryptionContext, PaymentCiphertext, PaymentEncryptionOpening};
use native::multi_asset::Digest;

pub const VERSION: u16 = 1;
pub const SIGNATURE_CONTEXT: &[u8] = b"siworld eng2 public fund claim v1";
pub const ENCODED_BYTES: usize = 4 + 2 + 32 + 8 + crate::fund_spend::ENCODED_BYTES + 32;
const SPEND_UNSIGNED_BYTES: usize =
    crate::fund_spend::ENCODED_BYTES - crate::fund_spend::SIGNATURE_BYTES;
const SIGNED_BYTES: usize = ENCODED_BYTES - crate::fund_spend::SIGNATURE_BYTES;
const MAGIC: &[u8; 4] = b"SW2F";

mod windowed;
pub use windowed::WindowedFundClaim;

/// All fields, including the single payment's encapsulation coins, are public.
/// The `spend.signature` authenticates this format, not the V1 spend message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicFundClaim {
    pub network: Hash,
    pub height: u64,
    pub spend: FundSpend,
    pub encapsulation_coins: [u8; 32],
}
impl PublicFundClaim {
    pub fn encode(&self) -> Vec<u8> {
        let spend = self.spend.encode();
        let mut bytes = Vec::with_capacity(ENCODED_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&spend[..SPEND_UNSIGNED_BYTES]);
        bytes.extend_from_slice(&self.encapsulation_coins);
        bytes.extend_from_slice(&self.spend.signature);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != ENCODED_BYTES
            || &bytes[..4] != MAGIC
            || bytes[4..6] != VERSION.to_le_bytes()
        {
            return Err("unsupported or noncanonical public fund claim".into());
        }
        let mut spend = Vec::with_capacity(crate::fund_spend::ENCODED_BYTES);
        spend.extend_from_slice(&bytes[46..46 + SPEND_UNSIGNED_BYTES]);
        spend.extend_from_slice(&bytes[SIGNED_BYTES..]);
        let result = Self {
            network: bytes[6..38].try_into().expect("fixed network width"),
            height: u64::from_le_bytes(bytes[38..46].try_into().expect("fixed height width")),
            spend: FundSpend::decode(&spend)?,
            encapsulation_coins: bytes[46 + SPEND_UNSIGNED_BYTES..SIGNED_BYTES]
                .try_into()
                .expect("fixed encapsulation coin width"),
        };
        if result.height == 0 {
            return Err("public fund claim requires an inclusion height".into());
        }
        Ok(result)
    }
    /// Complete canonical versioned claim, excluding only its signature bytes.
    pub fn signing_message(&self) -> Vec<u8> {
        self.encode()[..SIGNED_BYTES].to_vec()
    }
}

/// Non-clone authority and full-destination capability; entitlement is separate.
pub struct AuthorizedFundClaim {
    network: Hash,
    height: u64,
    member: u8,
    amount: u64,
    counter: u64,
    commitment: Digest,
    ciphertext: [u8; 1313],
}

/// Non-clone output whose immutable authority, destination and ledger debit
/// have all been checked. Publish it only with its enclosing staged ledger.
pub struct DebitedFundOutput {
    network: Hash,
    height: u64,
    commitment: Digest,
    ciphertext: [u8; 1313],
}
impl DebitedFundOutput {
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn commitment(&self) -> Digest {
        self.commitment
    }
    pub fn ciphertext(&self) -> &[u8; 1313] {
        &self.ciphertext
    }
}
impl AuthorizedFundClaim {
    /// Consume authority exactly once against an isolated candidate ledger.
    /// The caller commits that ledger and this output together, or neither.
    pub fn debit(
        self,
        staged: &mut crate::eng2_fund::FundLedger,
    ) -> Result<DebitedFundOutput, String> {
        if staged.network() != self.network || staged.height() != self.height {
            return Err("fund debit ledger context differs from authorized claim".into());
        }
        staged.spend(self.member, u128::from(self.amount), self.counter)?;
        Ok(DebitedFundOutput {
            network: self.network,
            height: self.height,
            commitment: self.commitment,
            ciphertext: self.ciphertext,
        })
    }
    pub fn verify(
        claim: &PublicFundClaim,
        config: &Config,
        frozen: &GovernanceState,
        height: u64,
    ) -> Result<Self, String> {
        if height == 0
            || claim.height != height
            || frozen.height() != height
            || claim.network != config.network
            || frozen.network() != config.network
        {
            return Err("public fund claim block context differs".into());
        }
        Self::verify_authenticated(
            claim,
            config,
            frozen,
            height,
            &claim.signing_message(),
            SIGNATURE_CONTEXT,
        )
    }
    fn verify_authenticated(
        claim: &PublicFundClaim,
        config: &Config,
        frozen: &GovernanceState,
        height: u64,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self, String> {
        let spend = &claim.spend;
        let key = config
            .fund_verifying_keys
            .get(usize::from(spend.account))
            .ok_or("fund member has no immutable claim authority")?;
        let note = spend.verify_signed_message(config.network, key, message, context)?;
        let destination = frozen.active_fund_destination(spend.account)?;
        let commitment = native::multi_asset::Hasher::new().note_cm(&note);
        let payment = PaymentCiphertext {
            kem_ciphertext: spend.ciphertext[..1088]
                .try_into()
                .expect("fixed KEM width"),
            body: spend.ciphertext[1088..1296]
                .try_into()
                .expect("fixed note width"),
            tag: spend.ciphertext[1296..1312]
                .try_into()
                .expect("fixed tag width"),
            view_tag: spend.ciphertext[1312],
        };
        let opening = PaymentEncryptionOpening::from_encapsulation_coins(claim.encapsulation_coins);
        let recovered = opening
            .verify_payment(
                destination,
                &commitment,
                &payment,
                &EncryptionContext::new(config.network),
            )
            .map_err(|_| "public fund claim payment relation failed".to_owned())?;
        if recovered.asset_id != note.asset_id
            || recovered.owner != note.owner
            || recovered.value != note.value
            || recovered.unlock_height != note.unlock_height
            || recovered.rho != note.rho
            || recovered.rseed != note.rseed
            || native::multi_asset::Hasher::new().note_cm(&recovered) != commitment
        {
            return Err("public fund claim recovered note differs".into());
        }
        Ok(Self {
            network: config.network,
            height,
            member: spend.account,
            amount: spend.amount,
            counter: spend.counter,
            commitment,
            ciphertext: spend.ciphertext,
        })
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn member(&self) -> u8 {
        self.member
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn counter(&self) -> u64 {
        self.counter
    }
    pub fn commitment(&self) -> Digest {
        self.commitment
    }
    pub fn ciphertext(&self) -> &[u8; 1313] {
        &self.ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65;
    use native::{
        codec::encode_digest,
        encryption::{
            EncryptionContext, PaymentAddress, PaymentCiphertext, encrypt_payment_with_opening,
        },
        multi_asset::{F, Hasher, Note, SIP_ASSET_ID},
    };
    use p3_field::PrimeCharacteristicRing;

    fn address(network: Hash, seed: u8) -> PaymentAddress {
        crate::wallet::WalletKeys::from_seed(network, zeroize::Zeroizing::new([seed; 32]), 0)
            .unwrap()
            .address()
    }
    fn genesis_governance(network: Hash, destination: PaymentAddress) -> GovernanceState {
        let key = |seed| {
            *ml_dsa_65::generate_key_pair([seed; 32])
                .verification_key
                .as_ref()
        };
        GovernanceState::new(
            network,
            key(1),
            key(2),
            [3, 4, 5].map(key),
            address(network, 31),
            vec![destination, address(network, 32)],
        )
        .unwrap()
    }
    fn governance(network: Hash, destination: PaymentAddress) -> GovernanceState {
        let mut state = genesis_governance(network, destination);
        state.apply_block(1, &[]).unwrap();
        state
    }
    fn payment_bytes(payment: &PaymentCiphertext) -> [u8; 1313] {
        let mut bytes = [0; 1313];
        bytes[..1088].copy_from_slice(&payment.kem_ciphertext);
        bytes[1088..1296].copy_from_slice(&payment.body);
        bytes[1296..1312].copy_from_slice(&payment.tag);
        bytes[1312] = payment.view_tag;
        bytes
    }
    fn resign(claim: &mut PublicFundClaim, signer: u8) {
        let pair = ml_dsa_65::generate_key_pair([signer; 32]);
        claim.spend.verifying_key = *pair.verification_key.as_ref();
        claim.spend.signature = *ml_dsa_65::sign(
            &pair.signing_key,
            &claim.signing_message(),
            SIGNATURE_CONTEXT,
            [18; 32],
        )
        .unwrap()
        .as_ref();
    }
    fn signed_with_context(
        network: Hash,
        destination: &PaymentAddress,
        context: EncryptionContext,
    ) -> PublicFundClaim {
        signed_at(network, destination, context, 1, 7, 123)
    }
    fn signed_at(
        network: Hash,
        destination: &PaymentAddress,
        context: EncryptionContext,
        height: u64,
        counter: u64,
        amount: u64,
    ) -> PublicFundClaim {
        let note = Note {
            asset_id: SIP_ASSET_ID,
            owner: destination.owner(),
            value: amount,
            unlock_height: 0,
            rho: crate::fund_spend::canonical_rho(network, 0, counter),
            rseed: [F::from_u32(9); 12],
        };
        let (payment, opening) =
            encrypt_payment_with_opening(destination, &note, &context).unwrap();
        let mut claim = PublicFundClaim {
            network,
            height,
            spend: FundSpend {
                account: 0,
                counter,
                amount: note.value,
                owner: encode_digest(&note.owner),
                rho: encode_digest(&note.rho),
                rseed: encode_digest(&note.rseed),
                commitment: encode_digest(&Hasher::new().note_cm(&note)),
                ciphertext: payment_bytes(&payment),
                verifying_key: [0; crate::fund_spend::VERIFYING_KEY_BYTES],
                signature: [0; crate::fund_spend::SIGNATURE_BYTES],
            },
            encapsulation_coins: *opening.expose_encapsulation_coins(),
        };
        resign(&mut claim, 83);
        claim
    }
    fn signed(network: Hash, destination: &PaymentAddress) -> PublicFundClaim {
        signed_with_context(network, destination, EncryptionContext::new(network))
    }

    fn signed_window(network: Hash, destination: &PaymentAddress) -> WindowedFundClaim {
        let mut result = WindowedFundClaim {
            claim: signed_at(
                network,
                destination,
                EncryptionContext::new(network),
                1,
                0,
                17,
            ),
            valid_until: 288,
        };
        result.claim.spend.signature = *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([83; 32]).signing_key,
            &result.signing_message().unwrap(),
            WindowedFundClaim::signature_context(),
            [21; 32],
        )
        .unwrap()
        .as_ref();
        result
    }

    #[test]
    fn windowed_claim_uses_unchanged_payload_through_288_inclusive_heights() {
        let network = [1; 32];
        let destination = address(network, 40);
        let config = Config::development(network, 0).unwrap();
        let claim = signed_window(network, &destination);
        let bytes = claim.encode().unwrap();
        assert_eq!(WindowedFundClaim::decode(&bytes).unwrap(), claim);
        assert!(PublicFundClaim::decode(&bytes).is_err());
        assert!(WindowedFundClaim::decode(&claim.claim.encode()).is_err());
        let mut state = genesis_governance(network, destination);
        for height in 1..=289 {
            state.apply_block(height, &[]).unwrap();
            if [1, 2, 287, 288].contains(&height) {
                let authority =
                    AuthorizedFundClaim::verify_windowed(&claim, &config, &state, height).unwrap();
                assert_eq!(authority.height(), height);
                assert_eq!(authority.amount(), 17);
            }
        }
        assert!(AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 289).is_err());
        assert_eq!(claim.encode().unwrap(), bytes);
        assert!(AuthorizedFundClaim::verify(&claim.claim, &config, &state, 289).is_err());
    }

    #[test]
    fn windowed_claim_authenticates_interval_and_current_destination() {
        let network = [1; 32];
        let destination = address(network, 40);
        let config = Config::development(network, 0).unwrap();
        let claim = signed_window(network, &destination);
        let state = governance(network, destination);
        let mut changed_end = claim.clone();
        changed_end.valid_until = 289;
        assert!(AuthorizedFundClaim::verify_windowed(&changed_end, &config, &state, 1).is_err());
        let mut changed_start = claim.clone();
        changed_start.claim.height = 2;
        changed_start.valid_until = 289;
        let mut next = state.clone();
        next.apply_block(2, &[]).unwrap();
        assert!(AuthorizedFundClaim::verify_windowed(&changed_start, &config, &next, 2).is_err());
        let other_destination = governance(network, address(network, 41));
        assert!(
            AuthorizedFundClaim::verify_windowed(&claim, &config, &other_destination, 1).is_err()
        );
        assert!(AuthorizedFundClaim::verify(&claim.claim, &config, &state, 1).is_err());
        let legacy = signed(network, &address(network, 40));
        assert!(AuthorizedFundClaim::verify(&legacy, &config, &state, 1).is_ok());
        let mut wrongly_reused_legacy = claim.clone();
        wrongly_reused_legacy.claim = legacy;
        assert!(
            AuthorizedFundClaim::verify_windowed(&wrongly_reused_legacy, &config, &state, 1)
                .is_err()
        );
    }

    #[test]
    fn windowed_claim_rejects_short_zero_overflow_and_noncanonical_windows() {
        let mut claim = signed_window([1; 32], &address([1; 32], 40));
        let bytes = claim.encode().unwrap();
        claim.valid_until = 287;
        assert!(claim.encode().is_err());
        claim.claim.height = 0;
        claim.valid_until = 288;
        assert!(claim.encode().is_err());
        claim.claim.height = u64::MAX - 286;
        claim.valid_until = u64::MAX;
        assert!(claim.encode().is_err());
        claim.claim.height = u64::MAX - 287;
        assert!(claim.encode().is_ok());
        let mut short = bytes.clone();
        short[46..54].copy_from_slice(&287u64.to_le_bytes());
        assert!(WindowedFundClaim::decode(&short).is_err());
        assert!(WindowedFundClaim::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(WindowedFundClaim::decode(&trailing).is_err());
    }

    #[test]
    fn windowed_claim_debit_at_last_height_rejects_replay_atomically() {
        let network = [1; 32];
        let destination = address(network, 40);
        let config = Config::development(network, 0).unwrap();
        let claim = signed_window(network, &destination);
        let mut state = genesis_governance(network, destination);
        let mut ledger =
            crate::eng2_fund::FundLedger::new(network, config.fund_allocation.clone().unwrap())
                .unwrap();
        for height in 1..=288 {
            state.apply_block(height, &[]).unwrap();
            ledger
                .advance(height, if height == 1 { 1_000_000 } else { 0 })
                .unwrap();
        }
        let output = AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 288)
            .unwrap()
            .debit(&mut ledger)
            .unwrap();
        assert_eq!(output.height(), 288);
        assert_eq!(ledger.balance(0).unwrap().spent, 17);
        let after_first_debit = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 288)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, after_first_debit);
    }

    #[test]
    fn restored_fund_state_reincludes_unchanged_claim_without_global_consumption() {
        let network = [1; 32];
        let destination = address(network, 40);
        let config = Config::development(network, 0).unwrap();
        let claim = signed_window(network, &destination);
        let signed_bytes = claim.encode().unwrap();
        let mut state = genesis_governance(network, destination);
        let mut ledger =
            crate::eng2_fund::FundLedger::new(network, config.fund_allocation.clone().unwrap())
                .unwrap();
        for height in 1..=25 {
            state.apply_block(height, &[]).unwrap();
            ledger
                .advance(height, if height == 1 { 1_000_000 } else { 0 })
                .unwrap();
        }
        let savepoint = (state.clone(), ledger.clone());
        let first = AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 25)
            .unwrap()
            .debit(&mut ledger)
            .unwrap();
        let consumed = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 25)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, consumed);

        // Restoring both state components removes only this branch's debit.
        (state, ledger) = savepoint.clone();
        for height in 26..=288 {
            state.apply_block(height, &[]).unwrap();
            ledger.advance(height, 0).unwrap();
        }
        let replacement = AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 288)
            .unwrap()
            .debit(&mut ledger)
            .unwrap();
        assert_eq!(first.height(), 25);
        assert_eq!(replacement.height(), 288);
        assert_eq!(ledger.balance(0).unwrap().spent, 17);
        assert_eq!(claim.encode().unwrap(), signed_bytes);
        let consumed = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 288)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, consumed);

        (state, ledger) = savepoint;
        for height in 26..=289 {
            state.apply_block(height, &[]).unwrap();
            ledger.advance(height, 0).unwrap();
        }
        let expired = (state.clone(), ledger.clone());
        assert!(AuthorizedFundClaim::verify_windowed(&claim, &config, &state, 289).is_err());
        assert_eq!((state, ledger), expired);
    }

    fn signed_governance(
        network: Hash,
        sequence: u64,
        kind: crate::eng2_governance::ActionKind,
        role: crate::eng2_governance::SignerRole,
    ) -> crate::eng2_governance::SignedAction {
        use crate::eng2_governance::{self, Action, Authorization, SignedAction, SignerRole};
        let action = Action {
            network,
            sequence,
            kind,
        };
        let seed = match role {
            SignerRole::Founder => 1,
            SignerRole::Revocation => 2,
            _ => panic!("fixture supports only destination owner roles"),
        };
        let signature = *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
            &action.signing_bytes(role).unwrap(),
            eng2_governance::SIGNATURE_CONTEXT,
            [20; 32],
        )
        .unwrap()
        .as_ref();
        SignedAction {
            action,
            signatures: vec![Authorization { role, signature }],
        }
    }

    fn claim_payment(claim: &PublicFundClaim) -> PaymentCiphertext {
        let bytes = &claim.spend.ciphertext;
        PaymentCiphertext {
            kem_ciphertext: bytes[..1088].try_into().unwrap(),
            body: bytes[1088..1296].try_into().unwrap(),
            tag: bytes[1296..1312].try_into().unwrap(),
            view_tag: bytes[1312],
        }
    }

    #[test]
    fn fund_recipient_rotation_preserves_entitlement_counters_and_immutable_authority() {
        use crate::{
            eng2_fund::FundLedger,
            eng2_governance::{self, ActionKind, DestinationTarget, SignerRole},
            wallet_crypto::RecoverableViewKey,
        };
        // Synthetic zero-subsidy intervening heights exercise the real governance,
        // fund ledger and claim capabilities without proofs or network execution.
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let authority = config.fund_verifying_keys[0];
        let owner = address(network, 40).owner();
        let old_view =
            RecoverableViewKey::from_seed(owner, zeroize::Zeroizing::new([70; 64])).unwrap();
        let new_view =
            RecoverableViewKey::from_seed(owner, zeroize::Zeroizing::new([71; 64])).unwrap();
        let old = old_view.address();
        let new = new_view.address();
        assert_eq!(old.owner(), new.owner());
        assert_ne!(old.encapsulation_key(), new.encapsulation_key());
        let mut governance = genesis_governance(network, old.clone());
        let allocation = config.fund_allocation.clone().unwrap();
        let mut ledger = FundLedger::new(network, allocation.clone()).unwrap();
        let mut address_bytes = [0; eng2_governance::ADDRESS_BYTES];
        address_bytes[..48].copy_from_slice(&encode_digest(&new.owner()));
        address_bytes[48..].copy_from_slice(new.encapsulation_key());
        let proposal = signed_governance(
            network,
            1,
            ActionKind::ProposeDestination {
                target: DestinationTarget::FundMember(0),
                address: Box::new(address_bytes),
            },
            SignerRole::Founder,
        );
        let inclusion = governance.apply_block(1, &[proposal]).unwrap();
        assert_eq!(inclusion.len(), 1);
        assert_eq!(inclusion[0].included_height, 1);
        assert_eq!(inclusion[0].effective_height, 4033);
        ledger.advance(1, 2020).unwrap();
        let context = EncryptionContext::new(network);
        for height in 2..=4031 {
            governance.apply_block(height, &[]).unwrap();
            ledger.advance(height, 0).unwrap();
            if height == 25 {
                let claim = signed_at(network, &old, context, height, 0, 17);
                AuthorizedFundClaim::verify(&claim, &config, &governance, height)
                    .unwrap()
                    .debit(&mut ledger)
                    .unwrap();
                let recovered = old_view
                    .decrypt_payment(
                        &native::codec::decode_digest(&claim.spend.commitment).unwrap(),
                        &claim_payment(&claim),
                        &context,
                    )
                    .unwrap();
                assert_eq!(recovered.value, 17);
                let commitment = Hasher::new().note_cm(&recovered);
                assert_eq!(encode_digest(&commitment), claim.spend.commitment);
                assert!(
                    new_view
                        .decrypt_payment(&commitment, &claim_payment(&claim), &context)
                        .is_err()
                );
            }
        }
        let mut canceled = governance.clone();
        let cancel = signed_governance(
            network,
            2,
            ActionKind::CancelDestination {
                proposal_sequence: 1,
            },
            SignerRole::Revocation,
        );
        canceled
            .apply_block(4032, std::slice::from_ref(&cancel))
            .unwrap();
        canceled.apply_block(4033, &[]).unwrap();
        assert_eq!(canceled.active_fund_destination(0).unwrap(), &old);
        governance.apply_block(4032, &[]).unwrap();
        ledger.advance(4032, 0).unwrap();
        assert_eq!(governance.active_fund_destination(0).unwrap(), &old);
        let before = ledger.balance(0).unwrap();
        assert_eq!(before.entitlement, 101);
        assert_eq!(before.direct_unlocked, 50);
        assert_eq!(before.vesting_unlocked, 0);
        assert_eq!(before.spent, 17);
        assert_eq!(before.spend_count, 1);
        assert_eq!(before.available().unwrap(), 33);
        let other_member = ledger.balance(1).unwrap();
        let total = ledger.total_entitlement();
        let old_claim = signed_at(network, &old, context, 4032, 1, 19);
        assert!(AuthorizedFundClaim::verify(&old_claim, &config, &governance, 4032).is_ok());
        let early = signed_at(network, &new, context, 4032, 1, 19);
        assert!(AuthorizedFundClaim::verify(&early, &config, &governance, 4032).is_err());
        let pending = governance.clone();
        assert!(governance.apply_block(4033, &[cancel]).is_err());
        assert_eq!(governance, pending);
        governance.apply_block(4033, &[]).unwrap();
        ledger.advance(4033, 0).unwrap();
        assert_eq!(governance.active_fund_destination(0).unwrap(), &new);
        assert_eq!(ledger.balance(0).unwrap(), before);
        assert_eq!(ledger.balance(1).unwrap(), other_member);
        assert_eq!(ledger.total_entitlement(), total);
        assert_eq!(config.fund_verifying_keys[0], authority);
        let restored_ledger = FundLedger::decode_component(
            &ledger.canonical_component_bytes().unwrap(),
            network,
            &allocation,
        )
        .unwrap();
        assert_eq!(restored_ledger, ledger);
        ledger = restored_ledger;
        let restored_governance = GovernanceState::decode_component(
            &governance.canonical_component_bytes().unwrap(),
            network,
        )
        .unwrap();
        assert_eq!(restored_governance, governance);
        let governance = restored_governance;
        let old_claim = signed_at(network, &old, context, 4033, 1, 19);
        assert!(AuthorizedFundClaim::verify(&old_claim, &config, &governance, 4033).is_err());
        assert!(AuthorizedFundClaim::verify(&old_claim, &config, &canceled, 4033).is_ok());
        let claim = signed_at(network, &new, context, 4033, 1, 19);
        assert_eq!(claim.spend.verifying_key, authority);
        assert!(AuthorizedFundClaim::verify(&claim, &config, &canceled, 4033).is_err());
        let mut wrong_authority = claim.clone();
        resign(&mut wrong_authority, 84);
        assert!(AuthorizedFundClaim::verify(&wrong_authority, &config, &governance, 4033).is_err());
        assert_eq!(ledger.balance(0).unwrap(), before);
        let output = AuthorizedFundClaim::verify(&claim, &config, &governance, 4033)
            .unwrap()
            .debit(&mut ledger)
            .unwrap();
        assert_eq!(output.ciphertext(), &claim.spend.ciphertext);
        let recovered = new_view
            .decrypt_payment(&output.commitment(), &claim_payment(&claim), &context)
            .unwrap();
        assert_eq!(recovered.value, 19);
        assert_eq!(recovered.owner, new.owner());
        assert!(
            old_view
                .decrypt_payment(&output.commitment(), &claim_payment(&claim), &context)
                .is_err()
        );
        let after = ledger.balance(0).unwrap();
        assert_eq!(after.entitlement, before.entitlement);
        assert_eq!(after.direct_unlocked, before.direct_unlocked);
        assert_eq!(after.vesting_unlocked, before.vesting_unlocked);
        assert_eq!(after.spent, 36);
        assert_eq!(after.spend_count, 2);
        assert_eq!(after.available().unwrap(), 14);
        assert_eq!(ledger.balance(1).unwrap(), other_member);
        assert_eq!(ledger.total_entitlement(), total);
        let after = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify(&claim, &config, &governance, 4033)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, after);
    }

    #[test]
    fn actual_signature_and_full_payment_relation_produce_a_bound_capability() {
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let destination = address(network, 40);
        let frozen = governance(network, destination.clone());
        let claim = signed(network, &destination);
        let capability = AuthorizedFundClaim::verify(&claim, &config, &frozen, 1).unwrap();
        assert_eq!(capability.network(), network);
        assert_eq!(capability.height(), 1);
        assert_eq!(capability.member(), 0);
        assert_eq!(capability.amount(), 123);
        assert_eq!(capability.counter(), 7);
        assert_eq!(
            encode_digest(&capability.commitment()),
            claim.spend.commitment
        );
        assert_eq!(capability.ciphertext(), &claim.spend.ciphertext);
        assert_eq!(PublicFundClaim::decode(&claim.encode()).unwrap(), claim);
        assert!(
            claim
                .spend
                .verify(network, &config.fund_verifying_keys[0])
                .is_err()
        );
    }

    #[test]
    fn same_owner_with_a_different_kem_key_cannot_receive_the_claim() {
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let destination = address(network, 40);
        let other_key = address(network, 41);
        let wrong =
            PaymentAddress::new(destination.owner(), *other_key.encapsulation_key()).unwrap();
        let claim = signed(network, &wrong);
        let other_frozen = governance(network, wrong);
        assert!(AuthorizedFundClaim::verify(&claim, &config, &other_frozen, 1).is_ok());
        let frozen = governance(network, destination);
        assert!(AuthorizedFundClaim::verify(&claim, &config, &frozen, 1).is_err());
    }

    #[test]
    fn even_authority_signed_ciphertext_coins_or_encryption_context_tampering_is_rejected() {
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let destination = address(network, 40);
        let frozen = governance(network, destination.clone());
        let original = signed(network, &destination);
        for offset in [0, 1088, 1296, 1312] {
            let mut changed = original.clone();
            changed.spend.ciphertext[offset] ^= 1;
            resign(&mut changed, 83);
            assert!(AuthorizedFundClaim::verify(&changed, &config, &frozen, 1).is_err());
        }
        let mut changed = original;
        changed.encapsulation_coins[0] ^= 1;
        resign(&mut changed, 83);
        assert!(AuthorizedFundClaim::verify(&changed, &config, &frozen, 1).is_err());
        let wrong_context =
            signed_with_context(network, &destination, EncryptionContext::new([2; 32]));
        assert!(AuthorizedFundClaim::verify(&wrong_context, &config, &frozen, 1).is_err());
    }

    #[test]
    fn every_versioned_claim_field_is_signed_and_the_inclusion_context_is_exact() {
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let destination = address(network, 40);
        let frozen = governance(network, destination.clone());
        let claim = signed(network, &destination);
        for offset in [
            0,
            4,
            6,
            38,
            46,
            47,
            55,
            63,
            111,
            159,
            207,
            255,
            1568,
            3520,
            3552,
            ENCODED_BYTES - 1,
        ] {
            let mut bytes = claim.encode();
            bytes[offset] ^= 1;
            assert!(
                PublicFundClaim::decode(&bytes)
                    .and_then(|value| AuthorizedFundClaim::verify(&value, &config, &frozen, 1))
                    .is_err(),
                "offset {offset}"
            );
        }
        assert!(PublicFundClaim::decode(&claim.encode()[..ENCODED_BYTES - 1]).is_err());
        let mut trailing = claim.encode();
        trailing.push(0);
        assert!(PublicFundClaim::decode(&trailing).is_err());
        let mut future = claim.clone();
        future.height = 2;
        resign(&mut future, 83);
        assert!(AuthorizedFundClaim::verify(&future, &config, &frozen, 1).is_err());
        assert!(AuthorizedFundClaim::verify(&claim, &config, &frozen, 2).is_err());
        assert!(AuthorizedFundClaim::verify(&claim, &config, &frozen, 0).is_err());
        let mut wrong_authority = claim;
        resign(&mut wrong_authority, 84);
        assert!(AuthorizedFundClaim::verify(&wrong_authority, &config, &frozen, 1).is_err());
        let other = governance([2; 32], address([2; 32], 40));
        assert!(AuthorizedFundClaim::verify(&wrong_authority, &config, &other, 1).is_err());
    }

    #[test]
    fn authority_is_consumed_only_after_actual_release_counter_and_ledger_context_checks() {
        let network = [1; 32];
        let config = Config::development(network, 0).unwrap();
        let destination = address(network, 40);
        let mut frozen = governance(network, destination.clone());
        let allocation = config.fund_allocation.clone().unwrap();
        let mut ledger = crate::eng2_fund::FundLedger::new(network, allocation.clone()).unwrap();
        for height in 1..=24 {
            ledger
                .advance(height, siworld_core::v1_economics::subsidy(height).unwrap())
                .unwrap();
            if height > 1 {
                frozen.apply_block(height, &[]).unwrap();
            }
        }
        let claim = signed_at(
            network,
            &destination,
            EncryptionContext::new(network),
            24,
            0,
            123,
        );
        let before = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify(&claim, &config, &frozen, 24)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, before);
        ledger
            .advance(25, siworld_core::v1_economics::subsidy(25).unwrap())
            .unwrap();
        frozen.apply_block(25, &[]).unwrap();
        let claim = signed_at(
            network,
            &destination,
            EncryptionContext::new(network),
            25,
            0,
            123,
        );
        let before = ledger.clone();
        let mut wrong_height = before.clone();
        wrong_height.advance(26, 0).unwrap();
        assert!(
            AuthorizedFundClaim::verify(&claim, &config, &frozen, 25)
                .unwrap()
                .debit(&mut wrong_height)
                .is_err()
        );
        let output = AuthorizedFundClaim::verify(&claim, &config, &frozen, 25)
            .unwrap()
            .debit(&mut ledger)
            .unwrap();
        assert_eq!(output.network(), network);
        assert_eq!(output.height(), 25);
        assert_eq!(encode_digest(&output.commitment()), claim.spend.commitment);
        assert_eq!(output.ciphertext(), &claim.spend.ciphertext);
        assert_eq!(
            ledger.balance(0).unwrap().spent,
            before.balance(0).unwrap().spent + 123
        );
        let after = ledger.clone();
        assert!(
            AuthorizedFundClaim::verify(&claim, &config, &frozen, 25)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, after);
        let too_much = signed_at(
            network,
            &destination,
            EncryptionContext::new(network),
            25,
            1,
            u64::MAX,
        );
        assert!(
            AuthorizedFundClaim::verify(&too_much, &config, &frozen, 25)
                .unwrap()
                .debit(&mut ledger)
                .is_err()
        );
        assert_eq!(ledger, after);
        let mut other = crate::eng2_fund::FundLedger::new([2; 32], allocation).unwrap();
        for height in 1..=25 {
            other.advance(height, 0).unwrap();
        }
        assert!(
            AuthorizedFundClaim::verify(&claim, &config, &frozen, 25)
                .unwrap()
                .debit(&mut other)
                .is_err()
        );
    }
}
