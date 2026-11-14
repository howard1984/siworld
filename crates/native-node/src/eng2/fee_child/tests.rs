use super::*;
use native::{
    encryption::{PaymentAddress, PaymentCiphertext},
    multi_asset::{Digest, F},
    settlement::{RewardAllocation, RewardMode, RewardPlan},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

fn protocol() -> ProtocolBinding {
    ProtocolBinding {
        genesis: [31; 32],
        rules: [37; 32],
        air: complete_fee::source_identity(),
    }
}
fn factory() -> TrustedFactory {
    TrustedFactory::from_local_configuration(
        [31; 32],
        protocol(),
        Identity {
            relation: Relation::CompleteFee,
            profile: [19; 32],
        },
    )
    .unwrap()
}

struct PublicFixture {
    policy: complete_fee::SettlementPolicy,
    address: PaymentAddress,
    fees: Vec<Digest>,
    rewards: Vec<Digest>,
    payment: PaymentCiphertext,
}
impl PublicFixture {
    fn new(mode: RewardMode) -> Self {
        // Synthetic fixed inputs; no secret material is used by this codec test.
        let pair = libcrux_ml_kem::mlkem768::portable::generate_key_pair([3; 64]);
        let owner = [F::from_u8(7); 12];
        let address = PaymentAddress::new(owner, *pair.public_key().as_slice()).unwrap();
        Self {
            policy: complete_fee::SettlementPolicy {
                plan: RewardPlan {
                    block_height: 17,
                    mode,
                    allocations: (0..mode.note_count())
                        .map(|i| RewardAllocation {
                            amount: 41 + i as u64,
                            unlock_height: 17 + i as u64,
                        })
                        .collect(),
                },
                fee_owner: owner,
                fees: complete_fee::FeeSchedule::from_previous_standard(100).unwrap(),
                max_slots: complete_fee::CAPACITY,
            },
            address,
            fees: (0..complete_fee::CAPACITY)
                .map(|i| [F::from_usize(i + 1); 12])
                .collect(),
            rewards: (0..mode.note_count())
                .map(|i| [F::from_usize(700 + i); 12])
                .collect(),
            payment: PaymentCiphertext {
                kem_ciphertext: [3; 1088],
                body: [4; 208],
                tag: [5; 16],
                view_tag: 6,
            },
        }
    }
    fn inputs(&self) -> StatementInputs<'_> {
        StatementInputs {
            policy: &self.policy,
            network: [31; 32],
            transaction_list_digest: [47; 32],
            address: &self.address,
            fee_commitments: &self.fees,
            reward_commitments: &self.rewards,
            fee_commitment: [F::from_u32(710); 12],
            ciphertext: &self.payment,
        }
    }
    fn input(&self) -> ChildInput {
        let factory = factory();
        let proof = v2::encode(factory.identity(), &[1, 2, 3], MAX_FEE_PROOF_BYTES).unwrap();
        let statement = canonical::encode(self.inputs()).unwrap();
        let binding = RequestBinding {
            attempt: [1; 32],
            network: [31; 32],
            genesis: protocol().genesis,
            rules: protocol().rules,
            profile: factory.identity().profile,
            verifier_keys: factory.identity().profile,
            proof: fee_guard::proof_digest(&proof),
            statement: fee_guard::statement_digest(&statement),
            canonical_context: [11; 32],
        };
        ChildInput {
            proof,
            statement,
            binding,
        }
    }
}

#[test]
fn canonical_roundtrip_preserves_the_entire_reconstructed_public_vector() {
    for mode in [RewardMode::Voyager, RewardMode::Holder] {
        let fixture = PublicFixture::new(mode);
        let bytes = canonical::encode(fixture.inputs()).unwrap();
        assert!(bytes.len() <= MAX_STATEMENT_BYTES);
        let rebuilt = canonical::decode(&bytes).unwrap();
        let expected =
            complete_fee::Statement::from_authenticated(fixture.inputs(), protocol()).unwrap();
        assert_eq!(
            rebuilt.statement(protocol()).unwrap().public_values(),
            expected.public_values()
        );
        assert_eq!(canonical::encode(fixture.inputs()).unwrap(), bytes);
    }
}

#[test]
fn noncanonical_lengths_fields_context_and_schedule_are_rejected() {
    let fixture = PublicFixture::new(RewardMode::Holder);
    let bytes = canonical::encode(fixture.inputs()).unwrap();
    for length in [0, 1, 15, 16, bytes.len() - 1] {
        assert!(canonical::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(canonical::decode(&trailing).is_err());
    for offset in [0, 8, 10, 11, 12] {
        let mut changed = bytes.clone();
        changed[offset] = 255;
        assert!(canonical::decode(&changed).is_err());
    }
    let mut field = bytes.clone();
    field[106..110].copy_from_slice(&F::ORDER_U32.to_le_bytes());
    assert!(canonical::decode(&field).is_err());
    let mut schedule = bytes.clone();
    schedule[96..104].copy_from_slice(&41u64.to_le_bytes());
    assert!(canonical::decode(&schedule).is_err());
    let mut network = bytes.clone();
    network[16..48].fill(0);
    assert!(canonical::decode(&network).is_err());
    let mut owner = bytes.clone();
    owner[154..158].copy_from_slice(&8u32.to_le_bytes());
    assert!(canonical::decode(&owner).is_err());
}

#[test]
fn changing_an_authenticated_ciphertext_changes_the_reconstructed_statement() {
    let fixture = PublicFixture::new(RewardMode::Voyager);
    let mut bytes = canonical::encode(fixture.inputs()).unwrap();
    let before = canonical::decode(&bytes)
        .unwrap()
        .statement(protocol())
        .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let after = canonical::decode(&bytes)
        .unwrap()
        .statement(protocol())
        .unwrap();
    assert_ne!(before.public_values(), after.public_values());
}

#[test]
fn request_mixing_is_rejected_before_any_preprocessing_setup() {
    let fixture = PublicFixture::new(RewardMode::Voyager);
    let factory = factory();
    // Only syntax is accepted here; these three proof body bytes are not valid.
    assert!(factory.preflight(&fixture.input()).is_ok());
    for field in 0..9 {
        let mut input = fixture.input();
        let binding = &mut input.binding;
        let digest = match field {
            0 => &mut binding.attempt,
            1 => &mut binding.network,
            2 => &mut binding.genesis,
            3 => &mut binding.rules,
            4 => &mut binding.profile,
            5 => &mut binding.verifier_keys,
            6 => &mut binding.statement,
            7 => &mut binding.proof,
            _ => &mut binding.canonical_context,
        };
        // Attempt/context are opaque owner captures. Nonzero substitutions are
        // checked by the parent receipt comparison, not authenticated here.
        if field == 0 || field == 8 {
            digest.fill(0);
        } else {
            digest[0] ^= 1;
        }
        assert_eq!(factory.verify_child(&input), Err(Error::InputBinding));
    }
    let mut input = fixture.input();
    input.proof[12] ^= 1;
    input.binding.proof = fee_guard::proof_digest(&input.proof);
    assert_eq!(factory.verify_child(&input), Err(Error::Frame));
    let mut input = fixture.input();
    input.statement[0] ^= 1;
    input.binding.statement = fee_guard::statement_digest(&input.statement);
    assert_eq!(factory.verify_child(&input), Err(Error::Encoding));
}

#[test]
fn arbitrary_configuration_cannot_select_another_air_or_relation() {
    let original = factory();
    for field in 0..5 {
        let mut network = original.network;
        let mut binding = original.binding;
        let mut identity = original.expected;
        match field {
            0 => network.fill(0),
            1 => binding.genesis.fill(0),
            2 => binding.rules.fill(0),
            3 => binding.air[0] ^= 1,
            _ => identity.relation = Relation::Transaction,
        }
        assert!(TrustedFactory::from_local_configuration(network, binding, identity).is_err());
    }
}

#[path = "held_body.rs"]
mod held_body;
