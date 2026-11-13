use super::*;
use ::native::settlement::{RewardAllocation, RewardMode, RewardPlan};
use p3_air::BaseAir;

fn reconstruct(case: u8, binding: ProtocolBinding) -> Result<Statement, Error> {
    let pair = libcrux_ml_kem::mlkem768::portable::generate_key_pair([case; 64]);
    let owner = [F::from_u8(7); 12];
    let address = PaymentAddress::new(owner, *pair.public_key().as_slice()).unwrap();
    let policy = SettlementPolicy {
        plan: RewardPlan {
            block_height: 17,
            mode: RewardMode::Voyager,
            allocations: vec![RewardAllocation {
                amount: 41,
                unlock_height: 17,
            }],
        },
        fee_owner: owner,
        fees: FeeSchedule::from_previous_standard(100).unwrap(),
        max_slots: CAPACITY,
    };
    let fees: Vec<_> = (0..CAPACITY).map(|i| [F::from_usize(i + 1); 12]).collect();
    let ciphertext = PaymentCiphertext {
        kem_ciphertext: [case; 1088],
        body: [case.wrapping_add(1); 208],
        tag: [case.wrapping_add(2); 16],
        view_tag: case,
    };
    Statement::from_authenticated(
        StatementInputs {
            policy: &policy,
            network: [31; 32],
            transaction_list_digest: [47; 32],
            address: &address,
            fee_commitments: &fees,
            reward_commitments: &[[F::from_u32(700); 12]],
            fee_commitment: [F::from_u32(701); 12],
            ciphertext: &ciphertext,
        },
        binding,
    )
}
fn binding() -> ProtocolBinding {
    ProtocolBinding {
        genesis: [31; 32],
        rules: [37; 32],
        air: source_identity(),
    }
}

#[test]
fn reconstructed_public_columns_equal_the_original_preprocessing_for_distinct_statements() {
    let mut fixed = None;
    for case in [3, 11] {
        let statement = reconstruct(case, binding()).unwrap();
        assert_eq!(statement.public.len(), 15322);
        let old = statement
            .air
            .original_for_test()
            .preprocessed_trace()
            .unwrap();
        for column in fixed_public::specs() {
            for row in 0..BASE_ROWS {
                let expected = if (column.first..column.first + column.rows).contains(&row) {
                    statement.public
                        [fixed_public::BASE_PUBLIC + column.public_offset + row - column.first]
                } else {
                    F::ZERO
                };
                assert_eq!(
                    old.values[row * fixed_public::PRE_WIDTH + column.pre],
                    expected,
                    "dynamic preprocessing differs at column {} row {}",
                    column.pre,
                    row
                );
            }
        }
        let current = statement.air.preprocessed_trace().unwrap();
        if let Some(previous) = &fixed {
            assert_eq!(&current.values, previous);
        } else {
            fixed = Some(current.values);
        }
    }
}

#[test]
fn public_reconstruction_rejects_wrong_complete_source_identity() {
    let mut wrong = binding();
    wrong.air[0] ^= 1;
    assert!(matches!(reconstruct(3, wrong), Err(Error::Statement)));
    let mut wrong = binding();
    wrong.rules = [0; 32];
    assert!(matches!(reconstruct(3, wrong), Err(Error::Statement)));
}
