//! Trace construction for the unchanged retained issuance AIR.
//! This adapter checks witnesses and creates no state-admission capability.
use ::native::air::{LinearLayers, P2, p2_constants};
use ::native::common::{DIGEST, F, LIMB_BITS, LIMBS, WIDTH};
use ::native::issuance::{IssuanceError, IssuanceWitness};
use ::native::issuance_air::IssuanceAir;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
const OWNER: usize = P2;
const VALUE: usize = OWNER + DIGEST;
const UNLOCK: usize = VALUE + LIMBS;
const ASSET: usize = UNLOCK + LIMBS;
const RHO: usize = ASSET + 16;
const RSEED: usize = RHO + DIGEST;
const BEFORE: usize = RSEED + DIGEST;
const AFTER: usize = BEFORE + LIMBS;
const CARRY: usize = AFTER + LIMBS;
const BITS: usize = CARRY + LIMBS - 1;
const RANGE_LANES: usize = 7;
const CONTEXT: usize = BITS + RANGE_LANES * LIMB_BITS;
const MAIN_WIDTH: usize = CONTEXT + 16;
fn range_column(index: usize) -> Option<usize> {
    match index {
        0..24 => Some(VALUE + index),
        24..28 => Some(BEFORE + index - 24),
        28..32 => Some(AFTER + index - 28),
        _ => None,
    }
}

fn byte_limbs(bytes: &[u8; 32]) -> [F; 16] {
    core::array::from_fn(|i| {
        F::from_u32(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32)
    })
}
pub(super) fn generate(
    air: &IssuanceAir,
    witness: &IssuanceWitness,
) -> Result<(RowMajorMatrix<F>, Vec<F>), IssuanceError> {
    witness.check()?;
    if witness.notes.len() != air.note_count {
        return Err(IssuanceError::NoteCountMismatch);
    }
    Ok(generate_trace(air, witness))
}
fn generate_trace(air: &IssuanceAir, witness: &IssuanceWitness) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut data = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for (i, note) in witness.notes.iter().enumerate() {
        let blocks = note.blocks();
        let (trace, _) = ::native::common::Hasher::new().sponge_trace(130, &blocks);
        inputs[i * 5..i * 5 + 5].copy_from_slice(&trace);
        let before = ::native::common::limbs(sum);
        sum = sum.checked_add(note.value).expect("checked witness sum");
        let after = ::native::common::limbs(sum);
        let value = ::native::common::limbs(note.value);
        let mut registers = vec![F::ZERO; MAIN_WIDTH - P2];
        for (col, values) in [
            (OWNER, note.owner.as_slice()),
            (VALUE, value.as_slice()),
            (
                UNLOCK,
                ::native::common::limbs(note.unlock_height).as_slice(),
            ),
            (ASSET, byte_limbs(&note.asset_id.0).as_slice()),
            (RHO, note.rho.as_slice()),
            (RSEED, note.rseed.as_slice()),
            (BEFORE, before.as_slice()),
            (AFTER, after.as_slice()),
        ] {
            registers[col - P2..col - P2 + values.len()].copy_from_slice(values);
        }
        let mut carry = 0u64;
        for k in 0..LIMBS - 1 {
            carry =
                (before[k].as_canonical_u32() as u64 + value[k].as_canonical_u32() as u64 + carry)
                    >> 16;
            registers[CARRY - P2 + k] = F::from_u64(carry);
        }
        for stage in 0..5 {
            let offset = (i * 5 + stage) * MAIN_WIDTH;
            data[offset + P2..offset + MAIN_WIDTH].copy_from_slice(&registers);
            for lane in 0..RANGE_LANES {
                if let Some(col) = range_column(stage * RANGE_LANES + lane) {
                    let value = data[offset + col].as_canonical_u32();
                    for bit in 0..LIMB_BITS {
                        data[offset + BITS + lane * LIMB_BITS + bit] =
                            F::from_u32((value >> bit) & 1);
                    }
                }
            }
        }
    }
    let binding = byte_limbs(&witness.declaration.binding());
    for row in 0..air.height {
        data[row * MAIN_WIDTH + CONTEXT..row * MAIN_WIDTH + CONTEXT + 16].copy_from_slice(&binding);
    }
    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for row in 0..air.height {
        data[row * MAIN_WIDTH..row * MAIN_WIDTH + P2]
            .copy_from_slice(&p2.values[row * P2..(row + 1) * P2]);
    }
    (
        RowMajorMatrix::new(data, MAIN_WIDTH),
        witness.declaration.public_inputs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn moved_trace_satisfies_retained_issuance_air_and_binds_supply() {
        for count in [1, 3] {
            let (_, witness, _) = ::native::issuance::sample_issuance(count);
            let air = IssuanceAir::new(count).with_min_height(128);
            let (trace, mut public) = generate(&air, &witness).unwrap();
            assert!(
                p3_air::check_all_constraints(&air, &trace, &public, Some(1))
                    .failures
                    .is_empty()
            );
            public[::native::issuance_air::PUBLIC_SUPPLY] += F::ONE;
            assert!(
                !p3_air::check_all_constraints(&air, &trace, &public, Some(1))
                    .failures
                    .is_empty()
            );
        }
    }
}
