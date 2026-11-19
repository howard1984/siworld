//! Inactive full encrypted-delivery wrapper for the fee-local V1 sum relation.
use super::fee_local_sum::FeeLocalSumWitness;
use super::{
    fee_local_sum as e,
    payment_closed::{self, PaymentClosedAir},
};
use ::native::{
    encryption::{EncryptionContext, PaymentAddress},
    multi_asset::F,
    settlement::MAX_REWARD_NOTES,
};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const PAYMENT_HEIGHT: usize = 512;
const SETTLEMENT_OFFSET: usize = payment_closed::WIDTH;
fn bridge_offset() -> usize {
    SETTLEMENT_OFFSET + e::MAIN_WIDTH
}
fn main_width() -> usize {
    bridge_offset() + 33
}
pub fn address_public_offset(capacity: usize) -> usize {
    17 + e::public_len(capacity)
}
pub struct FeeLocalCompleteAir {
    pub payment: PaymentClosedAir,
    pub settlement: e::FeeLocalSumAir,
}
impl Clone for FeeLocalCompleteAir {
    fn clone(&self) -> Self {
        Self {
            payment: self.payment.clone(),
            settlement: e::FeeLocalSumAir::new(self.settlement.capacity)
                .with_min_height(self.settlement.height),
        }
    }
}
pub fn canonical_address(address: &PaymentAddress) -> [u8; 1232] {
    let mut bytes = [0; 1232];
    for (i, field) in address.owner().iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
    bytes[48..].copy_from_slice(address.encapsulation_key());
    bytes
}
impl BaseAir<F> for FeeLocalCompleteAir {
    fn width(&self) -> usize {
        main_width()
    }
    fn num_public_values(&self) -> usize {
        address_public_offset(self.settlement.capacity) + 616
    }
    fn preprocessed_width(&self) -> usize {
        payment_closed::PRE_WIDTH + self.settlement.preprocessed_width() + 8
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let payment = self.payment.preprocessed_trace().unwrap();
        let settlement = self.settlement.preprocessed_trace().unwrap();
        let width = self.preprocessed_width();
        let sw = self.settlement.preprocessed_width();
        let lp = payment_closed::PRE_WIDTH + sw;
        let height = self.settlement.height;
        let mut values = F::zero_vec(height * width);
        for row in 0..height {
            let off = row * width;
            if row < PAYMENT_HEIGHT {
                values[off..off + payment_closed::PRE_WIDTH].copy_from_slice(
                    &payment.values
                        [row * payment_closed::PRE_WIDTH..(row + 1) * payment_closed::PRE_WIDTH],
                );
            }
            values[off + payment_closed::PRE_WIDTH..off + lp]
                .copy_from_slice(&settlement.values[row * sw..(row + 1) * sw]);
            values[off + lp] =
                F::from_bool(row == self.settlement.capacity + MAX_REWARD_NOTES * 6 + 1);
            values[off + lp + 1] = F::from_bool(row == 32 || row == 33);
            values[off + lp + 2] = F::from_usize(if row == 33 { 2 } else { 0 });
            values[off + lp + 3] = F::from_bool((36..60).contains(&row));
            values[off + lp + 4] = F::from_usize(row.saturating_sub(36));
            values[off + lp + 5] = F::from_bool(row == 34 || row == 35 || (60..84).contains(&row));
            values[off + lp + 6] = F::from_bool(row < PAYMENT_HEIGHT);
            values[off + lp + 7] = F::from_bool(row == PAYMENT_HEIGHT - 1);
        }
        Some(RowMajorMatrix::new(values, width))
    }
}
fn limb<AB: AirBuilder<F = F>>(bits: &[AB::Var], width: usize) -> AB::Expr {
    (0..width)
        .map(|i| AB::Expr::from(bits[i]) * F::from_u32(1 << i))
        .sum()
}
impl<AB> Air<AB> for FeeLocalCompleteAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        let window_pre = b.preprocessed().clone();
        let fixed_offset = payment_closed::PRE_WIDTH + self.settlement.preprocessed_width();
        let active: AB::Expr = window_pre.current_slice()[fixed_offset + 6].into();
        let last: AB::Expr = window_pre.current_slice()[fixed_offset + 7].into();
        self.payment.eval(&mut super::fixed_window::FixedWindow {
            inner: b,
            active: active.clone(),
            last,
        });
        self.settlement
            .eval_at(b, SETTLEMENT_OFFSET, payment_closed::PRE_WIDTH, 17);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = main.current_slice();
        let p = pre.current_slice();
        let public = b.public_values().to_vec();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let lp = payment_closed::PRE_WIDTH + self.settlement.preprocessed_width();
        let fixed = &p[lp..];
        let capacity = self.settlement.capacity;
        for value in &l[..payment_closed::WIDTH] {
            b.assert_zero((AB::Expr::ONE - active.clone()) * x(*value));
        }
        let address = canonical_address(&self.payment.address);
        for i in 0..616 {
            b.assert_eq(
                public[address_public_offset(capacity) + i],
                F::from_u16(u16::from_le_bytes([address[i * 2], address[i * 2 + 1]])),
            );
        }
        for i in 0..12 {
            b.assert_eq(
                public[17 + e::fee_owner_offset(capacity) + i],
                self.payment.address.owner()[i],
            );
            b.assert_eq(
                public[17 + e::fee_commitment_offset(capacity) + i],
                self.payment.commitment[i],
            );
        }
        for i in 0..16 {
            b.assert_eq(
                public[17 + e::reward_mode_offset(capacity) + 2 + i],
                F::from_u16(u16::from_le_bytes([
                    self.payment.context.network[i * 2],
                    self.payment.context.network[i * 2 + 1],
                ])),
            );
        }
        let plain = &l[payment_closed::PLAIN_OFFSET..];
        for i in 0..4 {
            b.push_interaction(
                "settlement-fee-limb",
                [
                    AB::Expr::from_usize(i),
                    x(l[SETTLEMENT_OFFSET + e::NOTE_AMOUNT + i]),
                ],
                Count::bounded(-x(fixed[0]), 1),
            );
        }
        for side in 0..2 {
            b.push_interaction(
                "settlement-fee-limb",
                [
                    x(fixed[2]) + F::from_usize(side),
                    limb::<AB>(&plain[side * 16..], 16),
                ],
                Count::bounded(x(fixed[1]), 1),
            );
        }
        for i in 0..24 {
            b.push_interaction(
                "settlement-note-field",
                [
                    AB::Expr::from_usize(i),
                    x(l[SETTLEMENT_OFFSET
                        + if i < 12 {
                            e::RHO + i
                        } else {
                            e::RSEED + i - 12
                        }]),
                ],
                Count::bounded(-x(fixed[0]), 1),
            );
        }
        let comp = &l[bridge_offset()..];
        for &bit in &comp[..32] {
            b.assert_bool(bit);
        }
        b.assert_bool(comp[32]);
        // Canonical F encoding is checked with exact 16-bit equations before
        // using the field-valued bus. Otherwise a plaintext word plus p could
        // alias the same field element and remain undecryptable by recipients.
        b.assert_zero(
            (limb::<AB>(plain, 16) + limb::<AB>(comp, 16) - x(comp[32]) * F::from_u32(65536))
                * x(fixed[3]),
        );
        b.assert_zero(
            (limb::<AB>(&plain[16..], 16) + limb::<AB>(&comp[16..], 16) + x(comp[32])
                - F::from_u32(32512))
                * x(fixed[3]),
        );
        b.push_interaction(
            "settlement-note-field",
            [
                x(fixed[4]),
                limb::<AB>(plain, 16) + limb::<AB>(&plain[16..], 16) * F::from_u32(65536),
            ],
            Count::bounded(x(fixed[3]), 1),
        );
        for &bit in &plain[..32] {
            b.assert_zero(x(bit) * x(fixed[5]));
        }
    }
}
fn fill_bridge(values: &mut [F], width: usize, payment: &RowMajorMatrix<F>) {
    for row in 36..60 {
        let word = (0..32).fold(0u32, |value, i| {
            value
                | (payment.values[row * payment.width + payment_closed::PLAIN_OFFSET + i]
                    .as_canonical_u32()
                    << i)
        });
        let complement = 2130706432u32.saturating_sub(word);
        let off = row * width + bridge_offset();
        for bit in 0..32 {
            values[off + bit] = F::from_bool(complement >> bit & 1 != 0);
        }
        values[off + 32] = F::from_bool(((word & 65535) + (complement & 65535)) >> 16 != 0);
    }
}
pub fn generate(
    w: &FeeLocalSumWitness,
    address: &PaymentAddress,
    coins: [u8; 32],
) -> Result<(FeeLocalCompleteAir, RowMajorMatrix<F>, Vec<F>), String> {
    w.validate()?;
    if address.owner() != w.policy.fee_owner
        || w.fee_destination_digest != super::fee_destination_digest(address)
    {
        return Err("authenticated full fee destination differs".into());
    }
    let context = EncryptionContext::new(w.network);
    let (payment, ptrace) =
        payment_closed::generate(address, coins, &w.settlement.fee_note, &context);
    let settlement =
        e::FeeLocalSumAir::new(w.settlement.slots.len()).with_min_height(PAYMENT_HEIGHT);
    let height = settlement.height;
    let strace = e::generate_trace(&settlement, w)?;
    assert_eq!(strace.values.len() / strace.width, height);
    let mut public = super::prefix::public_hash(payment.kem.0.public_key_hash());
    public.push(F::from_u8(payment.view_tag));
    public.extend(w.public_inputs()?);
    public.extend(
        canonical_address(address)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| F::from_u16(u16::from_le_bytes(*bytes))),
    );
    let width = main_width();
    let mut values = F::zero_vec(height * width);
    for row in 0..height {
        if row < PAYMENT_HEIGHT {
            values[row * width..row * width + SETTLEMENT_OFFSET].copy_from_slice(
                &ptrace.values[row * payment_closed::WIDTH..(row + 1) * payment_closed::WIDTH],
            );
        }
        values[row * width + SETTLEMENT_OFFSET..row * width + bridge_offset()]
            .copy_from_slice(&strace.values[row * e::MAIN_WIDTH..(row + 1) * e::MAIN_WIDTH]);
    }
    fill_bridge(&mut values, width, &ptrace);
    Ok((
        FeeLocalCompleteAir {
            payment,
            settlement,
        },
        RowMajorMatrix::new(values, width),
        public,
    ))
}
