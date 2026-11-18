//! Same-AIR KEM to payment KDF/ChaCha linkage. Poly1305 is not included.
use super::{
    arx_closed::{self, ArxClosedAir},
    kem_closed::{self, KemClosedAir},
    kem_reference, prefix,
};
use ::native::multi_asset::F;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const HEIGHT: usize = 512;
pub(crate) const WIDTH: usize = kem_closed::WIDTH + arx_closed::WIDTH;
pub(crate) const PRE_WIDTH: usize = kem_closed::PRE_WIDTH + arx_closed::PRE_WIDTH;
#[derive(Clone)]
pub struct KemArxClosedAir(pub KemClosedAir);
impl BaseAir<F> for KemArxClosedAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        17
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let kem = self.0.preprocessed_trace().unwrap();
        let arx = ArxClosedAir.preprocessed_trace().unwrap();
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for row in 0..HEIGHT {
            values[row * PRE_WIDTH..row * PRE_WIDTH + kem_closed::PRE_WIDTH].copy_from_slice(
                &kem.values[row * kem_closed::PRE_WIDTH..(row + 1) * kem_closed::PRE_WIDTH],
            );
            values[row * PRE_WIDTH + kem_closed::PRE_WIDTH..(row + 1) * PRE_WIDTH].copy_from_slice(
                &arx.values[row * arx_closed::PRE_WIDTH..(row + 1) * arx_closed::PRE_WIDTH],
            );
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}
impl<AB> Air<AB> for KemArxClosedAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
        arx_closed::eval_at(builder, kem_closed::WIDTH, kem_closed::PRE_WIDTH, 16);
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let local = main.current_slice();
        let p = pre.current_slice();
        let k: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        for i in 0..16 {
            builder.assert_zero(
                (AB::Expr::from(local[kem_closed::WIDTH + arx_closed::SECRET_OFFSET + i])
                    - AB::Expr::from(prefix::output(k, i)))
                    * AB::Expr::from(p[8]),
            );
        }
    }
}
pub fn generate(
    public_key: &[u8; 1184],
    coins: [u8; 32],
) -> (KemArxClosedAir, RowMajorMatrix<F>, u8) {
    let (air, kem) = kem_closed::generate(public_key, coins);
    let (_, secret) = kem_reference::encapsulate_reference(public_key, coins);
    let (arx, tag) = arx_closed::generate(secret);
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for row in 0..HEIGHT {
        values[row * WIDTH..row * WIDTH + kem_closed::WIDTH]
            .copy_from_slice(&kem.values[row * kem_closed::WIDTH..(row + 1) * kem_closed::WIDTH]);
        values[row * WIDTH + kem_closed::WIDTH..(row + 1) * WIDTH]
            .copy_from_slice(&arx.values[row * arx_closed::WIDTH..(row + 1) * arx_closed::WIDTH]);
    }
    (
        KemArxClosedAir(air),
        RowMajorMatrix::new(values, WIDTH),
        tag,
    )
}
