//! Scalar geometry for an experimental D8/W24/digest12 backend.

use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear as F, default_koalabear_poseidon2_24};
use p3_symmetric::Permutation;

pub type E = BinomialExtensionField<F, 8>;

/// The external digest never changes to a whole number of extension lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest12(pub [F; 12]);

impl Digest12 {
    /// Decode an internal two-lane repacking, including its four zero pads.
    /// This must not be applied to the raw middle permutation-output lane.
    pub fn from_packed(packed: [E; 2]) -> Result<Self, &'static str> {
        let coefficients: Vec<_> = packed
            .iter()
            .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
            .collect();
        if coefficients[12..].iter().any(|v| *v != F::ZERO) {
            return Err("noncanonical internal digest padding");
        }
        Ok(Self(coefficients[..12].try_into().unwrap()))
    }
}

/// Pack the exact scalar geometry; only a final partial lane may be padded.
pub fn pack<const N: usize, const L: usize>(scalars: &[F; N]) -> Result<[E; L], &'static str> {
    if !matches!((N, L), (12, 2) | (24, 3)) {
        return Err("expected digest12/two lanes or state24/three lanes");
    }
    Ok(core::array::from_fn(|lane| {
        E::from_basis_coefficients_fn(|coefficient| {
            scalars
                .get(lane * 8 + coefficient)
                .copied()
                .unwrap_or(F::ZERO)
        })
    }))
}

/// Extract designated output scalars. Unused real permutation outputs are
/// unconstrained here and must never be confused with internal packing pads.
pub fn digest_from_permutation(state: [E; 3]) -> Digest12 {
    Digest12(core::array::from_fn(|i| {
        state[i / 8].as_basis_coefficients_slice()[i % 8]
    }))
}

/// Native binary compression using the standard Plonky3 W24 permutation.
/// Domain roles and recursive MMCS integration remain separate design work.
pub fn compress(left: Digest12, right: Digest12) -> Digest12 {
    let input = core::array::from_fn(|i| if i < 12 { left.0[i] } else { right.0[i - 12] });
    let output = default_koalabear_poseidon2_24().permute(input);
    Digest12(output[..12].try_into().unwrap())
}

/// Constrain lifted base scalars and their D8 repacking with ALU operations.
/// `x^p=x` restricts a scalar to the prime subfield; recomposition alone is
/// insufficient when private inputs may contain arbitrary extension values.
/// This correctness scaffold is not an optimized permutation/recursive AIR.
pub fn constrain_repacking<const N: usize, const L: usize>(
    b: &mut CircuitBuilder<E>,
    scalars: [ExprId; N],
    packed: [ExprId; L],
) -> Result<(), &'static str> {
    if !matches!((N, L), (12, 2) | (24, 3)) {
        return Err("unsupported scalar geometry");
    }
    let one = b.alloc_const(E::ONE, "one");
    for scalar in scalars {
        let mut power = one;
        // KoalaBear's prime order. The roots of X^p-X in D8 are exactly F.
        for bit in (0..31).rev() {
            power = b.mul(power, power);
            if (2130706433u32 >> bit) & 1 == 1 {
                power = b.mul(power, scalar);
            }
        }
        b.connect(power, scalar);
    }
    for (lane, target) in packed.into_iter().enumerate() {
        let mut total = b.alloc_const(E::ZERO, "zero");
        for coefficient in 0..8 {
            if let Some(scalar) = scalars.get(lane * 8 + coefficient) {
                let basis =
                    E::from_basis_coefficients_fn(
                        |i| if i == coefficient { F::ONE } else { F::ZERO },
                    );
                let basis = b.alloc_const(basis, "extension basis");
                let term = b.mul(*scalar, basis);
                total = b.add(total, term);
            }
        }
        b.connect(total, target);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use p3_circuit::CircuitRunner;

    fn values<const N: usize>() -> [F; N] {
        core::array::from_fn(|i| F::from_u32(i as u32 + 1))
    }
    fn circuit<const N: usize, const L: usize>() -> p3_circuit::Circuit<E> {
        let mut b = CircuitBuilder::<E>::new();
        let scalars = core::array::from_fn(|_| b.alloc_private_input("base scalar"));
        let packed = core::array::from_fn(|_| b.public_input());
        constrain_repacking::<N, L>(&mut b, scalars, packed).unwrap();
        b.build().unwrap()
    }
    fn run<const N: usize, const L: usize>(
        c: &p3_circuit::Circuit<E>,
        scalars: &[E; N],
        packed: &[E; L],
    ) -> bool {
        let mut r = CircuitRunner::new(c);
        r.set_private_inputs(scalars).unwrap();
        r.set_public_inputs(packed).unwrap();
        r.run().is_ok()
    }
    fn check<const N: usize, const L: usize>() {
        let raw = values::<N>();
        let packed = pack::<N, L>(&raw).unwrap();
        let scalars = raw.map(E::from);
        let c = circuit::<N, L>();
        assert!(run(&c, &scalars, &packed));
        for i in 0..N {
            let mut wrong = scalars;
            wrong[i] += E::ONE;
            assert!(!run(&c, &wrong, &packed), "scalar {i}");
            // A matching repack cannot authorize a non-base scalar witness.
            for j in 1..8 {
                let delta =
                    E::from_basis_coefficients_fn(|k| if k == j { F::ONE } else { F::ZERO });
                wrong = scalars;
                wrong[i] += delta;
                let mut matching = packed;
                matching[i / 8] += delta
                    * E::from_basis_coefficients_fn(|k| if k == i % 8 { F::ONE } else { F::ZERO });
                assert!(!run(&c, &wrong, &matching), "scalar {i} coefficient {j}");
            }
        }
        for lane in 0..L {
            for limb in 0..8 {
                let mut wrong = packed;
                wrong[lane] +=
                    E::from_basis_coefficients_fn(|k| if k == limb { F::ONE } else { F::ZERO });
                assert!(!run(&c, &scalars, &wrong), "lane {lane} coefficient {limb}");
            }
        }
    }
    #[test]
    fn digest_keeps_twelve_scalars_and_constrains_only_internal_padding() {
        check::<12, 2>();
        let raw = values::<24>();
        let native = default_koalabear_poseidon2_24().permute(raw);
        assert!(native[12..].iter().any(|x| *x != F::ZERO));
        let state = pack::<24, 3>(&native).unwrap();
        let digest = digest_from_permutation(state);
        assert_eq!(digest.0, native[..12]);
        assert_eq!(
            compress(
                Digest12(values()),
                Digest12(core::array::from_fn(|i| F::from_u32(i as u32 + 13)))
            ),
            digest
        );
        let mut bad = pack::<12, 2>(&digest.0).unwrap();
        assert_eq!(Digest12::from_packed(bad).unwrap(), digest);
        bad[1] += E::from_basis_coefficients_fn(|i| if i == 4 { F::ONE } else { F::ZERO });
        assert!(Digest12::from_packed(bad).is_err());
    }
    #[test]
    fn state_binds_all_twenty_four_inputs_and_eight_coefficients() {
        check::<24, 3>();
    }
    #[test]
    fn malformed_geometry_is_rejected() {
        assert!(pack::<12, 1>(&values()).is_err());
        assert!(pack::<12, 3>(&values()).is_err());
        let mut b = CircuitBuilder::<E>::new();
        let scalars = core::array::from_fn(|_| b.alloc_private_input("scalar"));
        let packed = [b.public_input()];
        assert!(constrain_repacking::<12, 1>(&mut b, scalars, packed).is_err());
    }
}
