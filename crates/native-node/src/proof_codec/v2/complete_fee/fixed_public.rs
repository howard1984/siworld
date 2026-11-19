//! Inactive source seam: statement-dependent preprocessing becomes bound main
//! columns, while all original encrypted-delivery constraints and buses remain.
use super::{fee_local_complete, kem_reference, payment_closed};
use ::native::multi_asset::F;
use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
pub const BASE_MAIN: usize = 7604;
pub const BASE_PUBLIC: usize = 7732;
pub const PRE_WIDTH: usize = 881;
pub const EXTRA_MAIN: usize = 64;
pub const NEW_RELATION_DOMAIN: &[u8] =
    b"siworld-fee-local-v1-salt9-fixed-preprocessing-relation-v1";
const SLOT_SELECTOR: usize = 297;
#[derive(Clone, Copy, Debug)]
pub struct DynamicColumn {
    pub pre: usize,
    pub first: usize,
    pub rows: usize,
    pub public_offset: usize,
}
pub fn specs() -> Vec<DynamicColumn> {
    let mut result = Vec::with_capacity(EXTRA_MAIN);
    let mut offset = 0;
    for (columns, first, rows) in [
        (64..73, 0, 512),
        (121..122, 0, 512),
        (142..143, 0, 512),
        (196..209, 0, 22),
        (209..217, 21, 1),
        (226..258, 32, 52),
    ] {
        for pre in columns {
            result.push(DynamicColumn {
                pre,
                first,
                rows,
                public_offset: offset,
            });
            offset += rows;
        }
    }
    assert_eq!(result.len(), EXTRA_MAIN);
    assert_eq!(offset, 7590);
    result
}
pub fn dynamic_public_len() -> usize {
    7590
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementError {
    Geometry,
    CanonicalAddress,
    CanonicalPublicPrefix,
    Binding,
}
/// This digest must come from the caller's authenticated full-block adapter.
/// Hash equality does not authenticate the source of a peer-supplied statement.
#[derive(Clone, Copy)]
pub struct TrustedStatementBinding(pub [u8; 32]);
pub fn canonical_statement_binding(
    air: &fee_local_complete::FeeLocalCompleteAir,
    base: &[F],
) -> Result<[u8; 32], StatementError> {
    if air.settlement.capacity != 576 || air.settlement.height != 1024 || base.len() != BASE_PUBLIC
    {
        return Err(StatementError::Geometry);
    }
    let payment = &air.payment;
    if payment.context.version != 2 || payment.context.network == [0; 32] {
        return Err(StatementError::Binding);
    }
    if payment.address.encapsulation_key() != &payment.kem.0.public_key {
        return Err(StatementError::CanonicalAddress);
    }
    let prefix = super::prefix::public_hash(payment.kem.0.public_key_hash());
    if base[..16] != prefix || base[16] != F::from_u8(payment.view_tag) {
        return Err(StatementError::CanonicalPublicPrefix);
    }
    let address = fee_local_complete::canonical_address(&payment.address);
    let canonical: Vec<F> = address
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| F::from_u16(u16::from_le_bytes([b[0], b[1]])))
        .collect();
    if base[BASE_PUBLIC - 616..] != canonical {
        return Err(StatementError::CanonicalAddress);
    }
    let mut h = blake3::Hasher::new_derive_key(
        "siworld fee-local fixed-preprocessing authenticated statement v1",
    );
    h.update(NEW_RELATION_DOMAIN);
    h.update(&payment.context.version.to_le_bytes());
    h.update(&payment.context.network);
    h.update(&address);
    h.update(&payment.kem.0.ciphertext);
    h.update(&payment.poly.body);
    h.update(&payment.poly.tag);
    h.update(&[payment.view_tag]);
    for f in &payment.commitment {
        h.update(&f.as_canonical_u32().to_le_bytes());
    }
    for f in base {
        h.update(&f.as_canonical_u32().to_le_bytes());
    }
    Ok(*h.finalize().as_bytes())
}
/// The returned table is derived locally from the canonical authenticated
/// statement. No peer table, key or preprocessing root is accepted here.
pub fn public_inputs(
    air: &fee_local_complete::FeeLocalCompleteAir,
    base: &[F],
    trusted: TrustedStatementBinding,
) -> Result<Vec<F>, StatementError> {
    if canonical_statement_binding(air, base)? != trusted.0 {
        return Err(StatementError::Binding);
    }
    let p = &air.payment;
    let (matrix, public_t) = kem_reference::public_polynomials(&p.kem.0.public_key);
    let aad = payment_closed::aad(&p.context, &p.commitment);
    let mut message = [0u8; 352];
    message[..117].copy_from_slice(&aad);
    message[128..336].copy_from_slice(&p.poly.body);
    message[336..344].copy_from_slice(&117u64.to_le_bytes());
    message[344..352].copy_from_slice(&208u64.to_le_bytes());
    let mut result = base.to_vec();
    result.reserve(dynamic_public_len());
    for spec in specs() {
        for row in spec.first..spec.first + spec.rows {
            let value = match spec.pre {
                64..=72 => {
                    let j = (spec.pre - 64) / 3;
                    let part = (spec.pre - 64) % 3;
                    let poly = row / 128;
                    let pair = row % 128;
                    let public = if poly < 3 {
                        &matrix[poly][j]
                    } else {
                        &public_t[j]
                    };
                    if part < 2 {
                        public[pair * 2 + part] as u32
                    } else {
                        let exponent = 2 * ((pair as u8).reverse_bits() as usize >> 1) + 1;
                        let gamma = (0..exponent).fold(1u32, |x, _| x * 17 % 3329);
                        gamma * public[pair * 2 + 1] as u32 % 3329
                    }
                }
                121 | 142 => {
                    let lane = usize::from(spec.pre == 142);
                    let index = row * 2 + lane;
                    let poly = index / 256;
                    let coefficient = index % 256;
                    let (offset, bits) = if poly < 3 { (poly * 320, 10) } else { (960, 4) };
                    (0..bits).fold(0u32, |v, bit| {
                        v | (((p.kem.0.ciphertext[offset + (coefficient * bits + bit) / 8]
                            >> ((coefficient * bits + bit) % 8))
                            & 1) as u32)
                            << bit
                    })
                }
                196..=208 => {
                    let digit = spec.pre - 196;
                    (0..10).fold(0u32, |v, bit| {
                        let position = digit * 10 + bit;
                        let value = if position < 128 {
                            (message[row * 16 + position / 8] >> (position % 8)) & 1
                        } else {
                            u8::from(position == 128)
                        };
                        v | ((value as u32) << bit)
                    })
                }
                209..=216 => {
                    let i = spec.pre - 209;
                    u16::from_le_bytes([p.poly.tag[i * 2], p.poly.tag[i * 2 + 1]]) as u32
                }
                226..=257 => {
                    let bit = spec.pre - 226;
                    ((p.poly.body[(row - 32) * 4 + bit / 8] >> (bit % 8)) & 1) as u32
                }
                _ => unreachable!(),
            };
            result.push(F::from_u32(value));
        }
    }
    assert_eq!(result.len(), BASE_PUBLIC + dynamic_public_len());
    Ok(result)
}
#[derive(Clone)]
pub struct Rows<T> {
    pub current: Vec<T>,
    pub next: Vec<T>,
}
impl<T> WindowAccess<T> for Rows<T> {
    fn current_slice(&self) -> &[T] {
        &self.current
    }
    fn next_slice(&self) -> &[T] {
        &self.next
    }
}
pub fn eval_binding_column<AB: AirBuilder<F = F>>(b: &mut AB, column: usize) {
    let spec = specs()[column];
    let pre = b.preprocessed().clone();
    let main = b.main();
    let public = b.public_values();
    let mut expected = AB::Expr::ZERO;
    for i in 0..spec.rows {
        expected += AB::Expr::from(pre.current_slice()[SLOT_SELECTOR + spec.first + i])
            * public[BASE_PUBLIC + spec.public_offset + i].into();
    }
    b.assert_eq(main.current_slice()[BASE_MAIN + column], expected);
}
/// Replaces only the original dynamic preprocessing variables. Every assertion,
/// extension assertion and bus interaction is forwarded to the original builder.
pub struct Mapped<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    pre: Rows<AB::Var>,
}
impl<'a, AB: AirBuilder> Mapped<'a, AB> {
    pub fn new(inner: &'a mut AB) -> Self {
        let p = inner.preprocessed();
        let m = inner.main();
        let mut pre = Rows {
            current: p.current_slice().to_vec(),
            next: p.next_slice().to_vec(),
        };
        for (i, spec) in specs().iter().enumerate() {
            pre.current[spec.pre] = m.current_slice()[BASE_MAIN + i];
            pre.next[spec.pre] = m.next_slice()[BASE_MAIN + i];
        }
        Self { inner, pre }
    }
}
impl<AB: AirBuilder> AirBuilder for Mapped<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = Rows<AB::Var>;
    type MainWindow = AB::MainWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.pre
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x)
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.inner.public_values()[..BASE_PUBLIC]
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}
impl<AB: ExtensionBuilder> ExtensionBuilder for Mapped<'_, AB> {
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;
    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, x: I) {
        self.inner.assert_zero_ext(x)
    }
}
impl<AB: PermutationAirBuilder> PermutationAirBuilder for Mapped<'_, AB> {
    type MP = AB::MP;
    type RandomVar = AB::RandomVar;
    type PermutationVar = AB::PermutationVar;
    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }
    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }
    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.inner.permutation_values()
    }
}
impl<AB: InteractionBuilder> InteractionBuilder for Mapped<'_, AB> {
    fn push_interaction<E: Into<Self::Expr>>(
        &mut self,
        name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Self::Expr>>,
    ) {
        self.inner.push_interaction(name, fields, count)
    }
    fn push_local_interaction(
        &mut self,
        tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Count<Self::Expr>)>,
    ) {
        self.inner.push_local_interaction(tuples)
    }
    fn push_exclusive_interaction(
        &mut self,
        name: &str,
        branches: impl IntoIterator<Item = (Self::Expr, Count<Self::Expr>, Vec<Self::Expr>)>,
    ) {
        self.inner.push_exclusive_interaction(name, branches)
    }
    fn num_global_interactions(&self) -> usize {
        self.inner.num_global_interactions()
    }
    fn num_local_interactions(&self) -> usize {
        self.inner.num_local_interactions()
    }
    fn num_exclusive_interactions(&self) -> usize {
        self.inner.num_exclusive_interactions()
    }
}
#[derive(Clone)]
pub struct FixedPublicAir {
    inner: fee_local_complete::FeeLocalCompleteAir,
}
impl FixedPublicAir {
    #[cfg(test)]
    pub(super) fn original_for_test(&self) -> &fee_local_complete::FeeLocalCompleteAir {
        &self.inner
    }
    pub fn new(inner: fee_local_complete::FeeLocalCompleteAir) -> Result<Self, StatementError> {
        if inner.width() != BASE_MAIN
            || inner.preprocessed_width() != PRE_WIDTH
            || inner.num_public_values() != BASE_PUBLIC
            || inner.settlement.capacity != 576
            || inner.settlement.height != 1024
        {
            return Err(StatementError::Geometry);
        }
        Ok(Self { inner })
    }
}
impl BaseAir<F> for FixedPublicAir {
    fn width(&self) -> usize {
        BASE_MAIN + EXTRA_MAIN
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn num_public_values(&self) -> usize {
        BASE_PUBLIC + dynamic_public_len()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut fixed = self.inner.preprocessed_trace()?;
        for row in fixed.values.as_chunks_mut::<PRE_WIDTH>().0 {
            for spec in specs() {
                row[spec.pre] = F::ZERO;
            }
        }
        Some(fixed)
    }
}
impl<AB> Air<AB> for FixedPublicAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        for column in 0..EXTRA_MAIN {
            eval_binding_column(b, column);
        }
        self.inner.eval(&mut Mapped::new(b));
    }
}

/// Validate legacy geometry before allocating the expanded witness. Dynamic
/// values are copied only from the locally reconstructed public statement;
/// all rows outside each column's declared support remain exactly zero.
pub fn extend_trace(
    base: RowMajorMatrix<F>,
    public: &[F],
) -> Result<RowMajorMatrix<F>, StatementError> {
    const HEIGHT: usize = 1024;
    if base.width != BASE_MAIN
        || base.values.len() != HEIGHT * BASE_MAIN
        || public.len() != BASE_PUBLIC + dynamic_public_len()
    {
        return Err(StatementError::Geometry);
    }
    let columns = specs();
    if columns.iter().any(|spec| {
        spec.first
            .checked_add(spec.rows)
            .is_none_or(|end| end > HEIGHT)
            || spec
                .public_offset
                .checked_add(spec.rows)
                .is_none_or(|end| end > dynamic_public_len())
    }) {
        return Err(StatementError::Geometry);
    }
    let width = BASE_MAIN + EXTRA_MAIN;
    let mut values = F::zero_vec(HEIGHT * width);
    for (source, target) in base
        .values
        .as_chunks::<BASE_MAIN>()
        .0
        .iter()
        .zip(values.chunks_exact_mut(width))
    {
        target[..BASE_MAIN].copy_from_slice(source);
    }
    for (column, spec) in columns.iter().enumerate() {
        for i in 0..spec.rows {
            values[(spec.first + i) * width + BASE_MAIN + column] =
                public[BASE_PUBLIC + spec.public_offset + i];
        }
    }
    Ok(RowMajorMatrix::new(values, width))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extension_rejects_old_geometry_and_copies_only_declared_support() {
        let public = vec![F::ONE; BASE_PUBLIC + dynamic_public_len()];
        assert!(extend_trace(RowMajorMatrix::new(vec![], BASE_MAIN), &public).is_err());
        assert!(
            extend_trace(
                RowMajorMatrix::new(F::zero_vec(1024 * BASE_MAIN), BASE_MAIN),
                &public[..public.len() - 1]
            )
            .is_err()
        );
        let expanded = extend_trace(
            RowMajorMatrix::new(vec![F::TWO; 1024 * BASE_MAIN], BASE_MAIN),
            &public,
        )
        .unwrap();
        let columns = specs();
        for (row, values) in expanded.values.chunks_exact(expanded.width).enumerate() {
            assert!(values[..BASE_MAIN].iter().all(|x| *x == F::TWO));
            for (column, spec) in columns.iter().enumerate() {
                assert_eq!(
                    values[BASE_MAIN + column],
                    F::from_bool((spec.first..spec.first + spec.rows).contains(&row))
                );
            }
        }
    }
}
