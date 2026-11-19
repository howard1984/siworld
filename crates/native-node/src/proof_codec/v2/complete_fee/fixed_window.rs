//! Embed a fixed, verifier-preprocessed execution window in a larger AIR.
//! Every constraint and interaction remains active on the complete original
//! window. Padding contributes neither constraints nor lookup multiplicities.
use p3_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};

pub struct FixedWindow<'a, AB: AirBuilder> {
    pub inner: &'a mut AB,
    pub active: AB::Expr,
    pub last: AB::Expr,
}
impl<AB: AirBuilder> AirBuilder for FixedWindow<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = AB::MainWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.last.clone()
    }
    fn is_transition(&self) -> Self::Expr {
        Self::Expr::ONE - self.last.clone()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into() * self.active.clone());
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}
impl<AB: ExtensionBuilder> ExtensionBuilder for FixedWindow<'_, AB> {
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;
    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, x: I) {
        self.inner.assert_zero_ext(x.into() * self.active.clone());
    }
}
impl<AB: PermutationAirBuilder> PermutationAirBuilder for FixedWindow<'_, AB> {
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
impl<AB: InteractionBuilder> InteractionBuilder for FixedWindow<'_, AB> {
    fn push_interaction<E: Into<Self::Expr>>(
        &mut self,
        name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Self::Expr>>,
    ) {
        let (value, weight) = count.into().into_parts();
        self.inner.push_interaction(
            name,
            fields,
            Count::bounded(value * self.active.clone(), weight),
        );
    }
    fn push_local_interaction(
        &mut self,
        tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Count<Self::Expr>)>,
    ) {
        let active = self.active.clone();
        self.inner
            .push_local_interaction(tuples.into_iter().map(|(fields, count)| {
                let (value, weight) = count.into_parts();
                (fields, Count::bounded(value * active.clone(), weight))
            }));
    }
    fn push_exclusive_interaction(
        &mut self,
        name: &str,
        branches: impl IntoIterator<Item = (Self::Expr, Count<Self::Expr>, Vec<Self::Expr>)>,
    ) {
        let active = self.active.clone();
        self.inner.push_exclusive_interaction(
            name,
            branches
                .into_iter()
                .map(|(flag, count, fields)| (flag * active.clone(), count, fields)),
        );
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
