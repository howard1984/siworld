//! Store adapter for the authenticated generation selector. Only the resident
//! owner may attach a selector, and the selected store carries it until replaced.

use super::{
    generations::{Error, Generation, GenerationControl, Record, StoreView},
    *,
};
use crate::identity::NativeIdentity;

impl Store {
    pub(super) fn attach_imported_selector(
        &mut self,
        directory: &Path,
        certificate: crate::eng2::certificate::Certificate,
    ) -> Result<(), String> {
        let result = (|| {
            let owner = &self
                .restart
                .as_ref()
                .ok_or(Error::Invalid("imported generation custody missing"))?
                .identity;
            let view = StoreView::new(Generation::initial(), self)?;
            GenerationControl::create_imported(directory, owner, &view, certificate)
        })();
        match result {
            Ok(control) => {
                self.generation_control = Some(control);
                Ok(())
            }
            Err(error) => {
                // The signed store already occupies its admitted name. Never
                // serve it without its selection or retry by replacing it.
                self.usable = false;
                Err(error.into())
            }
        }
    }

    pub(crate) fn initialize_selected(
        directory: &Path,
        genesis: Genesis,
        limits: Limits,
        identity: NativeIdentity,
    ) -> Result<Self, String> {
        let mut store = Self::create(&Generation::initial().path(directory), genesis, limits)?;
        store.enable_authenticated_restart(identity)?;
        if store.engine.genesis().checkpoint_fork_choice() {
            let owner = &store
                .restart
                .as_ref()
                .ok_or("generation custody missing")?
                .identity;
            let view = StoreView::new(Generation::initial(), &store)?;
            store.generation_control = Some(GenerationControl::create(directory, owner, &view)?);
        }
        Ok(store)
    }

    pub(crate) fn resume_selected(
        directory: &Path,
        genesis: Genesis,
        limits: Limits,
    ) -> Result<Self, String> {
        if !genesis.checkpoint_fork_choice() {
            return Self::resume_existing(&Generation::initial().path(directory), genesis, limits);
        }
        let identity = NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing generation owner identity unavailable")?;
        let (control, mut selected) =
            GenerationControl::open_existing(directory, &identity, |path| {
                Self::resume_existing(path, genesis, limits)
            })?;
        if selected.finalized.is_some() {
            return Err("selected generation carries an unexpected independent floor".into());
        }
        selected.generation_control = Some(control);
        Ok(selected)
    }

    pub(super) fn advance_selected_floor(
        &mut self,
        certified: &crate::eng2::runtime_export::CertifiedCheckpoint,
    ) -> Result<(), String> {
        let mut control = self
            .generation_control
            .take()
            .ok_or("generation selector unavailable")?;
        let result = (|| {
            let owner = &self
                .restart
                .as_ref()
                .ok_or(Error::Invalid("generation custody missing"))?
                .identity;
            let expected = control.current()?.clone();
            let view = StoreView::new(expected.generation(), self)?;
            control.advance_floor(owner, &expected, &view, certified)?;
            Ok(())
        })();
        self.generation_control = Some(control);
        self.resolve_selection_result(result)
    }

    pub(super) fn resolve_selection_result<T>(
        &mut self,
        result: Result<T, Error>,
    ) -> Result<T, String> {
        if result
            .as_ref()
            .is_err_and(|error| *error == Error::CommitUncertain)
        {
            self.usable = false;
        }
        result.map_err(Into::into)
    }

    pub(in crate::eng2) fn generation_directory(&self) -> Result<&Path, String> {
        Ok(self
            .generation_control
            .as_ref()
            .ok_or("generation selector unavailable")?
            .directory())
    }

    pub(in crate::eng2) fn publish_shadow_generation(
        &mut self,
        expected: &Record,
        generation: Generation,
        target: &mut Option<Store>,
    ) -> Result<(), String> {
        let candidate = target.as_ref().ok_or("sealed shadow store unavailable")?;
        let Some(mut control) = self.generation_control.take() else {
            return Err("generation selector unavailable".into());
        };
        let result = (|| {
            let owner = &self
                .restart
                .as_ref()
                .ok_or(Error::Invalid("generation custody missing"))?
                .identity;
            let live = StoreView::new(expected.generation(), self)?;
            let shadow = StoreView::new(generation, candidate)?;
            control.publish(owner, expected, &live, &shadow)
        })();
        self.generation_control = Some(control);
        self.resolve_selection_result(result)?;
        let mut target = target
            .take()
            .expect("sealed shadow store was checked before publication");
        target.generation_control = self.generation_control.take();
        target.commit_observer = self.commit_observer.take();
        *self = target;
        Ok(())
    }

    pub(in crate::eng2) fn generation_record(&self) -> Result<Record, String> {
        Ok(self
            .generation_control
            .as_ref()
            .ok_or("generation selector unavailable")?
            .current()?
            .clone())
    }
}
