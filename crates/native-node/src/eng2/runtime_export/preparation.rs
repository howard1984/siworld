//! Internal completion of independently reconstructed local archive work.
//! No externally constructed prepared result is a signing capability.
use super::*;

impl PreparedCheckpoint {
    /// Capture only compact current execution components under the owner.
    /// Permanent reconstruction data is handled by the independent worker.
    pub(super) fn current_proposal(
        store: &Store,
        limits: ImportLimits,
    ) -> Result<Option<(Statement, AuthorizationWitness)>, String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let state = engine.state();
        let Some(height) = eligible_checkpoint(state.height()) else {
            return Ok(None);
        };
        let anchor = store.header(height)?;
        let authorization = store.header(state.height())?;
        let witness = state.checkpoint_witness(
            Binding {
                genesis: engine.genesis().id(),
                rules_commitment: engine.genesis().rules_commitment(),
                parent: authorization.parent,
            },
            limits.chain,
        )?;
        if commitment::aggregate_descriptors(
            state.network(),
            state.height(),
            authorization.parent,
            &witness.descriptors,
        )
        .map_err(|_| "invalid current checkpoint execution witness")?
            != authorization.execution_commitment
        {
            return Err("checkpoint witness differs from the executed current header".into());
        }
        let roster = state.governance().active_roster();
        let statement = Statement {
            network: state.network(),
            checkpoint_height: height,
            checkpoint_block: anchor.id().map_err(|_| "invalid checkpoint anchor")?,
            authorization_height: state.height(),
            authorization_block: state.tip(),
            roster_sequence: roster.epoch_sequence,
            roster_digest: roster.digest(state.network()),
        };
        statement
            .encode()
            .map_err(|_| "invalid checkpoint proposal statement")?;
        witness
            .encode(limits.chain.max_component_bytes)
            .map_err(|_| "invalid checkpoint proposal witness")?;
        Ok(Some((statement, witness)))
    }

    /// Only an owned result of full native archive reconstruction reaches this
    /// internal constructor. The original owner must be held throughout it.
    pub(super) fn from_validated_archive(
        store: &Store,
        archive: archive_work::ValidatedArchive,
        statement: Statement,
        witness: AuthorizationWitness,
        limits: ImportLimits,
    ) -> Result<Self, String> {
        archive.check_current(store)?;
        let engine = store.engine();
        let state = engine.state();
        if archive.state().height() != statement.checkpoint_height
            || archive.state().tip() != statement.checkpoint_block
        {
            return Err(
                "checkpoint preparation differs from independently validated archive".into(),
            );
        }
        let (anchor, authorization, roster) =
            Self::proposal_context(store, &statement, &witness, limits)?;
        // The witness governance vector is the only separate dynamic metadata;
        // roster keys, headers, descriptors, statement and certificate are inline.
        // Charge capacities rather than encoded lengths, including spare bytes.
        let retained_metadata = std::mem::size_of::<CertifiedCheckpoint>()
            .checked_add(witness.governance.capacity())
            .ok_or("checkpoint retained metadata byte bound overflow")?;
        let (snapshot, reservation) = archive.into_snapshot(retained_metadata)?;
        let value = Self {
            network: state.network(),
            genesis: engine.genesis().id(),
            rules: engine.genesis().rules_commitment(),
            anchor,
            authorization,
            roster,
            statement,
            witness,
            snapshot,
            _snapshot_reservation: Some(reservation),
        };
        value.check_current(store)?;
        Ok(value)
    }
    /// Validate bounded authority metadata against actual executed headers.
    /// This does not validate the archive or grant signing/publication rights.
    pub(super) fn proposal_context(
        store: &Store,
        statement: &Statement,
        witness: &AuthorizationWitness,
        limits: ImportLimits,
    ) -> Result<(Header, Header, ActiveRoster), String> {
        store.ensure_exportable()?;
        let state = store.engine().state();
        statement
            .encode()
            .map_err(|_| "invalid checkpoint proposal statement")?;
        if statement.network != state.network()
            || !confirmed_checkpoint(statement.checkpoint_height, statement.authorization_height)
            || statement.authorization_height > state.height()
        {
            return Err("checkpoint proposal differs from current execution context".into());
        }
        let anchor = store.header(statement.checkpoint_height)?;
        let authorization = store.header(statement.authorization_height)?;
        if anchor
            .id()
            .map_err(|_| "invalid checkpoint anchor identity")?
            != statement.checkpoint_block
            || authorization
                .id()
                .map_err(|_| "invalid checkpoint authorization identity")?
                != statement.authorization_block
        {
            return Err("checkpoint preparation is outside the executed canonical prefix".into());
        }
        witness
            .encode(limits.chain.max_component_bytes)
            .map_err(|_| "invalid checkpoint authorization witness")?;
        let descriptor = Component::from_local_encoding(
            ComponentId::Governance,
            &witness.governance,
            limits.chain.max_component_bytes,
        )
        .map_err(|_| "checkpoint governance witness exceeds bounds")?
        .descriptor();
        if witness.descriptors[7] != descriptor
            || commitment::aggregate_descriptors(
                state.network(),
                authorization.height,
                authorization.parent,
                &witness.descriptors,
            )
            .map_err(|_| "invalid checkpoint authorization descriptors")?
                != authorization.execution_commitment
        {
            return Err("checkpoint witness differs from executed authorization header".into());
        }
        let governance = GovernanceState::decode_component(&witness.governance, state.network())?;
        let roster = governance.active_roster().clone();
        if governance.height() != authorization.height
            || roster.activated_height > authorization.height
            || roster.epoch_sequence != statement.roster_sequence
            || roster.digest(state.network()) != statement.roster_digest
            || roster.digest(state.network())
                != state.governance().active_roster().digest(state.network())
        {
            return Err("checkpoint witness does not authorize its signer epoch".into());
        }
        Ok((anchor, authorization, roster))
    }
}
