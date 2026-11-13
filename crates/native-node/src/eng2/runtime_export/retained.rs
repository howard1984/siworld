//! Retained records can establish obsolescence, never current signing authority.
use super::*;

pub(super) enum Restored<T> {
    Absent,
    Current(T),
    Retired(u64),
}

struct SavedContext {
    anchor: Header,
    authorization: Header,
    roster: ActiveRoster,
    current: bool,
}

/// The retained resolver is an independently stored exact-header lookup. Every
/// returned frame and identity is checked before it can establish retirement.
/// At most 24 old-branch links may precede a canonical common point. A prefix
/// temporarily below the authorization head is subject to the same bound.
pub(super) fn authorization(
    network: Hash,
    head: u64,
    statement: &Statement,
    mut canonical: impl FnMut(u64) -> Result<Header, String>,
    retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
) -> Result<(Header, bool), String> {
    if statement.authorization_height.saturating_sub(head) > 24 {
        return Err("saved authorization exceeds the retained transition window".into());
    }
    let height = statement.authorization_height;
    if height <= head {
        let header = canonical(height)?;
        if header
            .id()
            .map_err(|_| "canonical authorization identity invalid")?
            == statement.authorization_block
        {
            exact_saved_header(&header, network, height, statement.authorization_block)?;
            return Ok((header, true));
        }
    }
    let original = retained(height, statement.authorization_block)?
        .ok_or("retained authorization header unavailable")?;
    exact_saved_header(&original, network, height, statement.authorization_block)?;
    let mut header = original.clone();
    for depth in 0..=24 {
        if header.height < statement.checkpoint_height {
            return Err(
                "retained authorization does not descend from the checkpoint prefix".into(),
            );
        }
        if header.height <= head {
            let known = canonical(header.height)?;
            if known
                .id()
                .map_err(|_| "canonical retained ancestor identity invalid")?
                == header
                    .id()
                    .map_err(|_| "retained ancestor identity invalid")?
            {
                return Ok((original, false));
            }
        }
        if depth == 24 || header.height <= statement.checkpoint_height {
            break;
        }
        let height = header
            .height
            .checked_sub(1)
            .ok_or("retained parent height invalid")?;
        let parent = retained(height, header.parent)?
            .ok_or("retained authorization ancestor unavailable")?;
        exact_saved_header(&parent, network, height, header.parent)?;
        header = parent;
    }
    Err("retained authorization has no canonical ancestor within 24 blocks".into())
}

fn context(
    store: &Store,
    statement: &Statement,
    witness: &AuthorizationWitness,
    snapshot: &[u8],
    limits: ImportLimits,
    retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
) -> Result<SavedContext, String> {
    let anchor = saved_anchor(store, statement, snapshot, limits)?;
    let (authorization, current) = authorization(
        statement.network,
        store.engine().state().height(),
        statement,
        |height| store.header(height),
        retained,
    )?;
    let roster = saved_roster(statement, witness, &authorization, limits)?;
    Ok(SavedContext {
        anchor,
        authorization,
        roster,
        current,
    })
}

pub(super) fn candidate(
    store: &Store,
    statement: Statement,
    witness: AuthorizationWitness,
    snapshot: Vec<u8>,
    votes: &[Vote],
    limits: ImportLimits,
    retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
) -> Result<Restored<PreparedCheckpoint>, String> {
    let checked = context(store, &statement, &witness, &snapshot, limits, retained)?;
    for vote in votes {
        verify_saved_vote(&checked.roster, &statement, vote)?;
    }
    if !checked.current {
        return Ok(Restored::Retired(statement.checkpoint_height));
    }
    let prepared = PreparedCheckpoint {
        network: statement.network,
        genesis: store.engine().genesis().id(),
        rules: store.engine().genesis().rules_commitment(),
        anchor: checked.anchor,
        authorization: checked.authorization,
        roster: checked.roster,
        statement,
        witness,
        snapshot,
        _snapshot_reservation: None,
        _native_identity: None,
    };
    prepared.check_current(store)?;
    Ok(Restored::Current(prepared))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publication(
    store: &Store,
    certificate: Certificate,
    witness: AuthorizationWitness,
    snapshot: Vec<u8>,
    published: u64,
    votes: &[Vote],
    limits: ImportLimits,
    retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
) -> Result<Restored<CertifiedCheckpoint>, String> {
    let checked = context(
        store,
        &certificate.statement,
        &witness,
        &snapshot,
        limits,
        retained,
    )?;
    for vote in votes {
        verify_saved_vote(&checked.roster, &certificate.statement, vote)?;
    }
    certificate
        .check_signatures(checked.roster.keys())
        .map_err(|_| "checkpoint publication signatures invalid")?;
    if published >= 1u64 << 53 {
        return Err("checkpoint publication time invalid".into());
    }
    if !checked.current {
        return Ok(Restored::Retired(certificate.statement.checkpoint_height));
    }
    let prepared = PreparedCheckpoint {
        network: certificate.statement.network,
        genesis: store.engine().genesis().id(),
        rules: store.engine().genesis().rules_commitment(),
        anchor: checked.anchor,
        authorization: checked.authorization,
        roster: checked.roster,
        statement: certificate.statement.clone(),
        witness,
        snapshot,
        _snapshot_reservation: None,
        _native_identity: None,
    };
    prepared.check_prefix(store)?;
    Ok(Restored::Current(CertifiedCheckpoint {
        prepared,
        certificate,
        published,
    }))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod native_tests;
