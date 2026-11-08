//! Offline admission of existing local state before a pinned roster transition.
use super::*;
use crate::engineering_checkpoint::Roster;

pub(super) fn check(directory: &Path) -> Result<Value, String> {
    let binding = crate::p2p::Binding::new(&local::load(directory)?);
    let roster = crate::engineering_checkpoint::release_roster(binding)?
        .ok_or("checkpoint transition requires a release-pinned engineering roster")?;
    check_inner(directory, &roster, seconds()?, seconds)
}

fn seconds() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes epoch")?
        .as_secs())
}

fn check_inner(
    directory: &Path,
    roster: &Roster,
    now: u64,
    completed: impl FnOnce() -> Result<u64, String>,
) -> Result<Value, String> {
    let _lease = Lease::acquire(directory)?;
    let first = roster.admission_first_sequence(now)?;
    let verifier = NativeVerifier::new()?;
    let store = Store::check_restart_existing(
        directory.join("chain.redb"),
        local::load(directory)?,
        &verifier,
    )?;
    let checked = store.verify_local_rewards()?;
    let accepted = store.checkpoint_before_transition(roster, now)?;
    let inventory = crate::identity::checkpoint_authority::public_journals_before_transition(
        directory, roster, now, accepted,
    )?;
    let finished = completed()?;
    if finished < now {
        return Err("checkpoint admission clock moved backwards".into());
    }
    roster.admission_first_sequence(finished)?;
    Ok(json!({
        "schema": 1,
        "height": store.state().height,
        "tip": local::hex(&store.state().tip),
        "state_fingerprint": local::hex(&store.state().fingerprint()),
        "cumulative_work": local::hex(&store.state().cumulative_work.to_big_endian()),
        "proof_replay_checked": false,
        "proof_tail_replay_checked": false,
        "authenticated_local_restart_checked": true,
        "local_reward_receipts_checked": checked,
        "checkpoint_transition_admission_checked": true,
        "transition_first_sequence": first,
        "admission_started_unix_seconds": now,
        "admission_completed_unix_seconds": finished,
        "accepted_checkpoint": accepted.map(|cursor| json!({
            "sequence": cursor.sequence, "height": cursor.height,
            "statement_digest": local::hex(&cursor.digest),
        })),
        "authenticated_checkpoint_absence": accepted.is_none(),
        "authority_journal_count": inventory.count,
        "maximum_authority_journal_sequence": inventory.maximum_sequence,
        "authority_journal_inventory_digest": local::hex(&inventory.digest),
        "validation_scope": "pre-transition-local-admission",
    }))
}

#[cfg(test)]
mod tests;
