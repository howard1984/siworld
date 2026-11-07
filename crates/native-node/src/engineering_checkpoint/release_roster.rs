//! Release-pinned engineering authority roster. Checkpoint and transport input
//! cannot install authorities or change the public network binding.
use super::Roster;
use crate::p2p::Binding;

pub fn release_roster(_binding: Binding) -> Result<Option<Roster>, String> {
    // Remains disabled until independently generated engineering public keys
    // are inspected and bound in a subsequent release.
    Ok(None)
}
