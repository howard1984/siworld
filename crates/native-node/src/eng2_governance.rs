//! Versioned governance state for the separately activated engineering network.
//! This module is not called by the existing network's state transition.
use crate::wire::Hash;
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
use native::{
    codec::{decode_digest, encode_digest},
    encryption::PaymentAddress,
};

pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const ADDRESS_BYTES: usize = 1232;
pub const OWNER_DELAY_BLOCKS: u64 = 4032;
pub const ROSTER_DELAY_BLOCKS: u64 = 24;
pub const MAX_ACTIONS_PER_BLOCK: usize = 32;
pub const MAX_FUND_MEMBERS: usize = 32;
pub const MAX_PENDING: usize = MAX_FUND_MEMBERS + 4;
pub const INITIAL_ISSUANCE_FEE_ATOMS: u64 = 5_000_000_000;
pub const MINIMUM_ISSUANCE_FEE_ATOMS: u64 = 100_000_000;
pub const MAXIMUM_ISSUANCE_FEE_ATOMS: u64 = 1_000_000_000_000;
pub const SIGNATURE_CONTEXT: &[u8] = b"siworld eng2 governance v1";
pub type PublicKey = [u8; PUBLIC_KEY_BYTES];
pub type AddressBytes = [u8; ADDRESS_BYTES];
mod codec;
mod windowed;
pub use windowed::WindowedSignedAction;

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn owner_keys(founder: &PublicKey, revocation: &PublicKey) -> Result<(), String> {
    require(
        founder != &[0; PUBLIC_KEY_BYTES]
            && revocation != &[0; PUBLIC_KEY_BYTES]
            && founder != revocation,
        "governance owner keys must be nonzero and distinct",
    )
}
fn roster_keys(keys: &[PublicKey; 3]) -> Result<(), String> {
    require(
        keys.iter().all(|key| key != &[0; PUBLIC_KEY_BYTES])
            && keys[0] != keys[1]
            && keys[0] != keys[2]
            && keys[1] != keys[2],
        "checkpoint roster requires three nonzero distinct keys",
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRole {
    Founder,
    Revocation,
    Checkpoint(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationTarget {
    Fees,
    FundMember(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotReplacement {
    pub slot: u8,
    pub key: PublicKey,
}
/// Genesis-bound public issuance-fee parameters, in SIP atoms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuanceFeeParameters {
    pub initial_atoms: u64,
    pub minimum_atoms: u64,
    pub maximum_atoms: u64,
}
impl Default for IssuanceFeeParameters {
    fn default() -> Self {
        Self {
            initial_atoms: INITIAL_ISSUANCE_FEE_ATOMS,
            minimum_atoms: MINIMUM_ISSUANCE_FEE_ATOMS,
            maximum_atoms: MAXIMUM_ISSUANCE_FEE_ATOMS,
        }
    }
}
impl IssuanceFeeParameters {
    fn validate(self) -> Result<(), String> {
        require(
            self == Self::default(),
            "issuance-fee genesis parameters differ from eng2 rules",
        )
    }
    fn check_amount(self, amount_atoms: u64) -> Result<(), String> {
        require(
            (self.minimum_atoms..=self.maximum_atoms).contains(&amount_atoms),
            "issuance fee is outside genesis bounds",
        )
    }
}
/// Public proposal status. A pending amount does not change the active fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingIssuanceFee {
    pub amount_atoms: u64,
    pub proposal_sequence: u64,
    pub included_height: u64,
    pub effective_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionKind {
    ProposeIssuanceFee {
        amount_atoms: u64,
    },
    CancelIssuanceFee {
        proposal_sequence: u64,
    },
    ProposeDestination {
        target: DestinationTarget,
        address: Box<AddressBytes>,
    },
    CancelDestination {
        proposal_sequence: u64,
    },
    CancelJointChange {
        proposal_sequence: u64,
    },
    RotateOwnerKeys {
        founder: Box<PublicKey>,
        revocation: Box<PublicKey>,
    },
    ReplaceCheckpointSigners {
        replacements: Vec<SlotReplacement>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub network: Hash,
    pub sequence: u64,
    pub kind: ActionKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub role: SignerRole,
    pub signature: [u8; SIGNATURE_BYTES],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAction {
    pub action: Action,
    pub signatures: Vec<Authorization>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRoster {
    keys: [PublicKey; 3],
    pub epoch_sequence: u64,
    pub activated_height: u64,
}
impl ActiveRoster {
    pub const THRESHOLD: u8 = 2;
    pub fn keys(&self) -> &[PublicKey; 3] {
        &self.keys
    }
    pub fn digest(&self, network: Hash) -> Hash {
        let mut hasher = blake3::Hasher::new_derive_key("siworld eng2 checkpoint roster v1");
        hasher.update(&network);
        hasher.update(&[3, Self::THRESHOLD]);
        hasher.update(&self.epoch_sequence.to_le_bytes());
        hasher.update(&self.activated_height.to_le_bytes());
        for key in &self.keys {
            hasher.update(key);
        }
        *hasher.finalize().as_bytes()
    }
}
/// Emit this record externally only after the complete block commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    pub sequence: u64,
    pub included_height: u64,
    pub effective_height: u64,
    pub action_digest: Hash,
    pub new_issuance_fee_atoms: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingKind {
    IssuanceFee {
        amount_atoms: u64,
    },
    Destination {
        target: DestinationTarget,
        address: Box<AddressBytes>,
    },
    OwnerKeys {
        founder: Box<PublicKey>,
        revocation: Box<PublicKey>,
    },
    Roster(Box<ActiveRoster>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    sequence: u64,
    included_height: u64,
    effective_height: u64,
    kind: PendingKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceState {
    network: Hash,
    height: u64,
    sequence: u64,
    founder: PublicKey,
    revocation: PublicKey,
    owner_epoch_sequence: u64,
    owner_activated_height: u64,
    roster: ActiveRoster,
    fees: PaymentAddress,
    fund: Vec<PaymentAddress>,
    pending: Vec<Pending>,
    issuance_fee_parameters: IssuanceFeeParameters,
    issuance_fee_atoms: u64,
    issuance_fee_epoch_sequence: u64,
    issuance_fee_activated_height: u64,
}
impl GovernanceState {
    pub fn new(
        network: Hash,
        founder: PublicKey,
        revocation: PublicKey,
        roster: [PublicKey; 3],
        fees: PaymentAddress,
        fund: Vec<PaymentAddress>,
    ) -> Result<Self, String> {
        Self::new_with_issuance_fee(
            network,
            founder,
            revocation,
            roster,
            fees,
            fund,
            IssuanceFeeParameters::default(),
        )
    }
    pub fn new_with_issuance_fee(
        network: Hash,
        founder: PublicKey,
        revocation: PublicKey,
        roster: [PublicKey; 3],
        fees: PaymentAddress,
        fund: Vec<PaymentAddress>,
        issuance_fee_parameters: IssuanceFeeParameters,
    ) -> Result<Self, String> {
        let state = Self {
            network,
            height: 0,
            sequence: 0,
            founder,
            revocation,
            owner_epoch_sequence: 0,
            owner_activated_height: 0,
            roster: ActiveRoster {
                keys: roster,
                epoch_sequence: 0,
                activated_height: 0,
            },
            fees,
            fund,
            pending: Vec::new(),
            issuance_fee_atoms: issuance_fee_parameters.initial_atoms,
            issuance_fee_parameters,
            issuance_fee_epoch_sequence: 0,
            issuance_fee_activated_height: 0,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn issuance_fee_atoms(&self) -> u64 {
        self.issuance_fee_atoms
    }
    pub fn issuance_fee_parameters(&self) -> IssuanceFeeParameters {
        self.issuance_fee_parameters
    }
    pub fn pending_issuance_fee(&self) -> Option<PendingIssuanceFee> {
        self.pending.iter().find_map(|item| match item.kind {
            PendingKind::IssuanceFee { amount_atoms } => Some(PendingIssuanceFee {
                amount_atoms,
                proposal_sequence: item.sequence,
                included_height: item.included_height,
                effective_height: item.effective_height,
            }),
            _ => None,
        })
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn active_roster(&self) -> &ActiveRoster {
        &self.roster
    }
    pub fn active_fee_destination(&self) -> &PaymentAddress {
        &self.fees
    }
    pub fn active_fund_destination(&self, member: u8) -> Result<&PaymentAddress, String> {
        self.fund
            .get(usize::from(member))
            .ok_or_else(|| "unknown governance fund member".into())
    }
    pub fn active_owner_keys(&self) -> (&PublicKey, &PublicKey) {
        (&self.founder, &self.revocation)
    }
    pub fn pending_roster(&self) -> Option<&ActiveRoster> {
        self.pending.iter().find_map(|item| match &item.kind {
            PendingKind::Roster(roster) => Some(roster.as_ref()),
            _ => None,
        })
    }
    pub fn canonical_fee_destination_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = canonical_address(&self.fees);
        decode_address(&bytes)?;
        Ok(bytes.to_vec())
    }
    /// One staged path activates old operations before authenticating new ones.
    /// Its caller still must stage and commit all other block state atomically.
    pub fn apply_block(
        &mut self,
        height: u64,
        actions: &[SignedAction],
    ) -> Result<Vec<Inclusion>, String> {
        require(
            self.height.checked_add(1) == Some(height),
            "governance height must advance exactly one block",
        )?;
        require(
            actions.len() <= MAX_ACTIONS_PER_BLOCK,
            "governance action count exceeds block bound",
        )?;
        let mut staged = self.clone();
        staged.activate(height)?;
        let mut events = Vec::with_capacity(actions.len());
        for action in actions {
            events.push(staged.include(height, action)?);
        }
        staged.height = height;
        staged.validate()?;
        *self = staged;
        Ok(events)
    }
    fn activate(&mut self, height: u64) -> Result<(), String> {
        let mut remaining = Vec::new();
        for item in self.pending.clone() {
            require(
                item.effective_height >= height,
                "governance activation was skipped",
            )?;
            if item.effective_height != height {
                remaining.push(item);
                continue;
            }
            match item.kind {
                PendingKind::IssuanceFee { amount_atoms } => {
                    self.issuance_fee_atoms = amount_atoms;
                    self.issuance_fee_epoch_sequence = item.sequence;
                    self.issuance_fee_activated_height = height;
                }
                PendingKind::Destination { target, address } => {
                    let address = decode_address(address.as_ref())?;
                    match target {
                        DestinationTarget::Fees => self.fees = address,
                        DestinationTarget::FundMember(member) => {
                            *self
                                .fund
                                .get_mut(usize::from(member))
                                .ok_or("unknown fund destination")? = address;
                        }
                    }
                }
                PendingKind::OwnerKeys {
                    founder,
                    revocation,
                } => {
                    self.founder = *founder;
                    self.revocation = *revocation;
                    self.owner_epoch_sequence = item.sequence;
                    self.owner_activated_height = height;
                }
                PendingKind::Roster(roster) => self.roster = *roster,
            }
        }
        self.pending = remaining;
        Ok(())
    }
    fn authenticate(&self, signed: &SignedAction) -> Result<(), String> {
        self.authenticate_message(
            signed,
            |role| signed.action.signing_bytes(role),
            SIGNATURE_CONTEXT,
        )
    }
    fn authenticate_message(
        &self,
        signed: &SignedAction,
        message: impl Fn(SignerRole) -> Result<Vec<u8>, String>,
        context: &[u8],
    ) -> Result<(), String> {
        let action = &signed.action;
        require(
            action.network == self.network && action.sequence > self.sequence,
            "governance network or monotonic sequence mismatch",
        )?;
        let roles: &[SignerRole] = match action.kind {
            ActionKind::ProposeDestination { .. } | ActionKind::ProposeIssuanceFee { .. } => {
                &[SignerRole::Founder]
            }
            ActionKind::CancelDestination { .. } | ActionKind::CancelIssuanceFee { .. } => {
                &[SignerRole::Revocation]
            }
            ActionKind::RotateOwnerKeys { .. }
            | ActionKind::ReplaceCheckpointSigners { .. }
            | ActionKind::CancelJointChange { .. } => {
                &[SignerRole::Founder, SignerRole::Revocation]
            }
        };
        require(
            signed.signatures.len() == roles.len()
                && signed
                    .signatures
                    .iter()
                    .map(|auth| auth.role)
                    .eq(roles.iter().copied()),
            "governance requires exact ordered owner roles",
        )?;
        for auth in &signed.signatures {
            let key = match auth.role {
                SignerRole::Founder => self.founder,
                SignerRole::Revocation => self.revocation,
                SignerRole::Checkpoint(_) => {
                    return Err("checkpoint signer cannot authorize governance".into());
                }
            };
            ml_dsa_65::verify(
                &MLDSA65VerificationKey::new(key),
                &message(auth.role)?,
                context,
                &MLDSA65Signature::new(auth.signature),
            )
            .map_err(|_| "governance ML-DSA-65 signature invalid")?;
        }
        Ok(())
    }
    fn include(&mut self, height: u64, signed: &SignedAction) -> Result<Inclusion, String> {
        self.authenticate(signed)?;
        let digest = blake3::derive_key(
            "siworld eng2 governance action v1",
            &signed.action.unsigned_bytes()?,
        );
        self.include_authenticated(height, &signed.action, digest)
    }
    fn include_authenticated(
        &mut self,
        height: u64,
        action: &Action,
        action_digest: Hash,
    ) -> Result<Inclusion, String> {
        let (kind, delay) = match &action.kind {
            ActionKind::ProposeIssuanceFee { amount_atoms } => {
                self.issuance_fee_parameters.check_amount(*amount_atoms)?;
                require(
                    !self
                        .pending
                        .iter()
                        .any(|item| matches!(item.kind, PendingKind::IssuanceFee { .. })),
                    "an issuance-fee proposal is already pending",
                )?;
                (
                    Some(PendingKind::IssuanceFee {
                        amount_atoms: *amount_atoms,
                    }),
                    OWNER_DELAY_BLOCKS,
                )
            }
            ActionKind::CancelIssuanceFee { proposal_sequence } => {
                let index = self
                    .pending
                    .iter()
                    .position(|item| {
                        item.sequence == *proposal_sequence
                            && matches!(item.kind, PendingKind::IssuanceFee { .. })
                            && item.effective_height > height
                    })
                    .ok_or("issuance-fee cancellation requires a pending pre-effective proposal")?;
                self.pending.remove(index);
                (None, 0)
            }
            ActionKind::ProposeDestination { target, address } => {
                self.check_target(*target)?;
                decode_address(address.as_ref())?;
                require(
                    !self.pending.iter().any(|item| {
                        matches!(&item.kind,
                    PendingKind::Destination { target: pending, .. } if pending == target)
                    }),
                    "a destination proposal is already pending for this target",
                )?;
                (
                    Some(PendingKind::Destination {
                        target: *target,
                        address: address.clone(),
                    }),
                    OWNER_DELAY_BLOCKS,
                )
            }
            ActionKind::CancelDestination { proposal_sequence } => {
                let index = self
                    .pending
                    .iter()
                    .position(|item| {
                        item.sequence == *proposal_sequence
                            && matches!(item.kind, PendingKind::Destination { .. })
                            && item.effective_height > height
                    })
                    .ok_or("destination cancellation requires a pending pre-effective proposal")?;
                self.pending.remove(index);
                (None, 0)
            }
            ActionKind::CancelJointChange { proposal_sequence } => {
                let index = self.pending.iter().position(|item| {
                    item.sequence == *proposal_sequence
                        && matches!(item.kind, PendingKind::OwnerKeys { .. } | PendingKind::Roster(_))
                        && item.effective_height > height
                }).ok_or("joint cancellation requires a pending pre-effective owner or roster change")?;
                self.pending.remove(index);
                (None, 0)
            }
            ActionKind::RotateOwnerKeys {
                founder,
                revocation,
            } => {
                owner_keys(founder, revocation)?;
                require(
                    founder.as_ref() != &self.founder || revocation.as_ref() != &self.revocation,
                    "owner rotation changes no key",
                )?;
                require(
                    !self
                        .pending
                        .iter()
                        .any(|item| matches!(item.kind, PendingKind::OwnerKeys { .. })),
                    "an owner rotation is already pending",
                )?;
                (
                    Some(PendingKind::OwnerKeys {
                        founder: founder.clone(),
                        revocation: revocation.clone(),
                    }),
                    OWNER_DELAY_BLOCKS,
                )
            }
            ActionKind::ReplaceCheckpointSigners { replacements } => {
                require(
                    !replacements.is_empty()
                        && replacements.len() <= 3
                        && replacements
                            .windows(2)
                            .all(|pair| pair[0].slot < pair[1].slot),
                    "roster replacement slots must be nonempty distinct and ordered",
                )?;
                require(
                    !self
                        .pending
                        .iter()
                        .any(|item| matches!(item.kind, PendingKind::Roster(_))),
                    "a checkpoint roster replacement is already pending",
                )?;
                let mut keys = self.roster.keys;
                for replacement in replacements {
                    let slot = usize::from(replacement.slot);
                    require(
                        slot < 3,
                        "checkpoint roster slot is outside fixed cardinality",
                    )?;
                    require(
                        keys[slot] != replacement.key,
                        "checkpoint replacement changes no key",
                    )?;
                    keys[slot] = replacement.key;
                }
                roster_keys(&keys)?;
                let effective_height = height
                    .checked_add(ROSTER_DELAY_BLOCKS)
                    .ok_or("roster activation height overflow")?;
                (
                    Some(PendingKind::Roster(Box::new(ActiveRoster {
                        keys,
                        epoch_sequence: action.sequence,
                        activated_height: effective_height,
                    }))),
                    ROSTER_DELAY_BLOCKS,
                )
            }
        };
        let effective_height = height
            .checked_add(delay)
            .ok_or("governance activation height overflow")?;
        if let Some(kind) = kind {
            require(
                self.pending.len() < MAX_PENDING,
                "governance pending operation bound exceeded",
            )?;
            self.pending.push(Pending {
                sequence: action.sequence,
                included_height: height,
                effective_height,
                kind,
            });
        }
        self.sequence = action.sequence;
        Ok(Inclusion {
            sequence: action.sequence,
            included_height: height,
            effective_height,
            new_issuance_fee_atoms: match action.kind {
                ActionKind::ProposeIssuanceFee { amount_atoms } => Some(amount_atoms),
                _ => None,
            },
            action_digest,
        })
    }
    fn check_target(&self, target: DestinationTarget) -> Result<(), String> {
        match target {
            DestinationTarget::Fees => Ok(()),
            DestinationTarget::FundMember(member) => require(
                usize::from(member) < self.fund.len(),
                "governance fund member is not registered",
            ),
        }
    }
    fn validate(&self) -> Result<(), String> {
        require(
            self.network != [0; 32]
                && self.fund.len() <= MAX_FUND_MEMBERS
                && self.pending.len() <= MAX_PENDING,
            "governance state context or bound invalid",
        )?;
        self.issuance_fee_parameters.validate()?;
        self.issuance_fee_parameters
            .check_amount(self.issuance_fee_atoms)?;
        require(
            self.issuance_fee_epoch_sequence <= self.sequence
                && self.issuance_fee_activated_height <= self.height
                && (self.issuance_fee_epoch_sequence == 0)
                    == (self.issuance_fee_activated_height == 0)
                && if self.issuance_fee_epoch_sequence == 0 {
                    self.issuance_fee_atoms == self.issuance_fee_parameters.initial_atoms
                } else {
                    self.issuance_fee_activated_height > OWNER_DELAY_BLOCKS
                },
            "active issuance-fee epoch invalid",
        )?;
        owner_keys(&self.founder, &self.revocation)?;
        roster_keys(&self.roster.keys)?;
        require(
            self.roster.epoch_sequence <= self.sequence
                && self.roster.activated_height <= self.height
                && self.owner_epoch_sequence <= self.sequence
                && self.owner_activated_height <= self.height,
            "active governance epoch exceeds committed context",
        )?;
        require(
            (self.roster.epoch_sequence == 0) == (self.roster.activated_height == 0)
                && (self.owner_epoch_sequence == 0) == (self.owner_activated_height == 0)
                && (self.roster.epoch_sequence == 0
                    || self.roster.activated_height > ROSTER_DELAY_BLOCKS)
                && (self.owner_epoch_sequence == 0
                    || self.owner_activated_height > OWNER_DELAY_BLOCKS),
            "active governance epoch activation context invalid",
        )?;
        decode_address(&canonical_address(&self.fees))?;
        for address in &self.fund {
            decode_address(&canonical_address(address))?;
        }
        require(
            self.pending
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence),
            "pending governance sequences are not canonical",
        )?;
        let mut destinations = Vec::new();
        let mut owner_pending = false;
        let mut roster_pending = false;
        let mut issuance_fee_pending = false;
        for item in &self.pending {
            require(
                item.sequence > 0
                    && item.sequence <= self.sequence
                    && item.included_height > 0
                    && item.included_height <= self.height
                    && item.effective_height > self.height,
                "pending governance context invalid",
            )?;
            let delay = match &item.kind {
                PendingKind::IssuanceFee { amount_atoms } => {
                    self.issuance_fee_parameters.check_amount(*amount_atoms)?;
                    require(
                        !issuance_fee_pending && item.sequence > self.issuance_fee_epoch_sequence,
                        "duplicate or obsolete pending issuance-fee proposal",
                    )?;
                    issuance_fee_pending = true;
                    OWNER_DELAY_BLOCKS
                }
                PendingKind::Destination { target, address } => {
                    self.check_target(*target)?;
                    decode_address(address.as_ref())?;
                    require(
                        !destinations.contains(target),
                        "duplicate pending destination target",
                    )?;
                    destinations.push(*target);
                    OWNER_DELAY_BLOCKS
                }
                PendingKind::OwnerKeys {
                    founder,
                    revocation,
                } => {
                    owner_keys(founder, revocation)?;
                    require(
                        !owner_pending
                            && item.sequence > self.owner_epoch_sequence
                            && (founder.as_ref() != &self.founder
                                || revocation.as_ref() != &self.revocation),
                        "duplicate or obsolete pending owner rotation",
                    )?;
                    owner_pending = true;
                    OWNER_DELAY_BLOCKS
                }
                PendingKind::Roster(roster) => {
                    roster_keys(&roster.keys)?;
                    require(
                        !roster_pending
                            && item.sequence > self.roster.epoch_sequence
                            && roster.keys != self.roster.keys
                            && roster.epoch_sequence == item.sequence
                            && roster.activated_height == item.effective_height,
                        "pending roster epoch invalid",
                    )?;
                    roster_pending = true;
                    ROSTER_DELAY_BLOCKS
                }
            };
            require(
                item.included_height.checked_add(delay) == Some(item.effective_height),
                "pending governance delay mismatch",
            )?;
        }
        Ok(())
    }
}
pub fn canonical_address(address: &PaymentAddress) -> AddressBytes {
    let mut bytes = [0; ADDRESS_BYTES];
    bytes[..48].copy_from_slice(&encode_digest(&address.owner()));
    bytes[48..].copy_from_slice(address.encapsulation_key());
    bytes
}
pub fn decode_address(bytes: &[u8]) -> Result<PaymentAddress, String> {
    require(
        bytes.len() == ADDRESS_BYTES,
        "governance address length invalid",
    )?;
    let owner = decode_digest(bytes[..48].try_into().expect("bounded owner"))
        .map_err(|_| "governance address owner is noncanonical")?;
    PaymentAddress::new(
        owner,
        bytes[48..].try_into().expect("bounded encapsulation key"),
    )
    .map_err(|_| "governance address ML-KEM key invalid".into())
}
#[cfg(test)]
mod tests;
