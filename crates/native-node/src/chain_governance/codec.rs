//! Bounded canonical governance/action encodings shared with offline signers.
use super::*;
const ACTION_MAGIC: &[u8; 8] = b"SWG2ACT1";
const STATE_MAGIC: &[u8; 8] = b"SWG2GOV2";
const MAX_UNSIGNED_BYTES: usize = 8192;
const MAX_SIGNED_BYTES: usize = 16384;
pub(super) const MAX_COMPONENT_BYTES: usize = 131072;
fn u64_bytes(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn role_byte(role: SignerRole) -> Result<u8, String> {
    match role {
        SignerRole::Founder => Ok(0),
        SignerRole::Revocation => Ok(1),
        SignerRole::Checkpoint(slot) if slot < 3 => Ok(2 + slot),
        _ => Err("unknown governance signer role".into()),
    }
}
fn target(out: &mut Vec<u8>, value: DestinationTarget) {
    match value {
        DestinationTarget::Fees => out.extend_from_slice(&[0, 0]),
        DestinationTarget::FundMember(member) => out.extend_from_slice(&[1, member]),
    }
}
fn roster(out: &mut Vec<u8>, value: &ActiveRoster) {
    u64_bytes(out, value.epoch_sequence);
    u64_bytes(out, value.activated_height);
    for key in &value.keys {
        out.extend_from_slice(key);
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (head, rest) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated governance encoding")?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("bounded governance field"))
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn target(&mut self) -> Result<DestinationTarget, String> {
        match (self.byte()?, self.byte()?) {
            (0, 0) => Ok(DestinationTarget::Fees),
            (1, member) if usize::from(member) < MAX_FUND_MEMBERS => {
                Ok(DestinationTarget::FundMember(member))
            }
            _ => Err("noncanonical governance destination target".into()),
        }
    }
    fn roster(&mut self) -> Result<ActiveRoster, String> {
        Ok(ActiveRoster {
            epoch_sequence: self.u64()?,
            activated_height: self.u64()?,
            keys: [self.array()?, self.array()?, self.array()?],
        })
    }
}
impl Action {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        require(
            self.network != [0; 32] && self.sequence > 0,
            "governance action context invalid",
        )?;
        let mut out = ACTION_MAGIC.to_vec();
        out.extend_from_slice(&self.network);
        u64_bytes(&mut out, self.sequence);
        match &self.kind {
            ActionKind::ProposeIssuanceFee { amount_atoms } => {
                out.push(5);
                u64_bytes(&mut out, *amount_atoms);
            }
            ActionKind::CancelIssuanceFee { proposal_sequence } => {
                out.push(6);
                u64_bytes(&mut out, *proposal_sequence);
            }
            ActionKind::ProposeDestination {
                target: destination,
                address,
            } => {
                out.push(0);
                target(&mut out, *destination);
                out.extend_from_slice(address.as_ref());
            }
            ActionKind::CancelDestination { proposal_sequence } => {
                out.push(1);
                u64_bytes(&mut out, *proposal_sequence);
            }
            ActionKind::CancelJointChange { proposal_sequence } => {
                out.push(4);
                u64_bytes(&mut out, *proposal_sequence);
            }
            ActionKind::RotateOwnerKeys {
                founder,
                revocation,
            } => {
                out.push(2);
                out.extend_from_slice(founder.as_ref());
                out.extend_from_slice(revocation.as_ref());
            }
            ActionKind::ReplaceCheckpointSigners { replacements } => {
                require(
                    replacements.len() <= 3,
                    "governance replacement count exceeds fixed roster",
                )?;
                out.extend_from_slice(&[3, replacements.len() as u8]);
                for item in replacements {
                    out.push(item.slot);
                    out.extend_from_slice(&item.key);
                }
            }
        }
        require(
            out.len() <= MAX_UNSIGNED_BYTES,
            "governance unsigned action byte bound exceeded",
        )?;
        Ok(out)
    }
    pub fn decode_unsigned(bytes: &[u8]) -> Result<Self, String> {
        require(
            bytes.len() <= MAX_UNSIGNED_BYTES,
            "governance unsigned action byte bound exceeded",
        )?;
        let mut reader = Reader(bytes);
        require(
            &reader.array::<8>()? == ACTION_MAGIC,
            "governance action version mismatch",
        )?;
        let network = reader.array()?;
        let sequence = reader.u64()?;
        let kind = match reader.byte()? {
            5 => ActionKind::ProposeIssuanceFee {
                amount_atoms: reader.u64()?,
            },
            6 => ActionKind::CancelIssuanceFee {
                proposal_sequence: reader.u64()?,
            },
            0 => ActionKind::ProposeDestination {
                target: reader.target()?,
                address: Box::new(reader.array()?),
            },
            1 => ActionKind::CancelDestination {
                proposal_sequence: reader.u64()?,
            },
            4 => ActionKind::CancelJointChange {
                proposal_sequence: reader.u64()?,
            },
            2 => ActionKind::RotateOwnerKeys {
                founder: Box::new(reader.array()?),
                revocation: Box::new(reader.array()?),
            },
            3 => {
                let count = usize::from(reader.byte()?);
                require(
                    count > 0 && count <= 3,
                    "governance replacement count invalid",
                )?;
                let mut replacements = Vec::with_capacity(count);
                for _ in 0..count {
                    replacements.push(SlotReplacement {
                        slot: reader.byte()?,
                        key: reader.array()?,
                    });
                }
                require(
                    replacements.iter().all(|item| item.slot < 3)
                        && replacements
                            .windows(2)
                            .all(|pair| pair[0].slot < pair[1].slot),
                    "noncanonical governance replacement slots",
                )?;
                ActionKind::ReplaceCheckpointSigners { replacements }
            }
            _ => return Err("unknown governance action type".into()),
        };
        let action = Self {
            network,
            sequence,
            kind,
        };
        require(
            reader.0.is_empty() && action.unsigned_bytes()? == bytes,
            "noncanonical governance action encoding",
        )?;
        match &action.kind {
            ActionKind::ProposeIssuanceFee { amount_atoms } => {
                IssuanceFeeParameters::default().check_amount(*amount_atoms)?;
            }
            ActionKind::ProposeDestination { address, .. } => {
                decode_address(address.as_ref())?;
            }
            ActionKind::CancelDestination { proposal_sequence }
            | ActionKind::CancelJointChange { proposal_sequence }
            | ActionKind::CancelIssuanceFee { proposal_sequence } => {
                require(*proposal_sequence > 0, "zero cancellation sequence")?;
            }
            ActionKind::RotateOwnerKeys {
                founder,
                revocation,
            } => owner_keys(founder, revocation)?,
            ActionKind::ReplaceCheckpointSigners { replacements } => {
                require(
                    replacements
                        .iter()
                        .all(|item| item.key != [0; PUBLIC_KEY_BYTES]),
                    "zero replacement signer key",
                )?;
            }
        }
        Ok(action)
    }
    /// The role is in the signed message as well as the typed authorization.
    pub fn signing_bytes(&self, role: SignerRole) -> Result<Vec<u8>, String> {
        let mut bytes = b"siworld eng2 governance action signature v1\0".to_vec();
        bytes.extend_from_slice(&self.unsigned_bytes()?);
        bytes.push(role_byte(role)?);
        Ok(bytes)
    }
}
impl SignedAction {
    pub const MAX_ENCODED_BYTES: usize = MAX_SIGNED_BYTES;
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        require(
            !self.signatures.is_empty() && self.signatures.len() <= 2,
            "governance signature count invalid",
        )?;
        let body = self.action.unsigned_bytes()?;
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out.push(self.signatures.len() as u8);
        let mut previous = None;
        for signature in &self.signatures {
            let role = role_byte(signature.role)?;
            require(
                previous.is_none_or(|old| old < role),
                "governance signature roles must be ordered and distinct",
            )?;
            previous = Some(role);
            out.push(role);
            out.extend_from_slice(&signature.signature);
        }
        require(
            out.len() <= MAX_SIGNED_BYTES,
            "governance signed action byte bound exceeded",
        )?;
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        require(
            bytes.len() <= MAX_SIGNED_BYTES,
            "governance signed action byte bound exceeded",
        )?;
        let mut reader = Reader(bytes);
        let length = u32::from_le_bytes(reader.array()?) as usize;
        require(
            length <= MAX_UNSIGNED_BYTES,
            "governance unsigned action byte bound exceeded",
        )?;
        let action = Action::decode_unsigned(reader.take(length)?)?;
        let count = usize::from(reader.byte()?);
        require(
            count > 0 && count <= 2,
            "governance signature count invalid",
        )?;
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            let role = match reader.byte()? {
                0 => SignerRole::Founder,
                1 => SignerRole::Revocation,
                code @ 2..=4 => SignerRole::Checkpoint(code - 2),
                _ => return Err("unknown governance signer role".into()),
            };
            signatures.push(Authorization {
                role,
                signature: reader.array()?,
            });
        }
        let result = Self { action, signatures };
        require(
            reader.0.is_empty() && result.encode()? == bytes,
            "noncanonical signed governance action",
        )?;
        Ok(result)
    }
}
impl GovernanceState {
    /// Component 8 includes complete governance reconstruction context.
    /// Component 7 independently binds the exact active fee address bytes.
    pub fn canonical_component_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = STATE_MAGIC.to_vec();
        out.extend_from_slice(&self.network);
        u64_bytes(&mut out, self.height);
        u64_bytes(&mut out, self.sequence);
        out.extend_from_slice(&self.founder);
        out.extend_from_slice(&self.revocation);
        u64_bytes(&mut out, self.owner_epoch_sequence);
        u64_bytes(&mut out, self.owner_activated_height);
        roster(&mut out, &self.roster);
        out.extend_from_slice(&canonical_address(&self.fees));
        out.push(self.fund.len() as u8);
        for address in &self.fund {
            out.extend_from_slice(&canonical_address(address));
        }
        u64_bytes(&mut out, self.issuance_fee_parameters.initial_atoms);
        u64_bytes(&mut out, self.issuance_fee_parameters.minimum_atoms);
        u64_bytes(&mut out, self.issuance_fee_parameters.maximum_atoms);
        u64_bytes(&mut out, self.issuance_fee_atoms);
        u64_bytes(&mut out, self.issuance_fee_epoch_sequence);
        u64_bytes(&mut out, self.issuance_fee_activated_height);
        out.push(self.pending.len() as u8);
        for item in &self.pending {
            u64_bytes(&mut out, item.sequence);
            u64_bytes(&mut out, item.included_height);
            u64_bytes(&mut out, item.effective_height);
            match &item.kind {
                PendingKind::IssuanceFee { amount_atoms } => {
                    out.push(3);
                    u64_bytes(&mut out, *amount_atoms);
                }
                PendingKind::Destination {
                    target: destination,
                    address,
                } => {
                    out.push(0);
                    target(&mut out, *destination);
                    out.extend_from_slice(address.as_ref());
                }
                PendingKind::OwnerKeys {
                    founder,
                    revocation,
                } => {
                    out.push(1);
                    out.extend_from_slice(founder.as_ref());
                    out.extend_from_slice(revocation.as_ref());
                }
                PendingKind::Roster(value) => {
                    out.push(2);
                    roster(&mut out, value);
                }
            }
        }
        require(
            out.len() <= MAX_COMPONENT_BYTES,
            "governance component byte bound exceeded",
        )?;
        Ok(out)
    }
    pub fn decode_component(bytes: &[u8], expected_network: Hash) -> Result<Self, String> {
        require(
            bytes.len() <= MAX_COMPONENT_BYTES,
            "governance component byte bound exceeded",
        )?;
        let mut reader = Reader(bytes);
        require(
            &reader.array::<8>()? == STATE_MAGIC,
            "governance component version mismatch",
        )?;
        let network = reader.array()?;
        require(
            network == expected_network,
            "governance component network mismatch",
        )?;
        let height = reader.u64()?;
        let sequence = reader.u64()?;
        let founder = reader.array()?;
        let revocation = reader.array()?;
        let owner_epoch_sequence = reader.u64()?;
        let owner_activated_height = reader.u64()?;
        let roster = reader.roster()?;
        let fees = decode_address(reader.take(ADDRESS_BYTES)?)?;
        let count = usize::from(reader.byte()?);
        require(
            count <= MAX_FUND_MEMBERS,
            "governance fund member count exceeds bound",
        )?;
        let mut fund = Vec::with_capacity(count);
        for _ in 0..count {
            fund.push(decode_address(reader.take(ADDRESS_BYTES)?)?);
        }
        let issuance_fee_parameters = IssuanceFeeParameters {
            initial_atoms: reader.u64()?,
            minimum_atoms: reader.u64()?,
            maximum_atoms: reader.u64()?,
        };
        let issuance_fee_atoms = reader.u64()?;
        let issuance_fee_epoch_sequence = reader.u64()?;
        let issuance_fee_activated_height = reader.u64()?;
        let count = usize::from(reader.byte()?);
        require(
            count <= MAX_PENDING,
            "governance pending count exceeds bound",
        )?;
        let mut pending = Vec::with_capacity(count);
        for _ in 0..count {
            let sequence = reader.u64()?;
            let included_height = reader.u64()?;
            let effective_height = reader.u64()?;
            let kind = match reader.byte()? {
                3 => PendingKind::IssuanceFee {
                    amount_atoms: reader.u64()?,
                },
                0 => PendingKind::Destination {
                    target: reader.target()?,
                    address: Box::new(reader.array()?),
                },
                1 => PendingKind::OwnerKeys {
                    founder: Box::new(reader.array()?),
                    revocation: Box::new(reader.array()?),
                },
                2 => PendingKind::Roster(Box::new(reader.roster()?)),
                _ => return Err("unknown pending governance type".into()),
            };
            pending.push(Pending {
                sequence,
                included_height,
                effective_height,
                kind,
            });
        }
        let state = Self {
            network,
            height,
            sequence,
            founder,
            revocation,
            owner_epoch_sequence,
            owner_activated_height,
            roster,
            fees,
            fund,
            pending,
            issuance_fee_parameters,
            issuance_fee_atoms,
            issuance_fee_epoch_sequence,
            issuance_fee_activated_height,
        };
        state.validate()?;
        require(
            reader.0.is_empty() && state.canonical_component_bytes()? == bytes,
            "noncanonical governance component encoding",
        )?;
        Ok(state)
    }
}
