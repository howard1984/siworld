//! Research-only reference model for confidential fee settlement.
//!
//! This module models the fee-opening checks that a future native block-level
//! settlement AIR must enforce. It is deliberately outside the node and
//! consensus crates: callers must not use it to credit a miner or mutate
//! state. The model is useful for sizing, test vectors, and rejection tests
//! while the settlement AIR and the wallet-to-miner witness channel remain
//! under design.

use crate::common::{Digest, F, FEE_BASE, FEE_BLIND_LEN, FEE_PRIORITY, Hasher};

/// The private fee opening carried by a wallet/mempool witness.
///
/// `dummy` and `priority` are witness flags. A dummy opening must have zero
/// fee and a real opening must have either the standard or priority fee. The
/// flags are intentionally not part of the public commitment statement; the
/// settlement relation checks them against the opening's fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeOpening {
    pub fee: u64,
    pub blind: [F; FEE_BLIND_LEN],
    pub dummy: bool,
    pub priority: bool,
}

/// The private fee witness delivered with a transaction through the mempool
/// sidecar.  The transaction's public proof statement carries the matching
/// commitment; the sidecar carries only the opening and the binding digest
/// needed to prevent moving an opening to another transaction.
///
/// This evaluation type intentionally has no signature or second encryption
/// layer.  Production transport confidentiality and peer authentication are
/// provided by the planned X25519 + ML-KEM connection handshake.  Every node
/// that receives a sidecar can independently recompute the commitment before
/// forwarding it or using it for settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSidecar {
    pub transaction_binding: Digest,
    pub opening: FeeOpening,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarError {
    Missing,
    TransactionBindingMismatch,
    CommitmentMismatch,
}

/// Validate a received sidecar against the transaction's public binding and
/// fee commitment.  Callers must discard a sidecar on any error and record the
/// bounded peer-abuse event in their normal relay diagnostics.
pub fn validate_sidecar<'a>(
    hasher: &Hasher,
    transaction_binding: &Digest,
    fee_commitment: &Digest,
    sidecar: Option<&'a FeeSidecar>,
) -> Result<&'a FeeOpening, SidecarError> {
    let sidecar = sidecar.ok_or(SidecarError::Missing)?;
    if &sidecar.transaction_binding != transaction_binding {
        return Err(SidecarError::TransactionBindingMismatch);
    }
    if &hasher.fee_commit(sidecar.opening.fee, &sidecar.opening.blind) != fee_commitment {
        return Err(SidecarError::CommitmentMismatch);
    }
    Ok(&sidecar.opening)
}

impl FeeOpening {
    pub fn dummy(blind: [F; FEE_BLIND_LEN]) -> Self {
        Self {
            fee: 0,
            blind,
            dummy: true,
            priority: false,
        }
    }

    pub fn standard(blind: [F; FEE_BLIND_LEN]) -> Self {
        Self {
            fee: FEE_BASE,
            blind,
            dummy: false,
            priority: false,
        }
    }

    pub fn priority(blind: [F; FEE_BLIND_LEN]) -> Self {
        Self {
            fee: FEE_PRIORITY,
            blind,
            dummy: false,
            priority: true,
        }
    }

    /// Construct an opening for a caller-supplied base fee. This is used by
    /// the reference model and tests; production fee schedules must remain
    /// anchored to the accepted snapshot in the transaction AIR.
    pub fn for_base_fee(
        base_fee: u64,
        dummy: bool,
        priority: bool,
        blind: [F; FEE_BLIND_LEN],
    ) -> Self {
        let fee = if dummy {
            0
        } else if priority {
            base_fee.checked_mul(4).expect("priority fee overflow")
        } else {
            base_fee
        };
        Self {
            fee,
            blind,
            dummy,
            priority,
        }
    }
}

/// One fixed-shape transaction position in the settlement witness.
///
/// The transaction proof and its binding digest are checked by the transaction
/// verifier. This reference model receives the already-decoded fee commitment
/// and checks only the opening and fee-accounting part of settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementSlot {
    pub commitment: Digest,
    pub opening: FeeOpening,
}

impl SettlementSlot {
    pub fn from_opening(hasher: &Hasher, opening: FeeOpening) -> Self {
        // The benchmark's existing fee commitment is used as a deterministic
        // oracle here. A production Scheme B commitment must replace this
        // call with the approved context-bound fee domain before activation.
        let commitment = hasher.fee_commit(opening.fee, &opening.blind);
        Self {
            commitment,
            opening,
        }
    }
}

/// Errors rejected by the reference settlement relation before any state
/// mutation. The production AIR should expose equivalent failure classes in
/// private diagnostics, while public protocol responses remain bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementError {
    EmptySettlement,
    DuplicateCommitment { index: usize },
    DummyFeeNonZero { index: usize, fee: u64 },
    RealFeeZero { index: usize },
    WrongFeeTier { index: usize, fee: u64 },
    CommitmentMismatch { index: usize },
    FeeSumOverflow,
    RewardOverflow,
    MinerUnlockOverflow,
    MinerAmountMismatch { expected: u64, actual: u64 },
}

/// Private result returned by the reference checker. `total_fee` is for
/// diagnostics and benchmark accounting only; it must not be serialized as a
/// public block field or emitted by node metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub total_fee: u64,
    pub miner_amount: u64,
    pub positions: usize,
}

/// Check a fixed-capacity fee settlement witness.
///
/// The `base_fee` and `issuance_reward` inputs are trusted values from the
/// candidate block context. Every commitment is recomputed from its opening,
/// each fee is checked against the standard/priority schedule, and the miner
/// amount must equal `issuance_reward + sum(fee_i)`. This function is a
/// research oracle, not a consensus transition.
pub fn verify_settlement(
    hasher: &Hasher,
    slots: &[SettlementSlot],
    base_fee: u64,
    issuance_reward: u64,
    miner_amount: u64,
) -> Result<SettlementReceipt, SettlementError> {
    if slots.is_empty() {
        return Err(SettlementError::EmptySettlement);
    }

    let mut total_fee = 0u64;
    let mut seen: Vec<Digest> = Vec::with_capacity(slots.len());
    for (index, slot) in slots.iter().enumerate() {
        if seen.iter().any(|commitment| commitment == &slot.commitment) {
            return Err(SettlementError::DuplicateCommitment { index });
        }
        seen.push(slot.commitment);

        let opening = &slot.opening;
        if opening.dummy {
            if opening.fee != 0 {
                return Err(SettlementError::DummyFeeNonZero {
                    index,
                    fee: opening.fee,
                });
            }
            if opening.priority {
                return Err(SettlementError::WrongFeeTier { index, fee: 0 });
            }
        } else {
            if opening.fee == 0 {
                return Err(SettlementError::RealFeeZero { index });
            }
            let standard = base_fee;
            let priority = base_fee
                .checked_mul(4)
                .ok_or(SettlementError::FeeSumOverflow)?;
            if opening.fee != standard && opening.fee != priority {
                return Err(SettlementError::WrongFeeTier {
                    index,
                    fee: opening.fee,
                });
            }
            if opening.priority != (opening.fee == priority) {
                return Err(SettlementError::WrongFeeTier {
                    index,
                    fee: opening.fee,
                });
            }
        }

        let expected = hasher.fee_commit(opening.fee, &opening.blind);
        if expected != slot.commitment {
            return Err(SettlementError::CommitmentMismatch { index });
        }
        total_fee = total_fee
            .checked_add(opening.fee)
            .ok_or(SettlementError::FeeSumOverflow)?;
    }

    let expected_miner_amount = issuance_reward
        .checked_add(total_fee)
        .ok_or(SettlementError::RewardOverflow)?;
    if miner_amount != expected_miner_amount {
        return Err(SettlementError::MinerAmountMismatch {
            expected: expected_miner_amount,
            actual: miner_amount,
        });
    }

    Ok(SettlementReceipt {
        total_fee,
        miner_amount,
        positions: slots.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{DIGEST, F};
    use p3_field::PrimeCharacteristicRing;

    fn blind(seed: u32) -> [F; FEE_BLIND_LEN] {
        core::array::from_fn(|i| F::from_u32(seed + i as u32))
    }

    fn valid_slots(h: &Hasher) -> Vec<SettlementSlot> {
        vec![
            SettlementSlot::from_opening(h, FeeOpening::dummy(blind(1))),
            SettlementSlot::from_opening(h, FeeOpening::standard(blind(11))),
            SettlementSlot::from_opening(h, FeeOpening::priority(blind(21))),
        ]
    }

    #[test]
    fn accepts_standard_priority_and_dummy_openings() {
        let h = Hasher::new();
        let slots = valid_slots(&h);
        let expected = FEE_BASE + FEE_PRIORITY;
        let receipt = verify_settlement(&h, &slots, FEE_BASE, 100, 100 + expected).unwrap();
        assert_eq!(receipt.total_fee, expected);
        assert_eq!(receipt.positions, 3);
    }

    #[test]
    fn rejects_commitment_sum_that_differs_from_miner_reward() {
        let h = Hasher::new();
        let slots = valid_slots(&h);
        let expected = FEE_BASE + FEE_PRIORITY;
        let err = verify_settlement(&h, &slots, FEE_BASE, 100, 100 + expected + 1).unwrap_err();
        assert_eq!(
            err,
            SettlementError::MinerAmountMismatch {
                expected: 100 + expected,
                actual: 100 + expected + 1,
            }
        );
    }

    #[test]
    fn rejects_forged_opening() {
        let h = Hasher::new();
        let opening = FeeOpening::standard(blind(3));
        let mut slot = SettlementSlot::from_opening(&h, opening);
        slot.opening.blind = blind(99);
        let err = verify_settlement(&h, &[slot], FEE_BASE, 0, FEE_BASE).unwrap_err();
        assert_eq!(err, SettlementError::CommitmentMismatch { index: 0 });
    }

    #[test]
    fn rejects_dummy_with_nonzero_fee() {
        let h = Hasher::new();
        let opening = FeeOpening {
            fee: FEE_BASE,
            blind: blind(5),
            dummy: true,
            priority: false,
        };
        let slot = SettlementSlot::from_opening(&h, opening);
        let err = verify_settlement(&h, &[slot], FEE_BASE, 0, FEE_BASE).unwrap_err();
        assert_eq!(
            err,
            SettlementError::DummyFeeNonZero {
                index: 0,
                fee: FEE_BASE,
            }
        );
    }

    #[test]
    fn rejects_real_with_zero_fee() {
        let h = Hasher::new();
        let opening = FeeOpening {
            fee: 0,
            blind: blind(7),
            dummy: false,
            priority: false,
        };
        let slot = SettlementSlot::from_opening(&h, opening);
        let err = verify_settlement(&h, &[slot], FEE_BASE, 0, 0).unwrap_err();
        assert_eq!(err, SettlementError::RealFeeZero { index: 0 });
    }

    #[test]
    fn sidecar_opening_must_match_public_commitment() {
        let h = Hasher::new();
        let binding = [F::from_u32(7); DIGEST];
        let opening = FeeOpening::standard(blind(31));
        let commitment = h.fee_commit(opening.fee, &opening.blind);
        let sidecar = FeeSidecar {
            transaction_binding: binding,
            opening: FeeOpening::standard(blind(32)),
        };
        assert_eq!(
            validate_sidecar(&h, &binding, &commitment, Some(&sidecar)),
            Err(SidecarError::CommitmentMismatch)
        );
    }

    #[test]
    fn missing_sidecar_is_rejected_before_settlement() {
        let h = Hasher::new();
        let binding = [F::from_u32(8); DIGEST];
        let commitment = h.fee_commit(FEE_BASE, &blind(41));
        assert_eq!(
            validate_sidecar(&h, &binding, &commitment, None),
            Err(SidecarError::Missing)
        );
    }

    #[test]
    fn sidecar_cannot_be_replayed_for_another_transaction() {
        let h = Hasher::new();
        let sidecar_binding = [F::from_u32(9); DIGEST];
        let transaction_binding = [F::from_u32(10); DIGEST];
        let opening = FeeOpening::priority(blind(51));
        let commitment = h.fee_commit(opening.fee, &opening.blind);
        let sidecar = FeeSidecar {
            transaction_binding: sidecar_binding,
            opening,
        };
        assert_eq!(
            validate_sidecar(&h, &transaction_binding, &commitment, Some(&sidecar)),
            Err(SidecarError::TransactionBindingMismatch)
        );
    }
}
