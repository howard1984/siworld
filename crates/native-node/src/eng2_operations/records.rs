//! Deterministic public governance records from the actual committed capability.
//! This adapter performs no persistence or notification. A runtime must finish
//! durable block/state saving before publishing this in-memory commit view.
use crate::{eng2::execution::CommittedBlock, eng2_governance::Inclusion, wire::Hash};
use serde_json::json;
pub const MAX_RECORD_BYTES: usize = 32768;

/// An empty governance block produces no record. The public API accepts no
/// candidate, prepared transition, generic JSON or freely constructible receipt.
///
/// A prepared or fabricated receipt cannot satisfy the committed-only interface:
/// ```compile_fail
/// use siworld_native_node::eng2::execution::CommittedBlock;
/// use siworld_native_node::eng2_operations::records::committed_governance_records;
/// let fabricated = CommittedBlock {
///     network: [1;32], height: 1, id: [2;32],
///     execution_commitment: [3;32], inclusions: vec![],
/// };
/// let _ = committed_governance_records(&fabricated);
/// ```
pub fn committed_governance_records(block: &CommittedBlock) -> Result<Option<Vec<u8>>, String> {
    encode(
        block.network(),
        block.height(),
        block.id(),
        block.execution_commitment(),
        block.inclusions(),
    )
}
fn encode(
    network: Hash,
    height: u64,
    id: Hash,
    commitment: Hash,
    inclusions: &[Inclusion],
) -> Result<Option<Vec<u8>>, String> {
    if inclusions.is_empty() {
        return Ok(None);
    }
    if inclusions.len() > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
        || inclusions.iter().any(|row| {
            row.included_height != height || row.sequence == 0 || row.effective_height < height
        })
        || !inclusions
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    {
        return Err("committed governance record invariant differs".into());
    }
    let records = inclusions.iter().map(|row| {
        let mut value = json!({"sequence":row.sequence.to_string(),
            "included_height":row.included_height.to_string(),"effective_height":row.effective_height.to_string(),
            "action_digest":super::hex(&row.action_digest)});
        if let Some(amount) = row.new_issuance_fee_atoms {
            value["new_issuance_fee_atoms"] = json!(amount.to_string());
        }
        value
    }).collect::<Vec<_>>();
    let bytes=serde_json::to_vec(&json!({"schema_version":1,"network":super::hex(&network),
        "height":height.to_string(),"block_id":super::hex(&id),"execution_commitment":super::hex(&commitment),
        "governance_inclusions":records}))
        .map_err(|_|"cannot encode committed governance record")?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("committed governance record exceeds bound".into());
    }
    Ok(Some(bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_complete_record_has_no_clock_or_candidate_fields() {
        let inclusion = Inclusion {
            sequence: 9007199254740993,
            included_height: 25,
            effective_height: 4057,
            action_digest: [7; 32],
            new_issuance_fee_atoms: None,
        };
        let first = encode(
            [1; 32],
            25,
            [2; 32],
            [3; 32],
            std::slice::from_ref(&inclusion),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            first,
            encode([1; 32], 25, [2; 32], [3; 32], &[inclusion])
                .unwrap()
                .unwrap()
        );
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(
            value["governance_inclusions"][0]["sequence"],
            "9007199254740993"
        );
        assert_eq!(value["height"], "25");
        assert!(first.len() < MAX_RECORD_BYTES);
    }
    #[test]
    fn empty_changes_have_no_record_and_inconsistent_inclusions_fail_closed() {
        assert!(
            encode([1; 32], 25, [2; 32], [3; 32], &[])
                .unwrap()
                .is_none()
        );
        let mut inclusion = Inclusion {
            sequence: 1,
            included_height: 24,
            effective_height: 4057,
            action_digest: [7; 32],
            new_issuance_fee_atoms: None,
        };
        assert!(
            encode(
                [1; 32],
                25,
                [2; 32],
                [3; 32],
                std::slice::from_ref(&inclusion)
            )
            .is_err()
        );
        inclusion.included_height = 25;
        assert!(
            encode(
                [1; 32],
                25,
                [2; 32],
                [3; 32],
                &[inclusion.clone(), inclusion]
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod issuance_fee_tests {
    use super::*;
    #[test]
    fn committed_public_record_includes_new_exact_issuance_fee_amount() {
        let record = Inclusion {
            sequence: 1,
            included_height: 25,
            effective_height: 4057,
            action_digest: [7; 32],
            new_issuance_fee_atoms: Some(100_000_000),
        };
        let bytes = encode([1; 32], 25, [2; 32], [3; 32], &[record])
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["governance_inclusions"][0]["new_issuance_fee_atoms"],
            "100000000"
        );
    }
}
