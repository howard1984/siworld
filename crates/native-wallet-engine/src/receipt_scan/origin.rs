//! Complete receipt output origins; category indexes are not identities.
use super::{Error, Result};
use crate::{
    eng2_history::ReceiptBlock,
    wire::{DigestBytes, Hash},
};
use native::codec::{PublicTransaction, encode_digest};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
pub enum OriginKind {
    Transaction {
        statement: Hash,
        slot: u32,
        output: u8,
    },
    Issuance {
        declaration: Hash,
        record: u32,
        output: u32,
    },
    Reward {
        ordinal: u32,
    },
    Fund {
        account: u8,
        counter: u64,
        ordinal: u32,
    },
}
#[derive(Clone, PartialEq, Eq)]
pub struct Origin {
    pub height: u64,
    pub block: Hash,
    pub kind: OriginKind,
    pub commitment: DigestBytes,
}
pub(crate) fn enumerate(receipt: &ReceiptBlock) -> Result<BTreeMap<DigestBytes, Vec<Origin>>> {
    let header = receipt.header();
    let block = header.id().map_err(|_| Error::Rejected("origin_header"))?;
    let mut result = BTreeMap::<DigestBytes, Vec<Origin>>::new();
    let mut insert = |commitment, kind| {
        result.entry(commitment).or_default().push(Origin {
            height: header.height,
            block,
            kind,
            commitment,
        });
    };
    for (slot, record) in receipt.transactions().iter().enumerate() {
        let public = PublicTransaction::decode(&record.body)
            .map_err(|_| Error::Rejected("origin_transaction"))?;
        let slot = u32::try_from(slot).map_err(|_| Error::Incomplete("origin_capacity"))?;
        for (index, cm) in public.cm.iter().enumerate() {
            insert(
                encode_digest(cm),
                OriginKind::Transaction {
                    statement: record.statement_id(&header.network),
                    slot,
                    output: u8::try_from(index)
                        .map_err(|_| Error::Incomplete("origin_capacity"))?,
                },
            );
        }
    }
    for (index, record) in receipt.issuances().iter().enumerate() {
        for (output, cm) in record
            .signed
            .declaration
            .note_commitments
            .iter()
            .enumerate()
        {
            insert(
                encode_digest(cm),
                OriginKind::Issuance {
                    declaration: record.signed.declaration.binding(),
                    record: u32::try_from(index)
                        .map_err(|_| Error::Incomplete("origin_capacity"))?,
                    output: u32::try_from(output)
                        .map_err(|_| Error::Incomplete("origin_capacity"))?,
                },
            );
        }
    }
    for (index, record) in receipt.rewards().iter().enumerate() {
        insert(
            record.commitment,
            OriginKind::Reward {
                ordinal: u32::try_from(index).map_err(|_| Error::Incomplete("origin_capacity"))?,
            },
        );
    }
    for (index, record) in receipt.fund_outputs().iter().enumerate() {
        insert(
            record.commitment,
            OriginKind::Fund {
                account: record.account,
                counter: record.counter,
                ordinal: u32::try_from(index).map_err(|_| Error::Incomplete("origin_capacity"))?,
            },
        );
    }
    Ok(result)
}

/// Enumerate authenticated public origins. The caller selects the exact header.
pub fn output_origins(receipt: &ReceiptBlock) -> Result<Vec<Origin>> {
    Ok(enumerate(receipt)?.into_values().flatten().collect())
}
