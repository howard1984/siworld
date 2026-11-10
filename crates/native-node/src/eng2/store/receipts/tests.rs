//! Synthetic public framing qualifies persistence only, never native acceptance.
use super::*;
use crate::{
    eng2::{body::Body, genesis::FeeMode, snapshot::tests::bootstrap},
    wire::*,
};
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;
use redb::{Database, ReadableDatabase, ReadableTableMetadata};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-receipt-persistence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn digest(value: u32) -> DigestBytes {
    let mut fields = [F::ZERO; 12];
    fields[0] = F::from_u32(value);
    encode_digest(&fields)
}

fn fixture() -> (Genesis, Header, usize, Vec<u8>) {
    let state = bootstrap();
    let genesis = Genesis::seal(
        state.chain().config.clone(),
        state.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let context = codec::Context::from_genesis(&genesis.encode().unwrap(), genesis.id()).unwrap();
    let mut transactions = (0..MIN_SLOTS)
        .map(|index| {
            let mut public = [0; PUBLIC_BYTES];
            for field in 0..5 {
                public[48 * field..48 * (field + 1)]
                    .copy_from_slice(&digest((10 + index * 5 + field) as u32));
            }
            Transaction {
                record: PublicRecord::new(
                    Snapshot {
                        height: 0,
                        block_id: genesis.id(),
                    },
                    public,
                    digest(100000 + index as u32),
                )
                .unwrap(),
                proof: vec![1; 2048],
            }
        })
        .collect::<Vec<_>>();
    transactions.sort_by_key(|tx| tx.record.statement_id(&context.config().network));
    let body = Body {
        network: context.config().network,
        height: 1,
        profile: context.profile(),
        transactions,
        reward_mode: RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: digest(200000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        }],
        fee_output: crate::eng2::execution::legacy_fee_output(),
        fund_claims: Vec::new(),
        governance: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![1],
    };
    let policy = crate::eng2::body::Policy {
        profile: context.profile(),
        max_body_bytes: codec::MAX_BODY_BYTES,
        max_settlement_proof_bytes: MAX_SETTLEMENT_PROOF,
    };
    let bytes = body.encode(policy).unwrap();
    let header = Header {
        network: body.network,
        height: 1,
        parent: genesis.id(),
        timestamp: 301,
        target: [255; 32],
        execution_commitment: [9; 32],
        body_commitment: body.commitment(policy).unwrap(),
        nonce: 1,
    };
    let receipt = codec::ReceiptBlock::export(&context, &header.encode().unwrap(), &bytes).unwrap();
    (genesis, header, bytes.len(), receipt)
}

fn database(directory: &Directory, header: &Header, body_bytes: usize) -> Database {
    let database = Database::create(directory.0.join("public.redb")).unwrap();
    let transaction = database.begin_write().unwrap();
    transaction
        .open_table(INDEX)
        .unwrap()
        .insert(
            header.height,
            super::super::compact_record(header, body_bytes)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    transaction.open_table(PERMANENT_RECEIPTS).unwrap();
    transaction.open_table(PERMANENT_RECEIPT_IDS).unwrap();
    transaction.commit().unwrap();
    database
}

#[test]
fn aborted_pair_is_atomic_and_completed_pair_is_idempotent() {
    let (genesis, header, body_bytes, bytes) = fixture();
    let directory = Directory::new();
    let database = database(&directory, &header, body_bytes);
    let checked = Checked::new(&genesis, &header, body_bytes, &bytes).unwrap();
    {
        let transaction = database.begin_write().unwrap();
        checked.write(&transaction).unwrap();
    }
    {
        let transaction = database.begin_read().unwrap();
        assert_eq!(
            transaction
                .open_table(PERMANENT_RECEIPTS)
                .unwrap()
                .len()
                .unwrap(),
            0
        );
        assert_eq!(
            transaction
                .open_table(PERMANENT_RECEIPT_IDS)
                .unwrap()
                .len()
                .unwrap(),
            0
        );
    }
    for _ in 0..2 {
        let transaction = database.begin_write().unwrap();
        checked.write(&transaction).unwrap();
        transaction.commit().unwrap();
    }
    drop(database);
    let reopened = redb::ReadOnlyDatabase::open(directory.0.join("public.redb")).unwrap();
    let transaction = reopened.begin_read().unwrap();
    let table = transaction.open_table(PERMANENT_RECEIPTS).unwrap();
    assert_eq!(table.len().unwrap(), 1);
    let stored = table.get(1).unwrap().unwrap();
    let verified = Checked::new(&genesis, &header, body_bytes, stored.value()).unwrap();
    let table = transaction.open_table(PERMANENT_RECEIPT_IDS).unwrap();
    assert_eq!(table.len().unwrap(), 1);
    assert_eq!(table.get(1).unwrap().unwrap().value(), verified.digest);
}

#[test]
fn authenticated_header_length_context_and_bytes_are_required() {
    let (genesis, header, body_bytes, bytes) = fixture();
    assert!(Checked::new(&genesis, &header, body_bytes + 1, &bytes).is_err());
    let mut changed_header = header.clone();
    changed_header.nonce += 1;
    assert!(Checked::new(&genesis, &changed_header, body_bytes, &bytes).is_err());
    let mut changed = bytes.clone();
    changed[8] ^= 1;
    assert!(Checked::new(&genesis, &header, body_bytes, &changed).is_err());
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(Checked::new(&genesis, &header, body_bytes, &changed).is_err());
    let directory = Directory::new();
    let database = database(&directory, &header, body_bytes + 1);
    let transaction = database.begin_write().unwrap();
    let checked = Checked::new(&genesis, &header, body_bytes, &bytes).unwrap();
    assert!(checked.write(&transaction).is_err());
    assert_eq!(
        transaction
            .open_table(PERMANENT_RECEIPTS)
            .unwrap()
            .len()
            .unwrap(),
        0
    );
    assert_eq!(
        transaction
            .open_table(PERMANENT_RECEIPT_IDS)
            .unwrap()
            .len()
            .unwrap(),
        0
    );
}

#[test]
fn conflicting_and_incomplete_pairs_are_preserved() {
    let (genesis, header, body_bytes, bytes) = fixture();
    let correct = *blake3::hash(&bytes).as_bytes();
    let bad = b"existing-conflicting-public-record".as_slice();
    for (stored_blob, stored_digest) in [
        (Some(bad), Some(correct)),
        (Some(bytes.as_slice()), Some([8; 32])),
        (Some(bad), Some([8; 32])),
        (Some(bytes.as_slice()), None),
        (None, Some(correct)),
    ] {
        let directory = Directory::new();
        let database = database(&directory, &header, body_bytes);
        let transaction = database.begin_write().unwrap();
        if let Some(value) = stored_blob {
            transaction
                .open_table(PERMANENT_RECEIPTS)
                .unwrap()
                .insert(1, value)
                .unwrap();
        }
        if let Some(value) = stored_digest {
            transaction
                .open_table(PERMANENT_RECEIPT_IDS)
                .unwrap()
                .insert(1, value.as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        let transaction = database.begin_write().unwrap();
        let checked = Checked::new(&genesis, &header, body_bytes, &bytes).unwrap();
        assert!(checked.write(&transaction).is_err());
        transaction.commit().unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(PERMANENT_RECEIPTS).unwrap();
        assert_eq!(table.len().unwrap(), u64::from(stored_blob.is_some()));
        if let Some(value) = stored_blob {
            assert_eq!(table.get(1).unwrap().unwrap().value(), value);
        }
        let table = transaction.open_table(PERMANENT_RECEIPT_IDS).unwrap();
        assert_eq!(table.len().unwrap(), u64::from(stored_digest.is_some()));
        if let Some(value) = stored_digest {
            assert_eq!(table.get(1).unwrap().unwrap().value(), value);
        }
    }
}
