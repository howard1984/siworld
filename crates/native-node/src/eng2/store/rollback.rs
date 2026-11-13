//! Bounded persistent snapshots of locally authenticated canonical states.
//!
//! Savepoints are recorded only after their complete state seal is committed.
//! This module owns the canonical database persistent-savepoint namespace.
//! It does not select or execute a competing branch.

use crate::wire::Hash;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

const POINTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-canonical-rollback-points-v1");
pub const RETAINED_STATES: usize = 25;
const RECORD_BYTES: usize = 72;

/// A persistent snapshot of one locally accepted state. This is not a peer
/// checkpoint certificate and cannot authorize an unverified branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackPoint {
    pub height: u64,
    pub block_id: Hash,
    pub execution_commitment: Hash,
    pub(super) savepoint: u64,
}

fn decode(height: u64, bytes: &[u8]) -> Result<RollbackPoint, String> {
    if bytes.len() != RECORD_BYTES {
        return Err("rollback point record width rejected".into());
    }
    Ok(RollbackPoint {
        height,
        savepoint: u64::from_le_bytes(bytes[..8].try_into().expect("checked point width")),
        block_id: bytes[8..40].try_into().expect("checked point width"),
        execution_commitment: bytes[40..].try_into().expect("checked point width"),
    })
}
fn encode(point: RollbackPoint) -> [u8; RECORD_BYTES] {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&point.savepoint.to_le_bytes());
    bytes[8..40].copy_from_slice(&point.block_id);
    bytes[40..].copy_from_slice(&point.execution_commitment);
    bytes
}

fn read_index(database: &Database) -> Result<Vec<RollbackPoint>, String> {
    let read = database
        .begin_read()
        .map_err(|_| "rollback point read unavailable")?;
    let table = match read.open_table(POINTS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(_) => return Err("rollback point table unavailable".into()),
    };
    table
        .iter()
        .map_err(|_| "rollback point range unavailable")?
        .map(|row| {
            let (height, bytes) = row.map_err(|_| "rollback point record unavailable")?;
            decode(height.value(), bytes.value())
        })
        .collect()
}

/// The index is itself part of a user-table snapshot. Restoring an older
/// snapshot can resurrect an index row for an already pruned savepoint. Such a
/// row never makes a deleted point usable and is omitted from this view.
pub(super) fn read(database: &Database) -> Result<Vec<RollbackPoint>, String> {
    let indexed = read_index(database)?;
    let transaction = database
        .begin_write()
        .map_err(|_| "rollback point registry read unavailable")?;
    let persistent: Vec<_> = transaction
        .list_persistent_savepoints()
        .map_err(|_| "rollback point registry unavailable")?
        .collect();
    transaction
        .abort()
        .map_err(|_| "rollback point registry read abort failed")?;
    Ok(indexed
        .into_iter()
        .filter(|point| persistent.contains(&point.savepoint))
        .collect())
}

/// Capture a fully committed state before opening any mutable data table.
/// Reopening after a crash between the canonical commit and this transaction
/// captures only the verified current head; it never invents historical points.
pub(super) fn remember(
    database: &Database,
    height: u64,
    block_id: Hash,
    execution_commitment: Hash,
) -> Result<(), String> {
    let indexed = read_index(database)?;
    let mut transaction = database
        .begin_write()
        .map_err(|_| "rollback point transaction unavailable")?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| "rollback point durability unavailable")?;
    transaction.set_quick_repair(true);
    let persistent: Vec<_> = transaction
        .list_persistent_savepoints()
        .map_err(|_| "rollback point registry unavailable")?
        .collect();
    if indexed.len() > RETAINED_STATES || indexed.iter().any(|point| point.height > height) {
        return Err("rollback point index exceeds accepted state window".into());
    }
    let previous: Vec<_> = indexed
        .iter()
        .copied()
        .filter(|point| persistent.contains(&point.savepoint))
        .collect();
    let stale: Vec<_> = indexed
        .iter()
        .filter(|point| !persistent.contains(&point.savepoint))
        .map(|point| point.height)
        .collect();
    if let Some(point) = previous.iter().find(|point| point.height == height) {
        if point.block_id != block_id || point.execution_commitment != execution_commitment {
            return Err("rollback point differs from accepted head".into());
        }
        if stale.is_empty() {
            transaction
                .abort()
                .map_err(|_| "rollback point no-op abort failed")?;
            return Ok(());
        }
        let mut table = transaction
            .open_table(POINTS)
            .map_err(|_| "rollback point repair table unavailable")?;
        for height in stale {
            table
                .remove(height)
                .map_err(|_| "rollback point stale index pruning failed")?;
        }
        drop(table);
        return transaction
            .commit()
            .map_err(|_| "rollback point repair commit failed".to_owned());
    }
    // The restored snapshot precedes insertion of its own index row. Its
    // retained point can therefore be unindexed after a committed restore.
    // This namespace has one owner; reclaim those points before recapturing.
    for id in persistent
        .iter()
        .filter(|id| !previous.iter().any(|point| point.savepoint == **id))
    {
        transaction
            .delete_persistent_savepoint(*id)
            .map_err(|_| "rollback unindexed point pruning failed")?;
    }
    let savepoint = transaction
        .persistent_savepoint()
        .map_err(|_| "rollback point creation failed")?;
    let point = RollbackPoint {
        height,
        block_id,
        execution_commitment,
        savepoint,
    };
    let obsolete = previous
        .len()
        .saturating_add(1)
        .saturating_sub(RETAINED_STATES);
    // Prune only the oldest accepted states from the bounded canonical window.
    for old in previous.iter().take(obsolete) {
        if !transaction
            .delete_persistent_savepoint(old.savepoint)
            .map_err(|_| "rollback point pruning failed")?
        {
            return Err("rollback point disappeared during pruning".into());
        }
    }
    {
        let mut table = transaction
            .open_table(POINTS)
            .map_err(|_| "rollback point table unavailable")?;
        for old in previous.iter().take(obsolete) {
            table
                .remove(old.height)
                .map_err(|_| "rollback point index pruning failed")?;
        }
        for height in stale {
            table
                .remove(height)
                .map_err(|_| "rollback point stale index pruning failed")?;
        }
        table
            .insert(height, encode(point).as_slice())
            .map_err(|_| "rollback point index write failed")?;
    }
    transaction
        .commit()
        .map_err(|_| "rollback point durable commit failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    const STATE: TableDefinition<u64, u64> = TableDefinition::new("fixture-state");
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "eng2-rollback-window-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn open(&self) -> Database {
            Database::create(self.0.join("state.redb")).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn commit(db: &Database, height: u64, value: u64) {
        let tx = db.begin_write().unwrap();
        {
            tx.open_table(STATE).unwrap().insert(height, value).unwrap();
        }
        tx.commit().unwrap();
    }
    #[test]
    fn retains_twenty_five_distinct_states_across_reopen() {
        let fixture = Fixture::new();
        let db = fixture.open();
        for height in 0..32 {
            commit(&db, height, 100 + height);
            remember(&db, height, [height as u8; 32], [7; 32]).unwrap();
        }
        let points = read(&db).unwrap();
        assert_eq!(points.len(), 25);
        assert_eq!(points[0].height, 7);
        assert_eq!(points[24].height, 31);
        drop(db);
        let db = fixture.open();
        assert_eq!(read(&db).unwrap(), points);
        let mut tx = db.begin_write().unwrap();
        let saved = tx.get_persistent_savepoint(points[0].savepoint).unwrap();
        tx.restore_savepoint(&saved).unwrap();
        {
            let table = tx.open_table(STATE).unwrap();
            assert_eq!(table.get(7).unwrap().unwrap().value(), 107);
            assert!(table.get(8).unwrap().is_none());
        }
        tx.abort().unwrap();
    }
    #[test]
    fn committed_restore_reconciles_resurrected_pruned_index_rows() {
        let fixture = Fixture::new();
        let db = fixture.open();
        for height in 0..32 {
            commit(&db, height, 100 + height);
            remember(&db, height, [height as u8; 32], [7; 32]).unwrap();
        }
        let points = read(&db).unwrap();
        let anchor = points.iter().find(|p| p.height == 25).unwrap();
        let mut tx = db.begin_write().unwrap();
        let saved = tx.get_persistent_savepoint(anchor.savepoint).unwrap();
        tx.restore_savepoint(&saved).unwrap();
        tx.commit().unwrap();
        // Snapshot metadata can mention deleted old points. They do not revive.
        assert!(
            read(&db)
                .unwrap()
                .iter()
                .all(|p| p.height >= 7 && p.height < 25)
        );
        remember(&db, 25, [25; 32], [7; 32]).unwrap();
        let after = read(&db).unwrap();
        assert_eq!(after.last().unwrap().height, 25);
        assert_eq!(read_index(&db).unwrap(), after);
        for height in 26..=33 {
            commit(&db, height, 200 + height);
            remember(&db, height, [height as u8; 32], [8; 32]).unwrap();
        }
        assert_eq!(read(&db).unwrap().len(), 25);
        let tx = db.begin_write().unwrap();
        assert_eq!(tx.list_persistent_savepoints().unwrap().count(), 25);
        tx.abort().unwrap();
    }
    #[test]
    fn repeated_capture_is_idempotent_and_conflicting_identity_rejected() {
        let fixture = Fixture::new();
        let db = fixture.open();
        commit(&db, 0, 100);
        remember(&db, 0, [1; 32], [2; 32]).unwrap();
        let before = read(&db).unwrap();
        remember(&db, 0, [1; 32], [2; 32]).unwrap();
        assert_eq!(read(&db).unwrap(), before);
        assert!(remember(&db, 0, [3; 32], [2; 32]).is_err());
        assert_eq!(read(&db).unwrap(), before);
    }
    #[test]
    fn missing_capture_after_canonical_commit_seeds_only_current_state() {
        let fixture = Fixture::new();
        let db = fixture.open();
        commit(&db, 24, 124);
        drop(db);
        let db = fixture.open();
        assert!(read(&db).unwrap().is_empty());
        remember(&db, 24, [4; 32], [5; 32]).unwrap();
        let points = read(&db).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].height, 24);
    }
}
