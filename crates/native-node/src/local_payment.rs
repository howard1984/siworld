//! Stopped-store engineering payment inclusion through the native node owner.

use crate::producer::{self, MiningSettings};
use crate::proofs::{NativeProver, NativeVerifier};
use crate::runtime::Node;
use crate::service::ClockGuard;
use crate::state::BlockVerifier;
use crate::wire::{Hash, MIN_SLOTS};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OPERATION_LIMIT: Duration = Duration::from_secs(60 * 60);

/// Public confirmation only. Wallet amounts, fee openings and recovery material
/// remain in the caller's encrypted vault and the node's private reward index.
pub struct PaymentMiningReceipt {
    pub transaction_id: Hash,
    pub height: u64,
    pub tip: Hash,
    pub state_fingerprint: Hash,
    pub local_reward_receipts_checked: u64,
}

fn admit_payment<V: BlockVerifier>(
    node: &mut Node<V>,
    envelope: &[u8],
    sidecar: &[u8],
) -> Result<Hash, String> {
    if node.state().config.fixture || node.state().config.fund_allocation.is_none() {
        return Err(
            "payment mining requires an ASERT engineering network and fund allocation".into(),
        );
    }
    if !node.mempool().is_empty() {
        return Err("stopped-store payment mining requires an empty pending pool".into());
    }
    node.submit_local(envelope, Some(sidecar))
        .map_err(|_| "native payment and fee sidecar admission rejected".into())
}

struct OperationClock {
    start: Instant,
    guard: ClockGuard,
}
impl OperationClock {
    fn wall_ms() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock precedes epoch")?
            .as_millis()
            .try_into()
            .map_err(|_| "system clock range exceeded".into())
    }
    fn new() -> Result<Self, String> {
        Ok(Self {
            start: Instant::now(),
            guard: ClockGuard::new(Self::wall_ms()?),
        })
    }
    fn now_seconds(&mut self) -> Result<u64, String> {
        let elapsed = self.start.elapsed();
        if elapsed >= OPERATION_LIMIT {
            return Err(
                "payment mining deadline exceeded; preserve wallet and node evidence".into(),
            );
        }
        let wall = Self::wall_ms()?;
        self.guard.observe(
            wall,
            elapsed
                .as_millis()
                .try_into()
                .map_err(|_| "payment operation duration range exceeded")?,
        )?;
        Ok(wall / 1000)
    }
}

/// Include one already authorized wallet packet with genuine native proofs and
/// PoW. The caller must retain the node-directory lifetime lease, its encrypted
/// payment journal, and exclusive ownership of this node throughout the call.
/// This function opens no listener and cannot access a concurrently running
/// service's store. It does not advance wallet policy time or unlock heights.
///
/// A one-hour cooperative bound is checked between synchronous proof operations
/// and during PoW; an in-progress prover call cannot be safely preempted. An
/// error after commit requires reconciliation against canonical history before
/// a caller considers retrying the retained journal entry.
pub fn submit_and_mine_with_node(
    node: &mut Node<NativeVerifier>,
    envelope: &[u8],
    sidecar: &[u8],
    settings: &MiningSettings,
) -> Result<PaymentMiningReceipt, String> {
    if std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("4")
        || std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").as_deref() != Ok("2")
    {
        return Err(
            "payment mining requires RAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2"
                .into(),
        );
    }
    let mut clock = OperationClock::new()?;
    node.store().verify_local_rewards()?;
    let transaction_id = admit_payment(node, envelope, sidecar)?;
    let permit = node
        .begin_production()
        .map_err(|_| "payment production authorization unavailable")?;
    let prover = NativeProver::new()?;
    let mut positions = node
        .select_pending(MIN_SLOTS)
        .map_err(|_| "native payment selection failed")?;
    if positions.len() != 1
        || positions[0]
            .transaction
            .record
            .statement_id(&node.state().config.network)
            != transaction_id
    {
        return Err("selected payment differs from the authorized packet".into());
    }
    while positions.len() < MIN_SLOTS {
        clock.now_seconds()?;
        positions.push(producer::prepare_padding(node.state(), &prover)?);
    }
    let minimum_timestamp = node
        .state()
        .median_time_past()
        .checked_add(1)
        .ok_or("payment block timestamp exhausted")?;
    let timestamp = clock.now_seconds()?.max(minimum_timestamp);
    let mut produced = producer::assemble(node.state(), &prover, positions, timestamp, settings)?;
    let mut seed = produced.block.pow_seed()?;
    let mut checked_at = Instant::now();
    loop {
        let work = siworld_core::pow::pow_hash(
            &seed,
            produced.block.nonce,
            node.state().config.pow_iterations,
        );
        if siworld_core::pow::meets_target(&work, &produced.block.target) {
            break;
        }
        if checked_at.elapsed() >= Duration::from_millis(500) {
            let timestamp = clock.now_seconds()?.max(minimum_timestamp);
            if timestamp > produced.block.timestamp {
                produced.block.timestamp = timestamp;
                seed = produced.block.pow_seed()?;
            }
            checked_at = Instant::now();
        }
        produced.block.nonce = produced
            .block
            .nonce
            .checked_add(1)
            .ok_or("payment proof-of-work nonce exhausted")?;
    }
    clock.now_seconds()?;
    if !produced.block.transactions.iter().any(|transaction| {
        transaction
            .record
            .statement_id(&node.state().config.network)
            == transaction_id
    }) {
        return Err("completed block omitted the authorized payment".into());
    }
    let prepared = node
        .bind_produced(permit, produced)
        .map_err(|_| "payment block became stale before commit")?;
    node.commit_produced(prepared)
        .map_err(|_| "native payment block or reward durability rejected")?;
    if node.mempool().contains(&transaction_id) {
        return Err("accepted payment remains reserved; reconcile retained evidence".into());
    }
    Ok(PaymentMiningReceipt {
        transaction_id,
        height: node.state().height,
        tip: node.state().tip,
        state_fingerprint: node.state().fingerprint(),
        local_reward_receipts_checked: node.store().verify_local_rewards()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};
    use crate::state::Config;
    use crate::store::Store;
    use crate::wire::Sidecar;
    use native::codec::encode_digest;
    use native::multi_asset::{F, Hasher};
    use p3_field::PrimeCharacteristicRing;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-local-payment-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(directory: &Directory, fixture: bool) -> Node<TestVerifier> {
        let config = if fixture {
            Config::development([47; 32], 0).unwrap()
        } else {
            Config::asert_development([47; 32], 1, [0xff; 32], 1)
                .unwrap()
                .with_test_fund_registry()
                .unwrap()
        };
        Node::new(
            Store::open(directory.0.join("chain.redb"), config, &TestVerifier).unwrap(),
            TestVerifier,
        )
    }

    fn packet(node: &Node<TestVerifier>) -> (Vec<u8>, Vec<u8>, crate::wire::Hash) {
        let network = node.state().config.network;
        let mut transaction = candidate(node.state(), 300).transactions.remove(0);
        let blind = [F::from_u32(22); 8];
        transaction.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &blind));
        let id = transaction.record.statement_id(&network);
        let sidecar = Sidecar {
            transaction_id: id,
            fee: 100,
            blind: [22; 8],
        };
        (
            transaction.encode_envelope(&network).unwrap(),
            sidecar.encode().unwrap().to_vec(),
            id,
        )
    }

    #[test]
    fn cheap_fixture_is_rejected_before_payment_reservation() {
        let directory = Directory::new();
        let mut node = setup(&directory, true);
        let (envelope, sidecar, _) = packet(&node);
        let before = node.state().fingerprint();
        assert!(admit_payment(&mut node, &envelope, &sidecar).is_err());
        assert_eq!(node.state().fingerprint(), before);
        assert_eq!(node.state().height, 0);
        assert_eq!(node.mempool().len(), 0);
    }

    #[test]
    fn invalid_sidecar_leaves_canonical_store_and_reservations_unchanged() {
        let directory = Directory::new();
        let mut node = setup(&directory, false);
        let (envelope, mut sidecar, _) = packet(&node);
        // The fee amount starts after the fixed header and transaction ID.
        sidecar[38] ^= 1;
        let before = node.state().fingerprint();
        assert!(admit_payment(&mut node, &envelope, &sidecar).is_err());
        assert_eq!(node.state().fingerprint(), before);
        assert_eq!(node.state().height, 0);
        assert_eq!(node.mempool().len(), 0);
        drop(node);
        let node = setup(&directory, false);
        assert_eq!(node.state().fingerprint(), before);
        assert_eq!(node.state().height, 0);
    }

    #[test]
    fn admitted_payment_is_reserved_without_an_unverified_canonical_write() {
        let directory = Directory::new();
        let mut node = setup(&directory, false);
        let (envelope, sidecar, id) = packet(&node);
        let before = node.state().fingerprint();
        assert_eq!(admit_payment(&mut node, &envelope, &sidecar).unwrap(), id);
        assert_eq!(node.state().fingerprint(), before);
        assert!(node.mempool().contains(&id));
        assert!(admit_payment(&mut node, &envelope, &sidecar).is_err());
        assert_eq!(node.mempool().len(), 1);
    }
}
