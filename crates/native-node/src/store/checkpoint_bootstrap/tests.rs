use super::*;
use crate::engineering_checkpoint::{self as auth, Vote};
use libcrux_ml_dsa::ml_dsa_65;
use siworld_core::pow;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-bootstrap-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(windows)]
        let _directory = siworld_miner_platform::Directory::create(&path).unwrap();
        #[cfg(not(windows))]
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct History {
    config: Config,
    permanent: Vec<Vec<u8>>,
    full: Vec<Block>,
    tail: Vec<Block>,
    certificate: Certificate,
    final_state: State,
    checkpoint_state: State,
}
fn roster(config: &Config) -> Roster {
    Roster::new(
        Binding::new(config),
        [17, 29].map(|seed| {
            *ml_dsa_65::generate_key_pair([seed; 32])
                .verification_key
                .as_ref()
        }),
    )
    .unwrap()
}
fn history() -> &'static History {
    static HISTORY: OnceLock<History> = OnceLock::new();
    HISTORY.get_or_init(|| {
        let config = Config::development([73; 32], 0).unwrap();
        let roster = roster(&config);
        let mut state = State::new(config.clone()).unwrap();
        let mut permanent = Vec::new();
        let mut full = Vec::new();
        let mut tail = Vec::new();
        let mut prefix =
            blake3::Hasher::new_derive_key("siworld engineering checkpoint permanent records v1");
        prefix.update(&blake3::derive_key(
            "siworld engineering checkpoint permanent prefix v1",
            &config.genesis_id(),
        ));
        let mut candidate = None;
        let mut checkpoint_state = None;
        for index in 0..96 {
            let block = crate::fixtures::candidate(&state, 1_000_000 + index * 10_000);
            state.apply(&block, &crate::fixtures::TestVerifier).unwrap();
            full.push(block.clone());
            if index < 72 {
                let compact = CompactBlock::export(&block).unwrap();
                prefix.update(&state.height.to_le_bytes());
                prefix.update(blake3::hash(&compact).as_bytes());
                permanent.push(compact);
                if index == 71 {
                    checkpoint_state = Some(state.clone());
                    candidate = Some(
                        engineering_checkpoint::summary(
                            &state,
                            &roster,
                            1,
                            21_600,
                            *prefix.finalize().as_bytes(),
                        )
                        .unwrap(),
                    );
                }
            } else {
                tail.push(block);
            }
        }
        let statement = candidate.unwrap().statement().clone();
        let votes = [17, 29]
            .into_iter()
            .enumerate()
            .map(|(index, seed)| {
                let pair = ml_dsa_65::generate_key_pair([seed; 32]);
                Vote {
                    signer: index as u8,
                    signature: *ml_dsa_65::sign(
                        &pair.signing_key,
                        &statement.encode(),
                        auth::CONTEXT,
                        [91; 32],
                    )
                    .unwrap()
                    .as_ref(),
                }
            })
            .collect();
        History {
            config,
            permanent,
            full,
            tail,
            certificate: Certificate { statement, votes },
            final_state: state,
            checkpoint_state: checkpoint_state.unwrap(),
        }
    })
}
fn fixture_session(directory: &Directory) -> CheckpointBootstrap {
    let history = history();
    CheckpointBootstrap::begin(
        &directory.0.join("stage.redb"),
        history.config.clone(),
        history.certificate.clone(),
        roster(&history.config),
        None,
        21_600,
        Work::zero(),
        BootstrapLimits::default(),
    )
    .unwrap()
}
#[test]
fn fresh_reconstruction_tail_and_atomic_adoption_reopen_match_full_verification() {
    let history = history();
    let stage_directory = Directory::new();
    let node = Directory::new();
    NativeIdentity::initialize(&node.0, Binding::new(&history.config)).unwrap();
    let mut session = fixture_session(&stage_directory);
    for compact in &history.permanent {
        session.push_permanent(compact).unwrap();
    }
    assert_eq!(session.progress().0, 72);
    assert_eq!(
        session.state.fingerprint(),
        history.certificate.statement.state_fingerprint
    );
    for block in &history.tail {
        session
            .push_tail(block, &crate::fixtures::TestVerifier)
            .unwrap();
    }
    let verified = session.finish().unwrap();
    assert_eq!(
        verified.state().fingerprint(),
        history.final_state.fingerprint()
    );
    assert_eq!(verified.checkpoint_height(), 72);
    let downloaded = verified.downloaded_bytes();
    let mut node_store = Store::open(
        node.0.join("chain.redb"),
        history.config.clone(),
        &crate::fixtures::TestVerifier,
    )
    .unwrap();
    assert_eq!(
        node_store
            .adopt_engineering_bootstrap(verified, 21_600)
            .unwrap(),
        downloaded
    );
    assert_eq!(
        node_store.state().fingerprint(),
        history.final_state.fingerprint()
    );
    assert_eq!(node_store.verify_local_rewards().unwrap(), 0);
    assert!(!stage_directory.0.join("stage.redb").exists());
    let metrics = node_store.storage_metrics().unwrap();
    assert_eq!(metrics["pruned_proof_blocks"], 72);
    drop(node_store);
    let reopened = Store::open_existing(
        node.0.join("chain.redb"),
        history.config.clone(),
        &crate::fixtures::TestVerifier,
    )
    .unwrap();
    assert_eq!(
        reopened.state().fingerprint(),
        history.final_state.fingerprint()
    );
    assert_eq!(
        reopened
            .latest_engineering_checkpoint()
            .unwrap()
            .unwrap()
            .statement,
        history.certificate.statement
    );
    assert_eq!(
        reopened.canonical_id(1).unwrap(),
        CompactBlock::decode(&history.permanent[0]).unwrap().id
    );
}
#[test]
fn tampered_prefix_wrong_order_expired_and_rollback_checkpoints_fail_closed() {
    let history = history();
    let directory = Directory::new();
    let mut session = fixture_session(&directory);
    assert!(session.push_permanent(&history.permanent[1]).is_err());
    assert!(session.push_permanent(&history.permanent[0]).is_err());
    assert!(session.finish().is_err());
    let directory = Directory::new();
    let mut session = fixture_session(&directory);
    let mut tampered = history.permanent[0].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(session.push_permanent(&tampered).is_err());
    assert!(session.finish().is_err());
    let directory = Directory::new();
    for previous in [
        None,
        Some(Cursor {
            sequence: 2,
            height: 72,
            digest: history.certificate.statement.digest(),
        }),
    ] {
        let now = if previous.is_none() {
            21_600 + auth::MAX_AGE_SECONDS + 1
        } else {
            21_600
        };
        assert!(
            CheckpointBootstrap::begin(
                &directory.0.join("absent.redb"),
                history.config.clone(),
                history.certificate.clone(),
                roster(&history.config),
                previous,
                now,
                Work::zero(),
                BootstrapLimits::default()
            )
            .is_err()
        );
        assert!(!directory.0.join("absent.redb").exists());
    }
}

#[test]
fn invalid_tail_proofs_poison_the_session_without_accepting_any_state() {
    let history = history();
    let directory = Directory::new();
    let mut session = fixture_session(&directory);
    // The complete prefix reconstruction is covered by the adoption test.
    // Start at that boundary here to isolate proof-verifier failure behavior.
    session.state = history.checkpoint_state.clone();
    session.checkpoint_state = Some(history.checkpoint_state.clone());
    let before = session.state.fingerprint();
    let mut invalid = history.tail[0].clone();
    invalid.transactions[0].proof = vec![2];
    assert!(
        session
            .push_tail(&invalid, &crate::fixtures::TestVerifier)
            .is_err()
    );
    assert_eq!(session.state.fingerprint(), before);
    assert!(
        session
            .push_tail(&history.tail[0], &crate::fixtures::TestVerifier)
            .is_err()
    );
    assert!(session.finish().is_err());
}

#[test]
fn reconstructed_holder_rewards_pool_and_unlocks_match_the_common_transition() {
    let config = Config::development([74; 32], 0)
        .unwrap()
        .with_economics(
            siworld_core::v1_economics::EconomicsParams::engineering([60, 120, 180, 240], 3)
                .unwrap(),
        )
        .unwrap();
    let mut verified = State::new(config.clone()).unwrap();
    let mut reconstructed = State::new(config).unwrap();
    for index in 0..70 {
        let mut block = crate::fixtures::candidate(&verified, 2_000_000 + index * 10_000);
        if index % 2 == 0 {
            block.reward_mode = crate::state::RewardMode::Holder;
            let original = block.rewards[0].clone();
            let base =
                100_000_000 + u32::from_le_bytes(original.commitment[..4].try_into().unwrap());
            block.rewards = (0..5)
                .map(|offset| {
                    let mut reward = original.clone();
                    reward.commitment[..4].copy_from_slice(&(base + offset).to_le_bytes());
                    reward
                })
                .collect();
            let seed = block.pow_seed().unwrap();
            while !pow::meets_target(
                &pow::pow_hash(&seed, block.nonce, verified.config.pow_iterations),
                &block.target,
            ) {
                block.nonce += 1;
            }
        }
        let compact = CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap();
        reconstruct_public_effects(&mut reconstructed, &compact).unwrap();
        verified
            .apply(&block, &crate::fixtures::TestVerifier)
            .unwrap();
        assert_eq!(reconstructed.fingerprint(), verified.fingerprint());
        assert_eq!(
            checkpoint::encode(&reconstructed).unwrap(),
            checkpoint::encode(&verified).unwrap()
        );
    }
    assert!(verified.economics.totals().issued > 0);
    assert!(verified.economics.totals().burned > 0);
}

#[test]
fn staging_refuses_existing_files_and_cleans_only_its_owned_temporary_file() {
    let directory = Directory::new();
    let existing = directory.0.join("existing.redb");
    std::fs::write(&existing, b"preserved unrelated contents").unwrap();
    assert!(Staging::new(&existing).is_err());
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"preserved unrelated contents"
    );
    let temporary = directory.0.join("temporary.redb");
    let staging = Staging::new(&temporary).unwrap();
    assert!(temporary.exists());
    drop(staging);
    assert!(!temporary.exists());
    #[cfg(unix)]
    {
        let temporary = directory.0.join("replaced.redb");
        let moved = directory.0.join("moved.redb");
        let staging = Staging::new(&temporary).unwrap();
        std::fs::rename(&temporary, &moved).unwrap();
        std::fs::write(&temporary, b"replacement must survive").unwrap();
        drop(staging);
        assert_eq!(
            std::fs::read(&temporary).unwrap(),
            b"replacement must survive"
        );
        assert!(moved.exists());
    }
}

fn reissued_certificate(
    history: &History,
    sequence: u64,
    issued: u64,
) -> (engineering_checkpoint::LocalCandidate, Certificate) {
    let roster = roster(&history.config);
    let candidate = engineering_checkpoint::summary(
        &history.checkpoint_state,
        &roster,
        sequence,
        issued,
        history.certificate.statement.permanent_prefix_digest,
    )
    .unwrap();
    let statement = candidate.statement().clone();
    let votes = [17, 29]
        .into_iter()
        .enumerate()
        .map(|(index, seed)| {
            let pair = ml_dsa_65::generate_key_pair([seed; 32]);
            Vote {
                signer: index as u8,
                signature: *ml_dsa_65::sign(
                    &pair.signing_key,
                    &statement.encode(),
                    auth::CONTEXT,
                    [92; 32],
                )
                .unwrap()
                .as_ref(),
            }
        })
        .collect();
    (candidate, Certificate { statement, votes })
}
#[test]
fn service_pruning_requires_explicit_qualification_and_fresh_quorum_then_resumes() {
    let history = history();
    let directory = Directory::new();
    NativeIdentity::initialize(&directory.0, Binding::new(&history.config)).unwrap();
    let verifier = crate::fixtures::TestVerifier;
    let roster = roster(&history.config);
    let mut store = Store::open(
        directory.0.join("chain.redb"),
        history.config.clone(),
        &verifier,
    )
    .unwrap();
    store.configure_storage(Role::Bootstrap).unwrap();
    for block in &history.full {
        store.append(block, &verifier).unwrap();
    }
    let extra = crate::fixtures::candidate(store.state(), 5_000_000);
    store.append(&extra, &verifier).unwrap();
    let expected = store.state().fingerprint();
    let first = 21_600;
    let ready = first + storage_policy::SERVICE_RETENTION_SECONDS;
    let (candidate, certificate) = reissued_certificate(history, 1, first);
    store
        .accept_engineering_checkpoint_cached(&certificate, &roster, first, &candidate)
        .unwrap();
    // Fixture networks ordinarily preserve legacy retention tests. Supplying
    // the explicit pinned roster exercises the production gate here.
    assert_eq!(
        store
            .expire_proofs_with_roster(first, true, &verifier, Some(&roster))
            .unwrap(),
        0
    );
    let (candidate, certificate) = reissued_certificate(history, 2, ready);
    store
        .accept_engineering_checkpoint_cached(&certificate, &roster, ready, &candidate)
        .unwrap();
    assert_eq!(
        store
            .expire_proofs_with_roster(ready, true, &verifier, Some(&roster))
            .unwrap(),
        0
    );
    assert!(store.block(1).is_ok());
    store
        .qualify_service_checkpoint_delivery(&roster, ready)
        .unwrap();
    assert_eq!(
        store
            .expire_proofs_with_roster(ready, true, &verifier, Some(&roster))
            .unwrap(),
        4
    );
    assert!(store.block(1).is_err());
    assert!(store.block(5).is_ok());
    let stale = ready + auth::MAX_AGE_SECONDS + 1;
    assert_eq!(
        store
            .expire_proofs_with_roster(stale, true, &verifier, Some(&roster))
            .unwrap(),
        0
    );
    assert!(store.block(5).is_ok());
    let (candidate, certificate) = reissued_certificate(history, 3, stale);
    store
        .accept_engineering_checkpoint_cached(&certificate, &roster, stale, &candidate)
        .unwrap();
    assert_eq!(
        store
            .expire_proofs_with_roster(stale, true, &verifier, Some(&roster))
            .unwrap(),
        4
    );
    while store
        .expire_proofs_with_roster(stale, true, &verifier, Some(&roster))
        .unwrap()
        > 0
    {}
    assert_eq!(store.storage_base.as_ref().unwrap().height, 72);
    assert!(store.block(72).is_err());
    // Height73 is finalized and older than24h, yet remains protected because
    // it follows the latest valid checkpoint. Capacity cannot weaken this.
    assert!(store.block(73).is_ok());
    assert!(store.block(97).is_ok());
    assert_eq!(store.state().fingerprint(), expected);
    drop(store);
    let reopened = Store::open_existing(
        directory.0.join("chain.redb"),
        history.config.clone(),
        &verifier,
    )
    .unwrap();
    assert_eq!(reopened.state().fingerprint(), expected);
    let transaction = reopened.database.begin_read().unwrap();
    let policy = transaction.open_table(retention::STORAGE).unwrap();
    assert_eq!(
        policy.get("qualified_roster").unwrap().unwrap().value(),
        roster.digest()
    );
}

fn recovery_snapshot(store: &Store) -> Vec<Vec<u8>> {
    let transaction = store.database.begin_read().unwrap();
    let names: BTreeSet<_> = transaction
        .list_tables()
        .unwrap()
        .map(|table| table.name().to_owned())
        .collect();
    let mut result: Vec<_> = names.iter().map(|name| name.as_bytes().to_vec()).collect();
    for definition in [
        META,
        retention::STORAGE,
        engineering_checkpoint::ATTESTATIONS,
    ] {
        if names.contains(definition.name()) {
            for row in transaction.open_table(definition).unwrap().iter().unwrap() {
                let (key, value) = row.unwrap();
                let mut entry = key.value().as_bytes().to_vec();
                entry.extend_from_slice(value.value());
                result.push(entry);
            }
        }
    }
    for definition in [
        BLOCKS,
        retention::FINALITY,
        super::super::protected_history::PROTECTED,
    ] {
        if names.contains(definition.name()) {
            for row in transaction.open_table(definition).unwrap().iter().unwrap() {
                let (height, value) = row.unwrap();
                let mut entry = height.value().to_le_bytes().to_vec();
                entry.extend_from_slice(blake3::hash(value.value()).as_bytes());
                result.push(entry);
            }
        }
    }
    result
}

#[test]
fn existing_service_recovery_preserves_protected_proofs_and_expires_atomically() {
    let history = history();
    let directory = Directory::new();
    NativeIdentity::initialize(&directory.0, Binding::new(&history.config)).unwrap();
    let verifier = crate::fixtures::TestVerifier;
    let roster = roster(&history.config);
    let mut store = Store::open(
        directory.0.join("chain.redb"),
        history.config.clone(),
        &verifier,
    )
    .unwrap();
    store.configure_storage(Role::Validator).unwrap();
    for block in &history.full[..28] {
        store.append(block, &verifier).unwrap();
    }
    let first_observation = 21_600;
    store
        .expire_proofs_with_roster(first_observation, true, &verifier, Some(&roster))
        .unwrap();
    let original_second = {
        let transaction = store.database.begin_write().unwrap();
        let record = transaction
            .open_table(BLOCKS)
            .unwrap()
            .get(2)
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        let id = store.canonical_id(2).unwrap();
        transaction
            .open_table(DETACHED)
            .unwrap()
            .insert(id.as_slice(), encode_detached(&record).as_slice())
            .unwrap();
        transaction.commit().unwrap();
        record
    };
    let recovered_at = first_observation + 2 * storage_policy::SERVICE_RETENTION_SECONDS;
    let (_, certificate) = reissued_certificate(history, 1, recovered_at);
    let build = |attempt| {
        let mut session = CheckpointBootstrap::begin(
            &directory.0.join(format!("service-stage-{attempt}.redb")),
            history.config.clone(),
            certificate.clone(),
            roster.clone(),
            None,
            recovered_at,
            Work::zero(),
            BootstrapLimits::default(),
        )
        .unwrap();
        for compact in &history.permanent {
            session.push_permanent(compact).unwrap();
        }
        for block in &history.tail {
            session.push_tail(block, &verifier).unwrap();
        }
        session.finish().unwrap()
    };
    // An incorrect old saved fingerprint fails after the first preservation
    // write; all new rows, protection markers, observations and head roll back.
    let verified = build(0);
    let old_state = store.state().fingerprint();
    let old_base = store.storage_base.as_ref().unwrap().fingerprint();
    let mut changed = original_second.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    {
        let transaction = store.database.begin_write().unwrap();
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(2, changed.as_slice())
            .unwrap();
        transaction.commit().unwrap();
    }
    let before = recovery_snapshot(&store);
    assert!(
        store
            .adopt_engineering_bootstrap(verified, recovered_at)
            .is_err()
    );
    assert_eq!(recovery_snapshot(&store), before);
    assert_eq!(store.state().fingerprint(), old_state);
    assert_eq!(store.storage_base.as_ref().unwrap().fingerprint(), old_base);
    {
        let transaction = store.database.begin_write().unwrap();
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(2, original_second.as_slice())
            .unwrap();
        transaction.commit().unwrap();
    }
    let verified = build(1);
    store
        .adopt_engineering_bootstrap(verified, recovered_at)
        .unwrap();
    assert_eq!(
        store.state().fingerprint(),
        history.final_state.fingerprint()
    );
    assert_eq!(store.storage_base.as_ref().unwrap().height, 72);
    for height in 1..=28 {
        assert_eq!(
            store.block(height).unwrap().id().unwrap(),
            store.canonical_id(height).unwrap()
        );
    }
    let genesis = crate::wire::Snapshot {
        height: 0,
        block_id: history.config.genesis_id(),
    };
    let batch = crate::sync::serve_batch(&store, genesis, genesis, 2, 640 * 1024 * 1024).unwrap();
    assert_eq!(batch.blocks.len(), 2);
    let metrics = store.storage_metrics().unwrap();
    assert_eq!(metrics["protected_historical_proof_blocks"], 28);
    assert_eq!(metrics["retained_proof_blocks"], 52);
    assert!(
        metrics["protected_historical_proof_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    store
        .qualify_service_checkpoint_delivery(&roster, recovered_at)
        .unwrap();
    drop(store);
    let mut store = Store::open_existing(
        directory.0.join("chain.redb"),
        history.config.clone(),
        &verifier,
    )
    .unwrap();
    assert_eq!(
        store.state().fingerprint(),
        history.final_state.fingerprint()
    );
    // A second long offline interval contributes no certain age. Even detached
    // proofs below the new base remain protected after this owner restarts.
    let resumed_at = recovered_at + 2 * storage_policy::SERVICE_RETENTION_SECONDS;
    let (candidate, certificate) = reissued_certificate(history, 2, resumed_at);
    store
        .accept_engineering_checkpoint_cached(&certificate, &roster, resumed_at, &candidate)
        .unwrap();
    assert_eq!(
        store
            .expire_proofs_with_roster(resumed_at, true, &verifier, Some(&roster))
            .unwrap(),
        0
    );
    assert!(store.block(1).is_ok());
    assert!(
        store.storage_metrics().unwrap()["detached_proof_body_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    let ready_at = resumed_at + storage_policy::SERVICE_RETENTION_SECONDS;
    // Expired publication pauses protected-history deletion too.
    assert_eq!(
        store
            .expire_proofs_with_roster(ready_at, true, &verifier, Some(&roster))
            .unwrap(),
        0
    );
    assert!(store.block(1).is_ok());
    let (candidate, certificate) = reissued_certificate(history, 3, ready_at);
    store
        .accept_engineering_checkpoint_cached(&certificate, &roster, ready_at, &candidate)
        .unwrap();
    {
        let transaction = store.database.begin_write().unwrap();
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(2, changed.as_slice())
            .unwrap();
        transaction.commit().unwrap();
    }
    let before = recovery_snapshot(&store);
    assert!(
        store
            .expire_proofs_with_roster(ready_at, true, &verifier, Some(&roster))
            .is_err()
    );
    assert_eq!(recovery_snapshot(&store), before);
    assert!(store.block(1).is_ok());
    {
        let transaction = store.database.begin_write().unwrap();
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(2, original_second.as_slice())
            .unwrap();
        transaction.commit().unwrap();
    }
    let mut expired = 0;
    loop {
        let count = store
            .expire_proofs_with_roster(ready_at, true, &verifier, Some(&roster))
            .unwrap();
        assert!(count <= 4);
        expired += count;
        if count == 0 {
            break;
        }
    }
    assert_eq!(expired, 28);
    assert!(store.block(1).is_err());
    assert_eq!(
        store.storage_metrics().unwrap()["protected_historical_proof_blocks"],
        0
    );
    assert_eq!(
        store.storage_metrics().unwrap()["detached_proof_body_bytes"],
        0
    );
    assert_eq!(
        store.state().fingerprint(),
        history.final_state.fingerprint()
    );
    drop(store);
    let reopened = Store::open_existing(
        directory.0.join("chain.redb"),
        history.config.clone(),
        &verifier,
    )
    .unwrap();
    assert_eq!(
        reopened.state().fingerprint(),
        history.final_state.fingerprint()
    );
}
