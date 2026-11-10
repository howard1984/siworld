use super::super::tests::{Directory, synthetic_candidate};
use super::*;
use crate::eng2::snapshot::tests::limits;
use std::{fs, os::unix::fs::symlink};

// This helper creates only temporary synthetic unit fixtures, never a runtime
// key initialization path. No seed is placed in assertions, output or arguments.
fn key_fixture(path: &Path, store: &Store, slot: u8, seed: u8) {
    use std::io::Write;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(KEY_MAGIC);
    for hash in [
        store.engine().state().network(),
        store.engine().genesis().id(),
        store.engine().genesis().rules_commitment(),
    ] {
        bytes.extend_from_slice(&hash);
    }
    bytes.push(slot);
    bytes.extend_from_slice(&[seed; 32]);
    let checksum = blake3::derive_key("siworld eng2 checkpoint test signer record v1", &bytes);
    bytes.extend_from_slice(&checksum);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
#[test]
fn existing_signer_requires_exact_context_authorized_slot_and_owner_only_file() {
    let dir = Directory::new();
    let store = dir.store();
    let key = dir.0.join("signer.bin");
    assert!(ExistingSigner::load(&key, &store).is_err());
    assert!(!key.exists());
    key_fixture(&key, &store, 0, 3);
    let signer = ExistingSigner::load(&key, &store).unwrap();
    assert_eq!(signer.slot(), 0);
    assert_eq!(
        signer.public_key(),
        &store.engine().state().governance().active_roster().keys()[0]
    );
    assert_eq!(format!("{signer:?}"), "ExistingCheckpointSigner(REDACTED)");
    let link = dir.0.join("symlink.bin");
    symlink(&key, &link).unwrap();
    assert!(ExistingSigner::load(&link, &store).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ExistingSigner::load(&key, &store).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let hard = dir.0.join("hardlink.bin");
    fs::hard_link(&key, &hard).unwrap();
    assert!(ExistingSigner::load(&key, &store).is_err());
    fs::remove_file(hard).unwrap();
    let wrong_slot = dir.0.join("wrong-slot.bin");
    key_fixture(&wrong_slot, &store, 1, 3);
    assert!(ExistingSigner::load(&wrong_slot, &store).is_err());
    let wrong_key = dir.0.join("wrong-key.bin");
    key_fixture(&wrong_key, &store, 0, 7);
    assert!(ExistingSigner::load(&wrong_key, &store).is_err());
    let bytes = Zeroizing::new(fs::read(&key).unwrap());
    for offset in [0, 8, 40, 72, 105, 137] {
        let bad = dir.0.join(format!("corrupt-{offset}.bin"));
        let mut copy = Zeroizing::new(bytes.to_vec());
        copy[offset] ^= 1;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&bad)
            .unwrap();
        std::io::Write::write_all(&mut file, &copy).unwrap();
        assert!(ExistingSigner::load(&bad, &store).is_err());
    }
}
#[test]
fn explicit_genesis_host_emits_unavailable_status_without_signing_or_fabricating_checkpoint() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let key = dir.0.join("signer.bin");
    key_fixture(&key, &store, 0, 3);
    let mut host = Host::open(&root, &store, limits(), Some(&key)).unwrap();
    let first = host.tick(&store, 100_000, &[]).unwrap();
    assert!(first.exported_current);
    assert!(!first.newly_published);
    assert_eq!(first.status.height, 0);
    assert!(first.status.pruning_paused);
    assert_eq!(first.status.alarm, Some(Alarm::Unavailable));
    assert_eq!(first.status.signer_slot, Some(0));
    assert!(first.proposal.is_none());
    assert!(first.vote.is_none());
    assert!(first.certificate.is_none());
    let state_before = store.engine().state().tip();
    let current = fs::read(root.join("explorer.json")).unwrap();
    let status = fs::read(root.join("checkpoint-status-eng2.json")).unwrap();
    assert!(!host.tick(&store, 100_001, &[]).unwrap().exported_current);
    assert_eq!(fs::read(root.join("explorer.json")).unwrap(), current);
    assert_eq!(
        fs::read(root.join("checkpoint-status-eng2.json")).unwrap(),
        status
    );
    assert!(host.tick(&store, 100_000, &[]).is_err());
    assert!(host.tick(&store, 1u64 << 53, &[]).is_err());
    assert_eq!(store.engine().state().tip(), state_before);
    assert!(!fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("vote-")
    }));
    drop(host);
    let mut reopened = Host::open(&root, &store, limits(), Some(&key)).unwrap();
    assert!(
        reopened
            .tick(&store, 100_002, &[])
            .unwrap()
            .exported_current
    );
}
#[test]
fn observer_rejects_unmatched_bounded_peer_inputs_without_chain_mutation() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut host = Host::open(&root, &store, limits(), None).unwrap();
    let candidate = synthetic_candidate();
    let proposal = Incoming::Proposal(Proposal {
        statement: candidate.statement.clone(),
        witness: candidate.witness.clone(),
    });
    assert!(
        host.tick(
            &store,
            100_000,
            &vec![proposal.clone(); MAX_MESSAGES_PER_TICK + 1]
        )
        .is_err()
    );
    assert!(host.tick(&store, 100_001, &[proposal]).is_err());
    let vote = Incoming::Vote {
        statement: candidate.statement.clone(),
        vote: Box::new(Vote {
            slot: 0,
            signature: [0; super::super::super::certificate::SIGNATURE_BYTES],
        }),
    };
    assert!(host.tick(&store, 100_002, &[vote]).is_err());
    let mut witness = candidate.witness;
    witness.governance = vec![0; limits().chain.max_component_bytes + 1];
    assert!(
        host.tick(
            &store,
            100_003,
            &[Incoming::Proposal(Proposal {
                statement: candidate.statement,
                witness
            })]
        )
        .is_err()
    );
    assert_eq!(store.engine().state().height(), 0);
    let result = host.tick(&store, 100_004, &[]).unwrap();
    assert_eq!(result.status.signer_slot, None);
    assert!(result.status.pruning_paused);
    assert!(result.vote.is_none());
    assert!(!root.join("checkpoint-eng2.json").exists());
}
