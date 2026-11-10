//! Explicit verification-only regression using an existing complete native history.

use super::*;
use redb::TableHandle;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf, time::Instant};

fn file_image(path: &Path) -> (u64, Hash) {
    let mut file = fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut size = 0;
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            return (size, hash.finalize().into());
        }
        size += count as u64;
        hash.update(&buffer[..count]);
    }
}

fn canonical_rows(store: &Store) -> [(u64, Hash); 3] {
    let transaction = store.database.begin_read().unwrap();
    let mut names: Vec<_> = transaction
        .list_tables()
        .unwrap()
        .map(|table| table.name().to_owned())
        .collect();
    names.sort();
    let mut expected = vec![META.name(), BLOCKS.name(), INDEX.name()];
    expected.sort();
    assert_eq!(names, expected, "fixture has unaccounted durable tables");
    let mut rows = [(0, [0; 32]); 3];
    let table = transaction.open_table(META).unwrap();
    let mut hash = Sha256::new();
    for row in table.iter().unwrap() {
        let (key, value) = row.unwrap();
        hash.update((key.value().len() as u64).to_le_bytes());
        hash.update(key.value().as_bytes());
        hash.update((value.value().len() as u64).to_le_bytes());
        hash.update(value.value());
    }
    rows[0] = (table.len().unwrap(), hash.finalize().into());
    for (index, definition) in [BLOCKS, INDEX].into_iter().enumerate() {
        let table = transaction.open_table(definition).unwrap();
        let mut hash = Sha256::new();
        for row in table.iter().unwrap() {
            let (key, value) = row.unwrap();
            hash.update(key.value().to_le_bytes());
            hash.update((value.value().len() as u64).to_le_bytes());
            hash.update(value.value());
        }
        rows[index + 1] = (table.len().unwrap(), hash.finalize().into());
    }
    rows
}

fn copied_parent(source: &Path, destination: &Path, genesis: &Genesis) -> (Vec<u8>, Header) {
    fs::copy(source.join("chain.redb"), destination).unwrap();
    // Only this disposable public copy is truncated. The production audit
    // independently verifies all remaining native bodies before either control.
    let database = Database::open(destination).unwrap();
    let transaction = database.begin_write().unwrap();
    let mut table = transaction.open_table(BLOCKS).unwrap();
    assert_eq!(table.len().unwrap(), 28);
    let record = table.get(28).unwrap().unwrap().value().to_vec();
    let header = Header::decode(
        &table.get(27).unwrap().unwrap().value()[..HEADER_BYTES],
        &genesis.config().network,
    )
    .unwrap();
    table.remove(28).unwrap();
    drop(table);
    transaction.open_table(INDEX).unwrap().remove(28).unwrap();
    let mut head = header.height.to_le_bytes().to_vec();
    head.extend_from_slice(&header.id().unwrap());
    head.extend_from_slice(&header.execution_commitment);
    transaction
        .open_table(META)
        .unwrap()
        .insert("head", head.as_slice())
        .unwrap();
    transaction.commit().unwrap();
    (record, header)
}

#[test]
#[ignore = "requires a completed native h28 public fixture and a new isolated destination"]
fn real_native_wrong_execution_root_rejects_without_parent_or_durable_mutation() {
    use std::os::unix::fs::DirBuilderExt;
    let start = Instant::now();
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE").expect("set native public fixture"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_ROOT_REJECTION_FIXTURE")
            .expect("set new isolated root-rejection destination"),
    );
    assert!(source.is_absolute() && destination.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    assert!(fs::symlink_metadata(&source).unwrap().file_type().is_dir());
    assert!(!destination.exists() && !destination.starts_with(&source));
    let public_files = ["genesis.bin", "chain.redb", "result.json"];
    for name in public_files {
        assert!(
            fs::symlink_metadata(source.join(name))
                .unwrap()
                .file_type()
                .is_file()
        );
    }
    let original = public_files.map(|name| file_image(&source.join(name)));
    let completed: serde_json::Value =
        serde_json::from_slice(&fs::read(source.join("result.json")).unwrap()).unwrap();
    assert_eq!(completed["native_proof_blocks"], "28");
    assert_eq!(completed["durable_reopen_audit"], "passed");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    assert_eq!(destination.canonicalize().unwrap(), destination);
    let genesis_bytes = fs::read(source.join("genesis.bin")).unwrap();
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    assert_eq!(crate::local::hex(&genesis().id()), completed["genesis_id"]);
    assert!(genesis().config().fixture);
    assert_eq!(genesis().config().genesis_target, [0xff; 32]);
    assert_eq!(genesis().config().pow_iterations, 0);
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let positive_path = destination.join("positive.redb");
    let negative_path = destination.join("negative.redb");
    let (record, parent) = copied_parent(&source, &positive_path, &genesis());
    let (negative_record, negative_parent) = copied_parent(&source, &negative_path, &genesis());
    assert_eq!(negative_record, record);
    assert_eq!(negative_parent, parent);
    drop(negative_record);

    let verifier = NativeVerifier::new().unwrap();
    let positive = Store::audit_existing(&positive_path, genesis(), limits, &verifier).unwrap();
    assert_eq!(positive.engine().state().height(), 27);
    assert_eq!(positive.engine().state().tip(), parent.id().unwrap());
    let binding = super::super::state_components::Binding {
        genesis: genesis().id(),
        rules_commitment: genesis().rules_commitment(),
        parent: parent.parent,
    };
    let parent_components = positive
        .engine()
        .state()
        .canonical_components(binding, limits)
        .unwrap();
    assert_eq!(
        positive
            .engine()
            .state()
            .execution_commitment(binding, limits)
            .unwrap(),
        parent.execution_commitment
    );
    let (header, body) = decode(positive.engine(), &record).unwrap();
    assert_eq!(header.height, 28);
    assert_eq!(header.parent, parent.id().unwrap());
    assert_eq!(header.target, [0xff; 32]);
    assert_eq!(crate::local::hex(&header.id().unwrap()), completed["tip"]);
    assert_eq!(
        crate::local::hex(&header.execution_commitment),
        completed["execution_commitment"]
    );
    let mut driver = super::super::driver::Driver::new(
        positive,
        verifier,
        super::super::snapshot::ImportLimits {
            chain: limits,
            max_snapshot_bytes: 512 * 1024 * 1024,
        },
    )
    .unwrap();
    let timer = Instant::now();
    let accepted = driver.accept(&header, &body).unwrap();
    let positive_ms = timer.elapsed().as_millis();
    assert_eq!(accepted.height(), 28);
    assert_eq!(accepted.execution_commitment(), header.execution_commitment);
    assert_eq!(driver.engine().state().tip(), header.id().unwrap());
    assert_eq!(driver.store().header(28).unwrap(), header);
    assert_eq!(canonical_rows(driver.store())[1].0, 28);
    drop(driver);

    let verifier = NativeVerifier::new().unwrap();
    let mut negative = Store::audit_existing(&negative_path, genesis(), limits, &verifier).unwrap();
    assert_eq!(negative.engine().state().height(), 27);
    assert_eq!(negative.engine().state().tip(), parent.id().unwrap());
    assert_eq!(
        negative
            .engine()
            .state()
            .canonical_components(binding, limits)
            .unwrap(),
        parent_components
    );
    let mut encoded_body = Vec::new();
    body.write_to(&mut encoded_body, negative.engine().body_policy())
        .unwrap();
    assert_eq!(encoded_body, record[HEADER_BYTES..]);
    drop(encoded_body);
    let mut changed = header.clone();
    changed.execution_commitment[0] ^= 1;
    let seed = changed.pow_seed().unwrap();
    changed.nonce = (0..128)
        .find(|nonce| {
            siworld_core::pow::meets_target(
                &siworld_core::pow::pow_hash(&seed, *nonce, genesis().config().pow_iterations),
                &changed.target,
            )
        })
        .expect("bounded work search exhausted under unchanged fixture difficulty");
    assert!(siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, changed.nonce, genesis().config().pow_iterations),
        &changed.target,
    ));
    let original_header = header.encode().unwrap();
    let changed_header = changed.encode().unwrap();
    assert_eq!(changed_header[..118], original_header[..118]);
    assert_eq!(changed_header[119..182], original_header[119..182]);
    assert_eq!(changed_header[118], original_header[118] ^ 1);
    let before_rows = canonical_rows(&negative);
    let before_file = file_image(&negative_path);
    let timer = Instant::now();
    let error = negative
        .append(&changed, &body, &verifier)
        .err()
        .expect("wrong execution root accepted");
    let negative_ms = timer.elapsed().as_millis();
    assert_eq!(
        error,
        "native execution commitment differs from complete checked state"
    );
    assert_eq!(file_image(&negative_path), before_file);
    assert_eq!(canonical_rows(&negative), before_rows);
    assert!(negative.usable);
    assert_eq!(negative.engine().state().height(), 27);
    assert_eq!(negative.engine().state().tip(), parent.id().unwrap());
    assert_eq!(
        negative
            .engine()
            .state()
            .canonical_components(binding, limits)
            .unwrap(),
        parent_components
    );
    assert_eq!(
        negative
            .engine()
            .state()
            .execution_commitment(binding, limits)
            .unwrap(),
        parent.execution_commitment
    );
    assert_eq!(negative.header(27).unwrap(), parent);
    assert!(negative.header(28).is_err());
    // File equality above is measured on the same open durable handle. Closing
    // redb may change bookkeeping bytes independently of rejected publication.
    drop(negative);
    assert_eq!(
        public_files.map(|name| file_image(&source.join(name))),
        original
    );
    println!(
        "{}",
        serde_json::json!({
            "scope": "existing-native-body-execution-root-rejection",
            "positive_native_driver_accept": "passed",
            "negative_final_execution_root_comparison": "rejected",
            "exact_rejection": error,
            "parent_height": "27", "body_height": "28",
            "parent_components_unchanged": 11,
            "durable_canonical_tables_unchanged": 3,
            "open_database_sha256_unchanged": crate::local::hex(&before_file.1),
            "public_source_sha256_unchanged": original.map(|(_, hash)| crate::local::hex(&hash)),
            "positive_ms": positive_ms.to_string(), "negative_ms": negative_ms.to_string(),
            "elapsed_ms": start.elapsed().as_millis().to_string(),
            "genesis": crate::local::hex(&genesis().id()), "accepted_tip": crate::local::hex(&header.id().unwrap()),
            "original_root": crate::local::hex(&header.execution_commitment),
            "rejected_root": crate::local::hex(&changed.execution_commitment),
            "target": crate::local::hex(&changed.target), "pow_iterations": "0",
            "nonce_candidates_bound": "128", "valid_nonce": changed.nonce.to_string(),
            "new_proof_generation": false, "identity_or_custody_access": false,
            "network_access": false,
        })
    );
}
