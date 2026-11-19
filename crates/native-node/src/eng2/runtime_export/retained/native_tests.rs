//! Explicit owner-local verification with retained public native checkpoint data.
//! This ignored test never opens a source database or generates block proofs.
use super::*;
use crate::eng2::{
    admission::AdmissionPlan,
    body::Body,
    execution::Engine,
    genesis::Genesis,
    import::{self, Input, Installation, Policy, Source},
    runtime_export::host::Host,
    selection::{HeaderRules, VerifiedHeaders},
    snapshot::ImportedAnchor,
    state_components::Limits,
    wallet_history::codec::{Context, HeaderPage, MAX_RECEIPT_BYTES, ReceiptBlock},
};
use crate::{identity::NativeIdentity, proofs::NativeVerifier};
use sha2::{Digest, Sha256};
use siworld_core::pow::Work;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn limits() -> ImportLimits {
    ImportLimits {
        chain: Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 16 * 1024 * 1024,
    }
}
fn require(condition: bool, error: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.into()) }
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, true, maximum)?
        .read_to_end(&mut bytes)
        .map_err(|_| "public retained fixture read failed")?;
    require(
        bytes.len() <= maximum,
        "public fixture read exceeded its cap",
    )?;
    Ok(bytes)
}
fn sha256(bytes: &[u8]) -> String {
    crate::local::hex(&Sha256::digest(bytes))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|_| "fresh retained fixture output unavailable".into())
}
fn mkdir(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "fresh retained fixture directory required".into())
}
struct PublicSource {
    root: PathBuf,
    reads: BTreeMap<PathBuf, (usize, String)>,
}
impl PublicSource {
    fn bytes(&mut self, relative: &str, maximum: usize) -> Result<Vec<u8>, String> {
        let path = self.root.join(relative);
        let bytes = read(&path, maximum)?;
        let value = (bytes.len(), sha256(&bytes));
        if let Some(previous) = self.reads.get(&path) {
            require(previous == &value, "public fixture changed between reads")?;
        } else {
            self.reads.insert(path, value);
        }
        Ok(bytes)
    }
    fn check_unchanged(&self) -> Result<(), String> {
        for (path, (length, digest)) in &self.reads {
            let bytes = read(path, *length)?;
            require(
                bytes.len() == *length && sha256(&bytes) == *digest,
                "public fixture changed during qualification",
            )?;
        }
        Ok(())
    }
}
impl Source for PublicSource {
    fn receipt(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
        require(
            (1..=72).contains(&height),
            "fixture receipt is outside permanent prefix",
        )?;
        self.bytes(&format!("public-artifacts/receipt-{height}.bin"), maximum)
    }
    fn body(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
        require(
            (73..=96).contains(&height),
            "fixture body is outside native tail",
        )?;
        self.bytes(&format!("public-artifacts/body-{height}.bin"), maximum)
    }
}
fn decoded_body(source: &mut PublicSource, engine: &Engine, height: u64) -> Result<Body, String> {
    let policy = engine.body_policy();
    Body::decode(
        &source.body(height, policy.max_body_bytes)?,
        engine.state().network(),
        height,
        policy,
    )
}
fn copy_export(source: &Path, target: &Path) -> Result<(), String> {
    mkdir(target)?;
    for entry in fs::read_dir(source).map_err(|_| "fixture export directory unavailable")? {
        let entry = entry.map_err(|_| "fixture export entry unavailable")?;
        let bytes = read(&entry.path(), 32 * 1024 * 1024)?;
        write_new(&target.join(entry.file_name()), &bytes)?;
    }
    Ok(())
}
fn tree(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root).map_err(|_| "fixture export audit unavailable")? {
        let entry = entry.map_err(|_| "fixture export audit entry unavailable")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "fixture filename is not UTF-8")?;
        result.insert(name, sha256(&read(&entry.path(), 32 * 1024 * 1024)?));
    }
    Ok(result)
}
fn error<T>(result: Result<T, String>) -> Result<String, String> {
    match result {
        Err(value) => Ok(value),
        Ok(_) => Err("expected fail-closed result".into()),
    }
}
fn run(root: &Path, source_root: &Path, page_path: &Path) -> Result<Value, String> {
    let started = Instant::now();
    let mut source = PublicSource {
        root: source_root.to_owned(),
        reads: BTreeMap::new(),
    };
    let genesis_bytes = source.bytes("genesis.bin", 1024 * 1024)?;
    let certificate_bytes = source.bytes(
        "checkpoint.bin",
        super::super::super::certificate::CERTIFICATE_BYTES,
    )?;
    let snapshot = source.bytes("snapshot.bin", limits().max_snapshot_bytes)?;
    let witness_bytes = source.bytes("witness.bin", limits().chain.max_component_bytes)?;
    for (bytes, expected) in [
        (
            genesis_bytes.as_slice(),
            "05f34f0b08d7d61aaa3b349842ebf0e2890b833f45392b2e3ec199cbc5350517",
        ),
        (
            certificate_bytes.as_slice(),
            "67b3ba8061f10cef2be38f219ac01bedd5b55e487cd2b2bc913eb83c108deff5",
        ),
        (
            snapshot.as_slice(),
            "fb4581b30a34e8bd59622fb04f9cac9af3675ab6216bfa93cb2225d06d9e4dd9",
        ),
        (
            witness_bytes.as_slice(),
            "416dac7d749a68d55e4f930acfcfe357f638aefb1d63c460ad86889896480975",
        ),
    ] {
        require(
            sha256(bytes) == expected,
            "pinned public checkpoint input differs",
        )?;
    }
    let genesis = || Genesis::decode(&genesis_bytes);
    require(
        genesis()?.config().pow_iterations == 0,
        "fixture must use existing fixed nonces without PoW search",
    )?;
    let network = genesis()?.config().network;
    let certificate = Certificate::decode(&certificate_bytes, network)
        .map_err(|_| "pinned checkpoint certificate framing invalid")?;
    require(
        certificate.statement.checkpoint_height == 72
            && certificate.statement.authorization_height == 96,
        "pinned checkpoint heights differ",
    )?;
    let witness = AuthorizationWitness::decode(&witness_bytes, limits().chain.max_component_bytes)
        .map_err(|_| "pinned checkpoint witness framing invalid")?;
    let context = Context::from_genesis(&genesis_bytes, genesis()?.id())?;
    let page_bytes = read(page_path, 128 * 1024)?;
    require(
        sha256(&page_bytes) == "4c4af24781f32ceaa909b7473d80fc722cac2ac1cb53a8e736281d259ccbd52a",
        "pinned public header page differs",
    )?;
    let page = HeaderPage::decode(
        &context,
        (96, certificate.statement.authorization_block),
        &page_bytes,
    )?;
    require(
        page.from == 1 && page.headers.len() == 96,
        "complete public headers required",
    )?;
    let headers = page
        .headers
        .iter()
        .map(|header| {
            Header::decode(
                &header
                    .encode()
                    .map_err(|_| "public header encoding invalid")?,
                &network,
            )
            .map_err(|_| "native header conversion invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let config = genesis()?.config().clone();
    let verified_headers = VerifiedHeaders::verify(
        HeaderRules {
            network,
            genesis: genesis()?.id(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            pow_iterations: config.pow_iterations,
            max_headers: 96,
        },
        headers.clone(),
    )
    .map_err(|_| "full fixed-nonce header validation failed")?;
    let plan = AdmissionPlan::select_signed(&[&verified_headers], Work::one())
        .and_then(|plan| plan.at_checkpoint(72, 73, 96))
        .map_err(|_| "signed fixture admission plan failed")?;
    for height in 1..=72 {
        ReceiptBlock::decode(
            &context,
            &headers[height as usize - 1]
                .encode()
                .map_err(|_| "receipt header encoding invalid")?,
            &source.receipt(height, MAX_RECEIPT_BYTES)?,
        )?;
    }
    let verify_started = Instant::now();
    let mut verified = import::verify(
        Input {
            genesis: &genesis_bytes,
            pinned_genesis: genesis()?.id(),
            plan: &plan,
            certificate: &certificate_bytes,
            witness: &witness_bytes,
            snapshot: &snapshot,
        },
        &mut source,
        Policy {
            state: limits(),
            max_headers: 96,
            max_verification_bytes: 2 * 1024 * 1024 * 1024,
        },
        || started.elapsed() > Duration::from_secs(240),
    )?;
    let import_ms = verify_started.elapsed().as_millis();
    println!("native retained fixture: full signed import96 verified in {import_ms} ms");
    require(
        verified.height() == 96 && verified.tip() == headers[95].id().unwrap(),
        "complete native signed import did not validate through 96",
    )?;
    let verified_bytes = verified.verification_bytes();
    // A test-only historical prefix constructor follows a full valid import.
    // It is not a network import with an authorization above its selected head.
    // Every retained state is independently native-executed again from the
    // authenticated snapshot, before the already checked rows are truncated.
    let anchor = ImportedAnchor::reconstruct(
        &plan,
        &genesis()?.initial_state()?,
        genesis()?.rules_commitment(),
        &snapshot,
        limits(),
    )?;
    let mut prefix = Engine::from_imported_anchor(genesis()?, anchor, limits().chain)?;
    let verifier = NativeVerifier::new()?;
    let replay_started = Instant::now();
    for height in 73..=94 {
        let header = &headers[height as usize - 1];
        let body = decoded_body(&mut source, &prefix, height)?;
        prefix.apply(header, &body, &verifier)?;
        let binding = Binding {
            genesis: genesis()?.id(),
            rules_commitment: genesis()?.rules_commitment(),
            parent: header.parent,
        };
        require(
            prefix
                .state()
                .execution_commitment(binding, limits().chain)?
                == header.execution_commitment
                && prefix.state().chain().cumulative_work
                    == verified_headers
                        .work_at(height)
                        .map_err(|_| "prefix cumulative work unavailable")?,
            "native prefix root or cumulative work differs",
        )?;
        require(
            started.elapsed() < Duration::from_secs(240),
            "native prefix replay deadline exceeded",
        )?;
    }
    let prefix_replay_ms = replay_started.elapsed().as_millis();
    verified.engine = prefix;
    verified.headers.truncate(94);
    verified.bodies.truncate(22);
    require(
        verified.height() == 94
            && verified.tip() == headers[93].id().unwrap()
            && verified.receipts.len() == 72
            && verified.anchor == 72,
        "test-only verified prefix crop differs",
    )?;
    write_new(&root.join("genesis.bin"), &genesis_bytes)?;
    drop(
        NativeIdentity::initialize(root, genesis()?.peer_binding())
            .map_err(|_| "new disposable fixture identity creation failed")?,
    );
    let install_started = Instant::now();
    let mut store = match verified.install(root, &mut source, || {
        started.elapsed() > Duration::from_secs(240)
    })? {
        Installation::Durable(store) => store,
        Installation::DurabilityUnconfirmed => {
            return Err("test prefix install durability unconfirmed".into());
        }
    };
    let install_ms = install_started.elapsed().as_millis();
    require(
        store.imported_checkpoint_height() == Some(72),
        "installed import prefix differs",
    )?;
    require(
        store.checkpoint_anchor(72, limits())?.height() == 72,
        "installed checkpoint archive anchor differs",
    )?;
    println!(
        "native retained fixture: independently replayed prefix94 installed; import prefix72 and archive72 checked"
    );
    for height in 95..=96 {
        let body = decoded_body(&mut source, store.engine(), height)?;
        store.append(&headers[height as usize - 1], &body, &verifier)?;
    }
    require(
        store
            .rollback_points()?
            .iter()
            .any(|point| point.height == 95),
        "normal append did not capture the actual 95 savepoint",
    )?;
    let receipt = store
        .permanent_receipt(1)?
        .ok_or("actual permanent receipt missing")?;
    let header = store.header(1)?;
    let size = store.block_size(1)?;
    let fields = public_receipt_fields(store.engine().genesis(), &header, size, &receipt)?;
    require(
        fields.0 == crate::wire::MIN_SLOTS,
        "actual receipt public transaction-slot count differs",
    )?;
    require(
        public_receipt_fields(store.engine().genesis(), &header, size + 1, &receipt).is_err(),
        "public receipt accepted an altered body length",
    )?;
    let mut wrong_header = header.clone();
    wrong_header.nonce += 1;
    require(
        public_receipt_fields(store.engine().genesis(), &wrong_header, size, &receipt).is_err(),
        "public receipt accepted a different exact header",
    )?;
    let mut wrong_context = receipt.clone();
    wrong_context[8] ^= 1;
    require(
        public_receipt_fields(store.engine().genesis(), &header, size, &wrong_context).is_err(),
        "public receipt accepted a different immutable context",
    )?;
    let mut corrupt = receipt.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    require(
        public_receipt_fields(store.engine().genesis(), &header, size, &corrupt).is_err(),
        "public receipt accepted a corrupt range proof",
    )?;
    let prepared = PreparedCheckpoint::restore(
        &store,
        certificate.statement.clone(),
        witness.clone(),
        snapshot.clone(),
        limits(),
    )?;
    let published = 100_000;
    let certified = prepared.certify(&store, certificate.votes.clone(), published)?;
    require(
        certified.certificate.encode().unwrap().as_slice() == certificate_bytes.as_slice(),
        "native public certificate changed during fixture construction",
    )?;
    let good = root.join("good-export");
    mkdir(&good)?;
    let mut export = PublicExport::open(&good, &store, limits())?;
    export.accept_proposal(
        &store,
        certificate.statement.clone(),
        witness.clone(),
        limits(),
    )?;
    require(
        export.publish_checkpoint(&store, &certified, limits())?,
        "native signed publication was not installed",
    )?;
    for vote in &certificate.votes {
        let journal = [
            certificate.statement.encode().unwrap().as_slice(),
            &[vote.slot],
            &vote.signature,
        ]
        .concat();
        write_new(
            &good.join(format!(
                "vote-{:020}-{:020}-{}.eng2.bin",
                certificate.statement.roster_sequence, 72, vote.slot
            )),
            &journal,
        )?;
    }
    drop(export);
    let original_cursor = read(&good.join("checkpoint-eng2.json"), 8192)?;
    let original_tree = tree(&good)?;
    let missing = root.join("missing-export");
    let bad = root.join("bad-signature-export");
    copy_export(&good, &missing)?;
    copy_export(&good, &bad)?;
    let mut bad_certificate = certificate.clone();
    bad_certificate.votes[0].signature[0] ^= 1;
    let bad_bytes = bad_certificate.encode().unwrap();
    let bad_digest = blake3::hash(&bad_bytes);
    let bad_name = format!("{}.certificate-eng2.bin", bad_digest.to_hex());
    write_new(&bad.join(&bad_name), &bad_bytes)?;
    let mut bad_cursor: Value = serde_json::from_slice(&original_cursor).unwrap();
    bad_cursor["certificate_digest"] = json!(bad_digest.to_hex().to_string());
    bad_cursor["certificate_file"] = json!(bad_name);
    fs::write(
        bad.join("checkpoint-eng2.json"),
        serde_json::to_vec(&bad_cursor).unwrap(),
    )
    .map_err(|_| "bad signature fixture cursor replacement failed")?;
    let bad_tree = tree(&bad)?;
    drop(store);
    let mut store = Store::resume_existing(&root.join("chain.redb"), genesis()?, limits().chain)?;
    let restore_started = Instant::now();
    store.restore_ancestor(95, headers[94].id().unwrap())?;
    let restore_ms = restore_started.elapsed().as_millis();
    let binding = Binding {
        genesis: genesis()?.id(),
        rules_commitment: genesis()?.rules_commitment(),
        parent: headers[94].parent,
    };
    require(
        store.engine().state().height() == 95
            && store
                .engine()
                .state()
                .execution_commitment(binding, limits().chain)?
                == headers[94].execution_commitment,
        "restored prefix fingerprint differs",
    )?;
    drop(store);
    let mut store = Store::resume_existing(&root.join("chain.redb"), genesis()?, limits().chain)?;
    println!(
        "native retained fixture: actual persistent restore95 and authenticated reopen passed"
    );
    let strict_error = error(Host::open(&good, &store, limits(), None))?;
    require(
        strict_error == "saved checkpoint authorization is above the canonical prefix",
        "strict open failed for an unexpected reason",
    )?;
    require(
        tree(&good)? == original_tree,
        "strict failure changed immutable publication evidence",
    )?;
    let missing_error = error(Host::open_retained(
        &missing,
        &store,
        limits(),
        None,
        |_, _| Ok(None),
    ))?;
    require(
        missing_error == "retained authorization header unavailable",
        "missing old header was not rejected exactly",
    )?;
    require(
        tree(&missing)? == original_tree,
        "missing-header failure changed publication evidence",
    )?;
    let mut resolver = |height: u64, id: Hash| -> Result<Option<Header>, String> {
        Ok(headers
            .get(height.saturating_sub(1) as usize)
            .filter(|header| header.id().ok() == Some(id))
            .cloned())
    };
    let bad_signature_error = error(Host::open_retained(&bad, &store, limits(), None, resolver))?;
    require(
        bad_signature_error == "checkpoint publication signatures invalid",
        "bad certificate signature was not rejected exactly",
    )?;
    require(
        tree(&bad)? == bad_tree,
        "bad-signature failure changed publication evidence",
    )?;
    let mut retained = Host::open_retained(&good, &store, limits(), None, resolver)?;
    require(
        retained.latest_checkpoint().is_none(),
        "retired authorization returned a publication capability",
    )?;
    // Projection must use authenticated permanent receipts where imported
    // historical proof bodies are intentionally unavailable.
    let tick = retained.tick(&store, published + 1, &[])?;
    require(
        tick.proposal.is_none() && tick.vote.is_none() && tick.certificate.is_none(),
        "retired authorization returned coordination capabilities",
    )?;
    let projection: Value =
        serde_json::from_slice(&read(&good.join("explorer.json"), MAX_PROJECTION_BYTES)?)
            .map_err(|_| "native imported public projection is malformed")?;
    require(
        projection["height"] == 95
            && projection["blocks"]
                .as_array()
                .is_some_and(|blocks| blocks.len() == 95),
        "native imported public projection omitted retained history",
    )?;
    // Classify both capability-producing paths against the same actual Store.
    require(
        matches!(
            publication(
                &store,
                certificate.clone(),
                witness.clone(),
                snapshot.clone(),
                published,
                &certificate.votes,
                limits(),
                &mut resolver
            )?,
            Restored::Retired(72)
        ),
        "retired publication returned a current capability",
    )?;
    require(
        matches!(
            candidate(
                &store,
                certificate.statement.clone(),
                witness.clone(),
                snapshot.clone(),
                &certificate.votes,
                limits(),
                &mut resolver
            )?,
            Restored::Retired(72)
        ),
        "retired candidate returned a preparation capability",
    )?;
    drop(retained);
    let publication_name = "checkpoint-publication-00000000000000000072.json";
    require(
        !good.join("checkpoint-eng2.json").exists()
            && read(&good.join(publication_name), 8192)? == original_cursor,
        "retirement lost the original publication time or retained the mutable cursor",
    )?;
    let mut preserved = tree(&good)?;
    preserved.remove("checkpoint-status-eng2.json");
    preserved.remove("explorer.json");
    let mut expected = original_tree.clone();
    expected.remove("checkpoint-eng2.json");
    require(
        preserved == expected,
        "retirement changed an immutable dependency or vote journal",
    )?;
    // Returning to the original chain must not refresh its first-publication
    // clock or recreate authority from the withdrawn anchor.
    let body = decoded_body(&mut source, store.engine(), 96)?;
    store.append(&headers[95], &body, &verifier)?;
    let reopened = Host::open_retained(&good, &store, limits(), None, resolver)?;
    require(
        reopened.latest_checkpoint().is_none(),
        "withdrawn publication reappeared after original-chain recovery",
    )?;
    require(
        !good.join("checkpoint-eng2.json").exists()
            && read(&good.join(publication_name), 8192)? == original_cursor,
        "original publication clock changed after recovery",
    )?;
    source.check_unchanged()?;
    require(
        read(page_path, 128 * 1024)? == page_bytes,
        "public header page changed during qualification",
    )?;
    Ok(
        json!({"scope":"owner-local-native-retained-checkpoint-prefix",
        "fixture_construction":"full signed import96; independently native replay to94; test-only checked prefix crop; normal append95/96; real persistent restore95",
        "checkpoint_height":72,"authorization_height":96,"restored_height":95,
        "import_verified_tail_blocks":24,"independent_prefix_replayed_blocks":22,"normal_verified_appends":3,
        "full_import_verification_ms":import_ms.to_string(),"prefix_replay_ms":prefix_replay_ms.to_string(),
        "prefix_install_ms":install_ms.to_string(),"restore_ms":restore_ms.to_string(),
        "verification_bytes":verified_bytes.to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),
        "strict_open_error":strict_error,"missing_header_error":missing_error,"bad_signature_error":bad_signature_error,
        "retired_returns_no_capability":true,"installed_import_prefix":72,"installed_archive_anchor":72,
        "public_explorer_tick_exercised":true,"public_projection_blocks":95,
        "receipt_projection_negative_cases":4,"original_publication_seconds":published,
        "immutable_dependencies_and_vote_journals_preserved":true,"original_public_inputs_unchanged":true,
        "source_database_reads":0,"source_identity_reads":0,"new_disposable_identities":1,
        "proof_generation":false,"pow_search":false,"network":false,"g2":false,
        "limitations":"Historical fixed native fixture; test-only prefix construction is not normal network admission94 or a genuine competing branch."}),
    )
}
#[test]
#[ignore = "requires explicit read-only signed native checkpoint fixtures and fresh private destination"]
fn real_signed_checkpoint_above_restored_prefix_is_retired() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_RETAINED_NATIVE_SOURCE").expect("public source required"),
    );
    let page = PathBuf::from(
        std::env::var_os("SIWORLD_RETAINED_NATIVE_HEADERS").expect("public header page required"),
    );
    let root = PathBuf::from(
        std::env::var_os("SIWORLD_RETAINED_NATIVE_DESTINATION")
            .expect("fresh destination required"),
    );
    assert!(source.is_absolute() && page.is_absolute() && root.is_absolute() && !root.exists());
    let parent = root.parent().unwrap().canonicalize().unwrap();
    assert!(
        parent == Path::new("/tmp").canonicalize().unwrap()
            || parent == std::env::temp_dir().canonicalize().unwrap()
    );
    assert!(!source.starts_with(&root) && !root.starts_with(&source));
    mkdir(&root).unwrap();
    let result = match run(&root, &source, &page) {
        Ok(value) => value,
        Err(error) => {
            let failed = json!({"passed":false,"scope":"owner-local-native-retained-checkpoint-prefix","error":error});
            write_new(
                &root.join("result.json"),
                &serde_json::to_vec_pretty(&failed).unwrap(),
            )
            .unwrap();
            panic!("retained native checkpoint qualification failed: {error}");
        }
    };
    write_new(
        &root.join("result.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}
