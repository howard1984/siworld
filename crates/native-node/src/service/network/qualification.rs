//! Explicit synthetic-wallet qualification. This optional binary is excluded
//! from the deployment payload. It uses the resident driver and NativeVerifier.
use super::*;
use crate::wallet::{FeeTier, Wallet};
use crate::wallet_policy::WalletPrivacyPolicy;
use crate::wallet_vault::WalletVault;
use crate::wire::Block;
use native::multi_asset::SIP_ASSET_ID;
use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroizing;

const FIXTURE_PASSWORD: &str = "isolated native wallet test passphrase";
fn fail<E>(_: E) -> String {
    "isolated qualification operation failed".into()
}
fn private_read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    local::regular_read(path, true, maximum)?
        .read_to_end(&mut out)
        .map_err(fail)?;
    Ok(out)
}
fn once(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = super::super::new_file(path)?;
    file.write_all(bytes).map_err(fail)?;
    file.sync_all().map_err(fail)
}
fn head(node: &Node<NativeVerifier>) -> Value {
    json!({"height":node.state().height,"tip":local::hex(&node.state().tip),
      "state_fingerprint":local::hex(&node.state().fingerprint()),
      "cumulative_work":local::hex(&node.state().cumulative_work.to_big_endian())})
}
fn open(root: &Path) -> Result<Node<NativeVerifier>, String> {
    let path = root.join("node");
    let config = local::load(&path)?;
    let store = Store::open_existing(path.join("chain.redb"), config, &NativeVerifier::new()?)?;
    store.require_local_reward_index()?;
    store.verify_local_rewards()?;
    Ok(Node::new(store, NativeVerifier::new()?))
}
fn prepare(root: &Path) -> Result<(), String> {
    let _lease = super::super::Lease::acquire(&root.join("node"))?;
    let node = open(root)?;
    if node.state().height != 26
        || node.state().config.fixture
        || node.state().config.economics.maturity != 24
    {
        return Err("a copied genuine 26-block synthetic fixture is required".into());
    }
    let mut vault = WalletVault::open(
        &root.join("synthetic-sender"),
        node.state().config.network,
        FIXTURE_PASSWORD,
    )?;
    let mut sender = vault.wallet()?;
    sender.set_privacy_policy(WalletPrivacyPolicy::default());
    let blocks = (1..=node.state().height)
        .map(|h| node.store().block(h))
        .collect::<Result<Vec<_>, _>>()?;
    sender.reconcile(
        node.state().config.clone(),
        &blocks,
        &NativeVerifier::new()?,
    )?;
    let receiver = Wallet::from_seed(node.state().config.network, Zeroizing::new([197; 32]), 0)?;
    let input = sender
        .receipts()
        .iter()
        .find(|n| {
            !n.spent
                && n.note().asset_id == SIP_ASSET_ID
                && n.note().value > 200_000_000
                && n.note().unlock_height <= node.state().height
        })
        .ok_or("no mature synthetic reward")?
        .commitment;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(fail)?
        .as_secs();
    let prepared = sender.prepare_transfer(
        node.state(),
        [Some(input), None],
        &receiver.address(),
        SIP_ASSET_ID,
        100_000_000,
        FeeTier::Standard,
        now,
    )?;
    let reservation = vault.reserve_payment(prepared.record())?;
    let prover = NativeProver::new()?;
    let payment = prepared.prove(&prover)?;
    vault.store_wallet_payment(&reservation, &payment, &receiver.address())?;
    let packet = runtime::encode_gossip(
        &payment.transaction,
        &payment.sidecar,
        &node.state().config.network,
    )?;
    once(&root.join("private-payment.bin"), &packet)?;
    let mut positions = vec![crate::pool::Padding {
        transaction: payment.transaction,
        opening: native::confidential_fees::FeeOpening {
            fee: payment.sidecar.fee,
            blind: payment.sidecar.blind.map(native::multi_asset::F::from_u32),
            dummy: false,
            priority: false,
        },
    }];
    while positions.len() < 64 {
        positions.push(producer::prepare_padding(node.state(), &prover)?);
    }
    let settings = producer::MiningSettings {
        mode: crate::state::RewardMode::Voyager,
        recipient: sender.address(),
    };
    let permit = node.begin_production().map_err(fail)?;
    let mut produced = producer::assemble(
        node.state(),
        &prover,
        positions,
        node.state().timestamp() + 300,
        &settings,
    )?;
    let seed = produced.block.pow_seed()?;
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(
            &seed,
            produced.block.nonce,
            node.state().config.pow_iterations,
        ),
        &produced.block.target,
    ) {
        produced.block.nonce = produced
            .block
            .nonce
            .checked_add(1)
            .ok_or("nonce exhausted")?;
    }
    let prepared = node.bind_produced(permit, produced).map_err(fail)?;
    once(
        &root.join("prepared-block.bin"),
        &prepared.block().encode()?,
    )?;
    atomic_json(
        &root.join("prepared.json"),
        &json!({"schema":1,"head":head(&node),"native_proofs":true,
        "synthetic_wallets_only":true,"maturity":24,"transaction_profile":[7,41,20],"settlement_profile":[8,36,20]}),
    )
}
fn poll(driver: &mut Driver, node: &mut Node<NativeVerifier>) -> Result<(), String> {
    driver.poll()?;
    for _ in 0..COMMAND_SLOTS {
        match driver.rx.try_recv() {
            Ok(command) => driver.handle(node, command)?,
            Err(mpsc::TryRecvError::Empty) => break,
            Err(_) => return Err("owner queue closed".into()),
        }
    }
    Ok(())
}
fn peer(root: &Path, peers: &Path, sender: bool, label: &str) -> Result<(), String> {
    if !matches!(label, "initial" | "restart") {
        return Err("explicit run label required".into());
    }
    let receipt = root.join(format!("{label}-final.json"));
    if receipt.exists() {
        return Err("qualification run already recorded".into());
    }
    let _lease = super::super::Lease::acquire(&root.join("node"))?;
    let mut node = open(root)?;
    let identity =
        Arc::new(NativeIdentity::load(&root.join("node"), &node.binding()).map_err(fail)?);
    let fingerprint = identity.descriptor().map_err(fail)?.fingerprint();
    let config = Configuration::load(&root.join("node"), peers, node.binding(), fingerprint)?;
    if config.mining {
        return Err("qualification uses gated prebuilt blocks".into());
    }
    let mut driver = Driver::new(identity, config, node.transport_budget())?;
    let mut statement = None;
    if sender {
        let packet = private_read(&root.join("private-payment.bin"), p2p::MAX_CONTROL_BYTES)?;
        statement = Some(
            node.resident_admit_relay([199; 32], &packet)
                .map_err(fail)?,
        );
    } else if root.join("pending-statement.bin").exists() {
        statement = Some(
            private_read(&root.join("pending-statement.bin"), 32)?
                .try_into()
                .map_err(fail)?,
        );
    }
    let mut pending_before_block = false;
    let mut acknowledged = false;
    let mut included = false;
    let mut included_gate_consumed = false;
    let started = Instant::now();
    let result: Result<(), String> = (|| {
        while started.elapsed() < Duration::from_secs(3600)
            && !root.join(format!("{label}-stop.request")).exists()
        {
            poll(&mut driver, &mut node)?;
            if statement.is_none() && !node.mempool().is_empty() {
                let id = node.mempool().ids()[0];
                once(&root.join("pending-statement.bin"), &id)?;
                statement = Some(id);
            }
            if let Some(id) = statement {
                pending_before_block |= node.state().height == 26 && node.mempool().contains(&id);
                acknowledged |= driver
                    .workers
                    .values()
                    .any(|w| w.acknowledged.contains(&id));
                if node.state().height >= 27 {
                    included = node
                        .store()
                        .block(27)?
                        .transactions
                        .iter()
                        .any(|tx| tx.record.statement_id(&node.state().config.network) == id);
                }
            }
            if sender && !included_gate_consumed && root.join("include.request").exists() {
                if !acknowledged {
                    return Err("remote proof acknowledgement required before inclusion".into());
                }
                let raw = private_read(
                    &root.join("prepared-block.bin"),
                    crate::wire::MAX_BLOCK_BYTES,
                )?;
                let block = Block::decode(&raw, &node.state().config.network)?;
                node.import_branch(26, &[block], crate::chain::CandidatePolicy::default())
                    .map_err(fail)?;
                included_gate_consumed = true;
            }
            atomic_json(
                &root.join(format!("{label}-status.json")),
                &json!({"schema":1,"head":head(&node),"native_proofs":true,
                "pending_verified_before_block":pending_before_block,"remote_acknowledged":acknowledged,
                "payment_included":included,"network":driver.status(false),"elapsed_ms":elapsed_ms(started,Instant::now())}),
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        if started.elapsed() >= Duration::from_secs(3600) {
            return Err("qualification deadline reached".into());
        }
        Ok(())
    })();
    let cleanup = driver.shutdown();
    let expected = head(&node);
    drop(node);
    let replayed = open(root)?;
    let same = head(&replayed) == expected;
    atomic_json(
        &receipt,
        &json!({"schema":1,"head":head(&replayed),"successful":result.is_ok()&&cleanup.is_ok()&&same,
        "native_proof_replay":same,"pending_verified_before_block":pending_before_block,"remote_acknowledged":acknowledged,
        "payment_included":included,"network":driver.status(false)}),
    )?;
    result?;
    cleanup?;
    if !same {
        return Err("replay head changed".into());
    }
    Ok(())
}
pub fn run(args: Vec<String>) -> Result<(), String> {
    if std::env::var("SIWORLD_RUN_PEER_QUALIFICATION").as_deref() != Ok("1") {
        return Err("explicit qualification opt-in required".into());
    }
    match args.as_slice() {
        [action, root] if action == "prepare" => prepare(Path::new(root)),
        [action, root, peers, role, label]
            if action == "run" && matches!(role.as_str(), "sender" | "validator") =>
        {
            peer(Path::new(root), Path::new(peers), role == "sender", label)
        }
        _ => Err("unsupported qualification command".into()),
    }
}
