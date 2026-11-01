use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const PASSWORD: &str = "synthetic test passphrase only";
const NETWORK: Hash = [93; 32];

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-native-vault-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
    fn wallet(&self) -> PathBuf {
        self.0.join("wallet")
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn zero_words() -> Zeroizing<String> {
    Zeroizing::new(format!("{}art", "abandon ".repeat(23)))
}

#[test]
fn generated_wallet_requires_matching_backup_challenge_before_publication() {
    let pending = PendingWallet::generate(NETWORK, 7).unwrap();
    let words = pending.recovery_words();
    let parts: Vec<&str> = words.expose().split(' ').collect();
    assert_eq!(parts.len(), 24);
    let challenge = pending.backup_challenge();
    assert!(challenge.iter().all(|index| (1..=24).contains(index)));
    assert_ne!(challenge[0], challenge[1]);
    assert_ne!(challenge[0], challenge[2]);
    assert_ne!(challenge[1], challenge[2]);
    let confirmed = pending
        .confirm_backup(challenge.map(|index| parts[index - 1]))
        .unwrap();
    let dir = Temporary::new();
    let unlocked = confirmed.create(&dir.wallet(), PASSWORD).unwrap();
    assert_eq!(unlocked.network(), NETWORK);
    assert_eq!(unlocked.account(), 7);
    assert_eq!(
        unlocked.descriptor(),
        RecoveryDescriptor {
            version: 1,
            network: NETWORK,
            account: 7
        }
    );

    let pending = PendingWallet::generate(NETWORK, 7).unwrap();
    assert!(pending.confirm_backup(["invalid"; 3]).is_err());
    assert!(PendingWallet::generate([0; 32], 0).is_err());
}

#[test]
fn mnemonic_entropy_restore_reopens_same_network_account_and_address() {
    let directory = Temporary::new();
    let wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 9, zero_words(), PASSWORD).unwrap();
    let address = wallet.keys().unwrap().address();
    let direct = WalletKeys::from_seed(NETWORK, Zeroizing::new([0; 32]), 9).unwrap();
    assert_eq!(address, direct.address());
    assert_eq!(wallet.wallet().unwrap().address(), address);
    assert_eq!(wallet.account(), 9);
    drop(wallet);
    let reopened = WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).unwrap();
    assert_eq!(reopened.keys().unwrap().address(), address);
    assert_eq!(reopened.account(), 9);
    drop(reopened);
    assert!(WalletVault::open(&directory.wallet(), [94; 32], PASSWORD).is_err());
}

#[test]
fn invalid_mnemonic_password_and_network_fail_before_creating_directory() {
    let directory = Temporary::new();
    for phrase in [
        "abandon ".repeat(12),
        "abandon ".repeat(24),
        format!("{}ART", "abandon ".repeat(23)),
        "x".repeat(MAX_MNEMONIC_BYTES + 1),
    ] {
        assert!(
            WalletVault::restore(
                &directory.wallet(),
                NETWORK,
                0,
                Zeroizing::new(phrase),
                PASSWORD
            )
            .is_err()
        );
        assert!(!directory.wallet().exists());
    }
    assert!(WalletVault::restore(&directory.wallet(), [0; 32], 0, zero_words(), PASSWORD).is_err());
    for password in ["", "short"] {
        assert!(
            WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), password).is_err()
        );
        assert!(!directory.wallet().exists());
    }
}

#[test]
fn encrypted_vault_is_fixed_width_authenticated_and_never_overwritten() {
    let directory = Temporary::new();
    let wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let path = directory.wallet().join(VAULT_FILENAME);
    let original = std::fs::read(&path).unwrap();
    assert_eq!(original.len(), VAULT_LEN);
    assert!(!original.windows(32).any(|bytes| bytes == [0; 32]));
    assert!(!original.windows(7).any(|bytes| bytes == b"abandon"));
    drop(wallet);
    assert!(WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(WalletVault::open(&directory.wallet(), NETWORK, "wrong passphrase").is_err());
    for index in [0, MAGIC.len(), HEADER_LEN - 1, HEADER_LEN, VAULT_LEN - 1] {
        let mut changed = original.clone();
        changed[index] ^= 1;
        std::fs::write(&path, &changed).unwrap();
        assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    }
    for length in [0, VAULT_LEN - 1, VAULT_LEN + 1, 4096] {
        std::fs::write(&path, vec![0; length]).unwrap();
        assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    }
}

#[test]
fn running_wallet_exclusively_owns_its_directory() {
    let directory = Temporary::new();
    let wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    drop(wallet);
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_ok());
}

#[cfg(unix)]
#[test]
fn directory_and_vault_reject_symlinks_hardlinks_and_unsafe_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = Temporary::new();
    let wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    drop(wallet);
    let path = directory.wallet().join(VAULT_FILENAME);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.0.join("linked");
    std::fs::hard_link(&path, &linked).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    std::fs::remove_file(&linked).unwrap();
    let symlinked = directory.0.join("symlinked");
    symlink(directory.wallet(), &symlinked).unwrap();
    assert!(WalletVault::open(&symlinked, NETWORK, PASSWORD).is_err());
    let sibling = directory.0.join("sibling");
    std::fs::create_dir(&sibling).unwrap();
    let link_parent = directory.0.join("link-parent");
    symlink(&sibling, &link_parent).unwrap();
    assert!(
        WalletVault::restore(
            &link_parent.join("wallet"),
            NETWORK,
            0,
            zero_words(),
            PASSWORD
        )
        .is_err()
    );
    assert!(!sibling.join("wallet").exists());
    std::fs::set_permissions(directory.wallet(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    std::fs::set_permissions(directory.wallet(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let original = directory.0.join("original-vault");
    std::fs::rename(&path, &original).unwrap();
    symlink(&original, &path).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
}

#[test]
fn interrupted_exclusive_publication_does_not_expose_partial_vault() {
    let directory = Temporary::new();
    let owned = storage::Directory::create(&directory.wallet()).unwrap();
    assert!(
        owned
            .publish_with(b"synthetic ciphertext", || Err("injected failure".into()))
            .is_err()
    );
    assert!(!directory.wallet().join(VAULT_FILENAME).exists());
    assert_eq!(std::fs::read_dir(directory.wallet()).unwrap().count(), 1);
    owned.publish_with(b"complete", || Ok(())).unwrap();
    assert!(owned.publish_with(b"replacement", || Ok(())).is_err());
    assert_eq!(
        std::fs::read(directory.wallet().join(VAULT_FILENAME)).unwrap(),
        b"complete"
    );
}

fn payment_fixture(
    tag: u32,
) -> (
    crate::state::Config,
    crate::wire::Block,
    crate::wire::Sidecar,
) {
    use p3_field::PrimeCharacteristicRing;
    let config = crate::state::Config::development(NETWORK, 0).unwrap();
    let state = crate::state::State::new(config.clone()).unwrap();
    let mut block = crate::fixtures::candidate(&state, tag);
    let blind = [native::multi_asset::F::from_u32(7); 8];
    block.transactions[0].record.fee_commit =
        native::codec::encode_digest(&native::multi_asset::Hasher::new().fee_commit(0, &blind));
    let id = block.transactions[0].record.statement_id(&NETWORK);
    let sidecar = crate::wire::Sidecar {
        transaction_id: id,
        fee: 0,
        blind: [7; 8],
    };
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&NETWORK));
    remine(&mut block, &config);
    (config, block, sidecar)
}
fn remine(block: &mut crate::wire::Block, config: &crate::state::Config) {
    let seed = block.pow_seed().unwrap();
    block.nonce = 0;
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
}

#[test]
fn reservation_is_durable_before_proof_and_rejects_every_input_overlap() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, sidecar) = payment_fixture(10_000);
    let tx = block
        .transactions
        .iter()
        .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
        .unwrap();
    let reservation = wallet.reserve_payment(&tx.record).unwrap();
    let id = reservation.id();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Reserved);
    assert!(wallet.payment_packet(id).is_err());
    assert!(wallet.reserve_payment(&tx.record).is_ok());
    let mut competing = block
        .transactions
        .iter()
        .find(|other| other.record != tx.record)
        .unwrap()
        .record
        .clone();
    let mut body = native::codec::PublicTransaction::decode(&competing.body).unwrap();
    body.nf[1] = native::codec::PublicTransaction::decode(&tx.record.body)
        .unwrap()
        .nf[1];
    competing.body = body.encode();
    assert!(wallet.reserve_payment(&competing).is_err());
    drop(wallet);
    let wallet = WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).unwrap();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Reserved);
    assert_eq!(wallet.payment_ids(), vec![id]);
}

#[test]
fn exact_prepared_packet_survives_restart_and_retries_only_identical_submission() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, sidecar) = payment_fixture(30_000);
    let tx = block
        .transactions
        .iter()
        .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
        .unwrap();
    let ticket = wallet.reserve_payment(&tx.record).unwrap();
    let id = ticket.id();
    let opening = || Zeroizing::new(b"synthetic private payment opening".to_vec());
    wallet
        .store_prepared_payment(&ticket, tx, &sidecar, opening(), |_, bytes| {
            if bytes == b"synthetic private payment opening" {
                Ok(())
            } else {
                Err("opening invalid".into())
            }
        })
        .unwrap();
    let expected = wallet.payment_packet(id).unwrap();
    let expected_envelope = expected.envelope().to_vec();
    assert!(
        wallet
            .submit_payment(id, |_| Err("transport interruption".into()))
            .is_err()
    );
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Prepared);
    let mut replacement = tx.clone();
    replacement.proof.push(1);
    assert!(
        wallet
            .store_prepared_payment(&ticket, &replacement, &sidecar, opening(), |_, _| Ok(()))
            .is_err()
    );
    drop(wallet);
    let mut wallet = WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).unwrap();
    wallet
        .submit_payment(id, |packet| {
            assert_eq!(packet.envelope(), expected_envelope);
            assert_eq!(packet.opening(), b"synthetic private payment opening");
            packet
                .sidecar()?
                .check_opening(&packet.transaction()?.record, &NETWORK)
        })
        .unwrap();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Submitted);
    wallet
        .submit_payment(id, |packet| {
            assert_eq!(packet.envelope(), expected_envelope);
            Ok(())
        })
        .unwrap();
}

#[test]
fn bad_sidecar_opening_payload_and_unreserved_transaction_are_rejected_atomically() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, mut sidecar) = payment_fixture(50_000);
    let tx = block
        .transactions
        .iter()
        .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
        .unwrap();
    let ticket = wallet.reserve_payment(&tx.record).unwrap();
    sidecar.fee = 1;
    assert!(
        wallet
            .store_prepared_payment(
                &ticket,
                tx,
                &sidecar,
                Zeroizing::new(vec![1]),
                |_, _| Ok(())
            )
            .is_err()
    );
    sidecar.fee = 0;
    assert!(
        wallet
            .store_prepared_payment(&ticket, tx, &sidecar, Zeroizing::new(vec![1]), |_, _| Err(
                "invalid opening".into()
            ))
            .is_err()
    );
    assert!(
        wallet
            .store_prepared_payment(
                &ticket,
                tx,
                &sidecar,
                Zeroizing::new(Vec::new()),
                |_, _| Ok(())
            )
            .is_err()
    );
    assert!(
        wallet
            .store_prepared_payment(
                &ticket,
                tx,
                &sidecar,
                Zeroizing::new(vec![1; 65_537]),
                |_, _| Ok(())
            )
            .is_err()
    );
    assert!(wallet.payment_status(ticket.id()).unwrap() == PaymentStatus::Reserved);
    assert!(wallet.payment_packet(ticket.id()).is_err());
}

#[test]
fn independently_replayed_journal_tracks_acceptance_orphan_and_conflicting_spend() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (config, block, sidecar) = payment_fixture(70_000);
    let tx = block
        .transactions
        .iter()
        .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
        .unwrap();
    let id = wallet.reserve_payment(&tx.record).unwrap().id();
    wallet
        .reconcile_payments(
            config.clone(),
            std::slice::from_ref(&block),
            &crate::fixtures::TestVerifier,
        )
        .unwrap();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Accepted);
    wallet
        .reconcile_payments(config.clone(), &[], &crate::fixtures::TestVerifier)
        .unwrap();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Orphaned);
    let state = crate::state::State::new(config.clone()).unwrap();
    let mut competing = crate::fixtures::candidate(&state, 90_000);
    let mut body =
        native::codec::PublicTransaction::decode(&competing.transactions[0].record.body).unwrap();
    body.nf[0] = native::codec::PublicTransaction::decode(&tx.record.body)
        .unwrap()
        .nf[0];
    competing.transactions[0].record.body = body.encode();
    competing
        .transactions
        .sort_by_key(|value| value.record.statement_id(&NETWORK));
    remine(&mut competing, &config);
    wallet
        .reconcile_payments(config, &[competing], &crate::fixtures::TestVerifier)
        .unwrap();
    assert!(wallet.payment_status(id).unwrap() == PaymentStatus::Conflicted);
    assert!(wallet.reserve_payment(&tx.record).is_err());
}

#[test]
fn missing_corrupt_or_different_account_journal_never_resets_to_empty() {
    let directory = Temporary::new();
    let wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    drop(wallet);
    let path = directory.wallet().join("payments.journal");
    let encoded = std::fs::read(&path).unwrap();
    let mut changed = encoded.clone();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, changed).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    let other = directory.0.join("other");
    let wallet = WalletVault::restore(&other, NETWORK, 1, zero_words(), PASSWORD).unwrap();
    drop(wallet);
    std::fs::write(other.join("payments.journal"), encoded).unwrap();
    assert!(WalletVault::open(&other, NETWORK, PASSWORD).is_err());
}

#[test]
fn deleted_live_lock_is_not_recreated_and_owner_cannot_continue() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, _) = payment_fixture(110_000);
    let lock = directory.wallet().join(".wallet.lock");
    std::fs::remove_file(&lock).unwrap();
    assert!(WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).is_err());
    assert!(!lock.exists());
    assert!(
        wallet
            .reserve_payment(&block.transactions[0].record)
            .is_err()
    );
    assert!(wallet.keys().is_err());
    assert!(wallet.wallet().is_err());
}

#[test]
fn reservation_capability_is_bound_to_seed_even_with_same_account_network() {
    let directory = Temporary::new();
    let pending = PendingWallet::generate(NETWORK, 0).unwrap();
    let words = pending.recovery_words();
    let parts: Vec<_> = words.expose().split(' ').collect();
    let positions = pending.backup_challenge();
    let mut first = pending
        .confirm_backup(positions.map(|index| parts[index - 1]))
        .unwrap()
        .create(&directory.wallet(), PASSWORD)
        .unwrap();
    let mut second = WalletVault::restore(
        &directory.0.join("second"),
        NETWORK,
        0,
        zero_words(),
        PASSWORD,
    )
    .unwrap();
    let (_, block, sidecar) = payment_fixture(130_000);
    let tx = block
        .transactions
        .iter()
        .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
        .unwrap();
    let first_ticket = first.reserve_payment(&tx.record).unwrap();
    let second_ticket = second.reserve_payment(&tx.record).unwrap();
    assert!(
        second
            .store_prepared_payment(
                &first_ticket,
                tx,
                &sidecar,
                Zeroizing::new(vec![1]),
                |_, _| Ok(())
            )
            .is_err()
    );
    second
        .store_prepared_payment(
            &second_ticket,
            tx,
            &sidecar,
            Zeroizing::new(vec![1]),
            |_, _| Ok(()),
        )
        .unwrap();
}

#[test]
fn payment_record_cap_rejects_without_discarding_history() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, _) = payment_fixture(150_000);
    for transaction in &block.transactions[..32] {
        wallet.reserve_payment(&transaction.record).unwrap();
    }
    let before = std::fs::read(directory.wallet().join("payments.journal")).unwrap();
    assert!(
        wallet
            .reserve_payment(&block.transactions[32].record)
            .is_err()
    );
    assert_eq!(wallet.payment_ids().len(), 32);
    assert_eq!(
        std::fs::read(directory.wallet().join("payments.journal")).unwrap(),
        before
    );
}

#[test]
fn external_journal_change_poisoning_requires_reopen_without_automatic_repair() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, _) = payment_fixture(170_000);
    let path = directory.wallet().join("payments.journal");
    let original = std::fs::read(&path).unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &changed).unwrap();
    assert!(
        wallet
            .reserve_payment(&block.transactions[0].record)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), changed);
    std::fs::write(&path, &original).unwrap();
    assert!(
        wallet
            .reserve_payment(&block.transactions[0].record)
            .is_err()
    );
    drop(wallet);
    let mut reopened = WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).unwrap();
    assert!(reopened.payment_ids().is_empty());
    reopened
        .reserve_payment(&block.transactions[0].record)
        .unwrap();
}

fn typed_opening_fixture() -> (
    crate::wire::Transaction,
    native::encryption::PaymentAddress,
    native::encryption::PaymentEncryptionOpening,
) {
    use p3_field::PrimeCharacteristicRing;
    let (_, block, _) = payment_fixture(190_000);
    let mut tx = block.transactions[0].clone();
    let address = WalletKeys::from_seed(NETWORK, Zeroizing::new([3; 32]), 0)
        .unwrap()
        .address();
    let note = native::multi_asset::Note {
        asset_id: native::multi_asset::SIP_ASSET_ID,
        owner: address.owner(),
        value: 100_000,
        unlock_height: 0,
        rho: [native::multi_asset::F::from_u32(9); 12],
        rseed: [native::multi_asset::F::from_u32(10); 12],
    };
    let mut public = native::codec::PublicTransaction::decode(&tx.record.body).unwrap();
    public.cm[0] = native::multi_asset::Hasher::new().note_cm(&note);
    let (ciphertext, opening) = native::encryption::encrypt_payment_with_opening(
        &address,
        &note,
        &native::encryption::EncryptionContext::new(NETWORK),
    )
    .unwrap();
    public.payment = ciphertext;
    tx.record.body = public.encode();
    (tx, address, opening)
}

#[test]
fn typed_payment_opening_rejects_wrong_recipient_network_transaction_coins_and_format() {
    let (tx, address, opening) = typed_opening_fixture();
    let stored = StoredPaymentOpening::from_payment(NETWORK, &tx, &address, &opening).unwrap();
    let encoded = stored.private_bytes();
    assert_eq!(encoded.len(), 1336);
    assert!(StoredPaymentOpening::decode_and_check(encoded, &tx, NETWORK).is_ok());
    assert!(StoredPaymentOpening::decode_and_check(encoded, &tx, [94; 32]).is_err());
    let mut different = tx.clone();
    different.record.snapshot.height += 1;
    assert!(StoredPaymentOpening::decode_and_check(encoded, &different, NETWORK).is_err());
    for offset in [0, 8, 40, 72, 120, 1304] {
        let mut changed = Zeroizing::new(encoded.to_vec());
        changed[offset] ^= 1;
        assert!(StoredPaymentOpening::decode_and_check(&changed, &tx, NETWORK).is_err());
    }
    assert!(StoredPaymentOpening::decode_and_check(&encoded[..1335], &tx, NETWORK).is_err());
    let wrong = WalletKeys::from_seed(NETWORK, Zeroizing::new([4; 32]), 0)
        .unwrap()
        .address();
    assert!(StoredPaymentOpening::from_payment(NETWORK, &tx, &wrong, &opening).is_err());
}

#[test]
fn genuine_prepared_transfer_opening_is_durable_and_typed_verified_after_reopen() {
    use native::encryption::{EncryptionContext, encrypt_payment_with_opening};
    use native::multi_asset::{F, Hasher, Note, SIP_ASSET_ID};
    use p3_field::PrimeCharacteristicRing;
    let directory = Temporary::new();
    let mut vault =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let mut sender = vault.wallet().unwrap();
    let config = crate::state::Config::development(NETWORK, 0).unwrap();
    let mut state = crate::state::State::new(config.clone()).unwrap();
    let mut funding = crate::fixtures::candidate(&state, 210_000);
    let note = Note {
        asset_id: SIP_ASSET_ID,
        owner: sender.address().owner(),
        value: 100_000_000,
        unlock_height: 0,
        rho: [F::from_u32(21); 12],
        rseed: [F::from_u32(22); 12],
    };
    let mut public =
        native::codec::PublicTransaction::decode(&funding.transactions[0].record.body).unwrap();
    public.cm[0] = Hasher::new().note_cm(&note);
    public.payment =
        encrypt_payment_with_opening(&sender.address(), &note, &EncryptionContext::new(NETWORK))
            .unwrap()
            .0;
    funding.transactions[0].record.body = public.encode();
    funding
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&NETWORK));
    remine(&mut funding, &config);
    state
        .apply(&funding, &crate::fixtures::TestVerifier)
        .unwrap();
    sender
        .reconcile(config, &[funding], &crate::fixtures::TestVerifier)
        .unwrap();
    let recipient = WalletKeys::from_seed(NETWORK, Zeroizing::new([5; 32]), 0)
        .unwrap()
        .address();
    let prepared = sender
        .prepare_transfer(
            &state,
            [Some(sender.receipts()[0].commitment), None],
            &recipient,
            SIP_ASSET_ID,
            100_000,
            crate::wallet::FeeTier::Standard,
            state.timestamp(),
        )
        .unwrap();
    let ticket = vault.reserve_payment(prepared.record()).unwrap();
    let tx = crate::wire::Transaction {
        record: prepared.record().clone(),
        proof: vec![1],
    };
    vault
        .store_prepared_with_opening(
            &ticket,
            &tx,
            prepared.sidecar(),
            &recipient,
            prepared.payment_opening(),
        )
        .unwrap();
    let id = ticket.id();
    drop(vault);
    let vault = WalletVault::open(&directory.wallet(), NETWORK, PASSWORD).unwrap();
    vault.verified_payment_opening(id).unwrap();
    assert_eq!(
        vault.payment_packet(id).unwrap().envelope(),
        tx.encode_envelope(&NETWORK).unwrap()
    );
}

#[test]
fn relay_callback_never_runs_after_live_journal_deletion_tampering_or_lock_loss() {
    for alteration in 0..3 {
        let directory = Temporary::new();
        let mut wallet =
            WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
        let (_, block, sidecar) = payment_fixture(250_000 + alteration * 20_000);
        let tx = block
            .transactions
            .iter()
            .find(|tx| tx.record.statement_id(&NETWORK) == sidecar.transaction_id)
            .unwrap();
        let ticket = wallet.reserve_payment(&tx.record).unwrap();
        wallet
            .store_prepared_payment(
                &ticket,
                tx,
                &sidecar,
                Zeroizing::new(vec![1]),
                |_, _| Ok(()),
            )
            .unwrap();
        let path = directory.wallet().join("payments.journal");
        match alteration {
            0 => std::fs::remove_file(&path).unwrap(),
            1 => {
                let mut changed = std::fs::read(&path).unwrap();
                *changed.last_mut().unwrap() ^= 1;
                std::fs::write(&path, changed).unwrap();
            }
            _ => std::fs::remove_file(directory.wallet().join(".wallet.lock")).unwrap(),
        }
        let mut called = false;
        assert!(
            wallet
                .submit_payment(ticket.id(), |_| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        assert!(wallet.payment_packet(ticket.id()).is_err());
        assert!(wallet.reserve_payment(&tx.record).is_err());
    }
}

#[test]
fn idempotent_reservation_rechecks_durable_file_and_poisoning_cannot_be_cleared_in_memory() {
    let directory = Temporary::new();
    let mut wallet =
        WalletVault::restore(&directory.wallet(), NETWORK, 0, zero_words(), PASSWORD).unwrap();
    let (_, block, _) = payment_fixture(330_000);
    let record = &block.transactions[0].record;
    wallet.reserve_payment(record).unwrap();
    let path = directory.wallet().join("payments.journal");
    let original = std::fs::read(&path).unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, changed).unwrap();
    assert!(wallet.reserve_payment(record).is_err());
    std::fs::write(&path, original).unwrap();
    assert!(wallet.reserve_payment(record).is_err());
}
