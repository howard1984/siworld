use super::*;
use crate::{
    eng2::{
        body::Body,
        genesis::{FeeMode, Genesis},
        header::Header,
        snapshot::tests::{bootstrap as state_fixture, limits},
    },
    wire::*,
};
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;

fn genesis() -> Genesis {
    let state = state_fixture();
    Genesis::seal(
        state.chain().config.clone(),
        state.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap()
}
fn digest(value: u32) -> DigestBytes {
    let mut fields = [F::ZERO; 12];
    fields[0] = F::from_u32(value);
    encode_digest(&fields)
}
/// Structurally valid public framing only; no native proof is generated or
/// accepted, and no synthetic block is inserted into an accepted Store.
fn fixture() -> (Genesis, Context, Header, Body) {
    let genesis = genesis();
    let context = Context::from_genesis(&genesis.encode().unwrap(), genesis.id()).unwrap();
    let transactions = (0..MIN_SLOTS)
        .map(|i| {
            let mut body = [0; PUBLIC_BYTES];
            for j in 0..5 {
                body[48 * j..48 * (j + 1)].copy_from_slice(&digest((10 + i * 5 + j) as u32));
            }
            Transaction {
                record: PublicRecord::new(
                    Snapshot {
                        height: 0,
                        block_id: genesis.id(),
                    },
                    body,
                    digest((100000 + i) as u32),
                )
                .unwrap(),
                proof: vec![7; 8192],
            }
        })
        .collect::<Vec<_>>();
    let mut body = Body {
        network: context.config().network,
        height: 1,
        profile: context.profile(),
        transactions,
        reward_mode: RewardMode::Holder,
        rewards: (0..5)
            .map(|i| RewardRecord {
                commitment: digest(200000 + i),
                ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
            })
            .collect(),
        fee_output: crate::eng2::execution::legacy_fee_output(),
        fund_claims: Vec::new(),
        governance: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![9; 8192],
    };
    body.transactions
        .sort_by_key(|tx| tx.record.statement_id(&body.network));
    let header = Header {
        network: body.network,
        height: body.height,
        parent: genesis.id(),
        timestamp: 301,
        target: [255; 32],
        execution_commitment: [21; 32],
        body_commitment: body.commitment(policy(&context)).unwrap(),
        nonce: 3,
    };
    (genesis, context, header, body)
}
fn policy(context: &Context) -> crate::eng2::body::Policy {
    crate::eng2::body::Policy {
        profile: context.profile(),
        max_body_bytes: codec::MAX_BODY_BYTES,
        max_settlement_proof_bytes: MAX_SETTLEMENT_PROOF,
    }
}
fn encode(context: &Context, header: &Header, body: &Body) -> Vec<u8> {
    ReceiptBlock::export(
        context,
        &header.encode().unwrap(),
        &body.encode(policy(context)).unwrap(),
    )
    .unwrap()
}
#[test]
fn pinned_bootstrap_matches_exact_engine_rules_profile_and_fee_mode() {
    let genesis = genesis();
    let bytes = genesis.encode().unwrap();
    let context = Context::from_genesis(&bytes, genesis.id()).unwrap();
    assert_eq!(context.genesis(), genesis.id());
    assert_eq!(context.rules(), genesis.rules_commitment());
    assert_eq!(context.config(), genesis.config());
    assert_eq!(
        context.profile(),
        crate::proofs::protocol_profile_fingerprint()
    );
    assert_eq!(context.fee_mode(), 0);
    assert_ne!(context.genesis(), context.config().genesis_id());
    assert!(Context::from_genesis(&bytes, context.config().genesis_id()).is_err());
    for at in [8, 9, 41, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(Context::from_genesis(&changed, genesis.id()).is_err());
    }
    assert!(Context::from_genesis(&bytes[..bytes.len() - 1], genesis.id()).is_err());
}
#[test]
fn receipt_codec_preserves_all_slots_records_and_tree_order_without_proofs() {
    let (_, context, header, body) = fixture();
    let bytes = encode(&context, &header, &body);
    let decoded = ReceiptBlock::decode(&context, &header.encode().unwrap(), &bytes).unwrap();
    assert_eq!(decoded.header().encode().unwrap(), header.encode().unwrap());
    assert_eq!(
        decoded.body_bytes(),
        body.encode(policy(&context)).unwrap().len()
    );
    assert_eq!(
        decoded.transactions(),
        body.transactions
            .iter()
            .map(|tx| tx.record.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(decoded.transactions().len(), MIN_SLOTS);
    assert_eq!(decoded.rewards(), body.rewards);
    assert!(
        decoded
            .issuances()
            .iter()
            .all(|record| record.proof.is_empty())
    );
    let outputs = decoded.outputs().unwrap();
    assert_eq!(outputs.len(), MIN_SLOTS * 3 + 5);
    assert_eq!(
        &outputs[outputs.len() - 5..],
        &body
            .rewards
            .iter()
            .map(|reward| reward.commitment)
            .collect::<Vec<_>>()
    );
    for transaction in &body.transactions {
        assert!(decoded.contains_statement(&transaction.record.statement_id(&body.network)));
    }
    assert!(!decoded.contains_statement(&[99; 32]));
    assert!(bytes.len() < body.encode(policy(&context)).unwrap().len());
    assert!(bytes.len() <= codec::MAX_RECEIPT_BYTES);
    let wallet = crate::wallet::Wallet::from_seed(
        context.config().network,
        zeroize::Zeroizing::new([42; 32]),
        0,
    )
    .unwrap();
    assert!(decoded.scan_receipts(&wallet).unwrap().is_empty());
}
#[test]
fn receipt_codec_rejects_context_header_and_authentication_tampering() {
    let (_, context, header, body) = fixture();
    let bytes = encode(&context, &header, &body);
    for at in [0, 8, 40, 72, 104, 136, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(ReceiptBlock::decode(&context, &header.encode().unwrap(), &changed).is_err());
    }
    assert!(
        ReceiptBlock::decode(
            &context,
            &header.encode().unwrap(),
            &bytes[..bytes.len() - 1]
        )
        .is_err()
    );
    let mut changed_header = header.clone();
    changed_header.height += 1;
    assert!(ReceiptBlock::decode(&context, &changed_header.encode().unwrap(), &bytes).is_err());
    // Keep the supplied header and envelope mutually consistent: the embedded
    // canonical body height still prevents reuse at another inclusion height.
    let mut changed = bytes.clone();
    changed[137..327].copy_from_slice(&changed_header.encode().unwrap());
    assert!(ReceiptBlock::decode(&context, &changed_header.encode().unwrap(), &changed).is_err());
    let mut raw = body.encode(policy(&context)).unwrap();
    raw.extend_from_slice(&[0; SIDECAR_BYTES]);
    let mut with_sidecar = header;
    with_sidecar.body_commitment =
        crate::eng2::header::body_commitment(&raw, codec::MAX_BODY_BYTES).unwrap();
    assert!(ReceiptBlock::export(&context, &with_sidecar.encode().unwrap(), &raw).is_err());
}
#[test]
fn existing_range_encoding_is_bound_to_domain_and_body_length() {
    let (_, context, header, body) = fixture();
    let raw_body = body.encode(policy(&context)).unwrap();
    let mut preimage = (raw_body.len() as u64).to_le_bytes().to_vec();
    preimage.extend(raw_body);
    let ranges = [(0, 93)];
    let proof = crate::ranges::RangeProof::create_bound(
        &preimage,
        &ranges,
        codec::BODY_DOMAIN,
        codec::MAX_BODY_BYTES + 8,
    )
    .unwrap();
    assert!(
        crate::ranges::RangeProof::verify_bound(
            &proof,
            header.body_commitment,
            codec::BODY_DOMAIN,
            codec::MAX_BODY_BYTES + 8
        )
        .is_ok()
    );
    assert!(crate::ranges::RangeProof::verify(&proof, header.body_commitment).is_err());
    let legacy = crate::ranges::RangeProof::create(&preimage, &ranges).unwrap();
    assert!(
        crate::ranges::RangeProof::verify_bound(
            &legacy,
            header.body_commitment,
            codec::BODY_DOMAIN,
            codec::MAX_BODY_BYTES + 8
        )
        .is_err()
    );
    let mut changed = preimage.clone();
    changed[0] ^= 1;
    let proof = crate::ranges::RangeProof::create_bound(
        &changed,
        &ranges,
        codec::BODY_DOMAIN,
        codec::MAX_BODY_BYTES + 8,
    )
    .unwrap();
    assert!(
        crate::ranges::RangeProof::verify_bound(
            &proof,
            header.body_commitment,
            codec::BODY_DOMAIN,
            codec::MAX_BODY_BYTES + 8
        )
        .is_err()
    );
    // A self-consistent hash cannot make a false canonical body-length prefix valid.
    let mut envelope = encode(&context, &header, &body);
    let wrong_root = *blake3::Hasher::new_derive_key(codec::BODY_DOMAIN)
        .update(&changed)
        .finalize()
        .as_bytes();
    let mut wrong_header = header;
    wrong_header.body_commitment = wrong_root;
    envelope[137..327].copy_from_slice(&wrong_header.encode().unwrap());
    envelope.truncate(327);
    envelope.extend(
        crate::ranges::RangeProof::create_bound(
            &changed,
            &[(0, changed.len())],
            codec::BODY_DOMAIN,
            codec::MAX_BODY_BYTES + 8,
        )
        .unwrap(),
    );
    assert!(ReceiptBlock::decode(&context, &wrong_header.encode().unwrap(), &envelope).is_err());
}
#[test]
fn only_actual_accepted_store_head_can_authorize_export() {
    let directory = Directory::new();
    let store = directory.store();
    let head = Head::capture(&store).unwrap();
    assert_eq!(head.height(), 0);
    let bytes = bootstrap(&store, &head).unwrap();
    assert_eq!(
        Context::from_genesis(&bytes, head.tip()).unwrap().rules(),
        store.engine().genesis().rules_commitment()
    );
    let budget = p2p::Budget::new(128);
    assert!(receipts(&store, &head, 1, &budget).is_err());
    assert!(receipts(&store, &head, 0, &budget).is_err());
    assert!(header_page(&store, &head, 1, 1, &budget).is_err());
    let mut forged = head.clone();
    forged.height = 1;
    assert!(receipts(&store, &forged, 1, &budget).is_err());
    assert!(bootstrap(&store, &forged).is_err());
    forged = head.clone();
    forged.tip[0] ^= 1;
    assert!(forged.check_current(&store).is_err());
    let projection = head.projection(123).unwrap();
    assert!(head.projection(u64::MAX).is_err());
    let mut keys = projection
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "fee_mode",
            "genesis",
            "height",
            "network",
            "profile",
            "published_unix_seconds",
            "rules",
            "tip",
            "version"
        ]
    );
    assert_eq!(budget.available().unwrap(), 128);
}
#[cfg(unix)]
#[test]
fn existing_file_export_publishes_bootstrap_without_claiming_receipt_availability() {
    use std::os::unix::fs::PermissionsExt;
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("public");
    let export = crate::eng2::runtime_export::PublicExport::open(&root, &store, limits()).unwrap();
    let head = export.publish_wallet_head(&store, 123).unwrap();
    let genesis = std::fs::read(root.join("wallet-genesis.bin")).unwrap();
    Context::from_genesis(&genesis, head.tip()).unwrap();
    assert_eq!(
        std::fs::metadata(root.join("wallet-genesis.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("wallet-head.json")).unwrap()).unwrap();
    assert_eq!(value, head.projection(123).unwrap());
    assert!(value.get("compact_available_height").is_none());
    assert!(
        export
            .publish_wallet_receipts(&store, &head, 1, &p2p::Budget::new(1024))
            .is_err()
    );
}

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let path =
            std::env::temp_dir().join(format!("eng2-wallet-export-{}", crate::local::hex(&id)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> Store {
        Store::create(&self.0.join("chain.redb"), genesis(), limits().chain).unwrap()
    }
    #[cfg(unix)]
    fn private(&self, name: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn portable_header_pages_reject_cross_context_head_length_and_order() {
    let (_, context, header, _) = fixture();
    let tip = header.id().unwrap();
    let mut page = b"SWE2WHP1".to_vec();
    for field in [
        context.config().network,
        context.genesis(),
        context.rules(),
        context.profile(),
    ] {
        page.extend_from_slice(&field);
    }
    page.push(context.fee_mode());
    page.extend_from_slice(&1u64.to_le_bytes());
    page.extend_from_slice(&tip);
    page.extend_from_slice(&1u64.to_le_bytes());
    page.extend_from_slice(&1u16.to_le_bytes());
    page.extend(header.encode().unwrap());
    let decoded = codec::HeaderPage::decode(&context, (1, tip), &page).unwrap();
    assert_eq!(decoded.headers.len(), 1);
    assert_eq!(decoded.headers[0].id().unwrap(), tip);
    assert!(codec::HeaderPage::decode(&context, (2, tip), &page).is_err());
    for at in [8, 40, 72, 104, 136, 177, 185, page.len() - 1] {
        let mut changed = page.clone();
        changed[at] ^= 1;
        assert!(codec::HeaderPage::decode(&context, (1, tip), &changed).is_err());
    }
    assert!(codec::HeaderPage::decode(&context, (1, tip), &page[..page.len() - 1]).is_err());
    page.extend_from_slice(&[0]);
    assert!(codec::HeaderPage::decode(&context, (1, tip), &page).is_err());
}

#[test]
fn public_fund_and_issuance_receipts_reuse_existing_decoders_in_native_output_order() {
    use native::{
        issuance::{
            AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration,
            SignedIssuance,
        },
        multi_asset::AssetId,
    };
    let (_, context, mut header, mut body) = fixture();
    for index in 0..2 {
        body.fund_claims
            .push(crate::eng2::fund_claim::PublicFundClaim {
                network: body.network,
                height: body.height,
                encapsulation_coins: [6; 32],
                spend: crate::fund_spend::FundSpend {
                    account: index,
                    counter: 1,
                    amount: 10,
                    owner: digest(400 + u32::from(index)),
                    rho: digest(500 + u32::from(index)),
                    rseed: digest(600 + u32::from(index)),
                    commitment: digest(700 + u32::from(index)),
                    ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
                    verifying_key: [1; crate::fund_spend::VERIFYING_KEY_BYTES],
                    signature: [2; crate::fund_spend::SIGNATURE_BYTES],
                },
            });
        body.issuances.push(crate::issuance::IssuanceRecord {
            signed: SignedIssuance {
                declaration: IssuanceDeclaration {
                    network: body.network,
                    version: 1,
                    issuer_key: [1; ISSUER_KEY_BYTES],
                    sequence: u64::from(index) + 1,
                    asset_id: AssetId([index + 1; 32]),
                    public_supply: 100,
                    metadata: AssetMetadata {
                        name: format!("TEST{index}"),
                        decimals: 0,
                    },
                    issuance_fee_atoms: 5_000_000_000,
                    note_commitments: (0..3)
                        .map(|n| {
                            native::codec::decode_digest(&digest(800 + u32::from(index) * 3 + n))
                                .unwrap()
                        })
                        .collect(),
                    note_ciphertext_digests: vec![[3; 32]; 3],
                },
                signature: Some([2; ISSUER_SIGNATURE_BYTES]),
            },
            ciphertexts: vec![vec![0; crate::issuance::CIPHERTEXT_BYTES]; 3],
            proof: vec![11; 8192],
            fee_commitment: digest(900 + u32::from(index)),
            fee_rho: digest(950 + u32::from(index)),
        });
    }
    body.issuances
        .sort_by_key(|item| item.signed.declaration.binding());
    header.body_commitment = body.commitment(policy(&context)).unwrap();
    let encoded = encode(&context, &header, &body);
    let decoded = ReceiptBlock::decode(&context, &header.encode().unwrap(), &encoded).unwrap();
    assert_eq!(
        decoded.fund_outputs(),
        body.fund_claims
            .iter()
            .map(|claim| claim.spend.clone())
            .collect::<Vec<_>>()
    );
    let expected_issuances = body
        .issuances
        .iter()
        .cloned()
        .map(|mut item| {
            item.proof.clear();
            item
        })
        .collect::<Vec<_>>();
    assert_eq!(decoded.issuances(), expected_issuances);
    let outputs = decoded.outputs().unwrap();
    assert_eq!(outputs.len(), MIN_SLOTS * 3 + 6 + 5 + 2);
    let issuance_outputs = decoded
        .issuances()
        .iter()
        .flat_map(|item| {
            item.signed
                .declaration
                .note_commitments
                .iter()
                .map(encode_digest)
        })
        .collect::<Vec<_>>();
    assert_eq!(&outputs[MIN_SLOTS * 3..MIN_SLOTS * 3 + 6], issuance_outputs);
    assert_eq!(
        &outputs[outputs.len() - 2..],
        body.fund_claims
            .iter()
            .map(|claim| claim.spend.commitment)
            .collect::<Vec<_>>()
    );
}

fn governance_fixture() -> (Context, Header, Body, Vec<Vec<u8>>) {
    use crate::eng2_governance::{Action, ActionKind, Authorization, SignedAction, SignerRole};
    let (_, context, mut header, mut body) = fixture();
    body.governance = (100..102)
        .map(|sequence| SignedAction {
            action: Action {
                network: body.network,
                sequence,
                kind: ActionKind::CancelDestination {
                    proposal_sequence: sequence - 1,
                },
            },
            signatures: vec![Authorization {
                role: SignerRole::Revocation,
                signature: [0xa3; 3309],
            }],
        })
        .collect();
    header.body_commitment = body.commitment(policy(&context)).unwrap();
    let records = body
        .governance
        .iter()
        .map(|action| action.encode().unwrap())
        .collect();
    (context, header, body, records)
}

#[test]
fn public_governance_frames_are_exactly_authenticated_without_authorizing_them() {
    let (context, header, body, records) = governance_fixture();
    let bytes = encode(&context, &header, &body);
    let decoded = ReceiptBlock::decode(&context, &header.encode().unwrap(), &bytes).unwrap();
    assert_eq!(decoded.governance_records(), records);
    for (bytes, action) in decoded.governance_records().iter().zip(&body.governance) {
        assert_eq!(
            crate::eng2_governance::SignedAction::decode(bytes).unwrap(),
            *action
        );
    }
    let at = bytes
        .windows(128)
        .position(|part| part == [0xa3; 128])
        .unwrap();
    let mut changed = bytes;
    changed[at] ^= 1;
    assert!(ReceiptBlock::decode(&context, &header.encode().unwrap(), &changed).is_err());
}

#[test]
fn valid_body_root_cannot_conceal_governance_disclosure() {
    let (context, header, body, records) = governance_fixture();
    let raw = body.encode(policy(&context)).unwrap();
    let mut preimage = (raw.len() as u64).to_le_bytes().to_vec();
    preimage.extend_from_slice(&raw);
    let at =
        8 + crate::eng2::body::PREFIX_BYTES + (body.rewards.len() + 1) * REWARD_RECORD_BYTES + 4;
    let end = at + records[0].len();
    let ranges = [(0, at), (end, preimage.len() - end)];
    let proof = crate::ranges::RangeProof::create_bound(
        &preimage,
        &ranges,
        codec::BODY_DOMAIN,
        codec::MAX_BODY_BYTES + 8,
    )
    .unwrap();
    let sparse = crate::ranges::RangeProof::verify_bound(
        &proof,
        header.body_commitment,
        codec::BODY_DOMAIN,
        codec::MAX_BODY_BYTES + 8,
    )
    .unwrap();
    assert!(sparse.read(at, records[0].len()).is_err());
    let mut envelope = encode(&context, &header, &body);
    envelope.truncate(327);
    envelope.extend(proof);
    let error = ReceiptBlock::decode(&context, &header.encode().unwrap(), &envelope)
        .err()
        .expect("concealed governance must be rejected");
    assert!(error.contains("concealed"));
}

#[test]
fn governance_frame_count_and_byte_limits_are_enforced_before_allocation() {
    let (context, mut header, body, _) = governance_fixture();
    let original = body.encode(policy(&context)).unwrap();
    let length_at =
        crate::eng2::body::PREFIX_BYTES + (body.rewards.len() + 1) * REWARD_RECORD_BYTES;
    for length in [0u32, 16385] {
        let mut raw = original.clone();
        raw[length_at..length_at + 4].copy_from_slice(&length.to_le_bytes());
        header.body_commitment =
            crate::eng2::header::body_commitment(&raw, codec::MAX_BODY_BYTES).unwrap();
        assert!(ReceiptBlock::export(&context, &header.encode().unwrap(), &raw).is_err());
    }
    let mut raw = original;
    raw[83] = 33;
    header.body_commitment =
        crate::eng2::header::body_commitment(&raw, codec::MAX_BODY_BYTES).unwrap();
    assert!(ReceiptBlock::export(&context, &header.encode().unwrap(), &raw).is_err());
}
