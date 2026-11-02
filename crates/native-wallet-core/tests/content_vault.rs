use siworld_native_wallet_core::content_vault::{self, Content, ENVELOPE_LEN};
use zeroize::Zeroizing;

const NETWORK: [u8; 32] = [3; 32];
const PASSWORD: &str = "synthetic-content-password";

fn sample() -> Content {
    Content {
        network: NETWORK,
        account: 7,
        created_at: 1_700_000_000_000,
        kind: 0,
        title: Zeroizing::new("Synthetic note".into()),
        secret: Zeroizing::new("Disposable test content".into()),
    }
}

#[test]
fn fixed_width_randomized_content_roundtrips_and_binds_context() {
    let a = content_vault::seal(&sample(), PASSWORD).unwrap();
    let b = content_vault::seal(&sample(), PASSWORD).unwrap();
    assert_eq!(a.len(), ENVELOPE_LEN);
    assert_ne!(a, b);
    assert!(!a.windows(9).any(|w| w == b"Synthetic"));
    let opened = content_vault::open(&a, PASSWORD, NETWORK, 7).unwrap();
    assert_eq!(opened.title.as_str(), "Synthetic note");
    assert_eq!(opened.secret.as_str(), "Disposable test content");
    assert_eq!(opened.created_at, sample().created_at);
    assert!(content_vault::open(&a, "incorrect-password", NETWORK, 7).is_err());
    assert!(content_vault::open(&a, PASSWORD, [4; 32], 7).is_err());
    assert!(content_vault::open(&a, PASSWORD, NETWORK, 8).is_err());
}

#[test]
fn content_rejects_tampering_wallet_vaults_and_invalid_lengths() {
    let bytes = content_vault::seal(&sample(), PASSWORD).unwrap();
    for at in [0, 8, 24, 48, ENVELOPE_LEN - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(content_vault::open(&changed, PASSWORD, NETWORK, 7).is_err());
    }
    for invalid in [
        vec![],
        bytes[..bytes.len() - 1].to_vec(),
        vec![0; ENVELOPE_LEN + 1],
    ] {
        assert!(content_vault::open(&invalid, PASSWORD, NETWORK, 7).is_err());
    }
    let wallet = siworld_native_wallet_core::vault::Material::generate(NETWORK, 7)
        .unwrap()
        .seal(PASSWORD)
        .unwrap();
    assert!(content_vault::open(&wallet, PASSWORD, NETWORK, 7).is_err());
}

#[test]
fn content_enforces_payload_kind_size_and_passphrase_limits() {
    let mut data = sample();
    assert!(content_vault::seal(&data, "short").is_err());
    data.title = Zeroizing::new(" ".into());
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data = sample();
    data.title = Zeroizing::new("x".repeat(81));
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data = sample();
    data.secret = Zeroizing::new("x".repeat(2049));
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data = sample();
    data.kind = 3;
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data = sample();
    data.network = [0; 32];
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data = sample();
    data.kind = 2;
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data.secret = Zeroizing::new(format!("0x{}", "01".repeat(32)));
    assert!(content_vault::seal(&data, PASSWORD).is_ok());
    data.secret = Zeroizing::new(format!("0x{}", "00".repeat(32)));
    assert!(content_vault::seal(&data, PASSWORD).is_err());
    data.secret = Zeroizing::new(format!("0x{}", "ff".repeat(32)));
    assert!(content_vault::seal(&data, PASSWORD).is_err());
}
