use siworld_native_wallet_core::{
    address, hex_array,
    identity::Identity,
    network,
    vault::{self, Material},
};
use zeroize::Zeroizing;

fn material(n: u8, account: u32) -> Material {
    Material {
        network: [n; 32],
        account,
        entropy: Zeroizing::new([7; 32]),
    }
}
fn identity(m: &Material) -> Identity {
    Identity::derive(&m.entropy, m.network, m.account).unwrap()
}

#[test]
fn raw_entropy_mnemonic_roundtrip() {
    let m = material(1, 42);
    let r = Material::restore(m.network, m.account, m.words()).unwrap();
    assert_eq!(r.entropy.as_ref(), m.entropy.as_ref());
    assert_eq!(identity(&m).address(), identity(&r).address());
}
#[test]
fn network_and_account_separate_identity() {
    let m = material(1, 0);
    assert_ne!(identity(&m).address(), identity(&material(2, 0)).address());
    assert_ne!(identity(&m).address(), identity(&material(1, 1)).address());
}
#[test]
fn rejects_legacy_and_bad_words() {
    for words in [
        "abandon ".repeat(11) + "about",
        "abandon ".repeat(23) + "abandon",
        "ABANDON ".repeat(23) + "ART",
    ] {
        assert!(Material::restore([1; 32], 0, Zeroizing::new(words)).is_err());
    }
}
#[test]
fn zero_network_and_noncanonical_hex_fail() {
    assert!(network(&"00".repeat(32)).is_err());
    assert!(network(&"AA".repeat(32)).is_err());
    assert!(hex_array::<1>("00 ").is_err());
    assert!(Material::generate([0; 32], 0).is_err());
}
#[test]
fn challenges_are_distinct_and_in_range() {
    for _ in 0..100 {
        let c = vault::challenge().unwrap();
        assert!(c.iter().all(|p| (1..=24).contains(p)));
        assert!(c[0] != c[1] && c[0] != c[2] && c[1] != c[2]);
    }
}
#[test]
fn vault_authentication_password_and_context() {
    let m = material(1, 42);
    let p = "synthetic-password-only";
    let encrypted = m.seal(p).unwrap();
    assert_eq!(encrypted.len(), vault::VAULT_LEN);
    let opened = Material::open(&encrypted, p, m.network).unwrap();
    assert_eq!(opened.account, m.account);
    assert_eq!(identity(&opened).address(), identity(&m).address());
    assert!(Material::open(&encrypted, "wrong-password", m.network).is_err());
    assert!(Material::open(&encrypted, p, [2; 32]).is_err());
    for i in [8, 24, 48, 115, 131] {
        let mut bad = encrypted.clone();
        bad[i] ^= 1;
        assert!(Material::open(&bad, p, m.network).is_err());
    }
    assert!(Material::open(&encrypted[..131], p, m.network).is_err());
    assert!(m.seal("too-short").is_err());
}
#[test]
fn password_rotation_keeps_identity() {
    let m = material(1, 0);
    let a = m.seal("first-synthetic-password").unwrap();
    let b = m.seal("second-synthetic-password").unwrap();
    assert_ne!(a, b);
    assert_eq!(
        identity(&Material::open(&a, "first-synthetic-password", m.network).unwrap()).address(),
        identity(&Material::open(&b, "second-synthetic-password", m.network).unwrap()).address()
    );
}
#[test]
fn full_and_short_address_roundtrip() {
    let m = material(1, 0);
    let id = identity(&m);
    let f = address::full(m.network, id.address()).unwrap();
    let s = address::short(m.network, id.address()).unwrap();
    assert_eq!(s.len(), 71);
    assert_eq!(
        address::resolve(&f, m.network, None).unwrap(),
        *id.address()
    );
    assert_eq!(
        address::resolve(&s, m.network, Some(&f)).unwrap(),
        *id.address()
    );
    assert!(address::resolve(&s, m.network, None).is_err());
    assert!(address::resolve(&f, [2; 32], None).is_err());
    assert!(address::resolve(&f.to_uppercase(), m.network, None).is_err());
    for i in [5, 60, f.len() - 1] {
        let mut bad = f.clone().into_bytes();
        bad[i] = if bad[i] == b'a' { b'b' } else { b'a' };
        assert!(address::resolve(std::str::from_utf8(&bad).unwrap(), m.network, None).is_err());
    }
    let other = address::full(m.network, identity(&material(1, 1)).address()).unwrap();
    assert!(address::resolve(&s, m.network, Some(&other)).is_err());
    assert!(address::resolve("tsi1legacy", m.network, None).is_err());
}
#[test]
fn canonical_recipient_checks_all_fields() {
    let m = material(1, 0);
    let id = identity(&m);
    let descriptor = address::Descriptor::new(m.network, 0, id.address());
    assert_eq!(descriptor.validate(m.network).unwrap(), *id.address());
    let mut bad = *id.address();
    bad[..4].copy_from_slice(&2_130_706_433u32.to_le_bytes());
    assert!(address::validate(&bad).is_err());
    let mut bad = *id.address();
    bad[48..].fill(255);
    assert!(address::validate(&bad).is_err());
    let mut j = serde_json::to_value(descriptor).unwrap();
    j["seed"] = "forbidden".into();
    assert!(serde_json::from_value::<address::Descriptor>(j).is_err());
}
