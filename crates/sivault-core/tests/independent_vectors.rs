use sha2::{Digest, Sha256};
use sivault_core::crypto;

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let hex = value.as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn matches_independent_libsodium_and_reference_argon2_vectors() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/independent.json")).unwrap();
    let safe: [u8; 16] = bytes(&vector["safe"]).try_into().unwrap();
    let salt: [u8; 16] = bytes(&vector["salt"]).try_into().unwrap();
    let stretched = crypto::stretch("cafe\u{301}", &salt).unwrap();
    assert_eq!(stretched.as_ref(), bytes(&vector["argon2id"]));
    let wrap = crypto::derive(&stretched, &safe, b"SVST0001/wrap");
    assert_eq!(wrap.as_ref(), bytes(&vector["wrap_key"]));
    let nonce: [u8; 24] = bytes(&vector["wrap_nonce"]).try_into().unwrap();
    let key: [u8; 32] = bytes(&vector["content_key"]).try_into().unwrap();
    let mut ad = b"SVST0001/wrap".to_vec();
    ad.extend(safe);
    assert_eq!(
        crypto::seal(&wrap, &nonce, &ad, &key).unwrap(),
        bytes(&vector["wrapped"])
    );
    let prefix: [u8; 19] = bytes(&vector["stream_prefix"]).try_into().unwrap();
    let ad = bytes(&vector["stream_ad"]);
    for chunk in vector["chunks"].as_array().unwrap() {
        let size = chunk["size"].as_u64().unwrap() as usize;
        let index = chunk["index"].as_u64().unwrap() as u32;
        let last = chunk["last"].as_bool().unwrap();
        let plain: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let ciphertext = crypto::encrypt_chunk(&key, &prefix, index, last, &ad, &plain).unwrap();
        assert_eq!(&Sha256::digest(&ciphertext)[..], bytes(&chunk["sha256"]));
        assert_eq!(&ciphertext[ciphertext.len() - 16..], bytes(&chunk["tag"]));
        assert_eq!(
            *crypto::decrypt_chunk(&key, &prefix, index, last, &ad, &ciphertext).unwrap(),
            plain
        );
    }
}

#[test]
fn opens_complete_empty_safe_from_independent_implementation() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/independent.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(".sivault-lock"), []).unwrap();
    for (name, encoded) in vector["empty_safe"].as_object().unwrap() {
        std::fs::write(temp.path().join(name), bytes(encoded)).unwrap();
    }
    let safe = sivault_core::standard::Safe::open(temp.path(), "cafe\u{301}", true).unwrap();
    assert!(safe.entries().is_empty());
}
