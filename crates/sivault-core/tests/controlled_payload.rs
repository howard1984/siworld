#![cfg(any(target_os = "linux", target_vendor = "apple"))]

use sivault_core::{
    Error,
    crypto::Secret,
    standard::{MAX_CONTROLLED_REGISTRATION, Safe},
};

#[test]
fn controlled_payload_requires_its_key_and_has_no_offline_password_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("controlled");
    let id = [1; 16];
    let key = Secret::new([2; 32]);
    let mut safe = Safe::create_controlled(&path, id, key.clone()).unwrap();
    safe.create_directory("Synthetic files", None).unwrap();
    assert!(Safe::read_controlled_registration(&path).is_err());
    assert!(safe.publish_controlled_registration(b"").is_err());
    assert!(matches!(
        safe.publish_controlled_registration(&vec![0; MAX_CONTROLLED_REGISTRATION + 1]),
        Err(Error::Limit)
    ));
    safe.publish_controlled_registration(b"synthetic record")
        .unwrap();
    assert!(
        safe.publish_controlled_registration(b"replacement")
            .is_err()
    );
    drop(safe);
    assert_eq!(
        Safe::read_controlled_registration(&path).unwrap(),
        b"synthetic record"
    );

    assert!(matches!(
        Safe::open(&path, "synthetic password", false),
        Err(Error::InvalidFormat)
    ));
    assert!(matches!(
        Safe::open_controlled(&path, [3; 16], key.clone(), false),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        Safe::open_controlled(&path, id, Secret::new([4; 32]), false),
        Err(Error::Authentication)
    ));
    let safe = Safe::open_controlled(&path, id, key, true).unwrap();
    assert_eq!(safe.entries()[0].name, "Synthetic files");
    assert!(matches!(
        safe.publish_controlled_registration(b"replacement"),
        Err(Error::ReadOnly)
    ));

    let offline = root.path().join("offline");
    let offline_safe = Safe::create(&offline, "synthetic password").unwrap();
    assert!(matches!(
        offline_safe.publish_controlled_registration(b"synthetic record"),
        Err(Error::InvalidFormat)
    ));
    drop(offline_safe);
    assert!(matches!(
        Safe::open_controlled(&offline, id, Secret::new([2; 32]), true),
        Err(Error::InvalidFormat)
    ));
}
