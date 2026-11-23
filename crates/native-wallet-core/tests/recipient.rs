use siworld_native_wallet_core::{
    identity::Identity,
    recipient::{Descriptor, Directory, Network, ShortAddress},
};

fn v2(network: Network, genesis: u8, owner: u8) -> Descriptor {
    let mut recipient = [0; 1232];
    recipient[0] = owner;
    Descriptor::new_v2(network, [genesis; 32], &recipient).unwrap()
}

#[test]
fn vectors_and_copy_errors() {
    let descriptor = v2(Network::Testnet, 1, 2);
    let short = descriptor.short_address();
    let text = short.encode();
    assert_eq!(
        text,
        "tsi1pwl6pnufr5kwq4a25yr4yneu2vk6qzt45sdy2urmqyvx75p69mtcq640vmd"
    );
    assert_eq!(text.len(), 63);
    assert!(text.starts_with("tsi1p"));
    assert_eq!(ShortAddress::parse(&text), Ok(short));
    assert_eq!(ShortAddress::parse(&text.to_uppercase()), Ok(short));
    assert!(ShortAddress::parse(&text.replacen('t', "T", 1)).is_err());
    assert!(ShortAddress::parse(&text[..62]).is_err());
    for i in 4..text.len() {
        let mut corrupted = text.as_bytes().to_vec();
        corrupted[i] = if corrupted[i] == b'q' { b'p' } else { b'q' };
        assert!(ShortAddress::parse(std::str::from_utf8(&corrupted).unwrap()).is_err());
    }
    let mainnet = v2(Network::Mainnet, 1, 2).short_address();
    assert_eq!(
        mainnet.encode(),
        "si1pm7fsphy3c868xclak3xd8xj9fnvrgumpt4mafwhd392hdwgcqz0qvtap8m"
    );
    assert_eq!(mainnet.encode().len(), 62);
    assert_ne!(mainnet.id, short.id);
    assert_ne!(v2(Network::Testnet, 2, 2).short_address().id, short.id);
}

#[test]
fn v2_vector_with_generated_owner_and_kem_key() {
    let identity = Identity::derive(&[42; 32].into(), [9; 32], 0).unwrap();
    let recipient = identity.address();
    assert!(recipient[..48].iter().filter(|&&byte| byte != 0).count() > 1);
    assert!(recipient[48..].iter().any(|&byte| byte != 0));
    let descriptor = Descriptor::new_v2(Network::Testnet, [9; 32], recipient).unwrap();
    assert_eq!(descriptor.native_recipient(), Ok(recipient));
    assert_eq!(
        descriptor.short_address().encode(),
        "tsi1p0uc8hk8zk6e5vhdzpuje0rjf2vwczppewg7fteq53cw07z9ccsqqpf5fwh"
    );
}

#[test]
fn exact_records_and_local_resolution() {
    let d = v2(Network::Testnet, 1, 2);
    let short = d.short_address();
    let text = short.encode();
    let mut directory = Directory::new(Network::Testnet, [1; 32]);
    assert!(directory.resolve_native(&text).is_err());
    assert!(
        directory
            .insert_expected(short, v2(Network::Testnet, 1, 3).encode())
            .is_err()
    );
    let other_chain = v2(Network::Testnet, 2, 2);
    assert!(
        directory
            .insert_expected(other_chain.short_address(), other_chain.encode())
            .is_err()
    );
    assert!(
        directory
            .insert_expected(short, &d.encode()[..1265])
            .is_err()
    );
    let mut invalid = d.encode().to_vec();
    invalid.push(0);
    assert!(Descriptor::decode(&invalid).is_err());
    invalid.pop();
    invalid[34..38].fill(255);
    assert!(Descriptor::decode(&invalid).is_err());
    for _ in 0..2 {
        directory.insert_expected(short, d.encode()).unwrap();
    }
    assert_eq!(directory.resolve_native(&text), d.native_recipient());
    assert_eq!(directory.descriptor(&text), Ok(&d));
}

#[test]
fn legacy_bytes_remain_resolvable_but_are_not_native_recipients() {
    let mut bytes = [0; 1250];
    bytes[1] = 1;
    bytes[2..34].fill(1);
    bytes[34] = 2;
    let d = Descriptor::decode(&bytes).unwrap();
    assert_eq!(d.encode(), bytes);
    let short = d.short_address();
    assert_eq!(
        short.encode(),
        "tsi1pce424sq7gxkpk02m0lsm7davgsmnlna6ler8cunz3uqv2wpy94fqkmkf6j"
    );
    assert_ne!(short.id, v2(Network::Testnet, 1, 2).short_address().id);
    let mut directory = Directory::new(Network::Testnet, [1; 32]);
    directory.insert_expected(short, &bytes).unwrap();
    assert_eq!(directory.descriptor(&short.encode()), Ok(&d));
    assert!(directory.resolve_native(&short.encode()).is_err());
}

#[test]
fn directory_pages_bind_snapshot_and_rebuild_without_recipient_queries() {
    let mut service = Directory::new(Network::Testnet, [1; 32]);
    let empty = service.snapshot();
    assert!(service.page(empty, 0, 1).unwrap().entries.is_empty());
    let mut wallet = Directory::new(Network::Testnet, [1; 32]);
    for owner in [42, 17, 3] {
        let d = v2(Network::Testnet, 1, owner);
        service
            .insert_expected(d.short_address(), d.encode())
            .unwrap();
    }
    let current = service.snapshot();
    assert!(service.page(empty, 0, 1).is_err());
    assert!(service.page(current, 4, 1).is_err());
    assert!(service.page(current, 0, 65).is_err());
    let first = service.page(current, 0, 2).unwrap();
    assert_eq!(first.next, Some(2));
    for (short, bytes) in first.entries {
        wallet.insert_expected(short, bytes).unwrap();
    }
    assert_ne!(wallet.snapshot(), current);
    let last = service.page(current, 2, 2).unwrap();
    assert!(last.next.is_none());
    for (short, bytes) in last.entries {
        wallet.insert_expected(short, bytes).unwrap();
    }
    assert_eq!(wallet.snapshot(), current);
    let d = v2(Network::Testnet, 1, 42);
    assert_eq!(
        wallet.resolve_native(&d.short_address().encode()),
        d.native_recipient()
    );
}
