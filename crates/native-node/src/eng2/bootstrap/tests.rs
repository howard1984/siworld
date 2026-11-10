use super::*;
use crate::eng2::{
    certificate::{SIGNATURE_BYTES, Statement, Vote},
    commitment::{COMPONENTS, Component, ComponentId},
};

pub(crate) fn framing_fixture() -> (Genesis, ImportLimits, Manifest) {
    let state = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain().config.clone(),
        state.governance().clone(),
        super::super::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let governance = b"synthetic framing only".to_vec();
    let descriptors = COMPONENTS.map(|id| {
        Component::from_local_encoding(
            id,
            if id == ComponentId::Governance {
                &governance
            } else {
                b"synthetic component"
            },
            MAX_GOVERNANCE_BYTES,
        )
        .unwrap()
        .descriptor()
    });
    let mut manifest = Manifest {
        network: genesis.config().network,
        genesis: genesis.id(),
        rules: genesis.rules_commitment(),
        profile: crate::proofs::protocol_profile_fingerprint(),
        tip_height: 96,
        tip_id: [7; 32],
        cumulative_work: Work::from(96),
        snapshot: Descriptor {
            length: 7,
            digest: *blake3::hash(b"fixture").as_bytes(),
        },
        certificate: Certificate {
            statement: Statement {
                network: genesis.config().network,
                checkpoint_height: 72,
                checkpoint_block: [2; 32],
                authorization_height: 96,
                authorization_block: [7; 32],
                roster_sequence: 0,
                roster_digest: [4; 32],
            },
            votes: [
                Vote {
                    slot: 0,
                    signature: [0; SIGNATURE_BYTES],
                },
                Vote {
                    slot: 1,
                    signature: [0; SIGNATURE_BYTES],
                },
            ],
        },
        witness: AuthorizationWitness {
            descriptors,
            governance,
        },
        bundle: [0; 32],
    };
    manifest.bundle = *blake3::hash(&manifest.prefix().unwrap()).as_bytes();
    let limits = crate::eng2::snapshot::tests::limits();
    (genesis, limits, manifest)
}
/// Deliberately synthetic transport fixture, inaccessible in production builds.
#[cfg(feature = "eng2-runtime")]
pub(crate) fn transport_fixture() -> Provider {
    transport_fixture_tag(7)
}
/// Distinct synthetic offers for transport rollover; no signature admission.
pub(crate) fn transport_fixture_tag(tag: u8) -> Provider {
    let (_, _, mut manifest) = framing_fixture();
    manifest.tip_id = [tag; 32];
    manifest.certificate.statement.authorization_block = [tag; 32];
    manifest.bundle = *blake3::hash(&manifest.prefix().unwrap()).as_bytes();
    let encoded = manifest.encode().unwrap();
    Provider {
        manifest,
        encoded,
        snapshot: b"fixture".to_vec(),
        _reservation: p2p::Budget::default().reserve(1024 * 1024).unwrap(),
    }
}

#[test]
fn manifest_binding_rejects_foreign_context_version_truncation_and_inconsistent_availability() {
    let (genesis, limits, manifest) = framing_fixture();
    let encoded = manifest.encode().unwrap();
    let decoded = Manifest::decode(&encoded, &genesis, limits).unwrap();
    assert_eq!(decoded.bundle(), manifest.bundle());
    assert_eq!(decoded.tip_height, 96);
    // Framing accepts no signature authority: this synthetic signature must
    // still fail a cryptographic check and can never construct a Provider.
    assert!(
        decoded
            .certificate
            .check_signatures(genesis.initial_governance().active_roster().keys())
            .is_err()
    );
    for offset in [0, 8, 40, 72, 104, 144, encoded.len() - 1] {
        let mut bad = encoded.clone();
        bad[offset] ^= 1;
        assert!(Manifest::decode(&bad, &genesis, limits).is_err());
    }
    for length in [0, 7, FIXED, encoded.len() - 1] {
        assert!(Manifest::decode(&encoded[..length], &genesis, limits).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Manifest::decode(&trailing, &genesis, limits).is_err());
    let mut bad = manifest.clone();
    bad.tip_height = 95;
    bad.bundle = *blake3::hash(&bad.prefix().unwrap()).as_bytes();
    assert!(Manifest::decode(&bad.encode().unwrap(), &genesis, limits).is_err());
    let mut bad = manifest.clone();
    bad.snapshot.length = 0;
    bad.bundle = *blake3::hash(&bad.prefix().unwrap()).as_bytes();
    assert!(Manifest::decode(&bad.encode().unwrap(), &genesis, limits).is_err());
}

#[test]
fn retained_offer_canonical_prefix_and_signer_epoch_invalidate_lookup_and_pins() {
    use super::leases::Registry;
    use std::{sync::Arc, time::Instant};
    let (genesis, _, _) = framing_fixture();
    let mut provider = transport_fixture();
    provider.manifest.tip_height = 120;
    provider.manifest.tip_id = [9; 32];
    provider.manifest.bundle = *blake3::hash(&provider.manifest.prefix().unwrap()).as_bytes();
    provider.encoded = provider.manifest.encode().unwrap();
    let provider = Arc::new(provider);
    let canonical = |height| match height {
        72 => Ok([2; 32]),
        96 => Ok([7; 32]),
        120 => Ok([9; 32]),
        _ => Err("missing canonical header".into()),
    };
    assert!(
        provider
            .check_bindings(genesis.id(), 121, [4; 32], canonical)
            .is_ok()
    );
    assert!(
        provider
            .check_bindings([0; 32], 121, [4; 32], canonical)
            .is_err()
    );
    assert!(
        provider
            .check_bindings(genesis.id(), 119, [4; 32], canonical)
            .is_err()
    );
    for changed in [72, 96, 120, 0] {
        let now = Instant::now();
        let mut registry = Registry::default();
        assert!(registry.publish(provider.clone(), now));
        let bundle = provider.manifest().bundle();
        assert!(registry.manifest([1; 32], None, now).is_some());
        assert!(registry.body_pins(now).protects(73));
        registry.reconcile(now, |offer| {
            offer
                .check_bindings(
                    genesis.id(),
                    121,
                    if changed == 0 { [5; 32] } else { [4; 32] },
                    |height| {
                        if height == changed {
                            Ok([99; 32])
                        } else {
                            canonical(height)
                        }
                    },
                )
                .is_ok()
        });
        assert!(registry.manifest([1; 32], Some(bundle), now).is_none());
        assert!(!registry.body_pins(now).protects(73));
        assert!(registry.current().is_none());
    }
    assert!(
        provider
            .check_bindings(genesis.id(), 121, [4; 32], |_| Err("read failed".into()))
            .is_err()
    );
}
