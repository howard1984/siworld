mod support;

use sivault_releaser::message::*;
use support::*;

fn init() -> Message {
    Message {
        domain: Domain {
            suite: 0x1234,
            network: id(0x11),
            safe: id(0x22),
            generation: 0x0102030405060708,
            slot: id(0x33),
            incarnation: id(0x44),
            request: id(0x55),
            operation: Operation::Normal,
        },
        body: Body::OpenInit {
            client_nonce: id(0x66),
            reply_key_digest: id(0x77),
            record: id(0x88),
            commit_certificate: None,
        },
    }
}

#[test]
fn literal_canonical_vector() {
    // Written from the field layout, independently of Message::encode.
    let text = include_str!("vectors/open-init.hex")
        .split_whitespace()
        .collect::<String>();
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let expected = pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 279);
    assert_eq!(init().encode().unwrap(), expected);
    assert_eq!(Message::decode(&expected).unwrap(), init());
}

#[test]
fn all_noncredential_types_round_trip() {
    let owner_bodies = vec![
        Body::Enroll {
            owner_key: id(1),
            manifest: id(2),
            releaser_key: id(3),
            ledger: id(4),
            allowance: 6,
            record_manifest: id(5),
            expiry: 100,
        },
        Body::EnrollAck {
            enroll: id(1),
            releaser_key: id(2),
            ledger: id(3),
            durable_record: id(4),
            status: Status::Accepted,
        },
        Body::CommandAck {
            command: id(1),
            protected_state: id(2),
            ledger_head: id(3),
            applied_counter: 7,
            phase: AckPhase::DeletionPending,
            status: Status::Accepted,
        },
    ];
    let mut messages = vec![init()];
    for body in owner_bodies {
        let mut domain = domain();
        domain.operation = Operation::Owner;
        messages.push(Message { domain, body });
    }
    messages.extend([
        refill(1, 6, 2),
        prepare(2),
        commit(3),
        retire(4),
        delete(5, 4),
        restore(6),
    ]);
    messages.push(Message {
        domain: domain(),
        body: Body::OpenChallenge {
            init: id(1),
            client_nonce: id(2),
            server_nonce: id(3),
            challenge: id(4),
            deadline: 20,
            reply_key_digest: id(5),
        },
    });
    messages.push(Message {
        domain: domain(),
        body: Body::Error {
            predecessor: id(1),
            stage: Stage::Init,
            status: Status::Rejected,
        },
    });
    let mut with_certificate = init();
    if let Body::OpenInit {
        commit_certificate, ..
    } = &mut with_certificate.body
    {
        *commit_certificate = Some(id(99));
    }
    messages.push(with_certificate);
    for message in messages {
        let bytes = message.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        assert_eq!(Message::decode(&bytes).unwrap().encode().unwrap(), bytes);
    }
}

#[test]
fn rejects_truncation_trailing_bytes_lengths_and_unknown_tags() {
    let bytes = init().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Message::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(Message::decode(&extra), Err(CodecError::Noncanonical));
    let mut duplicate = bytes.clone();
    duplicate.push(0);
    duplicate[178..182].copy_from_slice(&98_u32.to_be_bytes());
    assert_eq!(Message::decode(&duplicate), Err(CodecError::Noncanonical));
    for (offset, value, expected) in [
        (0, 0, CodecError::InvalidMagic),
        (7, 2, CodecError::UnsupportedVersion),
        (40, 255, CodecError::UnknownTag),
        (41, 0, CodecError::UnknownTag),
        (40, 5, CodecError::CredentialMessageUnsupported),
        (40, 6, CodecError::CredentialMessageUnsupported),
        (278, 2, CodecError::Noncanonical),
    ] {
        let mut altered = bytes.clone();
        altered[offset] = value;
        assert_eq!(Message::decode(&altered), Err(expected));
    }
    let mut oversized_body = bytes;
    oversized_body[178..182].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(Message::decode(&oversized_body), Err(CodecError::Truncated));
    assert_eq!(
        Message::decode(&vec![0; MAX_MESSAGE_BYTES + 1]),
        Err(CodecError::TooLarge)
    );
}

#[test]
fn operation_domains_and_share_set_order_are_canonical() {
    let mut message = init();
    message.domain.operation = Operation::Owner;
    assert_eq!(message.encode(), Err(CodecError::InvalidDomain));
    let mut message = refill(1, 0, 1);
    message.domain.operation = Operation::Normal;
    assert_eq!(message.encode(), Err(CodecError::InvalidDomain));
    for shares in [
        vec![],
        vec![id(1), id(1)],
        vec![id(2), id(1)],
        vec![id(1); MAX_SHARE_IDS + 1],
    ] {
        let mut message = delete(2, 1);
        if let Body::Owner {
            action: Action::Delete { share_ids, .. },
            ..
        } = &mut message.body
        {
            *share_ids = shares;
        }
        assert_eq!(message.encode(), Err(CodecError::Noncanonical));
    }
    let mut bytes = delete(2, 1).encode().unwrap();
    let len = bytes.len();
    let first = bytes[len - 64..len - 32].to_vec();
    bytes[len - 32..].copy_from_slice(&first);
    assert_eq!(Message::decode(&bytes), Err(CodecError::Noncanonical));
}

#[test]
fn every_domain_component_changes_the_transcript() {
    let original = init();
    let baseline = original.encode().unwrap();
    let mut domains = Vec::new();
    let d = original.domain;
    domains.push(Domain {
        suite: d.suite + 1,
        ..d
    });
    domains.push(Domain {
        network: id(1),
        ..d
    });
    domains.push(Domain { safe: id(1), ..d });
    domains.push(Domain {
        generation: d.generation + 1,
        ..d
    });
    domains.push(Domain { slot: id(1), ..d });
    domains.push(Domain {
        incarnation: id(1),
        ..d
    });
    domains.push(Domain {
        request: id(1),
        ..d
    });
    domains.push(Domain {
        operation: Operation::Recovery,
        ..d
    });
    domains.push(Domain {
        operation: Operation::Decoy,
        ..d
    });
    for domain in domains {
        let message = Message {
            domain,
            body: original.body.clone(),
        };
        let bytes = message.encode().unwrap();
        assert_ne!(bytes, baseline);
        assert_eq!(Message::decode(&bytes).unwrap().domain, domain);
    }
}
