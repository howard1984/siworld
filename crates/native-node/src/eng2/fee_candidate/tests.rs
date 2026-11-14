use super::{ordered_fee_commitments, receive::*};
use crate::proof_codec::v2::{self, FRAME_BYTES, Identity, MAX_FEE_PROOF_BYTES, Relation};
use native::multi_asset::F;
use p3_field::PrimeCharacteristicRing;
use std::io::{Cursor, Read};

const IDENTITY: Identity = Identity {
    relation: Relation::CompleteFee,
    profile: [61; 32],
};

#[test]
fn native_slot_prefix_and_canonical_tail_are_distinct_from_fixed_fee_capacity() {
    for count in [64, 560, 576] {
        let fees = (0..count)
            .map(|i| [F::from_usize(i + 1); 12])
            .collect::<Vec<_>>();
        let actual = ordered_fee_commitments([7; 32], 25, count, &fees).unwrap();
        assert_eq!(actual.len(), 576);
        assert_eq!(&actual[..count], fees);
        let expected_tail = crate::state::tail_slots([7; 32], 25, count).unwrap();
        assert_eq!(
            &actual[count..],
            expected_tail
                .iter()
                .map(|slot| slot.commitment)
                .collect::<Vec<_>>()
        );
        if count < 576 {
            assert_ne!(actual[count], [F::ZERO; 12]);
            assert_ne!(
                actual[count],
                ordered_fee_commitments([7; 32], 26, count, &fees).unwrap()[count]
            );
        }
    }
    for count in [0, 63, 65, 592] {
        assert!(ordered_fee_commitments([7; 32], 25, count, &vec![[F::ONE; 12]; count]).is_err());
    }
    assert!(ordered_fee_commitments([7; 32], 25, 64, &[[F::ONE; 12]; 63]).is_err());
}

#[test]
fn declarations_reject_overflow_and_capacity_before_reading() {
    for frame in [
        0,
        FRAME_BYTES as u64,
        MAX_FEE_PROOF_BYTES as u64 + 1,
        u64::MAX,
    ] {
        assert_eq!(
            FeeFirstLengths::check(frame, 1, frame, usize::MAX),
            Err(LengthError::FeeFrame)
        );
    }
    assert_eq!(
        FeeFirstLengths::check(49, 0, 49, 100),
        Err(LengthError::Payload)
    );
    assert_eq!(
        FeeFirstLengths::check(49, u64::MAX, 48, usize::MAX),
        Err(LengthError::Total)
    );
    assert_eq!(
        FeeFirstLengths::check(49, 2, 50, 100),
        Err(LengthError::Total)
    );
    assert_eq!(
        FeeFirstLengths::check(49, 2, 51, 50),
        Err(LengthError::Total)
    );
    assert!(
        FeeFirstLengths::check(
            MAX_FEE_PROOF_BYTES as u64,
            1,
            MAX_FEE_PROOF_BYTES as u64 + 1,
            MAX_FEE_PROOF_BYTES + 1
        )
        .is_ok()
    );
}

#[test]
fn mismatched_fee_header_never_reaches_frame_body_or_payload_parser() {
    let frame = v2::encode(IDENTITY, &[11], MAX_FEE_PROOF_BYTES).unwrap();
    for changed in [
        Identity {
            profile: [62; 32],
            ..IDENTITY
        },
        Identity {
            relation: Relation::Settlement,
            ..IDENTITY
        },
    ] {
        let mut cursor = Cursor::new(frame.as_slice());
        let lengths =
            FeeFirstLengths::check(frame.len() as u64, 1, frame.len() as u64 + 1, 100).unwrap();
        let mut called = false;
        let result = read_fee_first_payload(&mut cursor, lengths, changed, |_| {
            called = true;
            Ok::<_, std::io::Error>(())
        });
        assert!(matches!(result, Err(DecodeError::Frame(_))));
        assert!(!called);
        assert_eq!(
            cursor.position(),
            if changed.relation == Relation::CompleteFee {
                48
            } else {
                0
            }
        );
    }
}

#[test]
fn payload_reader_cannot_consume_a_following_packet() {
    let frame = v2::encode(IDENTITY, &[11], MAX_FEE_PROOF_BYTES).unwrap();
    let mut data = frame.clone();
    data.extend_from_slice(&[21, 22, 99]);
    let mut cursor = Cursor::new(data);
    let lengths =
        FeeFirstLengths::check(frame.len() as u64, 2, frame.len() as u64 + 2, 100).unwrap();
    let received = read_fee_first_payload(&mut cursor, lengths, IDENTITY, |payload| {
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    })
    .unwrap();
    assert_eq!(received.frame(), frame);
    assert_eq!(received.payload(), &[21, 22]);
    let mut next = [0];
    cursor.read_exact(&mut next).unwrap();
    assert_eq!(next, [99]);
}

#[test]
fn decoder_rejects_unconsumed_or_truncated_declared_payload() {
    let frame = v2::encode(IDENTITY, &[11], MAX_FEE_PROOF_BYTES).unwrap();
    let lengths =
        FeeFirstLengths::check(frame.len() as u64, 2, frame.len() as u64 + 2, 100).unwrap();
    let mut data = frame.clone();
    data.push(21);
    let mut cursor = Cursor::new(data);
    let result = read_fee_first_payload(&mut cursor, lengths, IDENTITY, |payload| {
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    assert!(matches!(
        result,
        Err(DecodeError::UnconsumedOrTruncatedPayload)
    ));
    let mut cursor = Cursor::new(frame);
    let result = read_fee_first_payload(&mut cursor, lengths, IDENTITY, |_| Ok::<_, ()>(()));
    assert!(matches!(
        result,
        Err(DecodeError::UnconsumedOrTruncatedPayload)
    ));
}
