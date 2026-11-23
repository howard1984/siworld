//! Declaration-first reception of an inactive V2 complete fee frame.
//!
//! The transport supplies its already decoded outer length. This module reads
//! no proof bytes and makes no body allocation until that length is admitted.
//! The caller must impose its transport read deadline and then perform bounded
//! body decoding and independent verification; this is not a validity receipt.
use super::{FRAME_BYTES, FrameError, Identity, MAX_FEE_PROOF_BYTES, Relation};
use std::io::{ErrorKind, Read};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    Frame(FrameError),
    Allocation,
    Io(ErrorKind),
}

pub fn read_fee_frame(
    reader: &mut impl Read,
    declared_complete_frame_bytes: u64,
    expected: Identity,
) -> Result<Vec<u8>, ReceiveError> {
    if expected.relation != Relation::CompleteFee {
        return Err(ReceiveError::Frame(FrameError::Identity));
    }
    let declared = usize::try_from(declared_complete_frame_bytes)
        .map_err(|_| ReceiveError::Frame(FrameError::Size))?;
    super::admit_declared_size(expected.relation, declared, MAX_FEE_PROOF_BYTES)
        .map_err(ReceiveError::Frame)?;
    let mut header = [0u8; FRAME_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|error| ReceiveError::Io(error.kind()))?;
    super::preflight_header(&header, expected, declared, MAX_FEE_PROOF_BYTES)
        .map_err(ReceiveError::Frame)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(declared)
        .map_err(|_| ReceiveError::Allocation)?;
    frame.extend_from_slice(&header);
    frame.resize(declared, 0);
    reader
        .read_exact(&mut frame[FRAME_BYTES..])
        .map_err(|error| ReceiveError::Io(error.kind()))?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Observed<'a> {
        bytes: &'a [u8],
        read: usize,
    }
    impl Read for Observed<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.bytes.len().min(out.len());
            out[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            self.read += n;
            Ok(n)
        }
    }
    const EXPECTED: Identity = Identity {
        relation: Relation::CompleteFee,
        profile: [19; 32],
    };

    #[test]
    fn excessive_declaration_reads_zero_proof_bytes() {
        for declared in [
            0,
            FRAME_BYTES as u64,
            MAX_FEE_PROOF_BYTES as u64 + 1,
            u64::MAX,
        ] {
            let mut reader = Observed {
                bytes: &[7; 64],
                read: 0,
            };
            assert_eq!(
                read_fee_frame(&mut reader, declared, EXPECTED),
                Err(ReceiveError::Frame(FrameError::Size))
            );
            assert_eq!(reader.read, 0);
        }
    }

    #[test]
    fn exact_five_mib_frame_is_received_without_relaxing_transaction_limit() {
        let frame = super::super::encode(
            EXPECTED,
            &vec![0; MAX_FEE_PROOF_BYTES - FRAME_BYTES],
            MAX_FEE_PROOF_BYTES,
        )
        .unwrap();
        let mut reader = Observed {
            bytes: &frame,
            read: 0,
        };
        assert_eq!(
            read_fee_frame(&mut reader, MAX_FEE_PROOF_BYTES as u64, EXPECTED),
            Ok(frame.clone())
        );
        assert_eq!(reader.read, MAX_FEE_PROOF_BYTES);
        assert!(reader.bytes.is_empty());
        let mut reader = Observed {
            bytes: &frame,
            read: 0,
        };
        let transaction = Identity {
            relation: Relation::Transaction,
            ..EXPECTED
        };
        assert_eq!(
            read_fee_frame(&mut reader, MAX_FEE_PROOF_BYTES as u64, transaction),
            Err(ReceiveError::Frame(FrameError::Identity))
        );
        assert_eq!(reader.read, 0);
    }

    #[test]
    fn excessive_inner_length_and_wrong_identity_read_only_header() {
        let mut frame = super::super::encode(EXPECTED, &[1, 2, 3], MAX_FEE_PROOF_BYTES).unwrap();
        frame[44..48].copy_from_slice(&(MAX_FEE_PROOF_BYTES as u32).to_le_bytes());
        let mut reader = Observed {
            bytes: &frame,
            read: 0,
        };
        assert_eq!(
            read_fee_frame(&mut reader, frame.len() as u64, EXPECTED),
            Err(ReceiveError::Frame(FrameError::Size))
        );
        assert_eq!(reader.read, FRAME_BYTES);
        frame[12] ^= 1;
        let mut reader = Observed {
            bytes: &frame,
            read: 0,
        };
        assert_eq!(
            read_fee_frame(&mut reader, frame.len() as u64, EXPECTED),
            Err(ReceiveError::Frame(FrameError::Identity))
        );
        assert_eq!(reader.read, FRAME_BYTES);
    }

    #[test]
    fn admitted_frame_consumes_only_its_declared_bytes() {
        let frame = super::super::encode(EXPECTED, &[1, 2, 3], MAX_FEE_PROOF_BYTES).unwrap();
        let mut stream = frame.clone();
        stream.extend_from_slice(&[99; 8]);
        let mut reader = Observed {
            bytes: &stream,
            read: 0,
        };
        assert_eq!(
            read_fee_frame(&mut reader, frame.len() as u64, EXPECTED),
            Ok(frame.clone())
        );
        assert_eq!(reader.read, frame.len());
        assert_eq!(reader.bytes, &[99; 8]);
        let mut truncated = &frame[..frame.len() - 1];
        assert_eq!(
            read_fee_frame(&mut truncated, frame.len() as u64, EXPECTED),
            Err(ReceiveError::Io(ErrorKind::UnexpectedEof))
        );
    }
}
