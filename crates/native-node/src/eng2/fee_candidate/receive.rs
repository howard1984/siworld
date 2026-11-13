//! Bounded fee-first payload adapter for an unselected future body layout.
//!
//! Outer framing must select this ordering and provide the three declarations.
//! The data portion is exactly one fee frame followed by one body payload; the
//! declared total excludes outer framing bytes. Retained Body/transport framing
//! is unchanged. Callers supply the trusted identity, read deadline and bounded
//! payload parser. Success is structural and grants no verification authority.

use crate::proof_codec::v2::{
    FRAME_BYTES, Identity, MAX_FEE_PROOF_BYTES,
    receive::{ReceiveError, read_fee_frame},
};
use std::io::{Read, Take};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthError {
    FeeFrame,
    Payload,
    Total,
}

/// Checked declarations. No allocation or read occurs during construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeFirstLengths {
    frame: u64,
    payload: u64,
}
impl FeeFirstLengths {
    pub fn check(
        declared_frame: u64,
        declared_payload: u64,
        declared_total: u64,
        max_data_bytes: usize,
    ) -> Result<Self, LengthError> {
        if declared_frame <= FRAME_BYTES as u64 || declared_frame > MAX_FEE_PROOF_BYTES as u64 {
            return Err(LengthError::FeeFrame);
        }
        if declared_payload == 0 {
            return Err(LengthError::Payload);
        }
        let total = declared_frame
            .checked_add(declared_payload)
            .ok_or(LengthError::Total)?;
        if declared_total != total || total > max_data_bytes as u64 {
            return Err(LengthError::Total);
        }
        Ok(Self {
            frame: declared_frame,
            payload: declared_payload,
        })
    }
}

#[derive(Debug)]
pub enum DecodeError<E> {
    Frame(ReceiveError),
    Payload(E),
    UnconsumedOrTruncatedPayload,
}

/// Structurally received bytes, not proof validity or canonical admission.
pub struct ReceivedFeeFirst<T> {
    frame: Vec<u8>,
    payload: T,
}
impl<T> ReceivedFeeFirst<T> {
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
    pub fn payload(&self) -> &T {
        &self.payload
    }
    pub fn into_parts(self) -> (Vec<u8>, T) {
        (self.frame, self.payload)
    }
}

/// Validate the fee declaration and 48-byte header before allocating its frame
/// or calling the payload parser. The parser cannot read beyond its declared
/// payload into a following packet. It must consume every declared payload byte.
/// This adapter never reserves or buffers the combined encoded body.
pub fn read_fee_first_payload<R: Read, T, E>(
    reader: &mut R,
    lengths: FeeFirstLengths,
    expected: Identity,
    decode_payload: impl FnOnce(&mut Take<&mut R>) -> Result<T, E>,
) -> Result<ReceivedFeeFirst<T>, DecodeError<E>> {
    let frame = read_fee_frame(reader, lengths.frame, expected).map_err(DecodeError::Frame)?;
    let mut payload = reader.take(lengths.payload);
    let decoded = decode_payload(&mut payload).map_err(DecodeError::Payload)?;
    if payload.limit() != 0 {
        return Err(DecodeError::UnconsumedOrTruncatedPayload);
    }
    Ok(ReceivedFeeFirst {
        frame,
        payload: decoded,
    })
}
