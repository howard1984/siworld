//! Bounded eng2-only checkpoint exchange payloads. Decoding grants no signing,
//! state-adoption or peer-authentication capability; Host checks actual Store.
use super::super::super::{
    certificate::{CERTIFICATE_BYTES, SIGNATURE_BYTES, STATEMENT_BYTES},
    commitment::DESCRIPTOR_BYTES,
};
use super::*;
const MAGIC: &[u8; 6] = b"SW2X\x01\x00";
pub(super) const MAX_GOVERNANCE_BYTES: usize = 131072;
const MAX_WITNESS_BYTES: usize = MAX_GOVERNANCE_BYTES + 10 + 11 * DESCRIPTOR_BYTES;
pub const MAX_CHECKPOINT_PACKET_BYTES: usize = 7 + CERTIFICATE_BYTES + 4 + MAX_WITNESS_BYTES;
const _: () = assert!(MAX_CHECKPOINT_PACKET_BYTES <= crate::p2p::MAX_CONTROL_BYTES - 64);
impl Incoming {
    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        match self {
            Self::Proposal(proposal) => {
                bytes.push(1);
                bytes.extend_from_slice(
                    &proposal
                        .statement
                        .encode()
                        .map_err(|_| "checkpoint proposal statement malformed")?,
                );
                append_witness(&mut bytes, &proposal.witness, limit)?;
            }
            Self::Vote { statement, vote } => {
                if vote.slot >= 3 {
                    return Err("checkpoint vote packet slot invalid".into());
                }
                bytes.push(2);
                bytes.extend_from_slice(
                    &statement
                        .encode()
                        .map_err(|_| "checkpoint vote statement malformed")?,
                );
                bytes.push(vote.slot);
                bytes.extend_from_slice(&vote.signature);
            }
            Self::Certified {
                certificate,
                witness,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(
                    &certificate
                        .encode()
                        .map_err(|_| "checkpoint certificate packet malformed")?,
                );
                append_witness(&mut bytes, witness, limit)?;
            }
        }
        if bytes.len() > MAX_CHECKPOINT_PACKET_BYTES {
            return Err("checkpoint packet exceeds hard byte bound".into());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: Hash, limit: usize) -> Result<Self, String> {
        if bytes.len() < 7
            || bytes.len() > MAX_CHECKPOINT_PACKET_BYTES
            || bytes.get(..6) != Some(MAGIC)
        {
            return Err("checkpoint packet version or byte bound invalid".into());
        }
        match bytes[6] {
            1 => {
                let end = 7 + STATEMENT_BYTES;
                let statement = Statement::decode(
                    bytes.get(7..end).ok_or("checkpoint proposal truncated")?,
                    network,
                )
                .map_err(|_| "checkpoint proposal statement malformed")?;
                let witness = read_witness(
                    bytes
                        .get(end..)
                        .ok_or("checkpoint proposal witness missing")?,
                    limit,
                )?;
                Ok(Self::Proposal(Proposal { statement, witness }))
            }
            2 => {
                if bytes.len() != 7 + STATEMENT_BYTES + 1 + SIGNATURE_BYTES {
                    return Err("checkpoint vote packet length invalid".into());
                }
                let end = 7 + STATEMENT_BYTES;
                let statement = Statement::decode(&bytes[7..end], network)
                    .map_err(|_| "checkpoint vote statement malformed")?;
                let slot = bytes[end];
                if slot >= 3 {
                    return Err("checkpoint vote packet slot invalid".into());
                }
                Ok(Self::Vote {
                    statement,
                    vote: Box::new(Vote {
                        slot,
                        signature: bytes[end + 1..]
                            .try_into()
                            .map_err(|_| "checkpoint vote packet signature malformed")?,
                    }),
                })
            }
            3 => {
                let end = 7 + CERTIFICATE_BYTES;
                let certificate = Certificate::decode(
                    bytes
                        .get(7..end)
                        .ok_or("checkpoint certificate packet truncated")?,
                    network,
                )
                .map_err(|_| "checkpoint certificate packet malformed")?;
                let witness = read_witness(
                    bytes
                        .get(end..)
                        .ok_or("checkpoint certificate witness missing")?,
                    limit,
                )?;
                Ok(Self::Certified {
                    certificate: Box::new(certificate),
                    witness,
                })
            }
            _ => Err("checkpoint packet kind unknown".into()),
        }
    }
}
impl Tick {
    /// At most three public packets, for an existing authenticated eng2 queue.
    /// Nothing here opens a connection or sends a packet.
    pub fn messages(&self) -> Vec<Incoming> {
        let mut result = Vec::new();
        if let Some(proposal) = &self.proposal {
            result.push(Incoming::Proposal(proposal.clone()));
            if let Some(vote) = &self.vote {
                result.push(Incoming::Vote {
                    statement: proposal.statement.clone(),
                    vote: Box::new(vote.clone()),
                });
            }
        }
        if let Some(certificate) = &self.certificate {
            result.push(Incoming::Certified {
                certificate: Box::new(certificate.certificate.clone()),
                witness: certificate.witness.clone(),
            });
        }
        result
    }
}
fn append_witness(
    out: &mut Vec<u8>,
    witness: &AuthorizationWitness,
    limit: usize,
) -> Result<(), String> {
    let witness = witness
        .encode(limit.min(MAX_GOVERNANCE_BYTES))
        .map_err(|_| "checkpoint packet witness exceeds bounds")?;
    out.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    out.extend_from_slice(&witness);
    Ok(())
}
fn read_witness(bytes: &[u8], limit: usize) -> Result<AuthorizationWitness, String> {
    let prefix = bytes
        .get(..4)
        .ok_or("checkpoint packet witness length missing")?;
    let length = u32::from_le_bytes(prefix.try_into().expect("fixed length")) as usize;
    if length > MAX_WITNESS_BYTES || length.checked_add(4) != Some(bytes.len()) {
        return Err("checkpoint packet witness length differs".into());
    }
    AuthorizationWitness::decode(&bytes[4..], limit.min(MAX_GOVERNANCE_BYTES))
        .map_err(|_| "checkpoint packet witness malformed".into())
}
#[cfg(test)]
mod tests {
    use super::super::super::tests::synthetic_candidate;
    use super::*;
    #[test]
    fn synthetic_packet_roundtrips_are_bounded_network_pinned_and_reject_trailing_or_alternate_versions()
     {
        // Packet roundtrips do not establish native execution or a valid quorum.
        let candidate = synthetic_candidate();
        let network = candidate.statement.network;
        let vote = |slot| Vote {
            slot,
            signature: [0; SIGNATURE_BYTES],
        };
        let packets = [
            Incoming::Proposal(Proposal {
                statement: candidate.statement.clone(),
                witness: candidate.witness.clone(),
            }),
            Incoming::Vote {
                statement: candidate.statement.clone(),
                vote: Box::new(vote(0)),
            },
            Incoming::Certified {
                certificate: Box::new(Certificate {
                    statement: candidate.statement.clone(),
                    votes: [vote(0), vote(1)],
                }),
                witness: candidate.witness,
            },
        ];
        for packet in packets {
            let bytes = packet.encode(MAX_GOVERNANCE_BYTES).unwrap();
            assert!(bytes.len() <= MAX_CHECKPOINT_PACKET_BYTES);
            assert_eq!(
                Incoming::decode(&bytes, network, MAX_GOVERNANCE_BYTES).unwrap(),
                packet
            );
            assert!(Incoming::decode(&bytes, [9; 32], MAX_GOVERNANCE_BYTES).is_err());
            for length in [0, 5, 7, bytes.len() - 1] {
                assert!(Incoming::decode(&bytes[..length], network, MAX_GOVERNANCE_BYTES).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Incoming::decode(&trailing, network, MAX_GOVERNANCE_BYTES).is_err());
            let mut unknown = bytes.clone();
            unknown[6] = 9;
            assert!(Incoming::decode(&unknown, network, MAX_GOVERNANCE_BYTES).is_err());
            let mut version = bytes;
            version[4] = 2;
            assert!(Incoming::decode(&version, network, MAX_GOVERNANCE_BYTES).is_err());
        }
        let mut oversized = vec![0; MAX_CHECKPOINT_PACKET_BYTES + 1];
        oversized[..6].copy_from_slice(MAGIC);
        assert!(Incoming::decode(&oversized, network, MAX_GOVERNANCE_BYTES).is_err());
    }
}
