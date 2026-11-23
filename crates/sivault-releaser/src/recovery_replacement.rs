//! Scope and commitment encoding for replacing only the normal credential.

use sha2::{Digest, Sha256};
use sivault_core::{
    Error, Result,
    controlled_credential::{Envelope, ReleaserVerifier},
    standard::Safe,
};

use crate::{message::Id, opening::OpeningRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub previous_version: u64,
    pub next_version: u64,
    pub record_id: Id,
    pub salt: Id,
    pub verifier_digest: Id,
    pub pending_wrap_digest: Id,
}

impl Proposal {
    pub fn new(
        current: &OpeningRecord,
        previous_version: u64,
        record_id: Id,
        salt: Id,
        verifier: &ReleaserVerifier,
        wrap: &Envelope,
    ) -> Result<Self> {
        if previous_version == 0
            || record_id == Id::default()
            || salt == Id::default()
            || current.record_id == record_id
            || current.salt == salt
        {
            return Err(Error::InvalidFormat);
        }
        Ok(Self {
            previous_version,
            next_version: previous_version.checked_add(1).ok_or(Error::Limit)?,
            record_id,
            salt,
            verifier_digest: digest(
                b"sivault/recovery/pending-normal-verifier/v1\0",
                &[&verifier.stored_key, verifier.server_key.as_ref()],
            ),
            pending_wrap_digest: wrap_digest(wrap),
        })
    }

    /// Bind to the original successful recovery session, not a retry channel.
    /// The result is a commitment, not an authorization or a durable receipt.
    pub fn commitment(
        &self,
        current: &OpeningRecord,
        request: Id,
        channel_binding: &[u8; 32],
        recovery_result: Id,
    ) -> Result<Id> {
        if self.previous_version == 0
            || self.previous_version.checked_add(1) != Some(self.next_version)
            || self.record_id == Id::default()
            || self.salt == Id::default()
            || self.record_id == current.record_id
            || self.salt == current.salt
            || self.verifier_digest == Id::default()
            || self.pending_wrap_digest == Id::default()
            || request == Id::default()
            || recovery_result == Id::default()
        {
            return Err(Error::InvalidFormat);
        }
        Ok(digest(
            b"sivault/recovery/replace-normal/v1\0",
            &[
                &current.context().encode(),
                &current.record.incarnation.0,
                &current.record.manifest.0,
                &current.record.root.0,
                &request.0,
                channel_binding,
                &recovery_result.0,
                &self.previous_version.to_be_bytes(),
                &self.next_version.to_be_bytes(),
                &self.record_id.0,
                &self.salt.0,
                &self.verifier_digest.0,
                &self.pending_wrap_digest.0,
            ],
        ))
    }
    pub fn stage_wrap(&self, safe: &Safe, commitment: Id, wrap: &Envelope) -> Result<()> {
        safe.stage_controlled_pending(self.next_version, &commitment.0, &self.pending_bytes(wrap)?)
    }

    pub fn readback_wrap(
        &self,
        path: &std::path::Path,
        commitment: Id,
        wrap: &Envelope,
    ) -> Result<()> {
        let expected = self.pending_bytes(wrap)?;
        let actual = Safe::read_controlled_pending(path, self.next_version, &commitment.0)?;
        if actual != expected {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    fn pending_bytes(&self, wrap: &Envelope) -> Result<Vec<u8>> {
        if self.pending_wrap_digest != wrap_digest(wrap) {
            return Err(Error::Authentication);
        }
        let mut bytes = b"SVPEND01".to_vec();
        bytes.extend_from_slice(&self.next_version.to_be_bytes());
        bytes.extend_from_slice(&self.record_id.0);
        bytes.extend_from_slice(&self.salt.0);
        bytes.extend_from_slice(&wrap.nonce);
        bytes.extend_from_slice(&wrap.ciphertext);
        Ok(bytes)
    }
}

fn wrap_digest(wrap: &Envelope) -> Id {
    digest(
        b"sivault/recovery/pending-normal-wrap/v1\0",
        &[&wrap.nonce, &wrap.ciphertext],
    )
}

fn digest(label: &[u8], parts: &[&[u8]]) -> Id {
    let mut hash = Sha256::new();
    hash.update(label);
    for part in parts {
        hash.update(part);
    }
    Id(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Record, SlotIdentity};
    use sivault_core::crypto::Secret;

    #[test]
    fn proposal_commits_to_the_session_and_next_verifier_and_wrap() {
        let scope = OpeningRecord {
            slot: SlotIdentity {
                suite: 1,
                network: Id([1; 32]),
                safe: Id([2; 32]),
                slot: Id([3; 32]),
                ledger: Id([4; 32]),
            },
            record: Record {
                generation: 1,
                incarnation: Id([5; 32]),
                manifest: Id([6; 32]),
                root: Id([7; 32]),
            },
            record_id: Id([8; 32]),
            salt: Id([9; 32]),
        };
        let verifier = ReleaserVerifier {
            stored_key: [12; 32],
            server_key: Secret::new([13; 32]),
        };
        let envelope = Envelope {
            nonce: [14; 24],
            ciphertext: [15; 48],
        };
        let proposal =
            Proposal::new(&scope, 1, Id([10; 32]), Id([11; 32]), &verifier, &envelope).unwrap();
        let request = Id([16; 32]);
        let channel = [17; 32];
        let result = Id([18; 32]);
        let expected = proposal
            .commitment(&scope, request, &channel, result)
            .unwrap();
        assert_ne!(
            proposal
                .commitment(&scope, Id([20; 32]), &channel, result)
                .unwrap(),
            expected
        );
        assert_ne!(
            proposal
                .commitment(&scope, request, &[20; 32], result)
                .unwrap(),
            expected
        );
        assert_ne!(
            proposal
                .commitment(&scope, request, &channel, Id([20; 32]))
                .unwrap(),
            expected
        );
        for different in [
            Proposal {
                verifier_digest: Id([20; 32]),
                ..proposal
            },
            Proposal {
                pending_wrap_digest: Id([20; 32]),
                ..proposal
            },
            Proposal {
                previous_version: 2,
                next_version: 3,
                ..proposal
            },
        ] {
            assert_ne!(
                different
                    .commitment(&scope, request, &channel, result)
                    .unwrap(),
                expected
            );
        }
        let mut different_scope = scope.clone();
        different_scope.record.generation = 2;
        assert_ne!(
            proposal
                .commitment(&different_scope, request, &channel, result)
                .unwrap(),
            expected
        );
        assert!(
            Proposal {
                next_version: 3,
                ..proposal
            }
            .commitment(&scope, request, &channel, result)
            .is_err()
        );

        #[cfg(unix)]
        {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("controlled");
            let safe = Safe::create_controlled(&path, [21; 16], Secret::new([22; 32])).unwrap();
            safe.publish_controlled_registration(b"original registration")
                .unwrap();
            assert!(proposal.readback_wrap(&path, expected, &envelope).is_err());
            proposal.stage_wrap(&safe, expected, &envelope).unwrap();
            proposal.stage_wrap(&safe, expected, &envelope).unwrap();
            drop(safe);
            proposal.readback_wrap(&path, expected, &envelope).unwrap();
            assert_eq!(
                Safe::read_controlled_registration(&path).unwrap(),
                b"original registration"
            );
            let changed = Envelope {
                nonce: [23; 24],
                ciphertext: envelope.ciphertext,
            };
            assert!(proposal.readback_wrap(&path, expected, &changed).is_err());
        }
    }
}
