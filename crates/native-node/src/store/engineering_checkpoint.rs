//! Compare engineering attestations against independently verified local state.
use super::*;
use crate::{
    engineering_checkpoint::{
        self as checkpoint_auth, Certificate, Cursor, Roster, Statement, Vote,
    },
    identity::checkpoint_authority::Authority,
    p2p::Binding,
};
use native::codec::encode_digest;

pub(super) const ATTESTATIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("engineering-checkpoint-attestations-v1");
pub struct LocalCandidate {
    statement: Statement,
    state_encoding: Vec<u8>,
}
impl LocalCandidate {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn state_encoding(&self) -> &[u8] {
        &self.state_encoding
    }
}
fn digest(domain: &str, emit: impl FnOnce(&mut blake3::Hasher)) -> crate::wire::Hash {
    let mut hash = blake3::Hasher::new_derive_key(domain);
    emit(&mut hash);
    *hash.finalize().as_bytes()
}
pub(super) fn summary(
    state: &State,
    roster: &Roster,
    sequence: u64,
    issued: u64,
    prefix: crate::wire::Hash,
) -> Result<LocalCandidate, String> {
    let bytes = checkpoint::encode(state)?;
    let totals = state.economics.totals();
    let statement = Statement {
        binding: Binding::new(&state.config),
        roster: roster.digest(),
        sequence,
        issued_unix_seconds: issued,
        height: state.height,
        block_id: state.tip,
        cumulative_work: state.cumulative_work.to_big_endian(),
        state_fingerprint: state.fingerprint(),
        state_encoding_digest: blake3::derive_key(
            "siworld engineering checkpoint state encoding v1",
            &bytes,
        ),
        permanent_prefix_digest: prefix,
        commitment_root: encode_digest(&state.tree.root()),
        nullifier_digest: digest("siworld engineering checkpoint nullifiers v1", |hash| {
            for value in &state.spent {
                hash.update(value);
            }
        }),
        recent_roots_digest: digest("siworld engineering checkpoint recent roots v1", |hash| {
            for value in &state.snapshots {
                hash.update(&value.selector.height.to_le_bytes());
                hash.update(&value.selector.block_id);
                hash.update(&value.commitment_root);
                hash.update(&value.recent_root);
            }
        }),
        holder_pool: totals.holder_pool,
        development_fund_digest: digest(
            "siworld engineering checkpoint development fund v1",
            |hash| {
                for value in state.economics.funds() {
                    for n in [
                        value.entitlement,
                        value.direct_unlocked,
                        value.vesting_unlocked,
                        value.spent,
                    ] {
                        hash.update(&n.to_le_bytes());
                    }
                    hash.update(&value.spend_count.to_le_bytes());
                }
            },
        ),
        cumulative_issued: totals.issued,
        cumulative_burned: totals.burned,
        locked_rewards: totals.locked_subsidy,
        locked_schedule_digest: digest(
            "siworld engineering checkpoint locked rewards v1",
            |hash| {
                for (height, amount) in state.economics.locked_schedule() {
                    hash.update(&height.to_le_bytes());
                    hash.update(&amount.to_le_bytes());
                }
            },
        ),
        asset_registry_digest: digest("siworld engineering checkpoint assets v1", |hash| {
            state.assets.visit_encoding(&mut |bytes| {
                hash.update(bytes);
            })
        }),
    };
    Statement::decode(&statement.encode())?;
    Ok(LocalCandidate {
        statement,
        state_encoding: bytes,
    })
}
impl Store {
    /// Requires a canonical, sufficiently confirmed checkpoint in this store.
    /// The ancestor is fully replayed using the supplied production verifier.
    pub fn engineering_checkpoint_candidate(
        &self,
        roster: &Roster,
        height: u64,
        sequence: u64,
        issued: u64,
        verifier: &impl BlockVerifier,
    ) -> Result<LocalCandidate, String> {
        if roster.binding() != Binding::new(&self.state.config) {
            return Err("checkpoint roster context differs from local state".into());
        }
        if height == 0
            || !height.is_multiple_of(checkpoint_auth::HEIGHT_INTERVAL)
            || height
                .checked_add(checkpoint_auth::CONFIRMATIONS)
                .is_none_or(|minimum| minimum > self.state.height)
        {
            return Err(
                "checkpoint height is not sufficiently confirmed on the canonical chain".into(),
            );
        }
        let policy = CandidatePolicy {
            max_replay_blocks: self.state.height,
            ..CandidatePolicy::default()
        };
        let state = self
            .ancestor_state(height, 0, policy, verifier)
            .map_err(|_| "checkpoint local verified replay unavailable")?;
        if self.canonical_id(height)? != state.tip {
            return Err("checkpoint is not on the local greatest-work chain".into());
        }
        let prefix = digest(
            "siworld engineering checkpoint permanent prefix v1",
            |hash| {
                hash.update(&self.state.config.genesis_id());
            },
        );
        let mut hash =
            blake3::Hasher::new_derive_key("siworld engineering checkpoint permanent records v1");
        hash.update(&prefix);
        for at in 1..=height {
            let bytes = self.public_compact_block(at)?;
            hash.update(&at.to_le_bytes());
            hash.update(blake3::hash(&bytes).as_bytes());
        }
        summary(
            &state,
            roster,
            sequence,
            issued,
            *hash.finalize().as_bytes(),
        )
    }
    pub fn sign_engineering_checkpoint(
        &self,
        authority: &Authority,
        roster: &Roster,
        candidate: &LocalCandidate,
    ) -> Result<Vote, String> {
        // A candidate cannot be retargeted to a different store or an abandoned
        // canonical branch between independent replay and signing.
        let statement = candidate.statement();
        if statement.binding != Binding::new(&self.state.config)
            || self.canonical_id(statement.height)? != statement.block_id
            || statement
                .height
                .checked_add(checkpoint_auth::CONFIRMATIONS)
                .is_none_or(|n| n > self.state.height)
        {
            return Err("checkpoint candidate no longer matches the local canonical chain".into());
        }
        authority.sign(candidate, roster)
    }
    pub fn accept_engineering_checkpoint(
        &mut self,
        certificate: &Certificate,
        roster: &Roster,
        now: u64,
        verifier: &impl BlockVerifier,
    ) -> Result<(), String> {
        let previous = self.latest_engineering_checkpoint()?;
        let cursor = previous.as_ref().map(|value| Cursor {
            sequence: value.statement.sequence,
            height: value.statement.height,
            digest: value.statement.digest(),
        });
        certificate.authenticate(roster, cursor, now)?;
        let expected = self.engineering_checkpoint_candidate(
            roster,
            certificate.statement.height,
            certificate.statement.sequence,
            certificate.statement.issued_unix_seconds,
            verifier,
        )?;
        if expected.statement != certificate.statement {
            return Err(
                "urgent checkpoint mismatch with independently verified local state".into(),
            );
        }
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "checkpoint storage unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "checkpoint durability unavailable")?;
        transaction
            .open_table(ATTESTATIONS)
            .map_err(|_| "checkpoint table unavailable")?
            .insert("accepted", certificate.encode()?.as_slice())
            .map_err(|_| "checkpoint commit unavailable")?;
        transaction
            .commit()
            .map_err(|_| "checkpoint commit failed")?;
        Ok(())
    }
    pub fn latest_engineering_checkpoint(&self) -> Result<Option<Certificate>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "checkpoint read unavailable")?;
        if !transaction
            .list_tables()
            .map_err(|_| "checkpoint schema unavailable")?
            .any(|table| table.name() == ATTESTATIONS.name())
        {
            return Ok(None);
        }
        let table = transaction
            .open_table(ATTESTATIONS)
            .map_err(|_| "checkpoint table unavailable")?;
        let bytes = table
            .get("accepted")
            .map_err(|_| "checkpoint read failed")?;
        bytes
            .map(|value| Certificate::decode(value.value()))
            .transpose()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-checkpoint-fixture-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn certificate(
        candidate: &LocalCandidate,
        roster: &Roster,
        a: &Authority,
        b: &Authority,
    ) -> Certificate {
        Certificate {
            statement: candidate.statement.clone(),
            votes: vec![
                a.sign(candidate, roster).unwrap(),
                b.sign(candidate, roster).unwrap(),
            ],
        }
    }
    #[test]
    fn local_replay_refuses_signed_state_mismatch_fork_and_insufficient_confirmations() {
        let directory = Directory::new();
        let first_key = Directory::new();
        let second_key = Directory::new();
        let config = Config::development([34; 32], 0).unwrap();
        let binding = Binding::new(&config);
        let a = Authority::initialize(&first_key.0, binding).unwrap();
        let b = Authority::initialize(&second_key.0, binding).unwrap();
        assert!(Authority::initialize(&first_key.0, binding).is_err());
        assert_eq!(
            Authority::load(&first_key.0, binding).unwrap().public_key(),
            a.public_key()
        );
        let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
        let verifier = crate::fixtures::TestVerifier;
        let mut store =
            Store::open(directory.0.join("chain.redb"), config.clone(), &verifier).unwrap();
        assert!(
            store
                .engineering_checkpoint_candidate(&roster, 72, 1, 21_600, &verifier)
                .is_err()
        );
        for index in 0..96 {
            let block = crate::fixtures::candidate(store.state(), 1_000_000 + index * 10_000);
            store.append(&block, &verifier).unwrap();
        }
        let original = store.state().fingerprint();
        let candidate = store
            .engineering_checkpoint_candidate(&roster, 72, 1, 21_600, &verifier)
            .unwrap();
        let first = store
            .sign_engineering_checkpoint(&a, &roster, &candidate)
            .unwrap();
        assert_eq!(
            first.signature,
            store
                .sign_engineering_checkpoint(&a, &roster, &candidate)
                .unwrap()
                .signature
        );
        let good = certificate(&candidate, &roster, &a, &b);
        store
            .accept_engineering_checkpoint(&good, &roster, 21_600, &verifier)
            .unwrap();
        assert_eq!(
            store
                .latest_engineering_checkpoint()
                .unwrap()
                .unwrap()
                .statement,
            good.statement
        );
        let mut bad = store
            .engineering_checkpoint_candidate(&roster, 72, 2, 43_200, &verifier)
            .unwrap();
        bad.statement.state_fingerprint[0] ^= 1;
        let wrong_state = certificate(&bad, &roster, &a, &b);
        assert!(wrong_state.authenticate(&roster, None, 43_200).is_ok());
        assert!(
            store
                .accept_engineering_checkpoint(&wrong_state, &roster, 43_200, &verifier)
                .unwrap_err()
                .contains("urgent checkpoint mismatch")
        );
        let mut equivocation = store
            .engineering_checkpoint_candidate(&roster, 72, 2, 43_200, &verifier)
            .unwrap();
        assert!(a.sign(&equivocation, &roster).is_err());
        equivocation.statement.sequence = 3;
        equivocation.statement.block_id[0] ^= 1;
        assert!(
            store
                .sign_engineering_checkpoint(&a, &roster, &equivocation)
                .is_err()
        );
        let wrong_fork = certificate(&equivocation, &roster, &a, &b);
        assert!(
            store
                .accept_engineering_checkpoint(&wrong_fork, &roster, 43_200, &verifier)
                .is_err()
        );
        assert_eq!(store.state().fingerprint(), original);
        drop(store);
        let reopened =
            Store::open_existing(directory.0.join("chain.redb"), config, &verifier).unwrap();
        assert_eq!(reopened.state().fingerprint(), original);
        assert_eq!(
            reopened
                .latest_engineering_checkpoint()
                .unwrap()
                .unwrap()
                .statement,
            good.statement
        );
        assert_eq!(
            std::fs::metadata(first_key.0.join("engineering-checkpoint-authority.secret"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
