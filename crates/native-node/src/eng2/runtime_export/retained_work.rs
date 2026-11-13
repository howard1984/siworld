//! Retained artifact authentication on the existing single archive worker.
//! Captures and results carry no signing readiness or filesystem write access.
use super::archive_work::{ArchiveWork, NativeArchiveIdentity, ValidatedArchive};
use super::retained::Restored;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub(super) struct LiveArchive {
    statement: Statement,
    native: NativeArchiveIdentity,
    publication: Option<(Hash, u64)>,
}
impl LiveArchive {
    pub(super) fn capture(value: &PreparedCheckpoint) -> Option<Self> {
        // A proof may be offered for reuse only while its original charged
        // snapshot is still owned by Host. Installation checks this again.
        value._snapshot_reservation.as_ref()?;
        Some(Self {
            statement: value.statement.clone(),
            native: value._native_identity.clone()?,
            publication: None,
        })
    }
    pub(super) fn matches(&self, value: &PreparedCheckpoint) -> bool {
        value._snapshot_reservation.is_some()
            && value.statement == self.statement
            && value
                ._native_identity
                .as_ref()
                .is_some_and(|native| native.same_live_validation(&self.native))
    }
}
struct SavedPreparedInput {
    statement: Statement,
    witness: AuthorizationWitness,
    snapshot: Vec<u8>,
}
pub(super) enum PreparedResult {
    Owned(Box<PreparedCheckpoint>),
    Reuse(Box<LiveArchive>),
}
pub(super) struct PublicationResult {
    pub(super) prepared: PreparedResult,
    pub(super) certificate: Certificate,
    pub(super) published: u64,
}
pub(super) struct RetainedWork {
    read: crate::eng2::store::CheckpointRestoreRead,
    headers: Option<crate::eng2::branches::CheckpointHeaders>,
    reader: files::RetainedReader,
    budget: crate::p2p::Budget,
    limits: ImportLimits,
    generation: u64,
    material_generation: u64,
    retired_through: Option<u64>,
    latest: Option<LiveArchive>,
    pending: Option<LiveArchive>,
    collected_votes: [Option<Vote>; 3],
    local_vote_provenance: Option<(Statement, Vote)>,
}
pub(super) struct ValidatedRetained {
    pub(super) revision: crate::eng2::store::CheckpointRevision,
    pub(super) generation: u64,
    pub(super) material_generation: u64,
    pub(super) retired_through: Option<u64>,
    pub(super) authenticated_retired_through: Option<u64>,
    pub(super) material: Hash,
    pub(super) cursor: Option<Vec<u8>>,
    pub(super) latest: Restored<PublicationResult>,
    pub(super) pending: Restored<PreparedResult>,
}
impl RetainedWork {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture(
        store: &Store,
        headers: Option<crate::eng2::branches::CheckpointHeaders>,
        export: &PublicExport,
        limits: ImportLimits,
        budget: &crate::p2p::Budget,
        generation: u64,
        retired_through: Option<u64>,
        latest: Option<&CertifiedCheckpoint>,
        pending: Option<&PreparedCheckpoint>,
    ) -> Result<Self, String> {
        let mut live_latest = latest
            .map(|value| {
                LiveArchive::capture(&value.prepared)
                    .ok_or("checkpoint live publication lacks native reservation")
            })
            .transpose()?;
        let live_pending = pending
            .map(|value| {
                LiveArchive::capture(value)
                    .ok_or("checkpoint live pending lacks native reservation")
            })
            .transpose()?;
        if let (Some(value), Some(live)) = (latest, &mut live_latest) {
            let certificate = value
                .certificate
                .encode()
                .map_err(|_| "live checkpoint certificate framing invalid")?;
            live.publication = Some((*blake3::hash(&certificate).as_bytes(), value.published));
        }
        Ok(Self {
            read: store.capture_checkpoint_restore(budget)?,
            headers,
            reader: export.retained_reader(budget)?,
            budget: budget.clone(),
            limits,
            generation,
            material_generation: export.material_generation(),
            retired_through,
            latest: live_latest,
            pending: live_pending,
            collected_votes: std::array::from_fn(|_| None),
            local_vote_provenance: None,
        })
    }
    pub(super) fn bind_pending_votes(
        &mut self,
        collected: &[Option<Vote>; 3],
        local: Option<&(Statement, Vote)>,
    ) -> Result<(), String> {
        // Preserve the single known local durable source even across a pause
        // that removed live pending. A matching cold candidate must retain it.
        self.local_vote_provenance = local.cloned();
        if self.pending.is_none() {
            return Ok(());
        }
        for (slot, vote) in collected.iter().enumerate() {
            if vote
                .as_ref()
                .is_some_and(|vote| usize::from(vote.slot) != slot)
            {
                return Err("checkpoint collected vote slot differs".into());
            }
        }
        self.collected_votes = (*collected).clone();
        Ok(())
    }
    fn cancelled(cancelled: &AtomicBool) -> Result<(), String> {
        if cancelled.load(Ordering::Acquire) {
            Err("checkpoint retained restoration cancelled".into())
        } else {
            Ok(())
        }
    }
    fn prepared(
        &self,
        input: SavedPreparedInput,
        votes: &[Vote],
        certificate: Option<&Certificate>,
        reuse: Option<&LiveArchive>,
        cancelled: &AtomicBool,
    ) -> Result<Restored<PreparedResult>, String> {
        let SavedPreparedInput {
            statement,
            witness,
            snapshot,
        } = input;
        Self::cancelled(cancelled)?;
        if statement.network != self.read.network()
            || !confirmed_checkpoint(statement.checkpoint_height, statement.authorization_height)
            || statement.checkpoint_height > self.read.head()
            || snapshot.len() > self.limits.max_snapshot_bytes
        {
            return Err("saved checkpoint has invalid captured context or byte bound".into());
        }
        statement
            .encode()
            .map_err(|_| "saved checkpoint statement invalid")?;
        let anchor = self.read.header(statement.checkpoint_height)?;
        exact_saved_header(
            &anchor,
            statement.network,
            statement.checkpoint_height,
            statement.checkpoint_block,
        )?;
        let (authorization, current) = retained::authorization(
            statement.network,
            self.read.head(),
            &statement,
            |height| self.read.header(height),
            &mut |height, id| {
                self.headers
                    .as_ref()
                    .map(|headers| headers.header(height, id))
                    .transpose()
                    .map(Option::flatten)
            },
        )?;
        let roster = saved_roster(&statement, &witness, &authorization, self.limits)?;
        for vote in votes {
            verify_saved_vote(&roster, &statement, vote)?;
        }
        if let Some(certificate) = certificate {
            certificate
                .check_signatures(roster.keys())
                .map_err(|_| "checkpoint publication signatures invalid")?;
        }
        // Reading this input also binds the complete exact base archive and
        // every ordered raw suffix body/header. A prefix hash is insufficient.
        let work = ArchiveWork::from_restore_read(
            &self.read,
            statement.checkpoint_height,
            self.limits,
            &self.budget,
        )?;
        let reusable = reuse
            .filter(|live| live.statement == statement)
            .map(|live| live.native.matches(&work, &snapshot))
            .transpose()?
            .unwrap_or(false);
        let archive: Option<ValidatedArchive> = if reusable {
            None
        } else {
            let validated = work.validate(cancelled)?;
            if validated.snapshot_bytes() != snapshot {
                return Err(
                    "saved checkpoint snapshot differs from complete native reconstruction".into(),
                );
            }
            Some(validated)
        };
        Self::cancelled(cancelled)?;
        // Obsolete records must pass all of the same native, witness, vote and
        // certificate checks before they can retire an advertisement.
        let obsolete_candidate = certificate.is_none()
            && (self
                .retired_through
                .is_some_and(|floor| statement.checkpoint_height <= floor)
                || eligible_checkpoint(self.read.head())
                    .is_some_and(|height| statement.checkpoint_height < height)
                || roster.digest(statement.network) != self.read.roster());
        if !current || obsolete_candidate {
            return Ok(Restored::Retired(statement.checkpoint_height));
        }
        if reusable {
            return Ok(Restored::Current(PreparedResult::Reuse(Box::new(
                reuse.expect("matched live archive").clone(),
            ))));
        }
        let archive = archive.ok_or("checkpoint native restoration result missing")?;
        let identity = archive.identity();
        let metadata = std::mem::size_of::<CertifiedCheckpoint>()
            .checked_add(witness.governance.capacity())
            .ok_or("checkpoint retained metadata capacity overflow")?;
        // Drop raw saved snapshot before reducing the native workspace guard.
        drop(snapshot);
        let (snapshot, reservation) = archive.into_snapshot(metadata)?;
        Ok(Restored::Current(PreparedResult::Owned(Box::new(
            PreparedCheckpoint {
                network: statement.network,
                genesis: self.read.genesis_id(),
                rules: self.read.rules(),
                anchor,
                authorization,
                roster,
                statement,
                witness,
                snapshot,
                _snapshot_reservation: Some(reservation),
                _native_identity: Some(identity),
            },
        ))))
    }
    fn publication(
        &self,
        saved: files::SavedPublication,
        reuse: Option<&LiveArchive>,
        cancelled: &AtomicBool,
    ) -> Result<Restored<PublicationResult>, String> {
        if saved.published >= 1u64 << 53 {
            return Err("checkpoint publication time invalid".into());
        }
        if let Some((digest, published)) = reuse
            .filter(|live| {
                live.statement.checkpoint_height == saved.certificate.statement.checkpoint_height
            })
            .and_then(|live| live.publication)
        {
            let certificate = saved
                .certificate
                .encode()
                .map_err(|_| "saved certificate framing invalid")?;
            if digest != *blake3::hash(&certificate).as_bytes() || published != saved.published {
                return Err("checkpoint original certificate or publication time changed".into());
            }
        }
        let votes = self.reader.votes(&saved.certificate.statement)?;
        let prepared = self.prepared(
            SavedPreparedInput {
                statement: saved.certificate.statement.clone(),
                witness: saved.witness,
                snapshot: saved.snapshot,
            },
            &votes,
            Some(&saved.certificate),
            reuse,
            cancelled,
        )?;
        Ok(match prepared {
            Restored::Absent => Restored::Absent,
            Restored::Retired(height) => Restored::Retired(height),
            Restored::Current(prepared) => Restored::Current(PublicationResult {
                prepared,
                certificate: saved.certificate,
                published: saved.published,
            }),
        })
    }
    fn candidate_record(
        &self,
        epoch: u64,
        height: u64,
        required: Option<&LiveArchive>,
        cancelled: &AtomicBool,
    ) -> Result<Restored<PreparedResult>, String> {
        let mut candidate = match self.reader.candidate(epoch, height, self.limits)? {
            Some((statement, witness, snapshot)) => {
                if statement.checkpoint_height != height || statement.roster_sequence != epoch {
                    return Err("saved candidate filename context differs".into());
                }
                if required.is_some_and(|live| live.statement != statement) {
                    return Err("checkpoint live candidate statement changed".into());
                }
                let mut votes = self.reader.votes(&statement)?;
                if self
                    .local_vote_provenance
                    .as_ref()
                    .filter(|(known, _)| *known == statement)
                    .is_some_and(|(_, local)| !votes.contains(local))
                {
                    return Err("checkpoint known local vote journal missing or changed".into());
                }
                if required.is_some() {
                    // Remote votes have no implied disk journal. Both retained
                    // disk entries and captured memory votes are freshly checked.
                    for vote in self.collected_votes.iter().flatten() {
                        if !votes.contains(vote) {
                            votes.push(vote.clone());
                        }
                    }
                }
                self.prepared(
                    SavedPreparedInput {
                        statement,
                        witness,
                        snapshot,
                    },
                    &votes,
                    None,
                    required.or(self.latest.as_ref()),
                    cancelled,
                )?
            }
            None if required.is_some() => {
                return Err("checkpoint live candidate material missing".into());
            }
            None => Restored::Absent,
        };
        if let Some(bytes) = self.reader.withdrawn(height)? {
            let saved = self.reader.read_publication(&bytes, self.limits)?;
            if saved.certificate.statement.checkpoint_height != height {
                return Err("withdrawn publication filename context differs".into());
            }
            let proof = self
                .latest
                .as_ref()
                .filter(|live| live.statement.checkpoint_height == height)
                .or(required);
            let _authenticated = self.publication(saved, proof, cancelled)?;
            candidate = Restored::Retired(height);
        }
        Ok(candidate)
    }
    pub(super) fn validate(self, cancelled: &AtomicBool) -> Result<ValidatedRetained, String> {
        Self::cancelled(cancelled)?;
        let cursor = self.reader.read_optional("checkpoint-eng2.json", 8192)?;
        let latest = match &cursor {
            Some(bytes) => {
                let saved = self.reader.read_publication(bytes, self.limits)?;
                let original = self
                    .reader
                    .withdrawn(saved.certificate.statement.checkpoint_height)?
                    .ok_or("checkpoint original publication record missing")?;
                if original != *bytes {
                    return Err("checkpoint cursor differs from original publication record".into());
                }
                self.publication(saved, self.latest.as_ref(), cancelled)?
            }
            None if self.latest.is_some() => {
                return Err("checkpoint live publication cursor missing".into());
            }
            None => Restored::Absent,
        };
        // A captured live candidate is a required record at its own exact
        // filename, independently of the local eligible height or current epoch.
        // Noncadence checkpoint heights remain valid under existing rules.
        let mut pending = if let Some(live) = &self.pending {
            self.candidate_record(
                live.statement.roster_sequence,
                live.statement.checkpoint_height,
                Some(live),
                cancelled,
            )?
        } else {
            Restored::Absent
        };
        let mut authenticated_retired_through = match &pending {
            Restored::Retired(height) => Some(*height),
            _ => None,
        };
        if let Some(height) = eligible_checkpoint(self.read.head()) {
            let same_record = self.pending.as_ref().is_some_and(|live| {
                live.statement.checkpoint_height == height
                    && live.statement.roster_sequence == self.read.epoch()
            });
            if !same_record {
                let eligible = self.candidate_record(self.read.epoch(), height, None, cancelled)?;
                if let Restored::Retired(height) = &eligible {
                    authenticated_retired_through =
                        Some(authenticated_retired_through.map_or(*height, |old| old.max(*height)));
                }
                // An independently authenticated live pending statement keeps
                // priority. Merely scanning a different eligible filename cannot
                // delete it or authorize signing with unchecked saved bytes.
                if !matches!(&pending, Restored::Current(_)) {
                    pending = eligible;
                }
            }
        }
        Self::cancelled(cancelled)?;
        Ok(ValidatedRetained {
            revision: self.read.revision(),
            generation: self.generation,
            material_generation: self.material_generation,
            retired_through: self.retired_through,
            authenticated_retired_through,
            material: self.reader.material_identity(),
            cursor,
            latest,
            pending,
        })
    }
}

#[cfg(all(test, feature = "eng2-runtime"))]
mod tests;
